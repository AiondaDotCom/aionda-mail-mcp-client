/**
 * KAT-Generator (Known Answer Tests) - Meilenstein M0 der macOS-App.
 *
 * Erzeugt deterministische Testvektoren aus der ECHTEN TypeScript-Krypto
 * (src/crypto/ bzw. typescript/manager/*). Der Swift-Core in
 * src/apps/apple/Packages/AiondaMailCore wird byte-für-byte dagegen
 * verifiziert.
 *
 * Aufruf:  npm run generate-kat
 *
 * Grundsatz: Es wird KEINE Krypto-Logik nachgebaut. Wo die echten Funktionen
 * intern Zufall ziehen, wird der Zufall von außen injiziert
 * (kat/lib/deterministic.ts). Wo eine Schreibrichtung im Produktivcode fehlt
 * (Legacy-Label, Negativ-Fall), wird die Eingabe hier konstruiert und
 * anschließend mit der echten Leserichtung geprüft.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

// --- echte Krypto aus dem Produktivcode ---------------------------------
import {
    encryptClientAesGcm, encryptPhpAesGcm, decryptPhpAesGcm, decryptClientAesGcm, decryptVaultData,
} from '../src/crypto/aes-gcm';
import { unpadFromBucket, isBucketPadded } from '../src/crypto/bucket-padding';
import { decompress } from '../src/crypto/decompression';
import { toHex, fromHex, fromBase64 } from '../src/crypto/encoding';
import { hybridEncapsulate, hybridDecapsulate } from '../src/crypto/hybrid-kem';
import { deriveFolderKey } from '../src/crypto/key-derivation';
import {
    decryptTaskField, encryptTaskField, wrapTaskKey, unwrapTaskKey,
    TASKS_AAD_VERSION, TASKS_HKDF_INFO, LEGACY_HKDF_INFO, TASK_WRAP_VERSION,
} from '../src/crypto/tasks-crypto';

// --- Entsperr-Kette: echte Bausteine aus dem Web-Manager ------------------
// Diese Funktionen liegen nicht im MCP-Client, sondern im Manager - genau die
// laufen im Browser, also muessen genau die die Vektoren erzeugen.
import {
    ANTEILSFORMAT_V1, ANTEILSFORMAT_V2, AnteilsformatFehler,
    entpackeAnteil, verpackeImAnteilsformat, verpackungsschluessel,
} from '../../typescript/manager/vault/anteilsformat';
import {
    derivePasswordKey, encryptShare, decryptShare, shamirSplit, shamirReconstruct,
    PASSWORD_DERIVATION_ARGON2ID, PASSWORD_DERIVATION_PBKDF2,
} from '../../typescript/manager/vault/vault-crypto';
import {
    normalizeRecoveryMnemonicInput,
} from '../../typescript/manager/vault/vault-recovery-normalizer';

// --- Generator-Bausteine -------------------------------------------------
import {
    installDeterministicRandom, withScriptedRandom, scriptNextX25519Ephemeral,
    x25519PublicFromPrivate, SeededStream,
} from './lib/deterministic';
import {
    concat, utf8, gzip, padToBucket, aesGcmEncryptRaw, hkdfBits, sha256, wrapWithLabel,
} from './lib/helpers';
import type {
    AesGcmCase, EmailFieldCase, FixtureFile, GeneratorInfo, HybridKemCase,
    KeyDerivationCase, PackFormatCase, PackFormatFile, WrappedTaskKeyCase,
    EmailRoundtripMaterial,
    PasswordKeyCase, RecoveryHashCase, ShamirCase, ShareFormatCase, ShareFormatRejectedCase, ShareXorCase,
    TaskFieldCase, UnlockChainMaterial, VaultUnlockFile, WrappedTaskKeyFile,
    KeyFingerprintCase, KeyInstallCase, KeyPinShape, KeyTransitionCase, KeyTransitionChainWalk, KeyTransitionFile,
} from './lib/types';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
    fingerprintFull, fingerprintPreimage, formatFingerprint, installRecord, seedAad, transitionRecord,
    INSTALL_CONTEXT, TRANSITION_CONTEXT, TRANSITION_REASON, TRANSITION_REASON_NAMES,
} from '../src/crypto/key-transition';
import type { TransitionReason } from '../src/crypto/key-transition';

const HERE = dirname(fileURLToPath(import.meta.url));
// Beim gebundelten Lauf liegt die Datei in kat/.build/ - dann eine Ebene hoch.
const KAT_DIR = HERE.endsWith('.build') ? dirname(HERE) : HERE;
const FIXTURE_DIR = process.env['AIONDA_KAT_OUTPUT_DIR']
    ? resolve(process.env['AIONDA_KAT_OUTPUT_DIR'])
    : join(KAT_DIR, 'fixtures');

const GENERATOR: GeneratorInfo = {
    source: '@aiondadotcom/mail-mcp-client@0.15.0',
    date: '2026-07-27',
};

const FOLDER_KEY_SALT = 'trashmail-folder-key-v1';

installDeterministicRandom('aionda-kat-v1');

/** Fester Byte-Strom für alle Schlüssel/IVs/Salts der Fixtures. */
const material = new SeededStream('aionda-kat-material-v1');

function writeFixture(fileName: string, payload: unknown): void {
    mkdirSync(FIXTURE_DIR, { recursive: true });
    writeFileSync(join(FIXTURE_DIR, fileName), `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

/** Wirft, wenn eine Erwartung verletzt ist - der Generator darf nie stillschweigend Müll schreiben. */
function assert(condition: boolean, message: string): asserts condition {
    if (!condition) { throw new Error(`KAT-Generator: ${message}`); }
}

// ===========================================================================
// 1. aes_gcm.json
// ===========================================================================

/** Klartexte: leer, 1 Byte, Umlaute/Emoji, 2048-Byte-Grenzfall. */
const AES_PLAINTEXTS: { slug: string; text: string }[] = [
    { slug: 'empty', text: '' },
    { slug: 'single_byte', text: 'A' },
    { slug: 'umlauts_emoji', text: 'Grüße aus München: äöü ÄÖÜ ß, Wetter schön 🌞📧 Straße' },
    { slug: 'boundary_2048', text: 'x'.repeat(2048) },
];

async function buildAesGcm(): Promise<FixtureFile<AesGcmCase>> {
    const cases: AesGcmCase[] = [];

    for (const { slug, text } of AES_PLAINTEXTS) {
        const key = material.bytes(32);
        const iv = material.bytes(12);
        const plain = utf8(text);

        // a) WebCrypto-Layout wie es Aufgaben-/Client-Felder speichern:
        //    iv(12) || ciphertext || tag  (echte Funktion: encryptTaskField)
        const stored = await encryptClientAesGcm(plain, key, iv);
        assert(toHex(stored.slice(0, 12)) === toHex(iv), `${slug}: IV nicht vorangestellt`);

        cases.push({
            name: `webcrypto_iv_prefixed_${slug}`,
            layout: 'webcrypto',
            blob_layout: 'iv||ciphertext||tag',
            key: toHex(key), iv: toHex(iv),
            plaintext: toHex(plain), plaintext_utf8: text,
            stored_blob: toHex(stored),
        });

        // b) WebCrypto-Layout mit separatem IV (z. B. encrypted_content_html):
        //    ciphertext || tag - identische Bytes, nur ohne IV-Präfix.
        cases.push({
            name: `webcrypto_detached_iv_${slug}`,
            layout: 'webcrypto',
            blob_layout: 'ciphertext||tag',
            key: toHex(key), iv: toHex(iv),
            plaintext: toHex(plain), plaintext_utf8: text,
            stored_blob: toHex(stored.slice(12)),
        });

        // c) PHP-Layout: nonce(12) || tag(16) || ciphertext (echte Funktion)
        const phpKey = material.bytes(32);
        const phpIv = material.bytes(12);
        const phpBlob = await withScriptedRandom([phpIv], () => encryptPhpAesGcm(plain, phpKey));
        const check = await decryptPhpAesGcm(phpBlob, phpKey);
        assert(toHex(check) === toHex(plain), `${slug}: PHP-Roundtrip fehlgeschlagen`);

        cases.push({
            name: `php_${slug}`,
            layout: 'php',
            blob_layout: 'nonce||tag||ciphertext',
            key: toHex(phpKey), iv: toHex(phpIv),
            plaintext: toHex(plain), plaintext_utf8: text,
            stored_blob: toHex(phpBlob),
        });
    }

    return {
        generator: GENERATOR,
        encoding: 'Alle Binärfelder lowercase Hex. blob_layout beschreibt, wie stored_blob persistiert wird.',
        cases,
    };
}

// ===========================================================================
// 2. key_derivation.json
// ===========================================================================

async function buildKeyDerivation(): Promise<FixtureFile<KeyDerivationCase>> {
    const cases: KeyDerivationCase[] = [];

    // Master Key = SHA-256(vault_key_string) - siehe src/proxy.ts bootstrap()
    for (const vaultKey of ['aionda-kat-vault-key', 'Schlüssel-mit-Ümläuten-und-ß-🔐']) {
        const digest = await sha256(utf8(vaultKey));
        cases.push({
            name: `sha256_master_${vaultKey.startsWith('aionda') ? 'ascii' : 'utf8'}`,
            kind: 'sha256_master',
            input: toHex(utf8(vaultKey)), input_utf8: vaultKey,
            salt: '', info: '',
            expected: toHex(digest),
        });
    }

    const masterKey = material.bytes(32);

    // HKDF mit dem Ordner-Label (echte Funktion deriveFolderKey)
    const folderUuid = 'c42f5c98-4a53-4bbb-9389-1ecb67e4577d';
    const folderKey = await deriveFolderKey(masterKey, folderUuid);
    const folderKeyCheck = await hkdfBits(masterKey, utf8(FOLDER_KEY_SALT), utf8(folderUuid));
    assert(toHex(folderKey) === toHex(folderKeyCheck), 'deriveFolderKey weicht von HKDF-Referenz ab');
    cases.push({
        name: 'hkdf_folder_key_v1',
        kind: 'hkdf',
        input: toHex(masterKey),
        salt: toHex(utf8(FOLDER_KEY_SALT)), salt_utf8: FOLDER_KEY_SALT,
        info: toHex(utf8(folderUuid)), info_utf8: folderUuid,
        expected: toHex(folderKey),
    });

    // HKDF mit den beiden Wrapping-Labels. Der Produktivcode leitet einen nicht
    // exportierbaren CryptoKey ab; die rohen Bytes kommen deshalb aus deriveBits
    // mit identischen Parametern. Die Gleichheit beider Wege wird in
    // verify-kat.ts nachgewiesen (Wrap mit deriveKey, Entpacken mit den Bytes).
    const wrapSalt = material.bytes(32);
    for (const label of [TASKS_HKDF_INFO, LEGACY_HKDF_INFO]) {
        cases.push({
            name: `hkdf_${label}`,
            kind: 'hkdf',
            input: toHex(masterKey),
            salt: toHex(wrapSalt),
            info: toHex(utf8(label)), info_utf8: label,
            expected: toHex(await hkdfBits(masterKey, wrapSalt, utf8(label))),
        });
    }

    // HKDF mit leerem Salt - Randfall, den CryptoKit anders defaulten könnte.
    cases.push({
        name: 'hkdf_empty_salt',
        kind: 'hkdf',
        input: toHex(masterKey),
        salt: '',
        info: toHex(utf8(TASKS_HKDF_INFO)), info_utf8: TASKS_HKDF_INFO,
        expected: toHex(await hkdfBits(masterKey, new Uint8Array(0), utf8(TASKS_HKDF_INFO))),
    });

    return {
        generator: GENERATOR,
        encoding: 'input/salt/info/expected lowercase Hex. *_utf8 sind Lesehilfen mit denselben Bytes. '
            + 'kind=sha256_master: expected = SHA-256(input). kind=hkdf: HKDF-SHA-256(ikm=input, salt, info) -> 32 Byte.',
        cases,
    };
}

// ===========================================================================
// 3. wrapped_key_tasks.json  (93 Byte: version(1) || salt(32) || iv(12) || ct+tag)
// ===========================================================================

async function buildWrappedTaskKeys(): Promise<WrappedTaskKeyFile> {
    const cases: WrappedTaskKeyCase[] = [];
    const fieldCases: TaskFieldCase[] = [];
    const masterKey = material.bytes(32);

    // a) Aktuelles Label - erzeugt von der echten wrapTaskKey()
    const saltA = material.bytes(32);
    const ivA = material.bytes(12);
    const payloadA = material.bytes(32);
    const blobA = await withScriptedRandom([saltA, ivA], () => wrapTaskKey(payloadA, masterKey));
    assert(blobA.length === 93, `wrapTaskKey lieferte ${blobA.length} statt 93 Byte`);
    assert(blobA[0] === TASK_WRAP_VERSION, 'Falsches Versionsbyte');
    assert(toHex(await unwrapTaskKey(blobA, masterKey)) === toHex(payloadA), 'tasks-v1 Roundtrip fehlgeschlagen');
    cases.push({
        name: 'tasks_v1',
        master_key: toHex(masterKey), salt: toHex(saltA), iv: toHex(ivA),
        payload_key: toHex(payloadA), label: TASKS_HKDF_INFO,
        additional_data_utf8: `${TASKS_AAD_VERSION}:wrapped-key`,
        wrapped_blob: toHex(blobA),
    });

    // b) Altes Kontakte-Label - Dual-Read muss das noch lesen können.
    //    Der Produktivcode schreibt dieses Layout nur über encryptVaultData();
    //    hier von Hand gebaut und mit BEIDEN echten Lesepfaden gegengeprüft.
    const saltB = material.bytes(32);
    const ivB = material.bytes(12);
    const payloadB = material.bytes(32);
    const blobB = await wrapWithLabel(payloadB, masterKey, saltB, ivB, LEGACY_HKDF_INFO, TASK_WRAP_VERSION);
    assert(blobB.length === 93, 'Legacy-Blob hat nicht 93 Byte');
    assert(toHex(await unwrapTaskKey(blobB, masterKey)) === toHex(payloadB), 'Dual-Read (contacts-v2) fehlgeschlagen');
    assert(toHex(await decryptVaultData(blobB, masterKey)) === toHex(payloadB), 'decryptVaultData liest Legacy-Blob nicht');
    cases.push({
        name: 'contacts_v2_dual_read',
        master_key: toHex(masterKey), salt: toHex(saltB), iv: toHex(ivB),
        payload_key: toHex(payloadB), label: LEGACY_HKDF_INFO,
        wrapped_blob: toHex(blobB),
    });

    // c) Negativ: fremdes Label -> beide Dual-Read-Versuche müssen scheitern.
    const saltC = material.bytes(32);
    const ivC = material.bytes(12);
    const payloadC = material.bytes(32);
    const bogusLabel = 'trashmail-bogus-v1';
    const blobC = await wrapWithLabel(payloadC, masterKey, saltC, ivC, bogusLabel, TASK_WRAP_VERSION);
    let threw = false;
    try { await unwrapTaskKey(blobC, masterKey); } catch { threw = true; }
    assert(threw, 'Negativ-Fall wurde fälschlich entpackt');
    cases.push({
        name: 'wrong_label_fails',
        master_key: toHex(masterKey), salt: toHex(saltC), iv: toHex(ivC),
        payload_key: toHex(payloadC), label: bogusLabel,
        wrapped_blob: toHex(blobC),
        expect: 'auth_failure',
    });

    // d) Die fünf produktiven Feldkontexte. Gleiche Bytes unter einem anderen
    // Kontext müssen an der Authentifizierung scheitern.
    for (const context of ['title', 'notes', 'steps', 'metadata', 'list-name']) {
        const fieldKey = material.bytes(32);
        const fieldIv = material.bytes(12);
        const plaintext = `KAT ${context}: Grüße 🔐`;
        const storedBase64 = await withScriptedRandom(
            [fieldIv],
            () => encryptTaskField(plaintext, fieldKey, context)
        );
        fieldCases.push({
            name: `task_field_${context}`,
            task_key: toHex(fieldKey),
            iv: toHex(fieldIv),
            plaintext_utf8: plaintext,
            field_context: context,
            additional_data_utf8: `${TASKS_AAD_VERSION}:${context}`,
            stored_blob: toHex(fromBase64(storedBase64)),
        });
    }

    // e) Altbestand ohne AAD bleibt lesbar. Die Schreibseite existiert im
    // Produktivcode bewusst nicht mehr, daher wird nur dieser Eingabeblob
    // konstruiert und danach mit decryptTaskField() gegengeprüft.
    const legacyKey = material.bytes(32);
    const legacyIv = material.bytes(12);
    const legacyText = 'Legacy-Titel ohne AAD';
    const legacyBlob = concat(legacyIv, await aesGcmEncryptRaw(utf8(legacyText), legacyKey, legacyIv));
    assert(
        await decryptTaskField(Buffer.from(legacyBlob).toString('base64'), legacyKey, 'title') === legacyText,
        'Legacy-Aufgabenfeld ohne AAD ist nicht mehr lesbar'
    );
    fieldCases.push({
        name: 'task_field_legacy_without_aad',
        task_key: toHex(legacyKey),
        iv: toHex(legacyIv),
        plaintext_utf8: legacyText,
        field_context: 'title',
        stored_blob: toHex(legacyBlob),
    });

    return {
        generator: GENERATOR,
        encoding: 'wrapped_blob = version(0x02) || salt(32) || iv(12) || ciphertext+tag(48) = 93 Byte. '
            + 'Wrapping-Key = HKDF-SHA-256(ikm=master_key, salt, info=label). '
            + `Aktuelle Blobs authentifizieren ${TASKS_AAD_VERSION}:wrapped-key. `
            + 'expect="auth_failure": das Entpacken MUSS scheitern (kein Klartext-Fallback). '
            + 'field_cases decken alle produktiven Feldkontexte und einen Legacy-Fall ohne AAD ab.',
        cases,
        field_cases: fieldCases,
    };
}

// ===========================================================================
// 4. email_field.json  (clientseitig verschlüsseltes Feld, z. B. encrypted_subject)
// ===========================================================================

interface EmailFieldSpec {
    name: string;
    text: string;
    compress: boolean;
    pad: boolean;
}

const EMAIL_FIELD_SPECS: EmailFieldSpec[] = [
    { name: 'subject_plain', text: 'Rechnung 2026-07 für Aionda GmbH', compress: false, pad: false },
    { name: 'subject_umlauts_emoji', text: 'Grüße aus München: Straße, Öl, Übung ✉️🔐', compress: false, pad: false },
    { name: 'body_html_gzip', text: `<html><body><p>${'Sehr geehrte Damen und Herren, '.repeat(40)}</p></body></html>`, compress: true, pad: false },
    { name: 'body_gzip_bucket_padded', text: `Vertraulicher Text. ${'Wiederholung zur Kompression. '.repeat(30)}`, compress: true, pad: true },
];

async function buildEmailField(): Promise<FixtureFile<EmailFieldCase>> {
    const cases: EmailFieldCase[] = [];
    const vaultKeyString = 'kat-vault-key-2026';
    const masterKey = await sha256(utf8(vaultKeyString));

    for (const spec of EMAIL_FIELD_SPECS) {
        const iv = material.bytes(12);
        const plain = utf8(spec.text);

        let payload = plain;
        if (spec.compress) { payload = gzip(payload); }
        if (spec.pad) { payload = padToBucket(payload, material.bytes(64)); }

        // Persistiertes Feld: iv(12) || ciphertext || tag
        const stored = concat(iv, await aesGcmEncryptRaw(payload, masterKey, iv));

        // Gegenprobe über den echten Lesepfad des MCP-Clients.
        let decoded = await decryptClientAesGcm(stored, masterKey);
        if (isBucketPadded(decoded)) { decoded = unpadFromBucket(decoded); }
        decoded = await decompress(decoded);
        assert(new TextDecoder().decode(decoded) === spec.text, `${spec.name}: Lesepfad liefert falschen Text`);

        cases.push({
            name: spec.name,
            vault_key_string: vaultKeyString,
            master_key: toHex(masterKey),
            iv: toHex(iv),
            plaintext: toHex(plain), plaintext_utf8: spec.text,
            stored_blob: toHex(stored),
            compressed: spec.compress,
            padded: spec.pad,
        });
    }

    return {
        generator: GENERATOR,
        encoding: 'master_key = SHA-256(UTF-8(vault_key_string)). stored_blob = iv(12) || ciphertext || tag(16). '
            + 'Lesepfad: AES-GCM entschlüsseln -> Bucket-Padding (0xDEAD) entfernen -> gzip (0x1f8b) entpacken -> UTF-8. '
            + 'plaintext ist der Klartext VOR Kompression/Padding.',
        cases,
    };
}

// ===========================================================================
// 5. hybrid_kem.json  (X25519 + ML-KEM-1024)
// ===========================================================================

interface KemVectors {
    cases: HybridKemCase[];
    /** Rohmaterial des ersten Falls für den Pack-/Mail-Roundtrip. */
    first: {
        x25519Private: Uint8Array;
        mlkemPrivate: Uint8Array;
        x25519Public: Uint8Array;
        mlkemPublic: Uint8Array;
    };
}

async function buildHybridKem(): Promise<{ file: FixtureFile<HybridKemCase>; vectors: KemVectors }> {
    const cases: HybridKemCase[] = [];
    let first: KemVectors['first'] | null = null;

    for (const label of ['recipient_a', 'recipient_b']) {
        const recipientX25519Priv = material.bytes(32);
        const recipientX25519Pub = x25519PublicFromPrivate(recipientX25519Priv);

        // ML-KEM-1024: keygen(seed) mit 64-Byte-Seed d||z (FIPS 203).
        // Genau diese Seed-Darstellung importiert CryptoKit auf Swift-Seite.
        const mlkemSeed = material.bytes(64);
        const mlkemKeys = ml_kem1024.keygen(mlkemSeed);

        // Absenderseite deterministisch machen: ephemerer X25519-Key +
        // ML-KEM-Nachricht m werden vorgegeben, danach läuft die ECHTE
        // hybridEncapsulate().
        const ephemeralPriv = material.bytes(32);
        const mlkemMessage = material.bytes(32);
        scriptNextX25519Ephemeral(ephemeralPriv);

        const result = await withScriptedRandom([mlkemMessage], () =>
            hybridEncapsulate(recipientX25519Pub, mlkemKeys.publicKey)
        );

        // Gegenprobe mit der echten Decapsulation.
        const back = await hybridDecapsulate(
            result.x25519Ciphertext, result.mlKemCiphertext,
            recipientX25519Priv, mlkemKeys.secretKey
        );
        assert(toHex(back) === toHex(result.sharedSecret), `${label}: KEM-Roundtrip fehlgeschlagen`);
        assert(result.mlKemCiphertext.length === 1568, 'ML-KEM-Ciphertext hat nicht 1568 Byte');
        assert(toHex(result.x25519Ciphertext) === toHex(x25519PublicFromPrivate(ephemeralPriv)),
            'Ephemerer Public Key wurde nicht injiziert');

        cases.push({
            name: `hybrid_kem_1024_${label}`,
            x25519_private: toHex(recipientX25519Priv),
            x25519_public: toHex(recipientX25519Pub),
            mlkem_seed: toHex(mlkemSeed),
            mlkem_public: toHex(mlkemKeys.publicKey),
            mlkem_private: toHex(mlkemKeys.secretKey),
            x25519_ephemeral_private: toHex(ephemeralPriv),
            mlkem_message: toHex(mlkemMessage),
            kem_x25519_ct: toHex(result.x25519Ciphertext),
            kem_mlkem_ct: toHex(result.mlKemCiphertext),
            shared_secret: toHex(result.sharedSecret),
        });

        if (!first) {
            first = {
                x25519Private: recipientX25519Priv,
                mlkemPrivate: mlkemKeys.secretKey,
                x25519Public: recipientX25519Pub,
                mlkemPublic: mlkemKeys.publicKey,
            };
        }
    }

    assert(first !== null, 'Kein KEM-Fall erzeugt');

    const file: FixtureFile<HybridKemCase> = {
        generator: GENERATOR,
        encoding: 'X25519 + ML-KEM-1024. shared_secret = HKDF-SHA-256(ikm = x25519_shared(32) || mlkem_shared(32), '
            + "salt = leer, info = UTF-8('trashmail-hybrid-kem-v1'), 32 Byte). "
            + 'mlkem_seed ist die 64-Byte-Seed-Darstellung d||z (FIPS 203 KeyGen) - genau die Form, die CryptoKit '
            + 'zum Import eines ML-KEM-Private-Keys erwartet. kem_x25519_ct = ephemerer X25519-Public-Key des Absenders. '
            + 'x25519_ephemeral_private und mlkem_message erlauben, die Encapsulation exakt zu reproduzieren.',
        cases,
    };

    return { file, vectors: { cases, first } };
}

// ===========================================================================
// 6. pack_format.json  (1661 Byte: version(1) || x25519(32) || mlkem(1568) || nonce(12) || wrapped+tag(48))
// ===========================================================================

const PACK_SIZE = 1 + 32 + 1568 + 12 + 48;

function packWrappedKey(
    version: number, x25519Ct: Uint8Array, mlkemCt: Uint8Array, nonce: Uint8Array, wrapped: Uint8Array
): Uint8Array {
    const blob = concat(new Uint8Array([version]), x25519Ct, mlkemCt, nonce, wrapped);
    assert(blob.length === PACK_SIZE, `Pack hat ${blob.length} statt ${PACK_SIZE} Byte`);
    return blob;
}

function packCase(
    name: string, version: number,
    x25519Ct: Uint8Array, mlkemCt: Uint8Array, nonce: Uint8Array, wrapped: Uint8Array
): PackFormatCase {
    return {
        name,
        blob: toHex(packWrappedKey(version, x25519Ct, mlkemCt, nonce, wrapped)),
        parsed: {
            version,
            x25519_ct: toHex(x25519Ct),
            mlkem_ct: toHex(mlkemCt),
            nonce: toHex(nonce),
            wrapped_key: toHex(wrapped),
        },
    };
}

async function buildPackFormat(vectors: KemVectors): Promise<PackFormatFile> {
    // a) Rein synthetischer Parse-Fall mit erkennbaren Mustern.
    const synthetic = packCase(
        'synthetic_pattern', 1,
        new Uint8Array(32).fill(0x11),
        new Uint8Array(1568).fill(0x22),
        new Uint8Array(12).fill(0x33),
        new Uint8Array(48).fill(0x44),
    );

    // b) Echter Fall: Hybrid-KEM aus hybrid_kem.json, dazu ein mit dem
    //    Shared Secret gewrappter Ephemeral-Key im PHP-Layout tag(16) || ct(32).
    const kem = vectors.cases[0];
    const sharedSecret = await hybridDecapsulate(
        fromHex(kem.kem_x25519_ct), fromHex(kem.kem_mlkem_ct),
        vectors.first.x25519Private, vectors.first.mlkemPrivate
    );
    assert(toHex(sharedSecret) === kem.shared_secret, 'Shared Secret weicht ab');

    const ephemeralKey = material.bytes(32);
    const wrapNonce = material.bytes(12);
    const ctPlusTag = await aesGcmEncryptRaw(ephemeralKey, sharedSecret, wrapNonce);
    // PHP-Reihenfolge für den gewrappten Key: tag(16) || ciphertext(32)
    const wrapped = concat(ctPlusTag.slice(32), ctPlusTag.slice(0, 32));
    assert(wrapped.length === 48, 'Gewrappter Key hat nicht 48 Byte');

    const real = packCase(
        'real_hybrid_kem_wrap', 1,
        fromHex(kem.kem_x25519_ct), fromHex(kem.kem_mlkem_ct), wrapNonce, wrapped
    );

    // Vollständige Mail dazu: Felder im PHP-Layout mit dem Ephemeral-Key.
    const subject = 'Quartalsbericht Q3 – vertraulich 🔐';
    const from = 'Stephan Ferraro <stephan.ferraro@aionda.com>';
    const to = 'kontakt-jw5fm6hm@dev.trashmail.com';
    const encField = async (text: string): Promise<string> =>
        toHex(await withScriptedRandom([material.bytes(12)], () =>
            encryptPhpAesGcm(utf8(text), ephemeralKey)));

    const roundtrip: EmailRoundtripMaterial = {
        x25519_private: toHex(vectors.first.x25519Private),
        mlkem_private: toHex(vectors.first.mlkemPrivate),
        ephemeral_key: toHex(ephemeralKey),
        wrapped_ephemeral_key: real.blob,
        encrypted_subject: await encField(subject),
        encrypted_from: await encField(from),
        encrypted_to: await encField(to),
        subject_utf8: subject,
        from_utf8: from,
        to_utf8: to,
    };

    return {
        generator: GENERATOR,
        encoding: 'blob = version(1) || x25519_ct(32) || mlkem_ct(1568) || nonce(12) || wrapped_key(48) = 1661 Byte. '
            + 'wrapped_key liegt im PHP-Layout tag(16) || ciphertext(32) vor und wird mit dem Hybrid-KEM-Shared-Secret '
            + 'und nonce entschlüsselt. email_roundtrip enthält eine komplette Mail für den End-zu-End-Test.',
        cases: [synthetic, real],
        email_roundtrip: roundtrip,
    };
}

// ===========================================================================
// 7. vault_unlock.json - Entsperrung eines menschlichen Postfachs
// ===========================================================================

/**
 * Ein Mensch hat keinen `tmv_`-Vault-Schluessel. Sein Master Key entsteht aus
 * zwei von drei Shamir-Anteilen. Diese Fixtures decken jeden Schritt der Kette
 * einzeln ab - und einmal die ganze Kette am Stueck.
 */
async function buildVaultUnlock(): Promise<VaultUnlockFile> {
    const passwordKeys: PasswordKeyCase[] = [];

    // PBKDF2-SHA256 mit 600.000 Runden ist absichtlich langsam; drei Faelle
    // reichen, um Kodierung (UTF-8!) und Salz-Behandlung festzunageln.
    //
    // 🚩 #478cc256 - JEDER Fall gibt es BEIDE Verfahren. Der Grund steht im
    // Ticket: Bleiben die Vektoren beim alten Verfahren, pruefen die Tests
    // weiter PBKDF2 und werden gruen, waehrend der Code Argon2id rechnet.
    // Und andersherum: faellt der PBKDF2-Zweig aus den Vektoren, merkt
    // niemand, wenn der Altbestand unlesbar wird - und der Altbestand ist
    // bei einer KDF-Migration genau der Teil, der nicht kaputtgehen darf.
    const passwords = [
        { name: 'ascii', value: 'correct-horse-battery-staple' },
        { name: 'umlaute', value: 'Käsebrötchen-mit-Soße-99!' },
        { name: 'emoji', value: 'schlüssel🔐ende' },
    ];
    for (const { name, value } of passwords) {
        const salt = material.bytes(32);

        const pbkdf2 = await derivePasswordKey(value, salt, PASSWORD_DERIVATION_PBKDF2);
        assert(pbkdf2.length === 32, 'derivePasswordKey muss 32 Byte liefern');
        passwordKeys.push({
            name: `pbkdf2_${name}`,
            password_utf8: value,
            password: toHex(utf8(value)),
            salt: toHex(salt),
            derivation: PASSWORD_DERIVATION_PBKDF2,
            iterations: 600000,
            memory_kib: null,
            parallelism: null,
            expected: toHex(pbkdf2),
        });

        // Dasselbe Passwort, dasselbe Salz, anderes Verfahren - damit steht in
        // der Fixture schwarz auf weiss, dass die beiden Zweige verschiedene
        // Schluessel liefern. Wer sie verwechselt, faellt hier auf.
        const argon2 = await derivePasswordKey(value, salt, PASSWORD_DERIVATION_ARGON2ID);
        assert(argon2.length === 32, 'derivePasswordKey muss 32 Byte liefern');
        assert(toHex(argon2) !== toHex(pbkdf2), 'Argon2id und PBKDF2 duerfen nicht dasselbe liefern');
        passwordKeys.push({
            name: `argon2id_${name}`,
            password_utf8: value,
            password: toHex(utf8(value)),
            salt: toHex(salt),
            derivation: PASSWORD_DERIVATION_ARGON2ID,
            iterations: 3,
            memory_kib: 65536,
            parallelism: 4,
            expected: toHex(argon2),
        });
    }

    // Der Recovery-Hash ist SHA-256 ueber die NORMALISIERTE Eingabe. Die
    // Normalisierung ist der fehleranfaellige Teil: Nutzer tippen Nummern,
    // Zeilenumbrueche und Grossbuchstaben mit hinein.
    const cleanMnemonic =
        'alter seek seminar goose enemy uncover forest toy head invite cousin yellow '
        + 'absurd design clown stone army wheel arrow ladder valve merge real kite';
    const messyMnemonic =
        '1. Alter\r\n2. Seek\r\n3. Seminar\r\n4. Goose\r\n5. Enemy\r\n6. Uncover\r\n'
        + '7. Forest\r\n8. Toy\r\n9. Head\r\n10. Invite\r\n11. Cousin\r\n12. Yellow\r\n'
        + '13. Absurd\r\n14. Design\r\n15. Clown\r\n16. Stone\r\n17. Army\r\n18. Wheel\r\n'
        + '19. Arrow\r\n20. Ladder\r\n21. Valve\r\n22. Merge\r\n23. Real\r\n24. Kite';

    const recoveryHashes: RecoveryHashCase[] = [];
    for (const [name, raw] of [['clean', cleanMnemonic], ['numbered_crlf', messyMnemonic]] as const) {
        const normalized = normalizeRecoveryMnemonicInput(raw);
        const digest = await sha256(utf8(normalized));
        recoveryHashes.push({
            name: `recovery_${name}`,
            raw_input: raw,
            normalized,
            expected: toHex(digest),
        });
    }
    assert(
        recoveryHashes[0].expected === recoveryHashes[1].expected,
        'Normalisierung muss saubere und unsaubere Eingabe auf denselben Hash bringen'
    );

    // XOR ist seine eigene Umkehrung - der Test faengt Laengen- und
    // Offset-Fehler, nicht die Mathematik.
    const shareXor: ShareXorCase[] = [];
    for (const name of ['share_xor_random', 'share_xor_short_key']) {
        const share = material.bytes(32);
        const derivedKey = material.bytes(32);
        const encrypted = encryptShare(share, derivedKey);
        assert(
            toHex(decryptShare(encrypted, derivedKey)) === toHex(share),
            'XOR-Roundtrip muss den Anteil zurueckgeben'
        );
        shareXor.push({
            name,
            share: toHex(share),
            derived_key: toHex(derivedKey),
            encrypted: toHex(encrypted),
        });
    }

    // Shamir 2-von-3 mit allen drei moeglichen Paaren.
    const secret = material.bytes(32);
    const split = shamirSplit(secret, 3, 2);
    const shamirCases: ShamirCase[] = [];
    for (const pair of [[1, 2], [1, 3], [2, 3]]) {
        const picked = split.filter(s => pair.includes(s.x));
        assert(
            toHex(shamirReconstruct(picked)) === toHex(secret),
            `Shamir-Rekonstruktion aus ${pair.join('+')} muss das Geheimnis treffen`
        );
        shamirCases.push({
            name: `shamir_2of3_${pair.join('_')}`,
            secret: toHex(secret),
            shares: split.map(s => ({ x: s.x, data: toHex(s.data) })),
            reconstruct_from: pair,
        });
    }

    // --- die ganze Kette --------------------------------------------------
    // Genau so liegt ein echtes Postfach in der Datenbank: drei verschluesselte
    // Anteile plus ein Master-Key-verschluesselter Schluesselbund.
    const chainPassword = 'ban@nwe4hew8crz3BDM';
    const chainMnemonic = cleanMnemonic;

    const recoveryHash = await sha256(utf8(normalizeRecoveryMnemonicInput(chainMnemonic)));

    /**
     * Baut eine vollstaendige Entsperr-Kette fuer EIN Ableitungsverfahren.
     *
     * 🚩 #478cc256 - Eine Funktion statt zweier abgeschriebener Bloecke. Zwei
     * Abschriften waeren genau die Zwillingsbildung, an der dieses Haus schon
     * mehrfach haengengeblieben ist; und eine Kette, die nur fuer ein
     * Verfahren existiert, kann die andere Richtung der Migration gar nicht
     * belegen.
     */
    async function baueKette(
        derivation: typeof PASSWORD_DERIVATION_PBKDF2 | typeof PASSWORD_DERIVATION_ARGON2ID
    ): Promise<UnlockChainMaterial> {
        const kettenMaster = material.bytes(32);
        const anteile = shamirSplit(kettenMaster, 3, 2);

        const passwordSalt = material.bytes(32);
        const passwordKey = await derivePasswordKey(chainPassword, passwordSalt, derivation);
        const passkeyPrf = material.bytes(32);

        const encryptedByType = [
            {
                index: anteile[0].x, type: 'password' as const, key: passwordKey,
                salt: toHex(passwordSalt), derivation
            },
            { index: anteile[1].x, type: 'passkey' as const, key: passkeyPrf, salt: undefined },
            { index: anteile[2].x, type: 'recovery' as const, key: recoveryHash, salt: undefined },
        ].map((entry, i) => ({
            index: entry.index,
            type: entry.type,
            encrypted: toHex(encryptShare(anteile[i].data, entry.key)),
            ...(entry.salt ? { salt: entry.salt } : {}),
            ...('derivation' in entry && entry.derivation ? { derivation: entry.derivation } : {}),
        }));

        // Gegenprobe im Generator selbst: Passwort + Wiederherstellung ergeben
        // den Master Key. Was hier nicht aufgeht, darf gar nicht als Fixture raus.
        const rebuilt = shamirReconstruct([
            { x: anteile[0].x, data: decryptShare(fromHex(encryptedByType[0].encrypted), passwordKey) },
            { x: anteile[2].x, data: decryptShare(fromHex(encryptedByType[2].encrypted), recoveryHash) },
        ]);
        assert(toHex(rebuilt) === toHex(kettenMaster), 'Entsperr-Kette muss den Master Key treffen');

        // Der Schluesselbund: x25519(32) || mlkem-seed(64), mit dem Master Key
        // verschluesselt (WebCrypto-Layout, IV getrennt gespeichert).
        const x25519Private = material.bytes(32);
        const mlKemSeed = material.bytes(64);
        const privateKeyIv = material.bytes(12);
        const encryptedPrivateKey = await aesGcmEncryptRaw(
            concat(x25519Private, mlKemSeed), kettenMaster, privateKeyIv
        );

        return {
            master_key: toHex(kettenMaster),
            password_utf8: chainPassword,
            recovery_mnemonic: chainMnemonic,
            shares: encryptedByType,
            encrypted_private_key: toHex(encryptedPrivateKey),
            private_key_iv: toHex(privateKeyIv),
            x25519_private: toHex(x25519Private),
            mlkem_private: toHex(mlKemSeed),
        };
    }

    const ketteBestand = await baueKette(PASSWORD_DERIVATION_PBKDF2);
    const ketteUmgestellt = await baueKette(PASSWORD_DERIVATION_ARGON2ID);
    assert(
        ketteBestand.master_key !== ketteUmgestellt.master_key,
        'Die beiden Ketten muessen verschiedene Postfaecher sein'
    );

    // Versioniertes Anteilsformat (#4fdb8c92) - ABSICHTLICH NACH den Ketten,
    // damit die bestehenden Vektoren (Shamir, Entsperrketten) ihre Bytes
    // behalten; der Zufallsstrom ist fortlaufend. Je zwei Faelle fuer Format 1
    // (Bestand, kein Kopf) und Format 2 (Kopfbyte, HKDF-gebundener
    // Schluessel). Bei Format 2 steht die Herabsetzung gleich daneben: der
    // Chiffretext ohne Kopf ist ein syntaktisch tadelloser Format-1-Anteil
    // und ergibt beim Lesen Muell - ein Leser, der daraus `share` macht, hat
    // die Version nicht in den Schluessel eingebunden.
    const shareFormat: ShareFormatCase[] = [];
    for (const version of [ANTEILSFORMAT_V1, ANTEILSFORMAT_V2] as const) {
        for (const lauf of ['a', 'b']) {
            const share = material.bytes(32);
            const derivedKey = material.bytes(32);
            const encrypted = verpackeImAnteilsformat(share, derivedKey, version);
            assert(encrypted.length === (version === ANTEILSFORMAT_V1 ? 32 : 33), 'Anteilsformat: falsche Gesamtlaenge');
            assert(toHex(entpackeAnteil(encrypted, derivedKey)) === toHex(share), 'Anteilsformat-Roundtrip muss den Anteil zurueckgeben');
            if (version === ANTEILSFORMAT_V1) {
                assert(toHex(encrypted) === toHex(encryptShare(share, derivedKey)), 'Format 1 muss byteidentisch zu encryptShare sein');
            }
            const fall: ShareFormatCase = {
                name: `share_format_v${version}_${lauf}`,
                version,
                share: toHex(share),
                derived_key: toHex(derivedKey),
                wrapping_key: toHex(verpackungsschluessel(version, derivedKey)),
                encrypted: toHex(encrypted),
            };
            if (version === ANTEILSFORMAT_V2) {
                const herabgesetzt = encrypted.subarray(1);
                const muell = entpackeAnteil(herabgesetzt, derivedKey);
                assert(toHex(muell) !== toHex(share), 'Herabsetzung auf Format 1 darf NICHT den Anteil ergeben');
                fall.downgraded_to_v1 = toHex(herabgesetzt);
                fall.downgraded_share = toHex(muell);
            }
            shareFormat.push(fall);
        }
    }

    // Was kein Leser oeffnen darf. Jeder Fall wird im Generator selbst gegen
    // den echten Leser gehalten: wirft er nicht, kommt die Fixture nicht raus.
    const koerper = material.bytes(33);
    const shareFormatRejected: ShareFormatRejectedCase[] = [
        { name: 'unknown_version_3', encrypted: toHex(concat(new Uint8Array([3]), koerper.subarray(0, 32))), reason: 'unknown_version' },
        { name: 'unknown_version_255', encrypted: toHex(concat(new Uint8Array([255]), koerper.subarray(0, 32))), reason: 'unknown_version' },
        { name: 'header_byte_1_has_no_header_format', encrypted: toHex(concat(new Uint8Array([1]), koerper.subarray(0, 32))), reason: 'unknown_version' },
        // 🚩 0x02 + 31 Byte waere 32 Byte lang und damit per Definition ein
        // Format-1-Anteil (die Laenge entscheidet zuerst) - der Generator hat
        // genau diesen Fall beim ersten Lauf abgelehnt. Deshalb 30 Byte.
        { name: 'v2_body_too_short', encrypted: toHex(concat(new Uint8Array([2]), koerper.subarray(0, 30))), reason: 'length_mismatch' },
        { name: 'v2_body_too_long', encrypted: toHex(concat(new Uint8Array([2]), koerper)), reason: 'length_mismatch' },
        { name: 'empty', encrypted: '', reason: 'empty' },
    ];
    for (const fall of shareFormatRejected) {
        let geworfen: unknown = null;
        try {
            entpackeAnteil(fromHex(fall.encrypted), koerper.subarray(0, 32));
        } catch (e) {
            geworfen = e;
        }
        assert(geworfen instanceof AnteilsformatFehler, `Leser muss ${fall.name} mit AnteilsformatFehler ablehnen`);
    }


    return {
        generator: GENERATOR,
        encoding:
            'Alle Byte-Felder als lowercase Hex, ausser raw_input/normalized/password_utf8 (Klartext). '
            + 'password_keys: derivation entscheidet - pbkdf2_sha256_600k = '
            + 'PBKDF2-SHA256(password, salt, iterations) -> 32 Byte; argon2id_m65536_t3_p4 = '
            + 'Argon2id(password, salt, t=iterations, m=memory_kib, p=parallelism) -> 32 Byte. '
            + 'recovery_hashes: SHA-256(normalizeRecoveryMnemonicInput(raw_input)). '
            + 'share_xor: encrypted = share XOR derived_key[0..len]. '
            + 'share_format (#4fdb8c92): version 1 = share XOR derived_key (32 Byte, kein Kopf); '
            + 'version 2 = 0x02 || share XOR wrapping_key (33 Byte), '
            + 'wrapping_key = HKDF-SHA-256(ikm=derived_key, salt=leer, info=UTF-8("aionda-vault-share-v2"), 32). '
            + 'downgraded_to_v1 = encrypted ohne Kopfbyte, downgraded_share = was ein Leser daraus macht (Muell, != share). '
            + 'share_format_rejected: jeder Leser MUSS diese Chiffretexte mit einem Formatfehler ablehnen. '
            + 'shamir: Lagrange-Interpolation in GF(2^8) bei x=0. '
            + 'unlock_chain: Passwort-Anteil + Wiederherstellungs-Anteil ergeben master_key; '
            + 'encrypted_private_key = AES-256-GCM(x25519_private || mlkem_private, master_key, private_key_iv) '
            + 'im Layout ciphertext||tag mit getrenntem IV.',
        password_keys: passwordKeys,
        recovery_hashes: recoveryHashes,
        share_xor: shareXor,
        share_format: shareFormat,
        share_format_rejected: shareFormatRejected,
        shamir: shamirCases,
        unlock_chain: ketteBestand,
        unlock_chain_argon2id: ketteUmgestellt,
    };
}

// ===========================================================================
// Hauptlauf
// ===========================================================================

// ===========================================================================
// 8. key_transition.json  (signierter Postfach-Schlüsselwechsel, #658912ef, Vertrag v2)
// ===========================================================================

/**
 * 🚩 Läuft als LETZTER Baustein: Er zieht aus demselben `material`-Strom wie
 * die anderen. Stünde er früher, verschöben sich alle späteren Fixtures
 * byteweise - und die Apple-Tests dazu würden rot, ohne dass sich an deren
 * Krypto etwas geändert hätte.
 */
async function buildKeyTransition(vectors: KemVectors): Promise<KeyTransitionFile> {
    const login = 'phpunit_kat_wechsel_alice';
    const signedAt = 1_760_000_000;
    const ctx = utf8(TRANSITION_CONTEXT);
    const ctxInstall = utf8(INSTALL_CONTEXT);

    // Alte KEM-Schlüssel = Empfänger A aus hybrid_kem.json.
    const oldX = vectors.first.x25519Public;
    const oldM = vectors.first.mlkemPublic;

    const signerSeed = material.bytes(32);
    const signer = ml_dsa65.keygen(signerSeed);
    const signer2Seed = material.bytes(32);
    const signer2 = ml_dsa65.keygen(signer2Seed);

    const newXPriv = material.bytes(32);
    const newX = x25519PublicFromPrivate(newXPriv);
    const newMSeed = material.bytes(64);
    const newM = ml_kem1024.keygen(newMSeed).publicKey;

    // Ein Angreifer: eigener Signierschlüssel, eigener X25519 (ML-KEM teilt er sich mit "neu").
    const attackerXPriv = material.bytes(32);
    const attackerX = x25519PublicFromPrivate(attackerXPriv);
    const attackerSeed = material.bytes(32);
    const attacker = ml_dsa65.keygen(attackerSeed);

    // Challenge-Material (Vertrag 3.3)
    const nonce = material.bytes(32);
    const secret = material.bytes(32);

    const fp = (x: Uint8Array, m: Uint8Array, sig: Uint8Array | null): Promise<Uint8Array> => fingerprintFull(x, m, sig);

    // Fingerabdrücke der Sätze
    const fpK0None = await fp(oldX, oldM, null);
    const fpK0S1 = await fp(oldX, oldM, signer.publicKey);
    const fpK0S2 = await fp(oldX, oldM, signer2.publicKey);
    const fpK0Att = await fp(oldX, oldM, attacker.publicKey);

    // Deterministisch signieren (FIPS 204 §3.4 ohne Zusatzentropie).
    const sign = (seed: Uint8Array, record: Uint8Array, context: Uint8Array): Uint8Array =>
        ml_dsa65.sign(record, ml_dsa65.keygen(seed).secretKey, { context, extraEntropy: false });

    interface AkteIn { login: string; oldFp: Uint8Array; oldSig: Uint8Array | null; newX: Uint8Array; newM: Uint8Array; newSig: Uint8Array }

    function fall(
        name: string,
        beschreibung: string,
        reason: TransitionReason,
        akte: AkteIn,
        signerPublic: Uint8Array,
        context: Uint8Array,
        signature: Uint8Array,
    ): KeyTransitionCase {
        const record = transitionRecord({
            reason,
            login: akte.login,
            oldFingerprint: akte.oldFp,
            newX25519PublicKey: akte.newX,
            newMlkemPublicKey: akte.newM,
            newSigningPublicKey: akte.newSig,
            signedAt,
        });
        const verify = ml_dsa65.verify(signature, record, signerPublic, { context });
        return {
            name,
            beschreibung,
            anlass: reason,
            anlass_name: TRANSITION_REASON_NAMES[reason],
            login: akte.login,
            old_x25519_public: toHex(oldX),
            old_mlkem_public: toHex(oldM),
            old_signing_public: akte.oldSig ? toHex(akte.oldSig) : null,
            old_fingerprint_preimage: toHex(fingerprintPreimage(oldX, oldM, akte.oldSig)),
            old_fingerprint_full: toHex(akte.oldFp),
            old_fingerprint_display: formatFingerprint(akte.oldFp),
            new_x25519_public: toHex(akte.newX),
            new_mlkem_public: toHex(akte.newM),
            new_signing_public: toHex(akte.newSig),
            signer_public: toHex(signerPublic),
            signed_at: signedAt,
            record: toHex(record),
            context_utf8: new TextDecoder().decode(context),
            signature: toHex(signature),
            verify,
        };
    }

    const rec = (reason: TransitionReason, a: AkteIn): Uint8Array => transitionRecord({
        reason, login: a.login, oldFingerprint: a.oldFp,
        newX25519PublicKey: a.newX, newMlkemPublicKey: a.newM, newSigningPublicKey: a.newSig, signedAt,
    });

    // Fall 1: Rotation (K0,S1) → (K1,S1), signiert von S1.
    const akte1: AkteIn = { login, oldFp: fpK0S1, oldSig: signer.publicKey, newX, newM, newSig: signer.publicKey };
    const sig1 = sign(signerSeed, rec(TRANSITION_REASON.rotation, akte1), ctx);
    // Fall 2: Signierschlüsselwechsel (K0,S1) → (K0,S2), signiert von S1.
    const akte2: AkteIn = { login, oldFp: fpK0S1, oldSig: signer.publicKey, newX: oldX, newM: oldM, newSig: signer2.publicKey };
    const sig2 = sign(signerSeed, rec(TRANSITION_REASON.signierschluessel, akte2), ctx);
    // Fall 3: Rotation NACH Fall 2: (K0,S2) → (K1,S2), signiert von S2.
    const akte3: AkteIn = { login, oldFp: fpK0S2, oldSig: signer2.publicKey, newX, newM, newSig: signer2.publicKey };
    const sig3 = sign(signer2Seed, rec(TRANSITION_REASON.rotation, akte3), ctx);
    // Angreifer: behauptet (K0,S_att) → (K_att,S_att), signiert mit S_att. Die
    // Signatur ist GÜLTIG - der Schutz liegt in der Kettenprüfung (Pin kennt S_att nicht).
    const akteAtt: AkteIn = { login, oldFp: fpK0Att, oldSig: attacker.publicKey, newX: attackerX, newM: newM, newSig: attacker.publicKey };
    const sigAtt = sign(attackerSeed, rec(TRANSITION_REASON.rotation, akteAtt), ctx);

    const cases: KeyTransitionCase[] = [
        fall('rotation_gueltig', 'KEM-Rotation, signiert vom eingerichteten Signierschlüssel S1',
            TRANSITION_REASON.rotation, akte1, signer.publicKey, ctx, sig1),
        fall('signierschluessel_gueltig', 'Wechsel des Signierschlüssels S1 → S2, KEM unverändert, signiert von S1',
            TRANSITION_REASON.signierschluessel, akte2, signer.publicKey, ctx, sig2),
        fall('rotation_nach_signierschluesselwechsel_gueltig', 'KEM-Rotation nach Fall 2, alter Satz (K0,S2), signiert von S2',
            TRANSITION_REASON.rotation, akte3, signer2.publicKey, ctx, sig3),
        fall('angreifer_rotation_gueltig_signiert', 'Angreifer: (K0,S_att) → (K_att,S_att), signiert von S_att - gültige Signatur, aber kein Pin kennt S_att',
            TRANSITION_REASON.rotation, akteAtt, attacker.publicKey, ctx, sigAtt),
        fall('rotation_fremder_zielschluessel', 'Signatur aus Fall 1, aber anderer neuer X25519-Schlüssel in der Akte → ungültig',
            TRANSITION_REASON.rotation, { ...akte1, newX: attackerX }, signer.publicKey, ctx, sig1),
        fall('rotation_falscher_kontext', 'Akte und Signatur aus Fall 1, aber Chat-Manifest-Kontext → ungültig',
            TRANSITION_REASON.rotation, akte1, signer.publicKey, utf8('aionda-chat-manifest-sig-v2'), sig1),
        fall('rotation_fremder_signierschluessel', 'Akte und Signatur aus Fall 1, geprüft gegen S2 → ungültig',
            TRANSITION_REASON.rotation, akte1, signer2.publicKey, ctx, sig1),
        fall('rotation_anderer_login', 'Akte aus Fall 1 mit anderem Login, Signatur aus Fall 1 → ungültig',
            TRANSITION_REASON.rotation, { ...akte1, login: 'phpunit_kat_wechsel_bob' }, signer.publicKey, ctx, sig1),
        fall('rotation_anderer_anlass', 'Akte aus Fall 1 mit anlass = 2, Signatur aus Fall 1 → ungültig',
            TRANSITION_REASON.signierschluessel, akte1, signer.publicKey, ctx, sig1),
        fall('rotation_alter_fingerabdruck_ohne_signierschluessel', 'Akte aus Fall 1, aber FP(alt) ohne Signierschlüssel (v1-Denke), Signatur aus Fall 1 → ungültig',
            TRANSITION_REASON.rotation, { ...akte1, oldFp: fpK0None, oldSig: null }, signer.publicKey, ctx, sig1),
    ];

    assert(cases.filter(c => c.verify).length === 4, 'key_transition: genau 4 gültige Fälle erwartet');
    assert(cases.filter(c => !c.verify).length === 6, 'key_transition: genau 6 ungültige Fälle erwartet');

    // Einrichtungsakten (Vertrag 3.3)
    function einrichtung(
        name: string, beschreibung: string,
        akte: { nonce: Uint8Array; secret: Uint8Array; curSig: Uint8Array | null; curFp: Uint8Array; newSig: Uint8Array; login: string },
        signerPublic: Uint8Array, context: Uint8Array, signature: Uint8Array,
    ): KeyInstallCase {
        const record = installRecord({
            login: akte.login, nonce: akte.nonce, sharedSecret: akte.secret,
            currentFingerprint: akte.curFp, newSigningPublicKey: akte.newSig,
        });
        return {
            name, beschreibung, login: akte.login,
            nonce: toHex(akte.nonce), shared_secret: toHex(akte.secret),
            current_x25519_public: toHex(oldX), current_mlkem_public: toHex(oldM),
            current_signing_public: akte.curSig ? toHex(akte.curSig) : null,
            current_fingerprint_full: toHex(akte.curFp),
            new_signing_public: toHex(akte.newSig),
            signer_public: toHex(signerPublic),
            record: toHex(record), context_utf8: new TextDecoder().decode(context),
            signature: toHex(signature),
            verify: ml_dsa65.verify(signature, record, signerPublic, { context }),
        };
    }
    const inst1 = { nonce, secret, curSig: null, curFp: fpK0None, newSig: signer.publicKey, login };
    const instRec1 = installRecord({ login, nonce, sharedSecret: secret, currentFingerprint: fpK0None, newSigningPublicKey: signer.publicKey });
    const instSig1 = sign(signerSeed, instRec1, ctxInstall);
    const inst2 = { nonce, secret, curSig: signer.publicKey, curFp: fpK0S1, newSig: signer2.publicKey, login };
    const instRec2 = installRecord({ login, nonce, sharedSecret: secret, currentFingerprint: fpK0S1, newSigningPublicKey: signer2.publicKey });
    const instSig2 = sign(signer2Seed, instRec2, ctxInstall);
    const fremderNonce = material.bytes(32);
    const fremdesSecret = material.bytes(32);

    const installCases: KeyInstallCase[] = [
        einrichtung('einrichtung_erstschluessel_gueltig', 'Erstschlüssel S1: Postfach ohne Signierschlüssel, Akte von S1 signiert', inst1, signer.publicKey, ctxInstall, instSig1),
        einrichtung('einrichtung_wechsel_gueltig', 'Wechsel auf S2 bei eingerichtetem S1: Einrichtungsakte von S2 signiert (die Wechselakte dazu ist Fall signierschluessel_gueltig)', inst2, signer2.publicKey, ctxInstall, instSig2),
        einrichtung('einrichtung_falsche_nonce', 'Akte mit anderer Nonce, Signatur aus dem Erstschlüsselfall → ungültig', { ...inst1, nonce: fremderNonce }, signer.publicKey, ctxInstall, instSig1),
        einrichtung('einrichtung_fremdes_secret', 'Akte mit anderem Shared Secret (kein Master Key), Signatur aus dem Erstschlüsselfall → ungültig', { ...inst1, secret: fremdesSecret }, signer.publicKey, ctxInstall, instSig1),
        einrichtung('einrichtung_falscher_kontext', 'Einrichtungsakte mit dem Wechsel-Kontext geprüft → ungültig', inst1, signer.publicKey, ctx, instSig1),
        einrichtung('einrichtung_anderer_zustand', 'Akte mit Fingerabdruck (K0,S1) statt (K0,ohne), Signatur aus dem Erstschlüsselfall → ungültig', { ...inst1, curSig: signer.publicKey, curFp: fpK0S1 }, signer.publicKey, ctxInstall, instSig1),
    ];
    assert(installCases.filter(c => c.verify).length === 2, 'key_transition: genau 2 gültige Einrichtungsfälle');
    assert(installCases.filter(c => !c.verify).length === 4, 'key_transition: genau 4 ungültige Einrichtungsfälle');

    const fpFall = (name: string, sig: Uint8Array | null, full: Uint8Array): KeyFingerprintCase => ({
        name, x25519_public: toHex(oldX), mlkem_public: toHex(oldM), signing_public: sig ? toHex(sig) : null,
        preimage: toHex(fingerprintPreimage(oldX, oldM, sig)), full: toHex(full), display: formatFingerprint(full),
    });
    const fingerprints: KeyFingerprintCase[] = [
        fpFall('ohne_signierschluessel', null, fpK0None),
        fpFall('mit_signierschluessel_s1', signer.publicKey, fpK0S1),
        fpFall('mit_signierschluessel_s2', signer2.publicKey, fpK0S2),
    ];

    const pin = (x: Uint8Array, m: Uint8Array, sig: Uint8Array | null): KeyPinShape =>
        ({ x25519_public: toHex(x), mlkem_public: toHex(m), signing_public: sig ? toHex(sig) : null });
    const pinK0None = pin(oldX, oldM, null);
    const pinK0S1 = pin(oldX, oldM, signer.publicKey);
    const walk = (name: string, p: KeyPinShape, d: KeyPinShape, chain: string[], expected: KeyTransitionChainWalk['expected'], beschreibung: string): KeyTransitionChainWalk =>
        ({ name, login, pin: p, delivered: { ...d, chain }, expected, beschreibung });

    const chainWalks: KeyTransitionChainWalk[] = [
        walk('gleich', pinK0S1, pinK0S1, [], 'gleich', 'Keine Änderung - nichts zu prüfen'),
        walk('gleich_ohne_signierschluessel', pinK0None, pinK0None, [], 'gleich', 'Kontakt ohne Signierschlüssel, unverändert'),
        walk('rotation_uebernehmen', pinK0S1, pin(newX, newM, signer.publicKey), ['rotation_gueltig'], 'uebernehmen', 'Ein signierter Schritt vom Pin zu den gelieferten Schlüsseln'),
        walk('zwei_schritte_uebernehmen', pinK0S1, pin(newX, newM, signer2.publicKey), ['signierschluessel_gueltig', 'rotation_nach_signierschluesselwechsel_gueltig'], 'uebernehmen', 'Signierschlüsselwechsel, dann Rotation - zwei Schritte, jeder vom jeweils vorigen Schlüssel signiert (ältester Eintrag zuerst)'),
        walk('ohne_kette_halt', pinK0S1, pin(newX, newM, signer.publicKey), [], 'halt', 'Server lässt die Kette weg → Halt'),
        walk('falsche_signatur_halt', pinK0S1, pin(attackerX, newM, signer.publicKey), ['rotation_fremder_zielschluessel'], 'halt', 'Eintrag mit umgedeutetem Zielschlüssel → Signatur ungültig → Halt'),
        walk('pin_ohne_signierschluessel_erstmals_halt', pinK0None, pinK0S1, [], 'halt', 'B1: KEM gleich, aber der Server nennt erstmals einen Signierschlüssel → Halt und Bestätigung (nie still lernen)'),
        walk('zweischritt_angriff_halt', pinK0None, pin(attackerX, newM, attacker.publicKey), ['angreifer_rotation_gueltig_signiert'], 'halt', 'B1: Pin ohne Signierschlüssel, Server liefert Angreifer-KEM + vom Angreifer signierten Eintrag → Halt'),
        walk('pin_ohne_signierschluessel_kette_halt', pinK0None, pin(newX, newM, signer.publicKey), ['rotation_gueltig'], 'halt', 'Pin kennt keinen Signierschlüssel - eine Kette ist nicht an Gemerktes gebunden → Halt'),
        walk('signierschluessel_weggelassen_halt', pinK0S1, pinK0None, [], 'halt', 'Server lässt den gemerkten Signierschlüssel weg → Halt'),
        walk('angreifer_signierschluessel_halt', pinK0S1, pin(attackerX, newM, attacker.publicKey), ['angreifer_rotation_gueltig_signiert'], 'halt', 'Pin (K0,S1); Eintrag geht von (K0,S_att) aus → kein Eintrag passt zum gemerkten Satz → Halt'),
        walk('zweiter_schritt_fehlt_halt', pinK0S1, pin(newX, newM, signer2.publicKey), ['signierschluessel_gueltig'], 'halt', 'Kette endet beim Signierschlüsselwechsel, geliefert sind schon rotierte KEM-Schlüssel → Halt'),
    ];

    const seedAadBytes = seedAad(login);

    return {
        generator: GENERATOR,
        encoding: 'Signierter Postfach-Schluesselwechsel, Vertrag v2 (docs/VAULT_SCHLUESSELWECHSEL_SIGNATUR.md, Abschnitt 3). '
            + 'Fingerabdruck v2: SHA-256("aionda-postfachschluessel-fingerabdruck-v2" || u32 32 || x25519 || u32 1568 || mlkem || u32 len || signing_public), len = 1952 oder 0. '
            + 'record = "aionda-vault-schluesselwechsel-v1" || u8 1 || u8 anlass || u16 len || login || old_fingerprint_full '
            + '|| u16 32 || new_x25519 || u16 1568 || new_mlkem || u16 1952 || new_signing_public || u64 signed_at (3635 + len Byte). '
            + 'install record = "aionda-vault-signierschluessel-einrichtung-v1" || u8 1 || u16 len || login || nonce(32) || shared_secret(32) '
            + '|| current_fingerprint_full || u16 1952 || new_signing_public (2098 + len Byte). '
            + 'Signaturen ML-DSA-65 mit ctx = context_utf8, hier deterministisch; verify = erwartetes Urteil. '
            + 'Alle Binaerfelder Hex. chain_walks beschreiben den Kettenlauf aus Vertrag Abschnitt 5 (v2).',
        material: {
            old_x25519_private: toHex(vectors.first.x25519Private),
            old_mlkem_seed: vectors.cases[0].mlkem_seed,
            new_x25519_private: toHex(newXPriv),
            new_mlkem_seed: toHex(newMSeed),
            signer_seed: toHex(signerSeed),
            signer_public: toHex(signer.publicKey),
            signer2_seed: toHex(signer2Seed),
            signer2_public: toHex(signer2.publicKey),
            attacker_seed: toHex(attackerSeed),
            attacker_public: toHex(attacker.publicKey),
            attacker_x25519_private: toHex(attackerXPriv),
            seed_aad: toHex(seedAadBytes),
            seed_aad_utf8: new TextDecoder().decode(seedAadBytes),
        },
        fingerprints,
        cases,
        install_cases: installCases,
        chain_walks: chainWalks,
    };
}

async function main(): Promise<void> {
    const aes = await buildAesGcm();
    writeFixture('aes_gcm.json', aes);

    const kdf = await buildKeyDerivation();
    writeFixture('key_derivation.json', kdf);

    const wrapped = await buildWrappedTaskKeys();
    writeFixture('wrapped_key_tasks.json', wrapped);

    const emailField = await buildEmailField();
    writeFixture('email_field.json', emailField);

    const { file: kemFile, vectors } = await buildHybridKem();
    writeFixture('hybrid_kem.json', kemFile);

    const pack = await buildPackFormat(vectors);
    writeFixture('pack_format.json', pack);

    const unlock = await buildVaultUnlock();
    writeFixture('vault_unlock.json', unlock);

    // Zuletzt - siehe Kopf von buildKeyTransition().
    const transition = await buildKeyTransition(vectors);
    writeFixture('key_transition.json', transition);

    const report = [
        ['aes_gcm.json', aes.cases.length],
        ['key_derivation.json', kdf.cases.length],
        ['wrapped_key_tasks.json', wrapped.cases.length + wrapped.field_cases.length],
        ['email_field.json', emailField.cases.length],
        ['hybrid_kem.json', kemFile.cases.length],
        ['pack_format.json', pack.cases.length],
        [
            'vault_unlock.json',
            unlock.password_keys.length + unlock.recovery_hashes.length
                + unlock.share_xor.length + unlock.share_format.length
                + unlock.share_format_rejected.length + unlock.shamir.length + 2,
        ],
        ['key_transition.json', transition.cases.length + transition.install_cases.length + transition.fingerprints.length + transition.chain_walks.length],
    ] as const;

    process.stdout.write(`KAT-Fixtures geschrieben nach ${FIXTURE_DIR}\n`);
    for (const [file, count] of report) {
        process.stdout.write(`  ${file.padEnd(24)} ${String(count).padStart(2)} Fälle\n`);
    }
}

main().catch((error: unknown) => {
    process.stderr.write(`KAT-Generator fehlgeschlagen: ${(error as Error).message}\n`);
    process.exitCode = 1;
});
