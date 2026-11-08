/**
 * KAT-Verifikation: prüft alle Fixtures GEGEN die echten TS-Funktionen.
 *
 * Wird zweimal genutzt:
 *  - als eigenständiges Skript (npm run verify-kat)
 *  - aus kat/kat.spec.ts heraus, damit die CI Fixture-Drift erkennt
 *
 * Die Prüfungen laufen bewusst über die ENTSCHLUESSELUNGSrichtung des
 * Produktivcodes. Wenn Swift dieselben Fixtures besteht, sind beide
 * Implementierungen byte-identisch.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

import {
    fingerprintFull, fingerprintPreimage, formatFingerprint, installRecord, seedAad, transitionRecord,
} from '../src/crypto/key-transition';
import type { KeyTransitionFile } from './lib/types';

import { decryptAesGcm, decryptPhpAesGcm, decryptClientAesGcm } from '../src/crypto/aes-gcm';
import { isBucketPadded, unpadFromBucket } from '../src/crypto/bucket-padding';
import { decompress } from '../src/crypto/decompression';
import { decryptEmail } from '../src/crypto/email-decryptor';
import { fromHex, toHex } from '../src/crypto/encoding';
import { hybridDecapsulate } from '../src/crypto/hybrid-kem';
import { deriveFolderKey } from '../src/crypto/key-derivation';
import { decryptTaskField, unwrapTaskKey } from '../src/crypto/tasks-crypto';

// Entsperr-Kette: die echten Bausteine aus dem Web-Manager.
import {
    AnteilsformatFehler, anteilsformatVon, entpackeAnteil, verpackeImAnteilsformat, verpackungsschluessel,
} from '../../typescript/manager/vault/anteilsformat';
import {
    derivePasswordKey, decryptShare, encryptShare, shamirReconstruct,
    PASSWORD_DERIVATION_PBKDF2, requirePasswordDerivation,
} from '../../typescript/manager/vault/vault-crypto';
import {
    normalizeRecoveryMnemonicInput,
} from '../../typescript/manager/vault/vault-recovery-normalizer';
import type { EncryptedEmail } from '../src/types/email';

import { hkdfBits, sha256, utf8, aesGcmEncryptRaw, concat } from './lib/helpers';
import type {
    AesGcmCase, EmailFieldCase, FixtureFile, HybridKemCase,
    KeyDerivationCase, PackFormatFile, VaultUnlockFile, WrappedTaskKeyFile,
} from './lib/types';

const HERE = dirname(fileURLToPath(import.meta.url));
// Beim gebundelten Lauf liegt die Datei in kat/.build/ - dann eine Ebene hoch.
const KAT_DIR = HERE.endsWith('.build') ? dirname(HERE) : HERE;
const FIXTURE_DIR = join(KAT_DIR, 'fixtures');

export interface CheckResult {
    fixture: string;
    checks: number;
    failures: string[];
}

function load<T>(fileName: string): T {
    return JSON.parse(readFileSync(join(FIXTURE_DIR, fileName), 'utf8')) as T;
}

/** Sammelt Fehler, statt beim ersten abzubrechen - so sieht man alle Drifts auf einmal. */
class Collector {
    readonly failures: string[] = [];
    checks = 0;

    equal(actual: string, expected: string, what: string): void {
        this.checks += 1;
        if (actual !== expected) {
            this.failures.push(`${what}: erwartet ${expected.slice(0, 64)}…, erhalten ${actual.slice(0, 64)}…`);
        }
    }

    true(condition: boolean, what: string): void {
        this.checks += 1;
        if (!condition) { this.failures.push(what); }
    }
}

// ---------------------------------------------------------------------------

async function verifyAesGcm(): Promise<CheckResult> {
    const file = load<FixtureFile<AesGcmCase>>('aes_gcm.json');
    const c = new Collector();

    for (const testCase of file.cases) {
        const key = fromHex(testCase.key);
        const iv = fromHex(testCase.iv);
        const blob = fromHex(testCase.stored_blob);
        let plaintext: Uint8Array;

        switch (testCase.blob_layout) {
            case 'iv||ciphertext||tag':
                plaintext = await decryptClientAesGcm(blob, key);
                break;
            case 'ciphertext||tag':
                plaintext = await decryptAesGcm(blob, key, iv);
                break;
            case 'nonce||tag||ciphertext':
                plaintext = await decryptPhpAesGcm(blob, key);
                break;
        }

        c.equal(toHex(plaintext), testCase.plaintext, `aes_gcm/${testCase.name}`);
        c.equal(new TextDecoder().decode(plaintext), testCase.plaintext_utf8, `aes_gcm/${testCase.name}/utf8`);
    }

    // Zusatz: der iv-präfixierte Fall muss auch über decryptTaskField lesbar sein.
    const taskCase = file.cases.find(x => x.blob_layout === 'iv||ciphertext||tag' && x.plaintext_utf8.length > 0);
    if (taskCase) {
        const b64 = Buffer.from(fromHex(taskCase.stored_blob)).toString('base64');
        c.equal(await decryptTaskField(b64, fromHex(taskCase.key)), taskCase.plaintext_utf8, 'aes_gcm/decryptTaskField');
    }

    return { fixture: 'aes_gcm.json', checks: c.checks, failures: c.failures };
}

async function verifyKeyDerivation(): Promise<CheckResult> {
    const file = load<FixtureFile<KeyDerivationCase>>('key_derivation.json');
    const c = new Collector();

    for (const testCase of file.cases) {
        if (testCase.kind === 'sha256_master') {
            c.equal(toHex(await sha256(fromHex(testCase.input))), testCase.expected, `kdf/${testCase.name}`);
            if (testCase.input_utf8 !== undefined) {
                c.equal(toHex(utf8(testCase.input_utf8)), testCase.input, `kdf/${testCase.name}/utf8`);
            }
            continue;
        }

        const bits = await hkdfBits(fromHex(testCase.input), fromHex(testCase.salt), fromHex(testCase.info));
        c.equal(toHex(bits), testCase.expected, `kdf/${testCase.name}`);

        // Der Ordner-Fall muss zusätzlich der echten deriveFolderKey() entsprechen.
        if (testCase.name === 'hkdf_folder_key_v1' && testCase.info_utf8) {
            const real = await deriveFolderKey(fromHex(testCase.input), testCase.info_utf8);
            c.equal(toHex(real), testCase.expected, 'kdf/deriveFolderKey');
        }
    }

    // Nachweis, dass deriveBits(256) und deriveKey(AES-GCM 256) dasselbe
    // Schlüsselmaterial liefern: mit den rohen Bytes verschlüsseln, mit dem
    // echten unwrapTaskKey-Pfad wieder lesen (siehe wrapped_key_tasks.json).
    return { fixture: 'key_derivation.json', checks: c.checks, failures: c.failures };
}

async function verifyWrappedTaskKeys(): Promise<CheckResult> {
    const file = load<WrappedTaskKeyFile>('wrapped_key_tasks.json');
    const c = new Collector();

    for (const testCase of file.cases) {
        const blob = fromHex(testCase.wrapped_blob);
        const masterKey = fromHex(testCase.master_key);

        c.true(blob.length === 93, `wrapped/${testCase.name}: ${blob.length} statt 93 Byte`);
        c.equal(toHex(blob.slice(1, 33)), testCase.salt, `wrapped/${testCase.name}/salt`);
        c.equal(toHex(blob.slice(33, 45)), testCase.iv, `wrapped/${testCase.name}/iv`);

        if (testCase.expect === 'auth_failure') {
            let threw = false;
            try { await unwrapTaskKey(blob, masterKey); } catch { threw = true; }
            c.true(threw, `wrapped/${testCase.name}: hätte scheitern müssen (Downgrade-Schutz)`);
            continue;
        }

        c.equal(toHex(await unwrapTaskKey(blob, masterKey)), testCase.payload_key, `wrapped/${testCase.name}`);

        // Gegenprobe: der Wrapping-Key ist genau HKDF(master, salt, label).
        const wrapKey = await hkdfBits(masterKey, fromHex(testCase.salt), utf8(testCase.label));
        const additionalData = testCase.additional_data_utf8 === undefined
            ? undefined
            : utf8(testCase.additional_data_utf8);
        const opened = await decryptAesGcm(blob.slice(45), wrapKey, fromHex(testCase.iv), additionalData);
        c.equal(toHex(opened), testCase.payload_key, `wrapped/${testCase.name}/hkdf`);
    }

    for (const fieldCase of file.field_cases) {
        const key = fromHex(fieldCase.task_key);
        const base64 = Buffer.from(fromHex(fieldCase.stored_blob)).toString('base64');
        c.equal(
            await decryptTaskField(base64, key, fieldCase.field_context),
            fieldCase.plaintext_utf8,
            `wrapped/${fieldCase.name}`
        );

        if (fieldCase.additional_data_utf8 !== undefined) {
            let wrongContextRejected = false;
            try {
                await decryptTaskField(base64, key, `${fieldCase.field_context}-falsch`);
            } catch {
                wrongContextRejected = true;
            }
            c.true(wrongContextRejected, `wrapped/${fieldCase.name}: fremder AAD-Kontext wurde angenommen`);
        }
    }

    return { fixture: 'wrapped_key_tasks.json', checks: c.checks, failures: c.failures };
}

async function verifyEmailField(): Promise<CheckResult> {
    const file = load<FixtureFile<EmailFieldCase>>('email_field.json');
    const c = new Collector();

    for (const testCase of file.cases) {
        const masterKey = await sha256(utf8(testCase.vault_key_string));
        c.equal(toHex(masterKey), testCase.master_key, `email_field/${testCase.name}/master_key`);

        const blob = fromHex(testCase.stored_blob);
        c.equal(toHex(blob.slice(0, 12)), testCase.iv, `email_field/${testCase.name}/iv`);

        let plaintext = await decryptClientAesGcm(blob, masterKey);
        c.true(isBucketPadded(plaintext) === testCase.padded, `email_field/${testCase.name}: padded-Flag stimmt nicht`);
        if (isBucketPadded(plaintext)) { plaintext = unpadFromBucket(plaintext); }

        const looksGzip = plaintext.length >= 2 && plaintext[0] === 0x1f && plaintext[1] === 0x8b;
        c.true(looksGzip === testCase.compressed, `email_field/${testCase.name}: compressed-Flag stimmt nicht`);

        plaintext = await decompress(plaintext);
        c.equal(toHex(plaintext), testCase.plaintext, `email_field/${testCase.name}`);
        c.equal(new TextDecoder().decode(plaintext), testCase.plaintext_utf8, `email_field/${testCase.name}/utf8`);
    }

    return { fixture: 'email_field.json', checks: c.checks, failures: c.failures };
}

async function verifyHybridKem(): Promise<CheckResult> {
    const file = load<FixtureFile<HybridKemCase>>('hybrid_kem.json');
    const c = new Collector();

    if (file.cases.length === 0) {
        return { fixture: 'hybrid_kem.json', checks: 0, failures: [] };
    }

    for (const testCase of file.cases) {
        // ML-KEM-Keypair muss sich aus dem 64-Byte-Seed reproduzieren lassen.
        const keys = ml_kem1024.keygen(fromHex(testCase.mlkem_seed));
        c.equal(toHex(keys.publicKey), testCase.mlkem_public, `kem/${testCase.name}/mlkem_public`);
        c.equal(toHex(keys.secretKey), testCase.mlkem_private, `kem/${testCase.name}/mlkem_private`);

        // Encapsulation mit vorgegebener Nachricht m ist deterministisch.
        const enc = ml_kem1024.encapsulate(keys.publicKey, fromHex(testCase.mlkem_message));
        c.equal(toHex(enc.cipherText), testCase.kem_mlkem_ct, `kem/${testCase.name}/mlkem_ct`);

        // Und die echte Decapsulation liefert das erwartete Shared Secret.
        const shared = await hybridDecapsulate(
            fromHex(testCase.kem_x25519_ct), fromHex(testCase.kem_mlkem_ct),
            fromHex(testCase.x25519_private), keys.secretKey
        );
        c.equal(toHex(shared), testCase.shared_secret, `kem/${testCase.name}/shared_secret`);

        c.true(fromHex(testCase.kem_mlkem_ct).length === 1568, `kem/${testCase.name}: ML-KEM-CT nicht 1568 Byte`);
        c.true(fromHex(testCase.mlkem_seed).length === 64, `kem/${testCase.name}: Seed nicht 64 Byte`);
    }

    return { fixture: 'hybrid_kem.json', checks: c.checks, failures: c.failures };
}

async function verifyPackFormat(): Promise<CheckResult> {
    const file = load<PackFormatFile>('pack_format.json');
    const c = new Collector();

    for (const testCase of file.cases) {
        const blob = fromHex(testCase.blob);
        c.true(blob.length === 1661, `pack/${testCase.name}: ${blob.length} statt 1661 Byte`);
        c.true(blob[0] === testCase.parsed.version, `pack/${testCase.name}/version`);
        c.equal(toHex(blob.slice(1, 33)), testCase.parsed.x25519_ct, `pack/${testCase.name}/x25519_ct`);
        c.equal(toHex(blob.slice(33, 1601)), testCase.parsed.mlkem_ct, `pack/${testCase.name}/mlkem_ct`);
        c.equal(toHex(blob.slice(1601, 1613)), testCase.parsed.nonce, `pack/${testCase.name}/nonce`);
        c.equal(toHex(blob.slice(1613)), testCase.parsed.wrapped_key, `pack/${testCase.name}/wrapped_key`);
    }

    // End-zu-End: komplette Mail über den echten decryptEmail()-Pfad.
    const rt = file.email_roundtrip;
    const email: EncryptedEmail = {
        uuid: 'kat-0000-0000-0000-000000000001',
        dea_id: 'kat-dea',
        wrapped_ephemeral_key: rt.wrapped_ephemeral_key,
        encrypted_subject: rt.encrypted_subject,
        encrypted_from: rt.encrypted_from,
        encrypted_to: rt.encrypted_to,
        size_bytes: 0,
        has_attachments: false,
        attachment_count: 0,
        is_read: false,
        is_starred: false,
        is_deleted: false,
        folder_type: 'inbox',
        received_at: '2026-07-27T12:00:00Z',
    } as unknown as EncryptedEmail;

    const decrypted = await decryptEmail(
        email,
        new Uint8Array(32),
        {
            x25519PrivateKey: fromHex(rt.x25519_private),
            mlKemPrivateKey: fromHex(rt.mlkem_private),
        }
    );
    c.equal(decrypted.subject, rt.subject_utf8, 'pack/email_roundtrip/subject');
    c.equal(decrypted.from, rt.from_utf8, 'pack/email_roundtrip/from');
    c.equal(decrypted.to, rt.to_utf8, 'pack/email_roundtrip/to');

    // Der gewrappte Key im Pack lässt sich mit dem Shared Secret öffnen
    // (PHP-Layout tag(16) || ciphertext(32)).
    const real = file.cases.find(x => x.name === 'real_hybrid_kem_wrap');
    if (real) {
        const shared = await hybridDecapsulate(
            fromHex(real.parsed.x25519_ct), fromHex(real.parsed.mlkem_ct),
            fromHex(rt.x25519_private), fromHex(rt.mlkem_private)
        );
        const wrapped = fromHex(real.parsed.wrapped_key);
        const reordered = concat(wrapped.slice(16), wrapped.slice(0, 16));
        const key = await decryptAesGcm(reordered, shared, fromHex(real.parsed.nonce));
        c.equal(toHex(key), rt.ephemeral_key, 'pack/real_hybrid_kem_wrap/ephemeral_key');

        // Gegenrichtung: mit demselben Shared Secret nachbauen -> identische Bytes.
        const again = await aesGcmEncryptRaw(fromHex(rt.ephemeral_key), shared, fromHex(real.parsed.nonce));
        c.equal(toHex(concat(again.slice(32), again.slice(0, 32))), real.parsed.wrapped_key, 'pack/rewrap');
    }

    return { fixture: 'pack_format.json', checks: c.checks, failures: c.failures };
}

/**
 * Entsperr-Kette eines menschlichen Postfachs.
 *
 * Geprüft wird gegen dieselben Funktionen, die im Browser laufen - inklusive
 * des Ernstfalls: aus Passwort und Wiederherstellungswörtern zurück zum Master
 * Key und damit den privaten Schlüsselbund öffnen.
 */
async function verifyVaultUnlock(): Promise<CheckResult> {
    const file = load<VaultUnlockFile>('vault_unlock.json');
    const c = new Collector();

    // 🚩 #478cc256 - jeder Fall nennt SEIN Verfahren; hier wird nichts
    // erschlossen. Faellt `derivation` aus der Fixture, wirft
    // requirePasswordDerivation - und die Reihe wird rot statt still auf
    // PBKDF2 zurueckzufallen und weiter gruen zu melden.
    for (const testCase of file.password_keys) {
        c.equal(toHex(utf8(testCase.password_utf8)), testCase.password, `unlock/${testCase.name}/utf8`);
        const derived = await derivePasswordKey(
            testCase.password_utf8,
            fromHex(testCase.salt),
            requirePasswordDerivation(testCase.derivation)
        );
        c.equal(toHex(derived), testCase.expected, `unlock/${testCase.name}`);
    }

    // Nenner mitlesen: beide Zweige MUESSEN vertreten sein. Eine Fixture, aus
    // der ein Zweig verschwindet, wuerde sonst lautlos weniger pruefen.
    for (const erwartet of ['pbkdf2_sha256_600k', 'argon2id_m65536_t3_p4']) {
        const anzahl = file.password_keys.filter(k => k.derivation === erwartet).length;
        c.checks += 1;
        if (anzahl === 0) {
            c.failures.push(`unlock/password_keys: kein einziger Fall fuer ${erwartet}`);
        }
    }

    for (const testCase of file.recovery_hashes) {
        const normalized = normalizeRecoveryMnemonicInput(testCase.raw_input);
        c.equal(normalized, testCase.normalized, `unlock/${testCase.name}/normalize`);
        c.equal(toHex(await sha256(utf8(normalized))), testCase.expected, `unlock/${testCase.name}`);
    }

    for (const testCase of file.share_xor) {
        const encrypted = encryptShare(fromHex(testCase.share), fromHex(testCase.derived_key));
        c.equal(toHex(encrypted), testCase.encrypted, `unlock/${testCase.name}`);
        const back = decryptShare(fromHex(testCase.encrypted), fromHex(testCase.derived_key));
        c.equal(toHex(back), testCase.share, `unlock/${testCase.name}/roundtrip`);
    }

    // Versioniertes Anteilsformat (#4fdb8c92): Schreiben, Lesen, Erkennen -
    // und bei Format 2 die Herabsetzung, die Muell ergeben MUSS.
    c.true(
        file.share_format.some(f => f.version === 1) && file.share_format.some(f => f.version === 2),
        'unlock/share_format: beide Versionen muessen vertreten sein'
    );
    for (const testCase of file.share_format) {
        const share = fromHex(testCase.share);
        const derivedKey = fromHex(testCase.derived_key);
        c.equal(toHex(verpackungsschluessel(testCase.version, derivedKey)), testCase.wrapping_key, `unlock/${testCase.name}/wrapping_key`);
        c.equal(toHex(verpackeImAnteilsformat(share, derivedKey, testCase.version)), testCase.encrypted, `unlock/${testCase.name}`);
        c.equal(String(anteilsformatVon(fromHex(testCase.encrypted))), String(testCase.version), `unlock/${testCase.name}/version`);
        c.equal(toHex(entpackeAnteil(fromHex(testCase.encrypted), derivedKey)), testCase.share, `unlock/${testCase.name}/roundtrip`);
        // decryptShare ist die EINE Lesestelle des Managers - sie muss dasselbe liefern.
        c.equal(toHex(decryptShare(fromHex(testCase.encrypted), derivedKey)), testCase.share, `unlock/${testCase.name}/decryptShare`);
        if (testCase.downgraded_to_v1 !== undefined && testCase.downgraded_share !== undefined) {
            c.equal(toHex(fromHex(testCase.encrypted).subarray(1)), testCase.downgraded_to_v1, `unlock/${testCase.name}/downgraded_to_v1`);
            const muell = decryptShare(fromHex(testCase.downgraded_to_v1), derivedKey);
            c.equal(toHex(muell), testCase.downgraded_share, `unlock/${testCase.name}/downgraded_share`);
            c.true(toHex(muell) !== testCase.share, `unlock/${testCase.name}: Herabsetzung darf den Anteil nicht preisgeben`);
        }
    }
    for (const testCase of file.share_format_rejected) {
        let fehler: unknown = null;
        try {
            decryptShare(fromHex(testCase.encrypted), new Uint8Array(32));
        } catch (e) {
            fehler = e;
        }
        c.true(fehler instanceof AnteilsformatFehler, `unlock/rejected/${testCase.name}: muss mit AnteilsformatFehler abgelehnt werden (${testCase.reason})`);
    }

    for (const testCase of file.shamir) {
        const picked = testCase.shares
            .filter(s => testCase.reconstruct_from.includes(s.x))
            .map(s => ({ x: s.x, data: fromHex(s.data) }));
        c.equal(toHex(shamirReconstruct(picked)), testCase.secret, `unlock/${testCase.name}`);
    }

    // --- Ernstfall: Passwort + Wiederherstellungswörter -> Master Key -------
    //
    // 🚩 #478cc256 - BEIDE Ketten, und die Reihenfolge ist Absicht: zuerst der
    // Bestand (PBKDF2), dann das umgestellte Postfach (Argon2id). Eine
    // KDF-Migration muss in beide Richtungen gemessen werden - was heute
    // lesbar ist, muss es morgen bleiben.
    const recoveryKey = await sha256(utf8(normalizeRecoveryMnemonicInput(file.unlock_chain.recovery_mnemonic)));

    async function pruefeKette(chain: typeof file.unlock_chain, bezeichnung: string): Promise<void> {
        const passwordShare = chain.shares.find(s => s.type === 'password');
        const recoveryShare = chain.shares.find(s => s.type === 'recovery');

        if (!passwordShare?.salt || !recoveryShare) {
            c.failures.push(`unlock/${bezeichnung}: Passwort- oder Wiederherstellungs-Anteil fehlt`);
            return;
        }

        // Auch hier: die Kennung kommt aus dem Anteil, sie wird nicht geraten.
        const passwordKey = await derivePasswordKey(
            chain.password_utf8,
            fromHex(passwordShare.salt),
            requirePasswordDerivation(passwordShare.derivation)
        );

        const masterKey = shamirReconstruct([
            { x: passwordShare.index, data: decryptShare(fromHex(passwordShare.encrypted), passwordKey) },
            { x: recoveryShare.index, data: decryptShare(fromHex(recoveryShare.encrypted), recoveryKey) },
        ]);
        c.equal(toHex(masterKey), chain.master_key, `unlock/${bezeichnung}/master_key`);

        // Der eigentliche Beweis: mit dem rekonstruierten Key öffnet sich der
        // Schlüsselbund. Genau so prüft der Web-Manager (verifyMasterKey).
        const bundle = await decryptAesGcm(
            fromHex(chain.encrypted_private_key),
            masterKey,
            fromHex(chain.private_key_iv)
        );
        c.equal(toHex(bundle.slice(0, 32)), chain.x25519_private, `unlock/${bezeichnung}/x25519`);
        c.equal(toHex(bundle.slice(32)), chain.mlkem_private, `unlock/${bezeichnung}/mlkem_seed`);

        // Gegenprobe: ein falsches Passwort darf NICHT durchrutschen.
        const wrongKey = await derivePasswordKey(
            `${chain.password_utf8}x`,
            fromHex(passwordShare.salt),
            requirePasswordDerivation(passwordShare.derivation)
        );
        const wrongMaster = shamirReconstruct([
            { x: passwordShare.index, data: decryptShare(fromHex(passwordShare.encrypted), wrongKey) },
            { x: recoveryShare.index, data: decryptShare(fromHex(recoveryShare.encrypted), recoveryKey) },
        ]);
        c.checks += 1;
        if (toHex(wrongMaster) === chain.master_key) {
            c.failures.push(`unlock/${bezeichnung}/wrong_password: falsches Passwort ergibt denselben Master Key`);
        }

        // 🚩 Und die Gegenprobe, die den MIGRATIONSFEHLER faengt: mit dem
        // JEWEILS ANDEREN Verfahren darf die Kette NICHT aufgehen. Ohne sie
        // wuerde ein Client, der die Kennung ignoriert und immer PBKDF2
        // rechnet, an der PBKDF2-Kette gruen bleiben - und niemand saehe,
        // dass er die Angabe gar nicht liest.
        const anderes = passwordShare.derivation === PASSWORD_DERIVATION_PBKDF2
            ? 'argon2id_m65536_t3_p4' as const
            : PASSWORD_DERIVATION_PBKDF2;
        const falschesVerfahren = await derivePasswordKey(
            chain.password_utf8, fromHex(passwordShare.salt), anderes
        );
        const falscherMaster = shamirReconstruct([
            { x: passwordShare.index, data: decryptShare(fromHex(passwordShare.encrypted), falschesVerfahren) },
            { x: recoveryShare.index, data: decryptShare(fromHex(recoveryShare.encrypted), recoveryKey) },
        ]);
        c.checks += 1;
        if (toHex(falscherMaster) === chain.master_key) {
            c.failures.push(
                `unlock/${bezeichnung}/falsches_verfahren: ${anderes} ergibt denselben Master Key `
                + '- die Ableitungsangabe waere dann wirkungslos'
            );
        }
    }

    await pruefeKette(file.unlock_chain, 'chain');
    await pruefeKette(file.unlock_chain_argon2id, 'chain_argon2id');

    return { fixture: 'vault_unlock.json', checks: c.checks, failures: c.failures };
}

/** Sanity-Check der Umgebung: echte WebCrypto, keine Test-Patches aktiv. */
function assertRealCrypto(): void {
    if (typeof webcrypto.subtle.decrypt !== 'function') {
        throw new Error('WebCrypto nicht verfügbar');
    }
}

// ---------------------------------------------------------------------------
// 8. key_transition.json  (#658912ef, Vertrag v2)
// ---------------------------------------------------------------------------

async function verifyKeyTransition(): Promise<CheckResult> {
    const file = load<KeyTransitionFile>('key_transition.json');
    const c = new Collector();
    const hexOrNull = (h: string | null): Uint8Array | null => (h === null ? null : fromHex(h));

    for (const f of file.fingerprints) {
        const x = fromHex(f.x25519_public);
        const m = fromHex(f.mlkem_public);
        const sig = hexOrNull(f.signing_public);
        c.equal(toHex(fingerprintPreimage(x, m, sig)), f.preimage, `${f.name}: preimage`);
        const full = await fingerprintFull(x, m, sig);
        c.equal(toHex(full), f.full, `${f.name}: full`);
        c.equal(formatFingerprint(full), f.display, `${f.name}: display`);
    }

    let gueltig = 0;
    let ungueltig = 0;
    for (const fall of file.cases) {
        const oldX = fromHex(fall.old_x25519_public);
        const oldM = fromHex(fall.old_mlkem_public);
        const oldSig = hexOrNull(fall.old_signing_public);
        c.equal(toHex(fingerprintPreimage(oldX, oldM, oldSig)), fall.old_fingerprint_preimage, `${fall.name}: fingerprint preimage`);
        const fp = await fingerprintFull(oldX, oldM, oldSig);
        c.equal(toHex(fp), fall.old_fingerprint_full, `${fall.name}: fingerprint full`);
        c.equal(formatFingerprint(fp), fall.old_fingerprint_display, `${fall.name}: fingerprint display`);

        const record = transitionRecord({
            reason: fall.anlass,
            login: fall.login,
            oldFingerprint: fp,
            newX25519PublicKey: fromHex(fall.new_x25519_public),
            newMlkemPublicKey: fromHex(fall.new_mlkem_public),
            newSigningPublicKey: fromHex(fall.new_signing_public),
            signedAt: fall.signed_at,
        });
        c.equal(toHex(record), fall.record, `${fall.name}: record`);
        c.true(record.length === 3635 + new TextEncoder().encode(fall.login).length, `${fall.name}: Aktenlänge 3635 + len(login)`);

        const verify = ml_dsa65.verify(
            fromHex(fall.signature), record, fromHex(fall.signer_public),
            { context: utf8(fall.context_utf8) },
        );
        c.true(verify === fall.verify, `${fall.name}: verify erwartet ${fall.verify}, erhalten ${verify}`);
        if (fall.verify) { gueltig += 1; } else { ungueltig += 1; }
    }
    c.true(gueltig > 0, 'kein gültiger Fall');
    c.true(ungueltig > 0, 'kein ungültiger Fall');

    let instGueltig = 0;
    let instUngueltig = 0;
    for (const fall of file.install_cases) {
        const curFp = await fingerprintFull(
            fromHex(fall.current_x25519_public), fromHex(fall.current_mlkem_public), hexOrNull(fall.current_signing_public),
        );
        c.equal(toHex(curFp), fall.current_fingerprint_full, `${fall.name}: current fingerprint`);
        const record = installRecord({
            login: fall.login,
            nonce: fromHex(fall.nonce),
            sharedSecret: fromHex(fall.shared_secret),
            currentFingerprint: curFp,
            newSigningPublicKey: fromHex(fall.new_signing_public),
        });
        c.equal(toHex(record), fall.record, `${fall.name}: install record`);
        c.true(record.length === 2098 + new TextEncoder().encode(fall.login).length, `${fall.name}: Einrichtungsaktenlänge 2098 + len(login)`);
        const verify = ml_dsa65.verify(fromHex(fall.signature), record, fromHex(fall.signer_public), { context: utf8(fall.context_utf8) });
        c.true(verify === fall.verify, `${fall.name}: verify erwartet ${fall.verify}, erhalten ${verify}`);
        if (fall.verify) { instGueltig += 1; } else { instUngueltig += 1; }
    }
    c.true(instGueltig > 0, 'kein gültiger Einrichtungsfall');
    c.true(instUngueltig > 0, 'kein ungültiger Einrichtungsfall');

    c.equal(toHex(seedAad(file.cases[0].login)), file.material.seed_aad, 'seed_aad');

    for (const walk of file.chain_walks) {
        for (const name of walk.delivered.chain) {
            c.true(file.cases.some(f => f.name === name), `${walk.name}: Kettenglied ${name} fehlt in cases`);
        }
    }

    return { fixture: 'key_transition.json', checks: c.checks, failures: c.failures };
}

export async function verifyAll(): Promise<CheckResult[]> {
    assertRealCrypto();
    return [
        await verifyAesGcm(),
        await verifyKeyDerivation(),
        await verifyWrappedTaskKeys(),
        await verifyEmailField(),
        await verifyHybridKem(),
        await verifyPackFormat(),
        await verifyVaultUnlock(),
        await verifyKeyTransition(),
    ];
}

/** Direktaufruf: npm run verify-kat */
const isDirectRun = process.argv[1] !== undefined && process.argv[1].includes('verify-kat');
if (isDirectRun) {
    verifyAll()
        .then(results => {
            let failed = 0;
            for (const result of results) {
                const status = result.failures.length === 0 ? 'OK  ' : 'FEHL';
                process.stdout.write(`[${status}] ${result.fixture.padEnd(24)} ${result.checks} Prüfungen\n`);
                for (const failure of result.failures) {
                    failed += 1;
                    process.stdout.write(`        ${failure}\n`);
                }
            }
            if (failed > 0) {
                process.stdout.write(`\n${failed} Abweichung(en) gefunden.\n`);
                process.exitCode = 1;
            } else {
                process.stdout.write('\nAlle KAT-Fixtures stimmen mit der TS-Krypto überein.\n');
            }
        })
        .catch((error: unknown) => {
            process.stderr.write(`KAT-Verifikation fehlgeschlagen: ${(error as Error).message}\n`);
            process.exitCode = 1;
        });
}
