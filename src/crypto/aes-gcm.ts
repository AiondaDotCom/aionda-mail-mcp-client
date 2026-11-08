/**
 * AES-256-GCM Decryption with PHP format byte reorder
 *
 * PHP format:  nonce (12 bytes) || tag (16 bytes) || ciphertext
 * WebCrypto:   ciphertext || tag (16 bytes)  (nonce passed separately)
 */
import { webcrypto } from 'node:crypto';

const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;

/**
 * Decrypt AES-256-GCM with separate IV
 */
export async function decryptAesGcm(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    additionalData?: Uint8Array
): Promise<Uint8Array> {
    const aesKey = await webcrypto.subtle.importKey(
        'raw',
        key,
        'AES-GCM',
        false,
        ['decrypt']
    );

    const plaintext = await webcrypto.subtle.decrypt(
        { name: 'AES-GCM', iv, ...(additionalData ? { additionalData } : {}) },
        aesKey,
        ciphertext
    );

    return new Uint8Array(plaintext);
}

/**
 * Decrypt a PHP-format AES-GCM encrypted field
 *
 * PHP: [12 bytes nonce][16 bytes tag][ciphertext]
 * Must reorder to WebCrypto: [ciphertext][tag]
 */
export async function decryptPhpAesGcm(
    encrypted: Uint8Array,
    key: Uint8Array
): Promise<Uint8Array> {
    const iv = encrypted.slice(0, NONCE_LENGTH);
    const tag = encrypted.slice(NONCE_LENGTH, NONCE_LENGTH + TAG_LENGTH);
    const ciphertext = encrypted.slice(NONCE_LENGTH + TAG_LENGTH);

    // Reorder: ciphertext || tag (WebCrypto format)
    const reordered = new Uint8Array(ciphertext.length + TAG_LENGTH);
    reordered.set(ciphertext, 0);
    reordered.set(tag, ciphertext.length);

    return decryptAesGcm(reordered, key, iv);
}

/**
 * Decrypt a client-encrypted field (sent emails, Master Key encrypted)
 *
 * Client format: [12 bytes IV][ciphertext || 16 bytes tag]
 * Already in WebCrypto format — NO reordering needed
 */
/**
 * Encrypt plaintext with AES-256-GCM in PHP format
 *
 * Output: [12 bytes nonce][16 bytes tag][ciphertext]
 */
export async function encryptPhpAesGcm(
    plaintext: Uint8Array,
    key: Uint8Array
): Promise<Uint8Array> {
    const iv = webcrypto.getRandomValues(new Uint8Array(NONCE_LENGTH));

    const aesKey = await webcrypto.subtle.importKey(
        'raw',
        key,
        'AES-GCM',
        false,
        ['encrypt']
    );

    const encrypted = await webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: TAG_LENGTH * 8 },
        aesKey,
        plaintext
    );

    // WebCrypto output: ciphertext || tag
    const encryptedBytes = new Uint8Array(encrypted);
    const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - TAG_LENGTH);
    const tag = encryptedBytes.slice(encryptedBytes.length - TAG_LENGTH);

    // Reorder to PHP format: nonce || tag || ciphertext
    const result = new Uint8Array(NONCE_LENGTH + TAG_LENGTH + ciphertext.length);
    result.set(iv, 0);
    result.set(tag, NONCE_LENGTH);
    result.set(ciphertext, NONCE_LENGTH + TAG_LENGTH);

    return result;
}

/**
 * Decrypt a client-encrypted field (sent emails, Master Key encrypted)
 *
 * Client format: [12 bytes IV][ciphertext || 16 bytes tag]
 * Already in WebCrypto format — NO reordering needed
 */
export async function decryptClientAesGcm(
    encrypted: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array
): Promise<Uint8Array> {
    const iv = encrypted.slice(0, NONCE_LENGTH);
    const ciphertextWithTag = encrypted.slice(NONCE_LENGTH);

    return decryptAesGcm(ciphertextWithTag, key, iv, additionalData);
}

/**
 * Encrypt a client-layout field: iv(12) || ciphertext || tag(16).
 *
 * `additionalData` is authenticated but not stored in the blob. Callers that
 * use it must provide the exact same bytes when decrypting.
 */
export async function encryptClientAesGcm(
    plaintext: Uint8Array,
    key: Uint8Array,
    iv?: Uint8Array,
    additionalData?: Uint8Array
): Promise<Uint8Array> {
    const usedIv = iv ?? webcrypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
    const aesKey = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    const encrypted = await webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv: usedIv, ...(additionalData ? { additionalData } : {}) },
        aesKey,
        plaintext
    );

    const result = new Uint8Array(NONCE_LENGTH + encrypted.byteLength);
    result.set(usedIv, 0);
    result.set(new Uint8Array(encrypted), NONCE_LENGTH);
    return result;
}

/**
 * Meldung, wenn WEDER Version 2 NOCH Version 1 aufgeht (#92e6ad10).
 * Sie darf nicht "v2" behaupten - der Blob kann ein Version-1-Blob sein.
 */
export const ENVELOPE_BEIDE_VERSIONEN_FEHLER =
    'Vault-Umschlag: weder als Version 2 noch als Version 1 lesbar';

/** Version 1 (Legacy): iv(12) || ciphertext || tag(16), Key = Master Key direkt. */
async function decryptVaultDataV1(
    encrypted: Uint8Array,
    masterKey: Uint8Array
): Promise<Uint8Array> {
    const iv = encrypted.slice(0, NONCE_LENGTH);
    const ciphertextWithTag = encrypted.slice(NONCE_LENGTH);
    return decryptAesGcm(ciphertextWithTag, masterKey, iv);
}

/** Version 2: 0x02 || salt(32) || iv(12) || ciphertext || tag(16). */
async function decryptVaultDataV2(
    encrypted: Uint8Array,
    masterKey: Uint8Array
): Promise<Uint8Array> {
    const { webcrypto } = await import('node:crypto');
    const salt = encrypted.slice(1, 33);
    const iv = encrypted.slice(33, 45);
    const ciphertext = encrypted.slice(45);

    const keyMaterial = await webcrypto.subtle.importKey(
        'raw', masterKey, 'HKDF', false, ['deriveKey']
    );
    const derivedKey = await webcrypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt,
            info: new TextEncoder().encode('trashmail-contacts-v2')
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );

    const plaintext = await webcrypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        derivedKey,
        ciphertext
    );
    return new Uint8Array(plaintext);
}

/**
 * Decrypt data encrypted by the browser's encryptData() function.
 * Supports Version 2 (HKDF + AES-GCM) and Version 1 (legacy: iv || ciphertext+tag).
 * This matches vault-crypto.ts encryptData/decryptData format.
 *
 * 🚩 Das erste Byte ist KEIN verlaesslicher Versionsmarker (#92e6ad10).
 * Ein Version-1-Blob beginnt mit dem IV, also mit einem Zufallsbyte; in
 * 1 von 256 Faellen ist das zufaellig 0x02, und der Blob war damit DAUERHAFT
 * unlesbar. Deshalb: scheitert der v2-Weg, wird danach der v1-Weg versucht.
 *
 * Kein Downgrade-Weg: Fuer jedes erste Byte ausser 0x02 - also fuer 255 von
 * 256 - fuehrt dieselbe Funktion ohnehin bedingungslos nach v1. Der Rueckfall
 * gibt einem Angreifer nichts, was er nicht schon hat. Beide Wege bleiben
 * AES-GCM-authentifiziert.
 */
export async function decryptVaultData(
    encrypted: Uint8Array,
    masterKey: Uint8Array
): Promise<Uint8Array> {
    if (encrypted[0] !== 0x02) {
        return decryptVaultDataV1(encrypted, masterKey);
    }

    try {
        return await decryptVaultDataV2(encrypted, masterKey);
    } catch {
        try {
            return await decryptVaultDataV1(encrypted, masterKey);
        } catch (v1Fehler) {
            // Die Ursache MUSS mitgehen: der Aufrufer soll am `name`
            // (`OperationError`) noch erkennen koennen, dass es ein
            // Schluessel- und kein Netzproblem war.
            const fehler = new Error(ENVELOPE_BEIDE_VERSIONEN_FEHLER);
            (fehler as { cause?: unknown }).cause = v1Fehler;
            throw fehler;
        }
    }
}

/**
 * Encrypt data matching the browser's encryptData() format (Version 2: HKDF + AES-GCM).
 */
export async function encryptVaultData(
    plaintext: Uint8Array,
    masterKey: Uint8Array
): Promise<Uint8Array> {
    const { webcrypto, randomBytes } = await import('node:crypto');
    const VERSION = 0x02;

    const salt = new Uint8Array(randomBytes(32));
    const iv = new Uint8Array(randomBytes(12));

    const keyMaterial = await webcrypto.subtle.importKey(
        'raw', masterKey, 'HKDF', false, ['deriveKey']
    );
    const derivedKey = await webcrypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt,
            info: new TextEncoder().encode('trashmail-contacts-v2')
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );

    const ciphertext = await webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        derivedKey,
        plaintext
    );

    // version(1) || salt(32) || iv(12) || ciphertext+tag
    const result = new Uint8Array(1 + 32 + 12 + ciphertext.byteLength);
    result[0] = VERSION;
    result.set(salt, 1);
    result.set(iv, 33);
    result.set(new Uint8Array(ciphertext), 45);
    return result;
}
