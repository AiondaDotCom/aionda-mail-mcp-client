/**
 * HKDF SHA-256 Key Derivation
 * Port of vault-crypto.ts deriveFolderKey()
 */
import { webcrypto } from 'node:crypto';

/**
 * Derive a folder-specific key from the master key using HKDF-SHA-256
 *
 * @param masterKey - 32-byte master key
 * @param folderUuid - UUID of the folder (used as HKDF info)
 * @returns 32-byte folder key
 */
export async function deriveFolderKey(
    masterKey: Uint8Array,
    folderUuid: string
): Promise<Uint8Array> {
    const keyMaterial = await webcrypto.subtle.importKey(
        'raw',
        masterKey,
        'HKDF',
        false,
        ['deriveBits']
    );

    const derivedBits = await webcrypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode('trashmail-folder-key-v1'),
            info: new TextEncoder().encode(folderUuid),
        },
        keyMaterial,
        256
    );

    return new Uint8Array(derivedBits);
}

/**
 * Derive an encryption key from master key with salt (Version 2 format)
 * Used for contacts/data encryption (encryptData/decryptData)
 */
export async function deriveEncryptionKey(
    masterKey: Uint8Array,
    salt: Uint8Array
): Promise<Awaited<ReturnType<typeof webcrypto.subtle.deriveKey>>> {
    const keyMaterial = await webcrypto.subtle.importKey(
        'raw',
        masterKey,
        'HKDF',
        false,
        ['deriveKey']
    );

    return webcrypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt,
            info: new TextEncoder().encode('trashmail-contacts-v2'),
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
}

/**
 * Mail-eigenen Schlüssel ableiten (`__DERIVED_KEY_ENCRYPTED__`).
 *
 * Byteweise derselbe wie `deriveEmailKey` im Web-Client
 * (typescript/manager/vault/vault-crypto.ts) und `KeyDerivation.emailKey()`
 * in der Apple-App: HKDF-SHA-256, Salz "trashmail-email-key-v1",
 * info = Mail-UUID. Anhänge benutzen den Schlüssel IHRER Mail. #c2fb3967
 *
 * @param masterKey - 32-Byte-Master-Key
 * @param emailUuid - UUID der Mail (nicht des Anhangs)
 * @returns 32-Byte-Schlüssel
 */
export async function deriveEmailKey(
    masterKey: Uint8Array,
    emailUuid: string
): Promise<Uint8Array> {
    if (!emailUuid) {
        throw new Error('deriveEmailKey ohne Mail-UUID aufgerufen');
    }
    const keyMaterial = await webcrypto.subtle.importKey(
        'raw',
        masterKey,
        'HKDF',
        false,
        ['deriveBits']
    );

    const derivedBits = await webcrypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode('trashmail-email-key-v1'),
            info: new TextEncoder().encode(emailUuid),
        },
        keyMaterial,
        256
    );

    return new Uint8Array(derivedBits);
}
