/**
 * Shared Folder Key Decryption
 *
 * Decrypts a shared folder's encrypted key using Hybrid KEM (X25519 + ML-KEM-1024).
 * The folder key was encrypted by the folder owner for the recipient's public keys.
 */
import { webcrypto } from 'node:crypto';
import { hybridDecapsulate } from './hybrid-kem';
import { fromBase64 } from './encoding';
import type { VaultPrivateKeys } from './email-decryptor';

/**
 * Decrypt the shared folder key from an incoming share.
 *
 * The folder owner encrypted the folder's master key using the recipient's
 * Hybrid KEM public keys (X25519 + ML-KEM-1024). This function:
 * 1. Decapsulates the hybrid shared secret
 * 2. Decrypts the AES-GCM wrapped folder key using the shared secret
 *
 * @param encryptedFolderKey - Base64-encoded encrypted folder key (ciphertext || tag, Nonce separat)
 * @param x25519Ephemeral - Base64-encoded X25519 ephemeral public key (32 bytes)
 * @param mlkemCiphertext - Base64-encoded ML-KEM-1024 ciphertext (1568 bytes)
 * @param keyNonce - Base64-encoded AES-GCM nonce (12 bytes)
 * @param privateKeys - Recipient's private keys
 * @returns Decrypted folder key (32 bytes)
 */
export async function decryptSharedFolderKey(
    encryptedFolderKey: string,
    x25519Ephemeral: string,
    mlkemCiphertext: string,
    keyNonce: string,
    privateKeys: VaultPrivateKeys
): Promise<Uint8Array> {
    // Decapsulate hybrid shared secret
    const sharedSecret = await hybridDecapsulate(
        fromBase64(x25519Ephemeral),
        fromBase64(mlkemCiphertext),
        privateKeys.x25519PrivateKey,
        privateKeys.mlKemPrivateKey
    );

    // Import shared secret as AES-GCM key
    const aesKey = await webcrypto.subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    // Decrypt the folder key
    const nonce = fromBase64(keyNonce);
    const encryptedData = fromBase64(encryptedFolderKey);

    const decrypted = await webcrypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey,
        encryptedData
    );

    return new Uint8Array(decrypted);
}
