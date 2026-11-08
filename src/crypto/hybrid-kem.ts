/**
 * Hybrid KEM: X25519 + ML-KEM-1024
 * Port from browser (WebCrypto) to Node.js
 */
import { webcrypto } from 'node:crypto';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

const HKDF_INFO = new TextEncoder().encode('trashmail-hybrid-kem-v1');

/**
 * Import X25519 private key for key agreement (from raw 32 bytes)
 */
async function importX25519PrivateKey(privateKeyBytes: Uint8Array): Promise<Awaited<ReturnType<typeof webcrypto.subtle.importKey>>> {
    const pkcs8Header = new Uint8Array([
        0x30, 0x2e,
        0x02, 0x01, 0x00,
        0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x6e,
        0x04, 0x22,
        0x04, 0x20,
    ]);
    const pkcs8 = new Uint8Array(pkcs8Header.length + privateKeyBytes.length);
    pkcs8.set(pkcs8Header, 0);
    pkcs8.set(privateKeyBytes, pkcs8Header.length);

    return webcrypto.subtle.importKey(
        'pkcs8',
        pkcs8,
        { name: 'X25519' },
        true,
        ['deriveBits']
    );
}

/**
 * Import X25519 public key
 */
async function importX25519PublicKey(publicKeyBytes: Uint8Array): Promise<Awaited<ReturnType<typeof webcrypto.subtle.importKey>>> {
    return webcrypto.subtle.importKey(
        'raw',
        publicKeyBytes,
        { name: 'X25519' },
        true,
        []
    );
}

/**
 * Perform X25519 key agreement
 */
async function x25519DeriveShared(
    privateKey: Uint8Array,
    publicKey: Uint8Array
): Promise<Uint8Array> {
    const privKey = await importX25519PrivateKey(privateKey);
    const pubKey = await importX25519PublicKey(publicKey);

    const sharedBits = await webcrypto.subtle.deriveBits(
        { name: 'X25519', public: pubKey },
        privKey,
        256
    );

    return new Uint8Array(sharedBits);
}

/**
 * Hybrid KEM Decapsulation
 *
 * Derives the shared secret from X25519 + ML-KEM-1024 ciphertexts
 * using recipient's private keys.
 *
 * @param x25519Ciphertext - Sender's ephemeral X25519 public key (32 bytes)
 * @param mlKemCiphertext - ML-KEM-1024 ciphertext (1568 bytes)
 * @param x25519PrivateKey - Recipient's X25519 private key (32 bytes)
 * @param mlKemPrivateKey - Recipient's ML-KEM-1024 private key (3168 bytes)
 * @returns 32-byte shared secret
 */
/**
 * Hybrid KEM Encapsulation result
 */
export interface HybridEncapsulateResult {
    sharedSecret: Uint8Array;
    x25519Ciphertext: Uint8Array;
    mlKemCiphertext: Uint8Array;
}

/**
 * Hybrid KEM Encapsulation
 *
 * Generates a shared secret encrypted for the recipient's public keys.
 * Inverse of hybridDecapsulate.
 *
 * @param x25519PublicKey - Recipient's X25519 public key (32 bytes)
 * @param mlKemPublicKey - Recipient's ML-KEM-1024 public key (1568 bytes)
 * @returns shared secret + ciphertexts for recipient to decapsulate
 */
export async function hybridEncapsulate(
    x25519PublicKey: Uint8Array,
    mlKemPublicKey: Uint8Array
): Promise<HybridEncapsulateResult> {
    // Generate ephemeral X25519 keypair
    const ephemeralKeyPair = (await webcrypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveBits']
    )) as unknown as { publicKey: Awaited<ReturnType<typeof webcrypto.subtle.importKey>>; privateKey: Awaited<ReturnType<typeof webcrypto.subtle.importKey>> };

    // Export ephemeral public key (= x25519Ciphertext for recipient)
    const ephemeralPubRaw = new Uint8Array(
        await webcrypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey)
    );

    // X25519 key agreement with recipient's public key
    const recipientPubKey = await importX25519PublicKey(x25519PublicKey);
    const x25519SharedBits = await webcrypto.subtle.deriveBits(
        { name: 'X25519', public: recipientPubKey },
        ephemeralKeyPair.privateKey,
        256
    );
    const x25519Shared = new Uint8Array(x25519SharedBits);

    // ML-KEM-1024 encapsulation
    const mlKemResult = ml_kem1024.encapsulate(mlKemPublicKey);

    // Combine secrets using HKDF-SHA256
    const combined = new Uint8Array(x25519Shared.length + mlKemResult.sharedSecret.length);
    combined.set(x25519Shared, 0);
    combined.set(mlKemResult.sharedSecret, x25519Shared.length);

    const sharedSecret = hkdf(sha256, combined, undefined, HKDF_INFO, 32);

    return {
        sharedSecret,
        x25519Ciphertext: ephemeralPubRaw,
        mlKemCiphertext: mlKemResult.cipherText,
    };
}

export async function hybridDecapsulate(
    x25519Ciphertext: Uint8Array,
    mlKemCiphertext: Uint8Array,
    x25519PrivateKey: Uint8Array,
    mlKemPrivateKey: Uint8Array
): Promise<Uint8Array> {
    // X25519 key agreement
    const x25519Shared = await x25519DeriveShared(x25519PrivateKey, x25519Ciphertext);

    // ML-KEM-1024 decapsulation
    const mlKemShared = ml_kem1024.decapsulate(mlKemCiphertext, mlKemPrivateKey);

    // Combine secrets using HKDF-SHA256
    const combined = new Uint8Array(x25519Shared.length + mlKemShared.length);
    combined.set(x25519Shared, 0);
    combined.set(mlKemShared, x25519Shared.length);

    return hkdf(sha256, combined, undefined, HKDF_INFO, 32);
}
