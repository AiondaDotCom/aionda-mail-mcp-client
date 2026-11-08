/**
 * Tests for hybridEncapsulate + hybridDecapsulate roundtrip
 * and the cross-vault key re-wrapping flow.
 */
import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { hybridEncapsulate, hybridDecapsulate } from '../../src/crypto/hybrid-kem';
import { decryptSharedFolderKey } from '../../src/crypto/shared-folder-key';
import { toBase64 } from '../../src/crypto/encoding';
import type { VaultPrivateKeys } from '../../src/crypto/email-decryptor';

/**
 * Generate a complete keypair (X25519 + ML-KEM) for testing
 */
async function generateTestKeypair() {
    // X25519
    const x25519KeyPair = await webcrypto.subtle.generateKey(
        { name: 'X25519' }, true, ['deriveBits']
    );
    const x25519PubRaw = new Uint8Array(
        await webcrypto.subtle.exportKey('raw', x25519KeyPair.publicKey)
    );
    const x25519PrivPkcs8 = new Uint8Array(
        await webcrypto.subtle.exportKey('pkcs8', x25519KeyPair.privateKey)
    );
    const x25519PrivRaw = x25519PrivPkcs8.slice(x25519PrivPkcs8.length - 32);

    // ML-KEM-1024
    const mlKemKeyPair = ml_kem1024.keygen();

    return {
        publicKeys: {
            x25519: x25519PubRaw,
            mlkem: mlKemKeyPair.publicKey,
        },
        privateKeys: {
            x25519PrivateKey: x25519PrivRaw,
            mlKemPrivateKey: mlKemKeyPair.secretKey,
        } as VaultPrivateKeys,
    };
}

describe('hybridEncapsulate', () => {
    it('encapsulate + decapsulate should produce the same shared secret', async () => {
        const { publicKeys, privateKeys } = await generateTestKeypair();

        const result = await hybridEncapsulate(publicKeys.x25519, publicKeys.mlkem);

        // Decapsulate with private keys
        const decapsulatedSecret = await hybridDecapsulate(
            result.x25519Ciphertext,
            result.mlKemCiphertext,
            privateKeys.x25519PrivateKey,
            privateKeys.mlKemPrivateKey
        );

        expect(decapsulatedSecret).toEqual(result.sharedSecret);
    });

    it('should produce different ciphertexts on each call', async () => {
        const { publicKeys } = await generateTestKeypair();

        const result1 = await hybridEncapsulate(publicKeys.x25519, publicKeys.mlkem);
        const result2 = await hybridEncapsulate(publicKeys.x25519, publicKeys.mlkem);

        // Different ephemeral keys each time
        expect(result1.x25519Ciphertext).not.toEqual(result2.x25519Ciphertext);
        expect(result1.sharedSecret).not.toEqual(result2.sharedSecret);
    });

    it('should fail with wrong private keys', async () => {
        const { publicKeys } = await generateTestKeypair();
        const wrongKeys = await generateTestKeypair();

        const result = await hybridEncapsulate(publicKeys.x25519, publicKeys.mlkem);

        const decapsulatedSecret = await hybridDecapsulate(
            result.x25519Ciphertext,
            result.mlKemCiphertext,
            wrongKeys.privateKeys.x25519PrivateKey,
            wrongKeys.privateKeys.mlKemPrivateKey
        );

        // Different secrets
        expect(decapsulatedSecret).not.toEqual(result.sharedSecret);
    });
});

describe('cross-vault key re-wrapping flow', () => {
    it('should re-wrap an ephemeral key from shared folder to own vault', async () => {
        // Setup: Owner and Agent have different keypairs
        const owner = await generateTestKeypair();
        const agent = await generateTestKeypair();

        // 1. Original ephemeral key (used to encrypt the email)
        const ephemeralKey = webcrypto.getRandomValues(new Uint8Array(32));

        // 2. Owner shares a folder with agent — encrypts folder key for agent
        const folderKey = webcrypto.getRandomValues(new Uint8Array(32));

        // Encrypt folder key for agent using hybridEncapsulate
        const folderKem = await hybridEncapsulate(agent.publicKeys.x25519, agent.publicKeys.mlkem);
        const folderAesKey = await webcrypto.subtle.importKey(
            'raw', folderKem.sharedSecret, { name: 'AES-GCM' }, false, ['encrypt']
        );
        const folderKeyNonce = webcrypto.getRandomValues(new Uint8Array(12));
        const encryptedFolderKey = new Uint8Array(await webcrypto.subtle.encrypt(
            { name: 'AES-GCM', iv: folderKeyNonce }, folderAesKey, folderKey
        ));

        // 3. Owner puts email in shared folder — wraps ephemeral key with folder key
        const rewrapAesKey = await webcrypto.subtle.importKey(
            'raw', folderKey, { name: 'AES-GCM' }, false, ['encrypt']
        );
        const rewrapNonce = webcrypto.getRandomValues(new Uint8Array(12));
        const rewrappedKey = new Uint8Array(await webcrypto.subtle.encrypt(
            { name: 'AES-GCM', iv: rewrapNonce }, rewrapAesKey, ephemeralKey
        ));

        // === AGENT SIDE: Cross-vault copy flow ===

        // 4. Agent decrypts folder key
        const decryptedFolderKey = await decryptSharedFolderKey(
            toBase64(encryptedFolderKey),
            toBase64(folderKem.x25519Ciphertext),
            toBase64(new Uint8Array(folderKem.mlKemCiphertext)),
            toBase64(folderKeyNonce),
            agent.privateKeys
        );
        expect(decryptedFolderKey).toEqual(folderKey);

        // 5. Agent decrypts the rewrapped ephemeral key with folder key
        const folderDecKey = await webcrypto.subtle.importKey(
            'raw', decryptedFolderKey, { name: 'AES-GCM' }, false, ['decrypt']
        );
        const decryptedEphemeralKey = new Uint8Array(await webcrypto.subtle.decrypt(
            { name: 'AES-GCM', iv: rewrapNonce }, folderDecKey, rewrappedKey
        ));
        expect(decryptedEphemeralKey).toEqual(ephemeralKey);

        // 6. Agent re-wraps ephemeral key with own vault public keys
        const ownKem = await hybridEncapsulate(agent.publicKeys.x25519, agent.publicKeys.mlkem);
        const wrapAesKey = await webcrypto.subtle.importKey(
            'raw', ownKem.sharedSecret, { name: 'AES-GCM' }, false, ['encrypt']
        );
        const wrapNonce = webcrypto.getRandomValues(new Uint8Array(12));
        const newWrappedRaw = new Uint8Array(await webcrypto.subtle.encrypt(
            { name: 'AES-GCM', iv: wrapNonce }, wrapAesKey, decryptedEphemeralKey
        ));

        // Reorder to PHP format: tag(16) || ciphertext
        const TAG_LENGTH = 16;
        const ciphertext = newWrappedRaw.slice(0, newWrappedRaw.length - TAG_LENGTH);
        const tag = newWrappedRaw.slice(newWrappedRaw.length - TAG_LENGTH);
        const phpFormat = new Uint8Array(TAG_LENGTH + ciphertext.length);
        phpFormat.set(tag, 0);
        phpFormat.set(ciphertext, TAG_LENGTH);

        // Pack: version(1) || x25519_ct(32) || mlkem_ct || wrap_nonce(12) || encrypted_key
        const packed = new Uint8Array(1 + 32 + ownKem.mlKemCiphertext.length + 12 + phpFormat.length);
        let offset = 0;
        packed[offset++] = 0x01;
        packed.set(ownKem.x25519Ciphertext, offset); offset += 32;
        packed.set(ownKem.mlKemCiphertext, offset); offset += ownKem.mlKemCiphertext.length;
        packed.set(wrapNonce, offset); offset += 12;
        packed.set(phpFormat, offset);

        // 7. Verify: Agent can decrypt the new wrapped key with own private keys
        // Parse packed format
        const version = packed[0];
        expect(version).toBe(1);
        const x25519Ct = packed.slice(1, 33);
        const mlKemCt = packed.slice(33, 33 + 1568);
        const iv = packed.slice(33 + 1568, 33 + 1568 + 12);
        const encKey = packed.slice(33 + 1568 + 12);

        // Decapsulate
        const decapSecret = await hybridDecapsulate(
            x25519Ct, mlKemCt,
            agent.privateKeys.x25519PrivateKey,
            agent.privateKeys.mlKemPrivateKey
        );

        // PHP format: tag(16) || ciphertext → WebCrypto: ciphertext || tag
        const decTag = encKey.slice(0, TAG_LENGTH);
        const decCiphertext = encKey.slice(TAG_LENGTH);
        const reordered = new Uint8Array(encKey.length);
        reordered.set(decCiphertext, 0);
        reordered.set(decTag, decCiphertext.length);

        const decAesKey = await webcrypto.subtle.importKey(
            'raw', decapSecret, { name: 'AES-GCM' }, false, ['decrypt']
        );
        const finalEphemeralKey = new Uint8Array(await webcrypto.subtle.decrypt(
            { name: 'AES-GCM', iv }, decAesKey, reordered
        ));

        // The final ephemeral key should match the original
        expect(finalEphemeralKey).toEqual(ephemeralKey);
    });
});
