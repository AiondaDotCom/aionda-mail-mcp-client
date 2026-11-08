import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { toBase64 } from '../../src/crypto/encoding';
import { decryptSharedFolderKey } from '../../src/crypto/shared-folder-key';
import type { VaultPrivateKeys } from '../../src/crypto/email-decryptor';

const HKDF_INFO = new TextEncoder().encode('trashmail-hybrid-kem-v1');

describe('decryptSharedFolderKey', () => {
    it('should decrypt a folder key encrypted with hybrid KEM', async () => {
        // Generate recipient X25519 keypair
        const x25519KeyPair = await webcrypto.subtle.generateKey(
            { name: 'X25519' },
            true,
            ['deriveBits']
        );
        const x25519PubRaw = new Uint8Array(
            await webcrypto.subtle.exportKey('raw', x25519KeyPair.publicKey)
        );
        const x25519PrivPkcs8 = new Uint8Array(
            await webcrypto.subtle.exportKey('pkcs8', x25519KeyPair.privateKey)
        );
        // Extract raw 32-byte private key from PKCS8 (last 32 bytes)
        const x25519PrivRaw = x25519PrivPkcs8.slice(x25519PrivPkcs8.length - 32);

        // Generate recipient ML-KEM-1024 keypair
        const mlKemKeyPair = ml_kem1024.keygen();

        const privateKeys: VaultPrivateKeys = {
            x25519PrivateKey: x25519PrivRaw,
            mlKemPrivateKey: mlKemKeyPair.secretKey,
        };

        // The "folder key" we want to encrypt and share
        const folderKey = webcrypto.getRandomValues(new Uint8Array(32));

        // --- Simulate server-side encryption (what the folder owner does) ---

        // Ephemeral X25519 keypair
        const ephemeralX25519 = await webcrypto.subtle.generateKey(
            { name: 'X25519' },
            true,
            ['deriveBits']
        );
        const ephemeralX25519Pub = new Uint8Array(
            await webcrypto.subtle.exportKey('raw', ephemeralX25519.publicKey)
        );

        // X25519 key agreement: ephemeral private x recipient public
        const recipientX25519Pub = await webcrypto.subtle.importKey(
            'raw', x25519PubRaw, { name: 'X25519' }, true, []
        );
        const x25519Shared = new Uint8Array(
            await webcrypto.subtle.deriveBits(
                { name: 'X25519', public: recipientX25519Pub },
                ephemeralX25519.privateKey,
                256
            )
        );

        // ML-KEM-1024 encapsulation
        const { sharedSecret: mlKemShared, cipherText: mlKemCiphertext } =
            ml_kem1024.encapsulate(mlKemKeyPair.publicKey);

        // Combine shared secrets via HKDF
        const combined = new Uint8Array(x25519Shared.length + mlKemShared.length);
        combined.set(x25519Shared, 0);
        combined.set(mlKemShared, x25519Shared.length);
        const sharedSecret = hkdf(sha256, combined, undefined, HKDF_INFO, 32);

        // Encrypt folder key with AES-GCM using the shared secret
        const nonce = webcrypto.getRandomValues(new Uint8Array(12));
        const aesKey = await webcrypto.subtle.importKey(
            'raw', sharedSecret, { name: 'AES-GCM' }, false, ['encrypt']
        );
        const encrypted = new Uint8Array(
            await webcrypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce },
                aesKey,
                folderKey
            )
        );

        // --- Now decrypt using our function ---
        const decryptedFolderKey = await decryptSharedFolderKey(
            toBase64(encrypted),
            toBase64(ephemeralX25519Pub),
            toBase64(new Uint8Array(mlKemCiphertext)),
            toBase64(nonce),
            privateKeys
        );

        expect(decryptedFolderKey).toEqual(folderKey);
    });

    it('should throw on wrong private keys', async () => {
        // Generate two different keypairs
        const correctKeypair = await webcrypto.subtle.generateKey(
            { name: 'X25519' }, true, ['deriveBits']
        );
        const wrongKeypair = await webcrypto.subtle.generateKey(
            { name: 'X25519' }, true, ['deriveBits']
        );

        const correctPubRaw = new Uint8Array(
            await webcrypto.subtle.exportKey('raw', correctKeypair.publicKey)
        );
        const wrongPrivPkcs8 = new Uint8Array(
            await webcrypto.subtle.exportKey('pkcs8', wrongKeypair.privateKey)
        );
        const wrongPrivRaw = wrongPrivPkcs8.slice(wrongPrivPkcs8.length - 32);

        // ML-KEM keypairs
        const correctMlKem = ml_kem1024.keygen();
        const wrongMlKem = ml_kem1024.keygen();

        const wrongKeys: VaultPrivateKeys = {
            x25519PrivateKey: wrongPrivRaw,
            mlKemPrivateKey: wrongMlKem.secretKey,
        };

        // Encrypt with correct public keys
        const ephemeral = await webcrypto.subtle.generateKey(
            { name: 'X25519' }, true, ['deriveBits']
        );
        const ephemeralPub = new Uint8Array(
            await webcrypto.subtle.exportKey('raw', ephemeral.publicKey)
        );
        const recipientPub = await webcrypto.subtle.importKey(
            'raw', correctPubRaw, { name: 'X25519' }, true, []
        );
        const x25519Shared = new Uint8Array(
            await webcrypto.subtle.deriveBits(
                { name: 'X25519', public: recipientPub },
                ephemeral.privateKey, 256
            )
        );
        const { sharedSecret: mlShared, cipherText: mlCt } =
            ml_kem1024.encapsulate(correctMlKem.publicKey);

        const combined = new Uint8Array(x25519Shared.length + mlShared.length);
        combined.set(x25519Shared, 0);
        combined.set(mlShared, x25519Shared.length);
        const secret = hkdf(sha256, combined, undefined, HKDF_INFO, 32);

        const nonce = webcrypto.getRandomValues(new Uint8Array(12));
        const aesKey = await webcrypto.subtle.importKey(
            'raw', secret, { name: 'AES-GCM' }, false, ['encrypt']
        );
        const folderKey = webcrypto.getRandomValues(new Uint8Array(32));
        const encrypted = new Uint8Array(
            await webcrypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce }, aesKey, folderKey
            )
        );

        // Attempt decrypt with wrong keys -> should throw
        await expect(
            decryptSharedFolderKey(
                toBase64(encrypted),
                toBase64(ephemeralPub),
                toBase64(new Uint8Array(mlCt)),
                toBase64(nonce),
                wrongKeys
            )
        ).rejects.toThrow();
    });
});
