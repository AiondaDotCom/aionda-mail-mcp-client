import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';
import { decryptAesGcm, decryptPhpAesGcm, decryptClientAesGcm } from '../../src/crypto/aes-gcm';

describe('AES-GCM', () => {
    const NONCE_LENGTH = 12;
    const TAG_LENGTH = 16;

    async function encrypt(plaintext: Uint8Array, key: Uint8Array): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
        const iv = new Uint8Array(NONCE_LENGTH);
        webcrypto.getRandomValues(iv);
        const aesKey = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
        const encrypted = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
        return { iv, ciphertext: new Uint8Array(encrypted) };
    }

    function generateKey(): Uint8Array {
        const key = new Uint8Array(32);
        webcrypto.getRandomValues(key);
        return key;
    }

    it('decryptAesGcm: round-trip', async () => {
        const key = generateKey();
        const plaintext = new TextEncoder().encode('Hello, TrashMail!');
        const { iv, ciphertext } = await encrypt(plaintext, key);
        const result = await decryptAesGcm(ciphertext, key, iv);
        expect(new TextDecoder().decode(result)).toBe('Hello, TrashMail!');
    });

    it('decryptPhpAesGcm: reorders PHP format (nonce||tag||ciphertext)', async () => {
        const key = generateKey();
        const plaintext = new TextEncoder().encode('PHP-encrypted data');
        const { iv, ciphertext } = await encrypt(plaintext, key);

        // WebCrypto output: ciphertext || tag
        // PHP format: nonce || tag || ciphertext_without_tag
        const tag = ciphertext.slice(ciphertext.length - TAG_LENGTH);
        const ctOnly = ciphertext.slice(0, ciphertext.length - TAG_LENGTH);

        const phpFormat = new Uint8Array(NONCE_LENGTH + TAG_LENGTH + ctOnly.length);
        phpFormat.set(iv, 0);
        phpFormat.set(tag, NONCE_LENGTH);
        phpFormat.set(ctOnly, NONCE_LENGTH + TAG_LENGTH);

        const result = await decryptPhpAesGcm(phpFormat, key);
        expect(new TextDecoder().decode(result)).toBe('PHP-encrypted data');
    });

    it('decryptClientAesGcm: no reorder needed (nonce||ciphertext||tag)', async () => {
        const key = generateKey();
        const plaintext = new TextEncoder().encode('Client-encrypted');
        const { iv, ciphertext } = await encrypt(plaintext, key);

        // Client format: nonce || ciphertext (with tag at end)
        const clientFormat = new Uint8Array(NONCE_LENGTH + ciphertext.length);
        clientFormat.set(iv, 0);
        clientFormat.set(ciphertext, NONCE_LENGTH);

        const result = await decryptClientAesGcm(clientFormat, key);
        expect(new TextDecoder().decode(result)).toBe('Client-encrypted');
    });

    it('fails with wrong key', async () => {
        const key = generateKey();
        const wrongKey = generateKey();
        const plaintext = new TextEncoder().encode('secret');
        const { iv, ciphertext } = await encrypt(plaintext, key);
        await expect(decryptAesGcm(ciphertext, wrongKey, iv)).rejects.toThrow();
    });
});
