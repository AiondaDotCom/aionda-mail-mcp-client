import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';
import { decryptEmail } from '../../src/crypto/email-decryptor';
import type { VaultPrivateKeys } from '../../src/crypto/email-decryptor';
import type { EncryptedEmail } from '../../src/types/email';
import { toHex } from '../../src/crypto/encoding';
import { deriveEmailKey } from '../../src/crypto/key-derivation';

describe('Email Decryptor', () => {
    const NONCE_LENGTH = 12;

    async function encryptField(plaintext: string, key: Uint8Array): Promise<string> {
        const iv = new Uint8Array(NONCE_LENGTH);
        webcrypto.getRandomValues(iv);

        const aesKey = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
        const encrypted = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext));
        const ct = new Uint8Array(encrypted);

        // Client format: iv || ciphertext (including tag)
        const result = new Uint8Array(NONCE_LENGTH + ct.length);
        result.set(iv, 0);
        result.set(ct, NONCE_LENGTH);
        return toHex(result);
    }

    it('decrypts client-encrypted email (Master Key)', async () => {
        const masterKey = new Uint8Array(32);
        webcrypto.getRandomValues(masterKey);

        const dummyPrivateKeys: VaultPrivateKeys = {
            x25519PrivateKey: new Uint8Array(32),
            mlKemPrivateKey: new Uint8Array(3168),
        };

        const email: EncryptedEmail = {
            uuid: 'test-uuid-123',
            dea_id: 1,
            encrypted_subject: await encryptField('Test Subject', masterKey),
            encrypted_from: await encryptField('sender@example.com', masterKey),
            encrypted_to: await encryptField('receiver@trashmail.com', masterKey),
            encrypted_body: await encryptField('<p>Hello World</p>', masterKey),
            wrapped_ephemeral_key: '__MASTER_KEY_ENCRYPTED__',
            ephemeral_key_iv: '',
            size_bytes: 1024,
            has_attachments: false,
            attachment_count: 0,
            is_read: false,
            is_starred: false,
            is_deleted: false,
            folder_type: 'inbox',
            received_at: '2026-02-28T12:00:00Z',
        };

        const decrypted = await decryptEmail(email, masterKey, dummyPrivateKeys);

        expect(decrypted.uuid).toBe('test-uuid-123');
        expect(decrypted.subject).toBe('Test Subject');
        expect(decrypted.from).toBe('sender@example.com');
        expect(decrypted.to).toBe('receiver@trashmail.com');
        expect(decrypted.body).toBe('<p>Hello World</p>');
        expect(decrypted.isRead).toBe(false);
        expect(decrypted.folderType).toBe('inbox');
        expect(decrypted.receivedAt).toBeInstanceOf(Date);
    });
    // #c2fb3967 - abgeleiteter Mail-Schlüssel (`__DERIVED_KEY_ENCRYPTED__`)
    describe('abgeleiteter Mail-Schlüssel', () => {
        const masterKey = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
        const uuid = '123e4567-e89b-12d3-a456-426614174000';
        const dummyPrivateKeys: VaultPrivateKeys = {
            x25519PrivateKey: new Uint8Array(32),
            mlKemPrivateKey: new Uint8Array(3168),
        };

        it('leitet byte-gleich zum Web-Client und zur Apple-App ab', async () => {
            // Vektor aus EmailFieldTests.testEmailKeyMatchesWebCryptoKnownAnswerVector
            const key = await deriveEmailKey(masterKey, uuid);
            expect(toHex(key)).toBe('133812383c5926e8fe7ec2a5d6176c6d947e0f6147847707321dbf5e8e287c9d');
        });

        for (const marker of ['__DERIVED_KEY_ENCRYPTED__', '5f5f444552495645445f4b45595f454e435259505445445f5f']) {
            it(`entschlüsselt Mail und Anhang mit Marker ${marker.slice(0, 12)}…`, async () => {
                const key = await deriveEmailKey(masterKey, uuid);
                const email: EncryptedEmail = {
                    uuid,
                    dea_id: 1,
                    encrypted_subject: await encryptField('Happy Birthday', key),
                    encrypted_from: await encryptField('a@example.com', key),
                    encrypted_to: await encryptField('b@example.com', key),
                    encrypted_body: await encryptField('<p>Hallo</p>', key),
                    wrapped_ephemeral_key: marker,
                    ephemeral_key_iv: '',
                    size_bytes: 1,
                    has_attachments: true,
                    attachment_count: 1,
                    is_read: false,
                    is_starred: false,
                    is_deleted: false,
                    folder_type: 'inbox',
                    received_at: '2026-11-07T09:00:00Z',
                    attachments: [{
                        uuid: 'att-1',
                        encrypted_filename: await encryptField('bild.png', key),
                        encrypted_mimetype: await encryptField('image/png', key),
                        wrapped_ephemeral_key: marker,
                        size_bytes: 1,
                    }],
                } as EncryptedEmail;

                const decrypted = await decryptEmail(email, masterKey, dummyPrivateKeys);

                expect(decrypted.subject).toBe('Happy Birthday');
                expect(decrypted.body).toBe('<p>Hallo</p>');
                expect(decrypted.attachments?.[0]?.filename).toBe('bild.png');
                expect(decrypted.attachments?.[0]?.mimetype).toBe('image/png');
            });
        }

        it('scheitert mit dem Master-Key statt des abgeleiteten Schlüssels', async () => {
            const key = await deriveEmailKey(masterKey, uuid);
            const email = {
                uuid,
                dea_id: 1,
                encrypted_subject: await encryptField('x', key),
                encrypted_from: await encryptField('x', key),
                encrypted_to: await encryptField('x', key),
                wrapped_ephemeral_key: '__MASTER_KEY_ENCRYPTED__',
                ephemeral_key_iv: '',
                size_bytes: 1,
                has_attachments: false,
                attachment_count: 0,
                is_read: false,
                is_starred: false,
                is_deleted: false,
                folder_type: 'inbox',
                received_at: '2026-11-07T09:00:00Z',
            } as EncryptedEmail;

            await expect(decryptEmail(email, masterKey, dummyPrivateKeys)).rejects.toThrow();
        });
    });
});
