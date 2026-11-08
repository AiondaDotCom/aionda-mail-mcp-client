/**
 * Email Decryption Pipeline
 *
 * Orchestrates: Hex decode → AES-GCM decrypt (with PHP reorder) → Unpad → Decompress → UTF-8 decode
 */
import { decryptAesGcm, decryptPhpAesGcm, decryptClientAesGcm } from './aes-gcm';
import { isBucketPadded, unpadFromBucket } from './bucket-padding';
import { decompress } from './decompression';
import { fromHex } from './encoding';
import { hybridDecapsulate } from './hybrid-kem';
import { deriveEmailKey } from './key-derivation';
import { decodeMimeEncodedWords, extractMessageId, extractReplyTo } from './mime-decoder';
import type { EncryptedEmail, DecryptedEmail, DecryptedAttachmentMeta, EncryptedAttachment } from '../types/email';

const MASTER_KEY_MARKER = '__MASTER_KEY_ENCRYPTED__';
const MASTER_KEY_MARKER_HEX = '5f5f4d41535445525f4b45595f454e435259505445445f5f';
/**
 * Zielformat seit 28.07.2026: Schlüssel = HKDF(masterKey, Mail-UUID).
 * Der Client kannte ihn nicht und hielt den Marker für eine KEM-Kapsel
 * („Unsupported wrapped key version: 0“, gemessen 08.11.2026). #c2fb3967
 */
const DERIVED_KEY_MARKER = '__DERIVED_KEY_ENCRYPTED__';
const DERIVED_KEY_MARKER_HEX = '5f5f444552495645445f4b45595f454e435259505445445f5f';

/**
 * Trägt die Zeile den Marker für den abgeleiteten Mail-Schlüssel?
 */
export function isDerivedKeyMarker(wrappedKey: string | null | undefined): boolean {
    return wrappedKey === DERIVED_KEY_MARKER || wrappedKey === DERIVED_KEY_MARKER_HEX;
}

/**
 * Vault private keys for Hybrid KEM decryption
 */
export interface VaultPrivateKeys {
    x25519PrivateKey: Uint8Array;
    mlKemPrivateKey: Uint8Array;
}

/**
 * Check if an email is client-encrypted (Master Key, not Hybrid KEM)
 */
export function isClientEncrypted(wrappedKey: string): boolean {
    if (!wrappedKey || wrappedKey.length === 0) return true;
    if (isDerivedKeyMarker(wrappedKey)) return true;
    if (wrappedKey === MASTER_KEY_MARKER) return true;
    if (wrappedKey === MASTER_KEY_MARKER_HEX) return true;
    if (wrappedKey === '000000000000000000000000') return true;

    if (wrappedKey.length >= 2 && /^[0-9a-fA-F]+$/.test(wrappedKey)) {
        const firstByte = parseInt(wrappedKey.substring(0, 2), 16);
        if (firstByte === 0) return true;
    }

    return false;
}

/**
 * Parse wrapped ephemeral key
 *
 * Format: [1 byte version][32 bytes x25519][1568 bytes mlkem][12 bytes IV][encrypted_key]
 */
interface ParsedWrappedKey {
    version: number;
    x25519Ciphertext: Uint8Array;
    mlKemCiphertext: Uint8Array;
    iv: Uint8Array;
    encryptedKey: Uint8Array;
}

export function parseWrappedKey(data: Uint8Array): ParsedWrappedKey {
    const version = data[0];
    if (version !== 1) {
        throw new Error(`Unsupported wrapped key version: ${version}`);
    }

    const x25519Ciphertext = data.slice(1, 33);
    const mlKemCiphertext = data.slice(33, 33 + 1568);
    const iv = data.slice(33 + 1568, 33 + 1568 + 12);
    const encryptedKey = data.slice(33 + 1568 + 12);

    return { version, x25519Ciphertext, mlKemCiphertext, iv, encryptedKey };
}

/**
 * Decrypt wrapped ephemeral key using Hybrid KEM
 */
export async function decryptWrappedKey(
    wrappedKey: ParsedWrappedKey,
    privateKeys: VaultPrivateKeys
): Promise<Uint8Array> {
    const sharedSecret = await hybridDecapsulate(
        wrappedKey.x25519Ciphertext,
        wrappedKey.mlKemCiphertext,
        privateKeys.x25519PrivateKey,
        privateKeys.mlKemPrivateKey
    );

    // PHP format for wrapped key: tag(16) || ciphertext
    const TAG_LENGTH = 16;
    const encData = wrappedKey.encryptedKey;

    if (encData.length <= TAG_LENGTH) {
        throw new Error(`Encrypted key too short: ${encData.length} bytes`);
    }

    const tag = encData.slice(0, TAG_LENGTH);
    const ciphertext = encData.slice(TAG_LENGTH);
    const reordered = new Uint8Array(encData.length);
    reordered.set(ciphertext, 0);
    reordered.set(tag, ciphertext.length);

    const decryptedData = await decryptAesGcm(reordered, sharedSecret, wrappedKey.iv);

    // Remove bucket padding + decompress
    let ephemeralKey = decryptedData;
    if (isBucketPadded(ephemeralKey)) {
        ephemeralKey = unpadFromBucket(ephemeralKey);
    }
    ephemeralKey = await decompress(ephemeralKey);

    if (ephemeralKey.length !== 32) {
        throw new Error(`Invalid ephemeral key length: ${ephemeralKey.length} (expected 32)`);
    }

    return ephemeralKey;
}

/**
 * Den Schlüssel bestimmen, der Inhalt und Anhänge einer Mail öffnet.
 *
 * Die EINZIGE Stelle im Client, die `wrapped_ephemeral_key` auswertet -
 * vorher stand die Unterscheidung dreimal (Mail, Anhang, Einliefern in einen
 * geteilten Ordner), und alle drei kannten den abgeleiteten Schlüssel nicht.
 *
 * @param wrappedKey  - Wert aus `wrapped_ephemeral_key` (Mail ODER Anhang)
 * @param emailUuid   - UUID der MAIL (auch beim Anhang)
 * @param masterKey   - Master Key
 * @param privateKeys - Hybrid-KEM-Schlüssel
 */
export async function resolveContentKey(
    wrappedKey: string,
    emailUuid: string,
    masterKey: Uint8Array,
    privateKeys: VaultPrivateKeys
): Promise<{ key: Uint8Array; clientEncrypted: boolean }> {
    if (isDerivedKeyMarker(wrappedKey)) {
        return { key: await deriveEmailKey(masterKey, emailUuid), clientEncrypted: true };
    }
    if (isClientEncrypted(wrappedKey)) {
        return { key: masterKey, clientEncrypted: true };
    }
    const wrapped = parseWrappedKey(fromHex(wrappedKey));
    return { key: await decryptWrappedKey(wrapped, privateKeys), clientEncrypted: false };
}

/**
 * Ein Feld in beiden Byte-Anordnungen versuchen, die bevorzugte zuerst.
 *
 * Sicher, weil AES-GCM authentifiziert: das falsche Layout scheitert am Tag
 * und kann nicht zufällig gelingen (Web-Client `decryptEmailField`, #7cbc485d).
 * Nötig, weil die Kapselart das Layout nicht verlässlich verrät.
 */
export async function decryptFieldBytes(
    encrypted: Uint8Array,
    key: Uint8Array,
    preferClientLayout: boolean
): Promise<Uint8Array> {
    const first = preferClientLayout ? decryptClientAesGcm : decryptPhpAesGcm;
    const second = preferClientLayout ? decryptPhpAesGcm : decryptClientAesGcm;
    let plaintext: Uint8Array;
    try {
        plaintext = await first(encrypted, key);
    } catch (firstError) {
        try {
            plaintext = await second(encrypted, key);
        } catch {
            throw firstError;
        }
    }
    if (isBucketPadded(plaintext)) {
        plaintext = unpadFromBucket(plaintext);
    }
    return decompress(plaintext);
}

/**
 * Decrypt a single encrypted email field (PHP format)
 */
async function decryptField(encryptedHex: string, key: Uint8Array): Promise<string> {
    const plaintext = await decryptFieldBytes(fromHex(encryptedHex), key, false);
    return new TextDecoder().decode(plaintext);
}

/**
 * Decrypt a client-encrypted field (sent emails, Master Key)
 */
async function decryptClientField(encryptedHex: string, key: Uint8Array): Promise<string> {
    const plaintext = await decryptFieldBytes(fromHex(encryptedHex), key, true);
    return new TextDecoder().decode(plaintext);
}

/**
 * Decrypt a full email
 *
 * @param email - Encrypted email from MCP server
 * @param masterKey - 32-byte vault master key
 * @param privateKeys - Hybrid KEM private keys (for server-encrypted emails)
 * @returns Decrypted email
 */
export async function decryptEmail(
    email: EncryptedEmail,
    masterKey: Uint8Array,
    privateKeys: VaultPrivateKeys,
    preDecryptedEphemeralKey?: Uint8Array
): Promise<DecryptedEmail> {
    let decryptFn: (hex: string) => Promise<string>;

    if (preDecryptedEphemeralKey) {
        // Shared folder path: ephemeral key already decrypted via folder key
        decryptFn = (hex: string): Promise<string> => decryptField(hex, preDecryptedEphemeralKey);
    } else {
        const { key, clientEncrypted } = await resolveContentKey(
            email.wrapped_ephemeral_key, email.uuid, masterKey, privateKeys
        );
        decryptFn = clientEncrypted
            ? (hex: string): Promise<string> => decryptClientField(hex, key)
            : (hex: string): Promise<string> => decryptField(hex, key);
    }

    // Decrypt fields in parallel
    const [subject, from, to] = await Promise.all([
        decryptFn(email.encrypted_subject),
        decryptFn(email.encrypted_from),
        decryptFn(email.encrypted_to),
    ]);

    let body: string | undefined;
    let bodyText: string | undefined;
    let headers: string | undefined;

    if (email.encrypted_body) {
        body = await decryptFn(email.encrypted_body);
    }
    if (email.encrypted_body_text) {
        bodyText = await decryptFn(email.encrypted_body_text);
    }
    if (email.encrypted_headers) {
        headers = await decryptFn(email.encrypted_headers);
    }

    // Decrypt attachment metadata
    let attachments: DecryptedAttachmentMeta[] | undefined;
    if (email.attachments && email.attachments.length > 0) {
        attachments = await Promise.all(
            email.attachments.map(async (att: EncryptedAttachment) => {
                const { key: attKey, clientEncrypted: attClientEnc } = await resolveContentKey(
                    att.wrapped_ephemeral_key, email.uuid, masterKey, privateKeys
                );
                const attDecryptFn = (hex: string): Promise<string> =>
                    decryptFieldBytes(fromHex(hex), attKey, attClientEnc)
                        .then((bytes) => new TextDecoder().decode(bytes));

                const [filename, mimetype] = await Promise.all([
                    attDecryptFn(att.encrypted_filename),
                    attDecryptFn(att.encrypted_mimetype),
                ]);

                return {
                    uuid: att.uuid,
                    filename: decodeMimeEncodedWords(filename),
                    mimetype,
                    sizeBytes: att.size_bytes,
                };
            })
        );
    }

    return {
        uuid: email.uuid,
        deaId: email.dea_id,
        subject: decodeMimeEncodedWords(subject),
        from: decodeMimeEncodedWords(from),
        to: decodeMimeEncodedWords(to),
        body,
        bodyText,
        headers,
        sizeBytes: email.size_bytes,
        hasAttachments: email.has_attachments,
        attachmentCount: email.attachment_count,
        isRead: email.is_read,
        isStarred: email.is_starred,
        isDeleted: email.is_deleted,
        folderType: email.folder_type,
        folderUuid: email.folder_uuid,
        receivedAt: new Date(email.received_at),
        attachments,
        threadId: email.thread_id,
        threadCount: email.thread_count,
        messageId: extractMessageId(headers),
        replyTo: extractReplyTo(headers),
        signatureStatus: email.signature_status,
    };
}
