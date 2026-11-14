/**
 * Anhang entschlüsseln (get_attachment), im Speicher.
 *
 * Eine Stelle für Proxy (stdio, schreibt danach auf die Platte) und
 * Bibliothek (AiondaMailClient, gibt die Bytes zurück).
 */
import { decryptFieldBytes, resolveContentKey } from './email-decryptor.js';
import type { VaultPrivateKeys } from './email-decryptor.js';
import { fromHex } from './encoding.js';
import type { DecryptedAttachment } from '../types/email.js';

export interface DecryptedAttachmentWithEmail extends DecryptedAttachment {
    /** UUID der Mail, zu der der Anhang gehört */
    emailUuid: string;
}

/**
 * @param sharedKeyForEmail liefert für eine Mail aus einem geteilten Ordner
 *        den Mail-Schlüssel des Eigentümers (sonst null).
 * @throws bei jedem Fehlschlag – kein Rückfall auf Geheimtext.
 */
export async function decryptAttachmentRecord(
    att: Record<string, unknown>,
    masterKey: Uint8Array,
    privateKeys: VaultPrivateKeys,
    sharedKeyForEmail: (emailUuid: string) => Promise<Uint8Array | null> = async () => null
): Promise<DecryptedAttachmentWithEmail> {
    // #c2fb3967 - eine Stelle für alle Kapselarten, auch den
    // abgeleiteten Mail-Schlüssel. Anhänge benutzen den Schlüssel
    // IHRER Mail, deshalb `email_uuid`.
    let { key: decryptionKey, clientEncrypted } = await resolveContentKey(
        att.wrapped_ephemeral_key as string,
        att.email_uuid as string,
        masterKey,
        privateKeys
    );
    const decryptAttField = (hex: string): Promise<Uint8Array> =>
        decryptFieldBytes(fromHex(hex), decryptionKey, clientEncrypted);

    // Anhang aus einem geteilten Ordner: Er gehört zum Schlüssel der
    // Mail des EIGENTÜMERS, den nur der Ordnerschlüssel liefert. Der
    // Server legt dafür kein Material an den Anhang; es kommt über die
    // Mail. AES-GCM ist authentifiziert - der erste Versuch scheitert
    // laut, er kann nicht falsch „gelingen".
    if (att.encrypted_filename) {
        try {
            await decryptAttField(att.encrypted_filename as string);
        } catch (ownKeyError) {
            const sharedKey = await sharedKeyForEmail(att.email_uuid as string);
            if (!sharedKey) throw ownKeyError;
            decryptionKey = sharedKey;
            clientEncrypted = true;
        }
    }

    let filename = 'attachment';
    if (att.encrypted_filename) {
        filename = new TextDecoder().decode(await decryptAttField(att.encrypted_filename as string));
    }
    let mimetype = 'application/octet-stream';
    if (att.encrypted_mimetype) {
        mimetype = new TextDecoder().decode(await decryptAttField(att.encrypted_mimetype as string));
    }
    const content = att.encrypted_content
        ? await decryptAttField(att.encrypted_content as string)
        : new Uint8Array(0);

    return {
        uuid: att.uuid as string,
        emailUuid: att.email_uuid as string,
        filename,
        mimetype,
        sizeBytes: content.length,
        content,
    };
}
