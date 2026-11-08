/**
 * Email Types — Encrypted and Decrypted
 */

export interface EncryptedEmail {
    uuid: string;
    dea_id: number;
    encrypted_subject: string;
    encrypted_from: string;
    encrypted_to: string;
    encrypted_body?: string;
    encrypted_body_text?: string | null;
    encrypted_headers?: string | null;
    wrapped_ephemeral_key: string;
    ephemeral_key_iv: string;
    size_bytes: number;
    has_attachments: boolean;
    attachment_count: number;
    is_read: boolean;
    is_starred: boolean;
    is_deleted: boolean;
    folder_type: string;
    folder_uuid?: string | null;
    received_at: string;
    attachments?: EncryptedAttachment[];
    thread_id?: string | null;
    thread_count?: number;
    signature_status?: string;
    migration_status?: string;
}

export interface EncryptedAttachment {
    uuid: string;
    encrypted_filename: string;
    encrypted_mimetype: string;
    encrypted_content?: string;
    size_bytes: number;
    wrapped_ephemeral_key: string;
    ephemeral_key_iv: string;
}

export interface DecryptedEmail {
    uuid: string;
    deaId: number;
    subject: string;
    from: string;
    to: string;
    body?: string;
    bodyText?: string;
    headers?: string;
    sizeBytes: number;
    hasAttachments: boolean;
    attachmentCount: number;
    isRead: boolean;
    isStarred: boolean;
    isDeleted: boolean;
    folderType: string;
    folderUuid?: string | null;
    receivedAt: Date;
    attachments?: DecryptedAttachmentMeta[];
    threadId?: string | null;
    threadCount?: number;
    messageId?: string | null;
    replyTo?: string | null;
    signatureStatus?: string;
}

export interface DecryptedAttachmentMeta {
    uuid: string;
    filename: string;
    mimetype: string;
    sizeBytes: number;
}

export interface DecryptedAttachment extends DecryptedAttachmentMeta {
    content: Uint8Array;
}
