/**
 * Folder Types — Encrypted and Decrypted
 */

export interface EncryptedFolder {
    uuid: string;
    folder_type: string;
    encrypted_name: string;
    email_count: number;
    unread_count: number;
}

export interface DecryptedFolder {
    uuid: string;
    folderType: string;
    name: string;
    emailCount: number;
    unreadCount: number;
}
