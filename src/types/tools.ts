/**
 * MCP Tool Input/Output Types
 * Derived from McpToolsService.php (26 tools)
 */

import type { EventType } from './events';

// ── Mailbox Read ──

export interface ListFoldersInput {
    // no params
}

export interface ListFoldersOutput {
    folders: EncryptedFolderInfo[];
    note: string;
}

export interface EncryptedFolderInfo {
    uuid: string;
    folder_type: string;
    encrypted_name: string;
    email_count: number;
    unread_count: number;
}

export interface ListEmailsInput {
    folder?: string;
    limit?: number;
    offset?: number;
}

export interface ListEmailsOutput {
    emails: EncryptedEmailSummary[];
    total: number;
    offset: number;
    limit: number;
}

export interface EncryptedEmailSummary {
    uuid: string;
    dea_id: number;
    encrypted_subject: string;
    encrypted_from: string;
    encrypted_to: string;
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
    thread_id?: string | null;
    thread_count?: number;
}

export interface ReadEmailInput {
    email_uuid: string;
}

export interface ReadEmailOutput {
    uuid: string;
    dea_id: number;
    encrypted_subject: string;
    encrypted_from: string;
    encrypted_to: string;
    encrypted_body: string;
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
    attachments?: EncryptedAttachmentInfo[];
    signature_status?: string;
    migration_status?: string;
}

export interface EncryptedAttachmentInfo {
    uuid: string;
    encrypted_filename: string;
    encrypted_mimetype: string;
    encrypted_content?: string;
    size_bytes: number;
    wrapped_ephemeral_key: string;
    ephemeral_key_iv: string;
}

// ── Mailbox Organize ──

export interface MarkReadInput {
    email_uuid: string;
}

export interface MarkReadOutput {
    marked: 'read';
}

export interface MarkUnreadInput {
    email_uuid: string;
}

export interface MarkUnreadOutput {
    marked: 'unread';
}

export interface MoveEmailInput {
    email_uuid: string;
    target_folder: string;
}

export interface MoveEmailOutput {
    moved_to: string;
}

// ── Mailbox Delete ──

export interface DeleteEmailInput {
    email_uuid: string;
}

export interface DeleteEmailOutput {
    deleted: boolean;
}

// ── DEA Read ──

export interface ListDeasInput {
    // no params
}

export interface ListDeasOutput {
    deas: DeaInfo[];
}

export interface DeaInfo {
    dea_uid: string;
    address: string;
    destination: string;
    from_name: string;
    forwards: number;
    masquerade: number;
    notify: number;
    vault_store: number;
    created_at: string;
}

export interface GetDeaInput {
    dea_uid: string;
}

export type GetDeaOutput = DeaInfo;

// ── Send/Reply/Forward ──

export interface SendEmailInput {
    from_identity: string;
    to: string;
    subject: string;
    body: string;
    cc?: string;
    bcc?: string;
    priority?: 'low' | 'normal' | 'high';
}

export interface SendEmailOutput {
    message_id: string;
    sent: boolean;
}

export interface ReplyEmailInput {
    email_uuid: string;
    body: string;
    original_from: string;
    original_subject: string;
    original_message_id?: string;
    to?: string;
    cc?: string;
    subject?: string;
    from_identity?: string;
}

export interface ReplyEmailOutput {
    message_id: string;
    replied_to: string;
}

export interface ForwardEmailInput {
    email_uuid: string;
    to: string;
    original_subject: string;
    original_body: string;
    body?: string;
    from_identity?: string;
}

export interface ForwardEmailOutput {
    message_id: string;
    forwarded_to: string;
}

// ── Drafts ──

export interface SaveDraftInput {
    subject?: string;
    body?: string;
    to?: string;
    cc?: string;
    from_identity?: string;
    draft_id?: string;
}

export interface SaveDraftOutput {
    draft_id: string;
    saved: boolean;
}

export interface ListDraftsInput {
    limit?: number;
    offset?: number;
}

export interface ListDraftsOutput {
    drafts: DraftInfo[];
}

export interface DraftInfo {
    uuid: string;
    encrypted_content: string;
    created_at: string;
    updated_at: string;
}

export interface GetDraftInput {
    draft_id: string;
}

export type GetDraftOutput = DraftInfo;

export interface DeleteDraftInput {
    draft_id: string;
}

export interface DeleteDraftOutput {
    deleted: boolean;
}

// ── DEA Write ──

export interface CreateDeaInput {
    name: string;
    domain?: string;
    forwards?: number;
    expire?: number;
    from_name?: string;
}

export interface CreateDeaOutput {
    dea_uid: string;
    address: string;
    created: boolean;
}

export interface UpdateDeaInput {
    dea_uid: string;
    forwards?: number;
    from_name?: string;
}

export interface UpdateDeaOutput {
    updated: boolean;
}

export interface DeleteDeaInput {
    dea_uid: string;
}

export interface DeleteDeaOutput {
    deleted: boolean;
}

// ── Shared Folders ──

export interface SharedFolderPermissions {
    can_read: number;
    can_send: number;
    can_move_in: number;
    can_move_out: number;
    can_delete: number;
    can_manage: number;
}

export type SharedFolderRolePreset = 'readonly' | 'einliefern' | 'bearbeiten' | 'antworten' | 'vollzugriff';

export interface IncomingShare {
    share_uuid: string;
    folder_uuid: string;
    owner_username: string;
    folder_encrypted_name: string;
    can_read: number;
    can_send: number;
    can_move_in: number;
    can_move_out: number;
    can_delete: number;
    can_manage: number;
    role_preset: SharedFolderRolePreset | null;
    encrypted_folder_key: string;
    x25519_ephemeral: string;
    mlkem_ciphertext: string;
    key_nonce: string;
    email_count: number;
    unread_count: number;
    created_at: string;
}

export interface OutgoingShare {
    share_uuid: string;
    folder_uuid: string;
    recipient_username: string;
    folder_encrypted_name: string;
    can_read: number;
    can_send: number;
    can_move_in: number;
    can_move_out: number;
    can_delete: number;
    can_manage: number;
    role_preset: SharedFolderRolePreset | null;
    created_at: string;
}

export interface ListSharedFoldersInput {
    direction?: 'incoming' | 'outgoing' | 'both';
}

export interface ListSharedFoldersOutput {
    incoming: IncomingShare[];
    outgoing: OutgoingShare[];
    note: string;
}

export interface ShareFolderInput {
    folder_uuid: string;
    recipient_username: string;
    role_preset: SharedFolderRolePreset;
    encrypted_folder_key: string;
    x25519_ephemeral: string;
    mlkem_ciphertext: string;
    key_nonce: string;
}

export interface ShareFolderOutput {
    share_uuid: string;
    created_at: string;
    shared: boolean;
}

export interface RevokeShareInput {
    share_uuid: string;
}

export interface RevokeShareOutput {
    revoked: boolean;
}

export interface UpdateSharePermissionsInput {
    share_uuid: string;
    role_preset?: SharedFolderRolePreset;
    can_read?: boolean;
    can_send?: boolean;
    can_move_in?: boolean;
    can_move_out?: boolean;
    can_delete?: boolean;
    can_manage?: boolean;
}

export interface UpdateSharePermissionsOutput {
    updated: boolean;
}

export interface GetRecipientKeysInput {
    recipient_username: string;
}

export interface GetRecipientKeysOutput {
    x25519_public_key: string;
    mlkem_public_key: string;
}

// ── Real-time Events ──

export type EventTopic = EventType;

export interface EventSubscribeInput {
    topics: EventTopic[];
    x25519_public_key: string;
    mlkem_public_key: string;
}

export interface EventSubscribeOutput {
    subscription_id: number;
    mercure_url: string;
    subscriber_jwt: string;
    topics: string[];
    note: string;
}

export interface GetMissedEventsInput {
    last_event_id?: number;
    limit?: number;
}

export interface EncryptedEventEntry {
    id: number;
    topic: string;
    encrypted: string;
    x25519_ephemeral: string;
    mlkem_ciphertext: string;
    timestamp: number;
}

export interface GetMissedEventsOutput {
    events: EncryptedEventEntry[];
    has_more: boolean;
    note: string;
}
