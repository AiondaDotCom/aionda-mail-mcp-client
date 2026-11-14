/**
 * MCP Tool Input/Output Types
 * Derived from McpToolsService.php (26 tools)
 */

import type { EventType } from './events.js';

// ── Mailbox Read ──

export interface ListFoldersInput {
    // no params
}

/**
 * Antwort von list_folders, wie McpToolsService::toolListFolders sie baut
 * (seit trashmail 01ab6cf5d, 22.03.2026; vorher gab es ein Feld `folders`).
 * Mit Ordnergrenze des Schlüssels nur die freigegebenen Ordner.
 */
export interface ListFoldersOutput {
    system_folders: SystemFolderInfo[];
    custom_folders: EncryptedFolderInfo[];
    shared_folders: { incoming: Record<string, unknown>[]; outgoing: Record<string, unknown>[] };
    note: string;
}

/** Systemordner: ohne UUID, angesprochen über den Namen (`inbox`, `sent`, …). */
export interface SystemFolderInfo {
    name: string;
    type: 'system';
    email_count: number;
    unread_count: number;
}

/** Eigener Ordner: Name verschlüsselt (Base64). Der Proxy ersetzt ihn durch `name`. */
export interface EncryptedFolderInfo {
    uuid: string;
    encrypted_name?: string;
    /** Nur im tmv_-Betrieb: vom Proxy entschlüsselter Name. */
    name?: string;
    parent_uuid?: string | null;
    color?: string | null;
    sort_order?: number;
    email_count: number;
    unread_count: number;
}

export interface ListEmailsInput {
    folder?: string;
    limit?: number;
    offset?: number;
    /**
     * Stabiler Zeiger: "start" für die älteste Mail, danach `next_cursor` der
     * vorigen Seite. Reihenfolge = Eingangsreihenfolge (älteste zuerst);
     * `offset` wird dann ignoriert. Mails jünger als 2 s hält der Server zurück.
     */
    after?: string;
}

export interface ListEmailsOutput {
    emails: EncryptedEmailSummary[];
    /** Nur im Offset-Modus. */
    total?: number;
    offset?: number;
    limit: number;
    /** Nur im Zeiger-Modus (`after`). */
    has_more?: boolean;
    /** Nur im Zeiger-Modus: UUID der letzten gelieferten Mail (bei leerer Seite: der übergebene Zeiger). */
    next_cursor?: string;
    /** Nur im Zeiger-Modus: "arrival_asc". */
    order?: string;
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

/**
 * Anhang für send/reply/forward. Entweder ein Pfad (liest der Proxy von der
 * Platte) oder der Inhalt im Speicher – Base64-Text oder Bytes.
 */
export type OutgoingAttachment =
    | { file_path: string; filename?: string; mimetype?: string }
    | { filename: string; content: string | Uint8Array; mimetype?: string; size?: number };

/** Wiederholungssicherer Versand (#3dac1ce0). */
export interface IdempotencyOption {
    /**
     * 1–128 druckbare ASCII-Zeichen. Derselbe Schlüssel binnen 24 h sendet nie
     * eine zweite Mail, sondern liefert das Ergebnis der ersten
     * (`idempotent_replay: true`). Wird als `idempotency_key` gesendet.
     */
    idempotencyKey?: string;
}

export interface SendEmailInput {
    from_identity: string;
    to: string;
    subject: string;
    body: string;
    /** Sprache des Textes (ISO 639-1); der Server verlangt sie. */
    lang?: string;
    cc?: string;
    bcc?: string;
    priority?: 'low' | 'normal' | 'high';
    attachments?: OutgoingAttachment[];
    idempotency_key?: string;
}

export interface SendEmailOutput {
    message_id: string;
    sent: boolean;
    /** true: derselbe idempotency_key wurde schon benutzt, es ging keine zweite Mail hinaus. */
    idempotent_replay?: boolean;
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
    lang?: string;
    attachments?: OutgoingAttachment[];
    idempotency_key?: string;
}

export interface ReplyEmailOutput {
    message_id: string;
    replied_to?: string;
    idempotent_replay?: boolean;
    [key: string]: unknown;
}

export interface ForwardEmailInput {
    email_uuid: string;
    to: string;
    original_subject: string;
    original_body: string;
    body?: string;
    from_identity?: string;
    lang?: string;
    attachments?: OutgoingAttachment[];
    idempotency_key?: string;
}

export interface ForwardEmailOutput {
    message_id: string;
    forwarded_to?: string;
    idempotent_replay?: boolean;
    [key: string]: unknown;
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

// ── MCP-Schlüsselverwaltung (#613404e4, #a14536ed, #f5292ca4) ──

/**
 * Feste Grenzen eines MCP-Schlüssels. `null` (oder fehlend) = keine Grenze;
 * eine LEERE Liste = nichts erlaubt.
 */
export interface McpKeyLimits {
    /** inbox, sent, drafts, spam, trash oder folder:<uuid> */
    allowed_folders?: string[] | null;
    /** Nur Mails der letzten N Tage (1–3650) */
    max_age_days?: number | null;
    /** Absenderadressen, von denen dieser Schlüssel senden darf */
    allowed_senders?: string[] | null;
    /** MCP-Werkzeuge, die dieser Schlüssel aufrufen darf */
    allowed_tools?: string[] | null;
    /** Versandgrenze je Stunde (0 = kein Versand, höchstens die Kontogrenze) */
    max_sends_per_hour?: number | null;
    /** Versandgrenze je Tag; kann die Kontogrenze nur senken (sonst Fehler 204) */
    max_sends_per_day?: number | null;
    /** IP-Adressen oder CIDR-Netze */
    allowed_source_ips?: string[] | null;
}

export interface McpKeyInfo {
    key_uuid: string;
    /** "personal" oder "ai_employee" */
    kind: string;
    name: string;
    limits: Required<McpKeyLimits>;
    suspended: boolean;
    suspended_at: string | null;
    rotation_successor: string | null;
    rotation_deadline: string | null;
    company_managed: boolean;
    suspended_by_company: boolean;
    account_daily_limit: number;
    last_used_at: string | null;
    last_source_ip: string | null;
    /** Nur bei suspend_mcp_key / suspend_employee_mcp_key */
    subscriptions_closed?: number;
}

export interface ListMcpKeysOutput {
    keys: McpKeyInfo[];
}

export interface McpKeyAccessLogEntry {
    at: string;
    method: string;
    tool: string | null;
    source_ip: string;
    success: boolean;
    error_code: number | null;
    duration_ms: number | null;
    old_mail: boolean;
}

export interface McpKeyAlert {
    type: string;
    detail: string;
    at: string;
}

export interface McpKeyAccessLogOutput {
    entries: McpKeyAccessLogEntry[];
    alerts: McpKeyAlert[];
}

export interface ListEmployeeMcpKeysOutput {
    employee_uuid: string;
    keys: McpKeyInfo[];
}
