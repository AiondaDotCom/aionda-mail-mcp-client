/**
 * AiondaMailClient — High-level typed MCP client (library use)
 *
 * Recommended (server integrations, personal keys, AI employees):
 *   const client = new AiondaMailClient({
 *       apiKey: process.env.AIONDA_MCP_KEY,     // tmmcp_… or tma_…
 *       vaultKey: process.env.AIONDA_VAULT_KEY, // tmv_…
 *       endpoint: 'https://mail.aionda.com',
 *   });
 *   await client.connect();                      // unlocks the vault locally
 *   for await (const page of client.iterateEmailPages({ folder: 'inbox', after: savedCursor })) { … }
 *
 * With a `tmv_…` vault key the client runs on the same engine as the stdio
 * proxy (McpDecryptingProxy): same key bootstrap, same session recovery,
 * same encryption of outgoing data, same shared-folder handling.
 *
 * Legacy: `vaultKey` as hex master key plus `vaultPrivateKeys` (hex) talks
 * to the server directly; no shared folders, no session recovery.
 */
import { McpTransport } from './transport.js';
import { McpSession } from './session.js';
import {
    McpDecryptionError,
    McpError,
    McpToolError,
    McpTransportError,
    mcpErrorFromCode,
    mcpErrorFromJsonRpc,
} from './errors.js';
import { MCP_ENDPOINT_PATH } from './constants.js';
import { decryptEmail } from './crypto/email-decryptor.js';
import { decryptAttachmentRecord } from './crypto/attachment-decryptor.js';
import type { DecryptedAttachmentWithEmail } from './crypto/attachment-decryptor.js';
import { fromBase64, fromHex, toBase64 } from './crypto/encoding.js';
import type { VaultPrivateKeys } from './crypto/email-decryptor.js';
import { decryptSharedFolderKey } from './crypto/shared-folder-key.js';
import { McpDecryptingProxy } from './proxy.js';
import type {
    McpToolDefinition,
    McpToolResult,
    ListFoldersOutput,
    ListEmailsInput,
    ListEmailsOutput,
    ReadEmailOutput,
    ListDeasOutput,
    DeaInfo,
    SendEmailInput,
    SendEmailOutput,
    ReplyEmailInput,
    ReplyEmailOutput,
    ForwardEmailInput,
    ForwardEmailOutput,
    SaveDraftInput,
    SaveDraftOutput,
    ListDraftsOutput,
    CreateDeaInput,
    CreateDeaOutput,
    UpdateDeaInput,
    UpdateDeaOutput,
    ListSharedFoldersOutput,
    ShareFolderInput,
    ShareFolderOutput,
    RevokeShareOutput,
    UpdateSharePermissionsInput,
    UpdateSharePermissionsOutput,
    GetRecipientKeysOutput,
    IncomingShare,
    IdempotencyOption,
    OutgoingAttachment,
    McpKeyLimits,
    McpKeyInfo,
    ListMcpKeysOutput,
    McpKeyAccessLogOutput,
    ListEmployeeMcpKeysOutput,
} from './types/index.js';
import type { DecryptedEmail, EncryptedEmail } from './types/email.js';
import type { DecryptedFolder } from './types/folder.js';

export interface AiondaMailClientOptions {
    /** MCP API key: personal key (tmmcp_*) or AI employee key (tma_*) */
    apiKey: string;
    /**
     * Vault key. `tmv_…` (recommended): the client fetches and unlocks the
     * vault keys itself on connect(). Legacy: hex-encoded 32-byte master key,
     * then also pass `vaultPrivateKeys`.
     */
    vaultKey?: string;
    /** Legacy only: hex-encoded vault private keys x25519(32) + mlkem(3168) */
    vaultPrivateKeys?: string;
    /** Server endpoint (default: https://trashmail.com) */
    endpoint?: string;
    /** Request timeout in ms (default: 30000) */
    timeout?: number;
}

/** Options for cursor-based listing (`list_emails` with `after`). */
export interface EmailPageOptions {
    /** inbox, sent, drafts, spam, trash or folder:<uuid> (default: inbox) */
    folder?: string;
    /** "start" (default) or the `nextCursor` of the previous page */
    after?: string;
    /** 1–50 (default: 50) */
    limit?: number;
}

/** An email the client could not decrypt. Its uuid still moves the cursor. */
export interface UndecryptableEmail {
    uuid: string;
    receivedAt: string;
    error: string;
}

/** One page of a cursor sync. Every listed uuid is in exactly one of `emails` / `failed`. */
export interface EmailPage {
    emails: DecryptedEmail[];
    failed: UndecryptableEmail[];
    /** Persist this after processing the page; pass it as `after` next time. */
    nextCursor: string;
    /** false: you are at the end for now – poll again later from `nextCursor`. */
    hasMore: boolean;
}

/** Common options of the convenience senders. */
interface OutgoingOptions extends IdempotencyOption {
    /** Language of the text (ISO 639-1: de, en, fr, es) – required by the server */
    lang: string;
    fromIdentity?: string;
    attachments?: OutgoingAttachment[];
}

export interface ReplyToEmailOptions extends OutgoingOptions {
    body: string;
    /** Override the recipient (default: Reply-To, else From of the original) */
    to?: string;
    cc?: string;
    /** Override the subject (default: "Re: <original subject>") */
    subject?: string;
}

export interface ForwardEmailToOptions extends OutgoingOptions {
    to: string;
    /** Optional cover text above the forwarded content */
    body?: string;
}

const IDEMPOTENCY_KEY_PATTERN = /^[\x21-\x7E]{1,128}$/;

export class AiondaMailClient {
    private transport: McpTransport | null = null;
    private session: McpSession | null = null;
    private proxy: McpDecryptingProxy | null = null;
    private proxyConnected = false;
    private masterKey: Uint8Array | null = null;
    private privateKeys: VaultPrivateKeys | null = null;

    constructor(options: AiondaMailClientOptions) {
        const baseUrl = options.endpoint ?? 'https://trashmail.com';
        const endpoint = baseUrl.endsWith(MCP_ENDPOINT_PATH)
            ? baseUrl
            : baseUrl + MCP_ENDPOINT_PATH;

        if (options.vaultKey?.startsWith('tmv_')) {
            if (options.vaultPrivateKeys) {
                throw new McpDecryptionError('vaultPrivateKeys is only for a hex master key; a tmv_ vault key brings its own keys.');
            }
            this.proxy = new McpDecryptingProxy({
                endpoint,
                apiKey: options.apiKey,
                vaultKey: options.vaultKey,
                preloadOcr: false,
                timeout: options.timeout ?? 30000,
            });
            return;
        }

        this.transport = new McpTransport({
            endpoint,
            apiKey: options.apiKey,
            timeout: options.timeout,
        });
        this.session = new McpSession(this.transport);

        if (options.vaultKey) {
            this.masterKey = fromHex(options.vaultKey);
        }

        if (options.vaultPrivateKeys) {
            const raw = fromHex(options.vaultPrivateKeys);
            this.privateKeys = {
                x25519PrivateKey: raw.slice(0, 32),
                mlKemPrivateKey: raw.slice(32),
            };
        }
    }

    // ── Lifecycle ──

    /**
     * Open the session. With a tmv_ key this also fetches and unlocks the
     * vault keys; a suspended or rotated key fails HERE with
     * McpKeySuspendedError / McpKeyRotatedError.
     */
    async connect(): Promise<void> {
        if (this.proxy) {
            try {
                await this.proxy.bootstrap();
            } catch (error) {
                throw toMcpError(error, (m) => new McpDecryptionError(m));
            }
            this.proxyConnected = true;
            return;
        }
        await this.session!.initialize();
    }

    async disconnect(): Promise<void> {
        if (this.proxy) {
            this.proxyConnected = false;
            return;
        }
        this.session!.destroy();
    }

    async ping(): Promise<void> {
        if (this.proxy) {
            await this.proxyRequest('ping');
            return;
        }
        await this.session!.ping();
    }

    isConnected(): boolean {
        if (this.proxy) return this.proxyConnected;
        return this.session!.isInitialized() && !this.session!.isExpired();
    }

    // ── Tools ──

    async listTools(): Promise<McpToolDefinition[]> {
        if (this.proxy) {
            const result = await this.proxyRequest('tools/list') as { tools: McpToolDefinition[] };
            return result.tools;
        }
        return this.session!.listTools();
    }

    /**
     * Raw MCP tool call. Returns the MCP result (`{content, isError}`) without
     * throwing on tool errors. With a tmv_ key it behaves exactly like the
     * stdio proxy: arguments get encrypted, results decrypted.
     */
    async callTool(name: string, args: Record<string, unknown> = {}): Promise<McpToolResult> {
        if (this.proxy) {
            return await this.proxyRequest('tools/call', { name, arguments: args }) as McpToolResult;
        }
        const result = await this.session!.callTool(name, args);
        return result as McpToolResult;
    }

    // ── Folders ──

    async listFolders(): Promise<ListFoldersOutput> {
        return this.serverTool<ListFoldersOutput>('list_folders');
    }

    /**
     * Folders with decrypted names (to find the uuid of a custom folder for
     * moveEmail / `folder:<uuid>`). System folders have no uuid on the
     * server; their `uuid` is the name the tools accept (`inbox`, `sent`, …).
     * With a folder limit only the allowed folders are listed.
     */
    async listFoldersDecrypted(): Promise<DecryptedFolder[]> {
        if (this.proxy) {
            this.ensureDecryptionReady();
        } else {
            this.ensureVaultKey();
        }
        // Im tmv_-Betrieb entschlüsselt der Proxy die Namen (`name`), sonst hier.
        const out = this.proxy ? await this.tool<ListFoldersOutput>('list_folders') : await this.listFolders();
        const system = (out.system_folders ?? []).map((f) => ({
            uuid: f.name,
            folderType: f.name,
            name: f.name,
            emailCount: f.email_count,
            unreadCount: f.unread_count,
        }));
        const custom = await Promise.all((out.custom_folders ?? []).map(async (f) => ({
            uuid: f.uuid,
            folderType: 'custom',
            name: typeof f.name === 'string' ? f.name : await this.decryptFolderName(f.encrypted_name),
            emailCount: f.email_count,
            unreadCount: f.unread_count,
        })));
        return [...system, ...custom];
    }

    /** Ordnername (Base64, PHP-AES-GCM, ggf. gepolstert/komprimiert); unlesbar → 'custom'. */
    private async decryptFolderName(encryptedName: string | undefined): Promise<string> {
        if (!encryptedName || !this.masterKey) return 'custom';
        try {
            const { decryptPhpAesGcm } = await import('./crypto/aes-gcm.js');
            const { decompress } = await import('./crypto/decompression.js');
            const { unpadFromBucket, isBucketPadded } = await import('./crypto/bucket-padding.js');
            let plaintext = await decryptPhpAesGcm(fromBase64(encryptedName), this.masterKey);
            if (isBucketPadded(plaintext)) plaintext = unpadFromBucket(plaintext);
            plaintext = await decompress(plaintext);
            return new TextDecoder().decode(plaintext);
        } catch {
            return 'custom';
        }
    }

    // ── Emails ──

    /**
     * Encrypted email list. Offset paging (newest first) or – with
     * `{ after }` – the stable cursor (arrival order, `next_cursor`, `has_more`).
     */
    async listEmails(folder?: string, limit?: number, offset?: number): Promise<ListEmailsOutput>;
    async listEmails(options: ListEmailsInput): Promise<ListEmailsOutput>;
    async listEmails(folderOrOptions: string | ListEmailsInput = 'inbox', limit = 20, offset = 0): Promise<ListEmailsOutput> {
        const args: Record<string, unknown> = typeof folderOrOptions === 'string'
            ? { folder: folderOrOptions, limit, offset }
            : { folder: 'inbox', limit: 20, ...folderOrOptions };
        return this.serverTool<ListEmailsOutput>('list_emails', args);
    }

    /**
     * One decrypted page of the cursor sync (`list_emails` with `after`).
     *
     * Throws McpCursorInvalidError (202) for an unknown cursor – restart with
     * "start" and deduplicate by uuid – and McpToolError if the server ignores
     * the cursor (no `next_cursor` in the answer: server too old).
     */
    async listEmailPage(options: EmailPageOptions = {}): Promise<EmailPage> {
        this.ensureDecryptionReady();
        const after = options.after ?? 'start';
        const out = await this.listEmails({ folder: options.folder ?? 'inbox', after, limit: options.limit ?? 50 });
        if (typeof out.next_cursor !== 'string' || typeof out.has_more !== 'boolean') {
            throw new McpToolError(
                'list_emails',
                'Server ignored "after": the answer has no next_cursor/has_more. The server does not support cursor paging.',
                -32603
            );
        }
        const page: EmailPage = { emails: [], failed: [], nextCursor: out.next_cursor, hasMore: out.has_more };
        for (const summary of out.emails ?? []) {
            try {
                page.emails.push(await this.decryptRecord(summary as unknown as EncryptedEmail));
            } catch (error) {
                page.failed.push({
                    uuid: summary.uuid,
                    receivedAt: summary.received_at,
                    error: error instanceof Error ? error.message : String(error),
                });
            }
        }
        return page;
    }

    /**
     * All pages from a cursor up to the current end. Persist `page.nextCursor`
     * after you processed each page; the generator stops at `hasMore === false`.
     */
    async *iterateEmailPages(options: EmailPageOptions = {}): AsyncGenerator<EmailPage, void, undefined> {
        let after = options.after ?? 'start';
        // Jeder Zeiger kommt in Ankunftsreihenfolge genau einmal vor. Ein schon
        // gesehener heißt: der Server rückt nicht vor – auch im Kreis A→B→A
        // (#4c81ed5b), nicht nur auf der Stelle.
        const seen = new Set<string>([after]);
        for (;;) {
            const page = await this.listEmailPage({ ...options, after });
            yield page;
            if (!page.hasMore) return;
            if (seen.has(page.nextCursor)) {
                throw new McpToolError('list_emails', `Cursor did not advance from ${after} (next ${page.nextCursor} was already seen) although has_more is true`, -32603);
            }
            seen.add(page.nextCursor);
            after = page.nextCursor;
        }
    }

    async readEmail(emailUuid: string): Promise<ReadEmailOutput> {
        return this.serverTool<ReadEmailOutput>('read_email', { email_uuid: emailUuid });
    }

    /** Read and decrypt one email (body, headers, attachment metadata). */
    async readEmailDecrypted(emailUuid: string): Promise<DecryptedEmail> {
        this.ensureDecryptionReady();
        const encrypted = await this.readEmail(emailUuid);
        try {
            return await this.decryptRecord(encrypted as unknown as EncryptedEmail);
        } catch (error) {
            throw new McpDecryptionError(
                `Failed to decrypt email ${emailUuid}: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    /** Encrypted attachment as the server returns it. */
    async getAttachment(attachmentUuid: string): Promise<Record<string, unknown>> {
        return this.serverTool<Record<string, unknown>>('get_attachment', { attachment_uuid: attachmentUuid });
    }

    /** Download and decrypt an attachment in memory (uuid from readEmailDecrypted().attachments). */
    async getAttachmentDecrypted(attachmentUuid: string): Promise<DecryptedAttachmentWithEmail> {
        this.ensureDecryptionReady();
        const att = await this.getAttachment(attachmentUuid);
        try {
            if (this.proxy) return await this.proxy.decryptAttachmentContent(att);
            return await decryptAttachmentRecord(att, this.masterKey!, this.privateKeys!);
        } catch (error) {
            throw new McpDecryptionError(
                `Failed to decrypt attachment ${attachmentUuid}: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    // ── Email Actions ──

    async markRead(emailUuid: string): Promise<void> {
        await this.tool('mark_read', { email_uuid: emailUuid });
    }

    async markUnread(emailUuid: string): Promise<void> {
        await this.tool('mark_unread', { email_uuid: emailUuid });
    }

    /** Move an email (target: inbox, sent, spam, trash or a custom folder uuid). */
    async moveEmail(emailUuid: string, targetFolder: string): Promise<void> {
        await this.tool('move_email', { email_uuid: emailUuid, target_folder: targetFolder });
    }

    async deleteEmail(emailUuid: string): Promise<void> {
        await this.tool('delete_email', { email_uuid: emailUuid });
    }

    // ── Send/Reply/Forward ──

    async sendEmail(params: SendEmailInput & IdempotencyOption): Promise<SendEmailOutput> {
        return this.outgoingTool<SendEmailOutput>('send_email', outgoingArgs(params));
    }

    async replyEmail(params: ReplyEmailInput & IdempotencyOption): Promise<ReplyEmailOutput> {
        return this.outgoingTool<ReplyEmailOutput>('reply_email', outgoingArgs(params));
    }

    async forwardEmail(params: ForwardEmailInput & IdempotencyOption): Promise<ForwardEmailOutput> {
        return this.outgoingTool<ForwardEmailOutput>('forward_email', outgoingArgs(params));
    }

    /**
     * Reply to a stored email. Reads and decrypts the original to fill
     * original_from (Reply-To, else From), original_subject and Message-ID.
     */
    async replyToEmail(emailUuid: string, options: ReplyToEmailOptions): Promise<ReplyEmailOutput> {
        const original = await this.readEmailDecrypted(emailUuid);
        return this.replyEmail({
            email_uuid: emailUuid,
            body: options.body,
            lang: options.lang,
            original_from: original.replyTo || original.from,
            original_subject: original.subject,
            ...(original.messageId ? { original_message_id: original.messageId } : {}),
            ...(options.to !== undefined ? { to: options.to } : {}),
            ...(options.cc !== undefined ? { cc: options.cc } : {}),
            ...(options.subject !== undefined ? { subject: options.subject } : {}),
            ...(options.fromIdentity !== undefined ? { from_identity: options.fromIdentity } : {}),
            ...(options.attachments !== undefined ? { attachments: options.attachments } : {}),
            ...(options.idempotencyKey !== undefined ? { idempotencyKey: options.idempotencyKey } : {}),
        });
    }

    /** Forward a stored email. Reads and decrypts the original subject and body. */
    async forwardEmailTo(emailUuid: string, options: ForwardEmailToOptions): Promise<ForwardEmailOutput> {
        const original = await this.readEmailDecrypted(emailUuid);
        return this.forwardEmail({
            email_uuid: emailUuid,
            to: options.to,
            lang: options.lang,
            original_subject: original.subject,
            original_body: original.body ?? original.bodyText ?? '',
            ...(options.body !== undefined ? { body: options.body } : {}),
            ...(options.fromIdentity !== undefined ? { from_identity: options.fromIdentity } : {}),
            ...(options.attachments !== undefined ? { attachments: options.attachments } : {}),
            ...(options.idempotencyKey !== undefined ? { idempotencyKey: options.idempotencyKey } : {}),
        });
    }

    // ── Drafts ──

    async saveDraft(params: SaveDraftInput): Promise<SaveDraftOutput> {
        return this.tool<SaveDraftOutput>('save_draft', params as unknown as Record<string, unknown>);
    }

    async listDrafts(limit = 20, offset = 0): Promise<ListDraftsOutput> {
        return this.tool<ListDraftsOutput>('list_drafts', { limit, offset });
    }

    async getDraft(draftId: string): Promise<unknown> {
        return this.tool('get_draft', { draft_id: draftId });
    }

    async deleteDraft(draftId: string): Promise<void> {
        await this.tool('delete_draft', { draft_id: draftId });
    }

    // ── DEA Management ──

    async listDeas(): Promise<DeaInfo[]> {
        return (await this.tool<ListDeasOutput>('list_deas')).deas;
    }

    async getDea(deaUid: string): Promise<DeaInfo> {
        return this.tool<DeaInfo>('get_dea', { dea_uid: deaUid });
    }

    async createDea(params: CreateDeaInput): Promise<CreateDeaOutput> {
        return this.tool<CreateDeaOutput>('create_dea', params as unknown as Record<string, unknown>);
    }

    async updateDea(params: UpdateDeaInput): Promise<UpdateDeaOutput> {
        return this.tool<UpdateDeaOutput>('update_dea', params as unknown as Record<string, unknown>);
    }

    async deleteDea(deaUid: string): Promise<void> {
        await this.tool('delete_dea', { dea_uid: deaUid });
    }

    // ── Shared Folders ──

    async listSharedFolders(direction: 'incoming' | 'outgoing' | 'both' = 'both'): Promise<ListSharedFoldersOutput> {
        return this.tool<ListSharedFoldersOutput>('list_shared_folders', { direction });
    }

    async shareFolder(params: ShareFolderInput): Promise<ShareFolderOutput> {
        return this.tool<ShareFolderOutput>('share_folder', params as unknown as Record<string, unknown>);
    }

    async revokeShare(shareUuid: string): Promise<RevokeShareOutput> {
        return this.tool<RevokeShareOutput>('revoke_share', { share_uuid: shareUuid });
    }

    async updateSharePermissions(params: UpdateSharePermissionsInput): Promise<UpdateSharePermissionsOutput> {
        return this.tool<UpdateSharePermissionsOutput>('update_share_permissions', params as unknown as Record<string, unknown>);
    }

    async getRecipientKeys(recipientUsername: string): Promise<GetRecipientKeysOutput> {
        return this.tool<GetRecipientKeysOutput>('get_recipient_keys', { recipient_username: recipientUsername });
    }

    async decryptSharedFolderKey(share: IncomingShare): Promise<Uint8Array> {
        this.ensurePrivateKeys();
        return decryptSharedFolderKey(
            share.encrypted_folder_key,
            share.x25519_ephemeral,
            share.mlkem_ciphertext,
            share.key_nonce,
            this.privateKeys!
        );
    }

    // ── MCP key management (only with an unrestricted personal key) ──

    /** Keys this account manages (personal keys, AI employees with MCP). */
    async listMcpKeys(): Promise<McpKeyInfo[]> {
        return (await this.tool<ListMcpKeysOutput>('list_mcp_keys')).keys;
    }

    /** Limits and state of a key; without keyUuid: the key in use (works for restricted keys too). */
    async getMcpKeyLimits(keyUuid?: string): Promise<McpKeyInfo> {
        return this.tool<McpKeyInfo>('get_mcp_key_limits', keyUuid !== undefined ? { key_uuid: keyUuid } : {});
    }

    /** Replace ALL limits of a key. Missing/null = no limit, [] = nothing allowed. */
    async setMcpKeyLimits(keyUuid: string, limits: McpKeyLimits): Promise<McpKeyInfo> {
        return this.tool<McpKeyInfo>('set_mcp_key_limits', { ...limits, key_uuid: keyUuid });
    }

    /** Suspend (or lift the suspension of) a key. Without keyUuid: suspend the key in use. */
    async suspendMcpKey(keyUuid?: string, suspended = true): Promise<McpKeyInfo> {
        return this.tool<McpKeyInfo>('suspend_mcp_key', { ...(keyUuid !== undefined ? { key_uuid: keyUuid } : {}), suspended });
    }

    /** Access log (no content) and warnings of a key. limit 1–500 (default 100). */
    async getMcpKeyAccessLog(keyUuid: string, limit?: number): Promise<McpKeyAccessLogOutput> {
        return this.tool<McpKeyAccessLogOutput>('get_mcp_key_access_log', { key_uuid: keyUuid, ...(limit !== undefined ? { limit } : {}) });
    }

    /** Company owner/admin: MCP keys of an employee (audited, visible to the employee). */
    async listEmployeeMcpKeys(employeeUuid: string): Promise<ListEmployeeMcpKeysOutput> {
        return this.tool<ListEmployeeMcpKeysOutput>('list_employee_mcp_keys', { employee_uuid: employeeUuid });
    }

    /** Company owner/admin: tighten an employee key's limits (206 if it would loosen, 204 above account limit). */
    async setEmployeeMcpKeyLimits(employeeUuid: string, keyUuid: string, limits: McpKeyLimits): Promise<McpKeyInfo> {
        return this.tool<McpKeyInfo>('set_employee_mcp_key_limits', { ...limits, employee_uuid: employeeUuid, key_uuid: keyUuid });
    }

    /** Company owner/admin: suspend an employee key, or lift a suspension the company set. */
    async suspendEmployeeMcpKey(employeeUuid: string, keyUuid: string, suspended = true): Promise<McpKeyInfo> {
        return this.tool<McpKeyInfo>('suspend_employee_mcp_key', { employee_uuid: employeeUuid, key_uuid: keyUuid, suspended });
    }

    // ── Private Helpers ──

    /** JSON-RPC request through the proxy engine; JSON-RPC errors become typed errors. */
    private async proxyRequest(method: string, params?: Record<string, unknown>): Promise<unknown> {
        let response;
        try {
            response = await this.proxy!.handleRequest({
                jsonrpc: '2.0', id: 1, method, ...(params !== undefined ? { params } : {}),
            });
        } catch (error) {
            throw toMcpError(error, (m) => new McpError(m, -32603));
        }
        if (response.error) {
            throw mcpErrorFromJsonRpc(response.error, method === 'tools/call' ? String(params?.name ?? '') : undefined);
        }
        return response.result;
    }

    /** Tool call with proxy semantics (encrypting/decrypting); throws typed errors. */
    private async tool<T = unknown>(name: string, args: Record<string, unknown> = {}): Promise<T> {
        return parseToolResult<T>(name, await this.callTool(name, args));
    }

    /**
     * Versand (send/reply/forward). Ein Netzfehler ohne `idempotency_key` ist
     * NICHT wiederholbar: die Mail kann schon draußen sein (#4c81ed5b).
     */
    private async outgoingTool<T>(name: string, args: Record<string, unknown>): Promise<T> {
        try {
            return await this.tool<T>(name, args);
        } catch (error) {
            if (error instanceof McpTransportError && args.idempotency_key === undefined) {
                throw new McpTransportError(
                    `${error.message} (${name} may already have been sent; without idempotencyKey a retry can send it twice)`,
                    error.code,
                    false
                );
            }
            throw error;
        }
    }

    /**
     * Tool call WITHOUT the proxy's result decryption – the typed readers
     * return the server's encrypted shape and decrypt explicitly.
     */
    private async serverTool<T = unknown>(name: string, args: Record<string, unknown> = {}): Promise<T> {
        if (!this.proxy) return this.tool<T>(name, args);
        let response;
        try {
            response = await this.proxy.callServerTool(name, args);
        } catch (error) {
            throw toMcpError(error, (m) => new McpError(m, -32603));
        }
        if (response.error) throw mcpErrorFromJsonRpc(response.error, name);
        return parseToolResult<T>(name, response.result as McpToolResult);
    }

    private async decryptRecord(email: EncryptedEmail): Promise<DecryptedEmail> {
        if (this.proxy) return this.proxy.decryptEmailRecord(email);
        return decryptEmail(email, this.masterKey!, this.privateKeys!);
    }

    private ensureDecryptionReady(): void {
        if (this.proxy) {
            if (!this.proxyConnected) {
                throw new McpDecryptionError('Vault is locked. Call connect() first.');
            }
            return;
        }
        this.ensureVaultKey();
        this.ensurePrivateKeys();
    }

    private ensureVaultKey(): void {
        if (!this.masterKey) {
            throw new McpDecryptionError('Vault key not provided. Pass vaultKey in constructor options.');
        }
    }

    private ensurePrivateKeys(): void {
        if (!this.privateKeys) {
            throw new McpDecryptionError(
                'Vault private keys not provided. Pass vaultPrivateKeys in constructor options.'
            );
        }
    }
}

/**
 * Ergebnis eines Werkzeugs auspacken. Der Server antwortet immer mit
 * `{content: [{type: 'text', text: JSON}], isError?}`; ein Fehler trägt
 * `{error: true, error_code, message}` und wird zur passenden Fehlerklasse.
 */
export function parseToolResult<T = unknown>(toolName: string, result: McpToolResult | undefined): T {
    const raw = result as unknown as { content?: { type: string; text?: string }[]; isError?: boolean } | undefined;
    const text = raw?.content?.find(c => c.type === 'text')?.text;
    let payload: Record<string, unknown> | null = null;
    if (typeof text === 'string') {
        try {
            payload = JSON.parse(text) as Record<string, unknown>;
        } catch {
            payload = null;
        }
    }
    if (raw?.isError) {
        const code = typeof payload?.error_code === 'number' ? payload.error_code : 1;
        const message = typeof payload?.message === 'string' ? payload.message
            : typeof payload?.msg === 'string' ? payload.msg
                : (text ?? 'Tool execution failed');
        throw mcpErrorFromCode(code, message, toolName, payload ?? undefined);
    }
    if (payload === null || typeof payload !== 'object') {
        throw new McpToolError(toolName, `${toolName}: server returned no JSON text content`, -32603);
    }
    return payload as T;
}

/** Fremde Ausnahmen (fetch, Zeitgrenze, Krypto) in McpError übersetzen. */
function toMcpError(error: unknown, otherwise: (message: string) => McpError): McpError {
    if (error instanceof McpError) return error;
    const message = error instanceof Error ? error.message : String(error);
    const name = error instanceof Error ? error.name : '';
    if (name === 'TimeoutError' || name === 'AbortError') return new McpTransportError('Request timeout', -32000);
    if (error instanceof TypeError && /fetch/i.test(message)) return new McpTransportError(`Transport error: ${message}`);
    return otherwise(message);
}

/** idempotencyKey → idempotency_key, Anhänge mit Bytes → Base64. */
function outgoingArgs(params: object & IdempotencyOption & { attachments?: OutgoingAttachment[] }): Record<string, unknown> {
    const { idempotencyKey, ...rest } = params as Record<string, unknown> & IdempotencyOption;
    const args: Record<string, unknown> = { ...rest };
    if (idempotencyKey !== undefined) {
        if (typeof idempotencyKey !== 'string' || !IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey)) {
            // Derselbe Wortlaut wie die Serverprüfung; lokal, damit nichts gesendet wird.
            throw new McpError('idempotencyKey must be 1-128 printable ASCII characters', 8);
        }
        args.idempotency_key = idempotencyKey;
    }
    if (Array.isArray(rest.attachments)) {
        args.attachments = (rest.attachments as OutgoingAttachment[]).map((a) => {
            if ('content' in a && a.content instanceof Uint8Array) {
                return { ...a, content: toBase64(a.content), size: a.size ?? a.content.length };
            }
            return a;
        });
    }
    return args;
}
