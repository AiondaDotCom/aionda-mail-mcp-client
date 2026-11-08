/**
 * AiondaMailClient — High-level typed MCP client
 *
 * Usage:
 *   const client = new AiondaMailClient({
 *       apiKey: 'tma_...',
 *       vaultKey: 'hex-encoded-master-key', // optional
 *       endpoint: 'https://trashmail.com/mcp',
 *   });
 *   await client.connect();
 *   const emails = await client.listEmails('inbox');
 */
import { McpTransport } from './transport';
import { McpSession } from './session';
import { McpDecryptionError } from './errors';
import { MCP_ENDPOINT_PATH } from './constants';
import { decryptEmail } from './crypto/email-decryptor';
import { decodeMimeEncodedWords } from './crypto/mime-decoder';
import { fromHex } from './crypto/encoding';
import type { VaultPrivateKeys } from './crypto/email-decryptor';
import { decryptSharedFolderKey } from './crypto/shared-folder-key';
import type {
    McpToolDefinition,
    McpToolResult,
    ListFoldersOutput,
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
} from './types';
import type { DecryptedEmail, EncryptedEmail } from './types/email';
import type { EncryptedFolder, DecryptedFolder } from './types/folder';

export interface AiondaMailClientOptions {
    /** MCP API key (tma_*) */
    apiKey: string;
    /** Hex-encoded 32-byte vault master key (optional — without it, only encrypted data) */
    vaultKey?: string;
    /** Hex-encoded vault private keys: x25519(32) + mlkem(3168) = 3200 bytes */
    vaultPrivateKeys?: string;
    /** Server endpoint (default: https://trashmail.com) */
    endpoint?: string;
    /** Request timeout in ms (default: 30000) */
    timeout?: number;
}

export class AiondaMailClient {
    private transport: McpTransport;
    private session: McpSession;
    private masterKey: Uint8Array | null = null;
    private privateKeys: VaultPrivateKeys | null = null;

    constructor(options: AiondaMailClientOptions) {
        const baseUrl = options.endpoint ?? 'https://trashmail.com';
        const endpoint = baseUrl.endsWith(MCP_ENDPOINT_PATH)
            ? baseUrl
            : baseUrl + MCP_ENDPOINT_PATH;

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

    async connect(): Promise<void> {
        await this.session.initialize();
    }

    async disconnect(): Promise<void> {
        this.session.destroy();
    }

    async ping(): Promise<void> {
        await this.session.ping();
    }

    isConnected(): boolean {
        return this.session.isInitialized() && !this.session.isExpired();
    }

    // ── Tools ──

    async listTools(): Promise<McpToolDefinition[]> {
        return this.session.listTools();
    }

    async callTool(name: string, args: Record<string, unknown> = {}): Promise<McpToolResult> {
        const result = await this.session.callTool(name, args);
        return result as McpToolResult;
    }

    // ── Folders ──

    async listFolders(): Promise<ListFoldersOutput> {
        const result = await this.callTool('list_folders');
        return result.data as ListFoldersOutput;
    }

    async listFoldersDecrypted(): Promise<DecryptedFolder[]> {
        this.ensureVaultKey();
        const output = await this.listFolders();
        return Promise.all(
            output.folders.map(async (f: EncryptedFolder) => {
                let name = f.folder_type;
                if (f.encrypted_name && this.masterKey) {
                    try {
                        const { decryptPhpAesGcm } = await import('./crypto/aes-gcm');
                        const { decompress } = await import('./crypto/decompression');
                        const { unpadFromBucket, isBucketPadded } = await import('./crypto/bucket-padding');
                        let plaintext = await decryptPhpAesGcm(fromHex(f.encrypted_name), this.masterKey);
                        if (isBucketPadded(plaintext)) plaintext = unpadFromBucket(plaintext);
                        plaintext = await decompress(plaintext);
                        name = new TextDecoder().decode(plaintext);
                    } catch {
                        name = f.folder_type;
                    }
                }
                return {
                    uuid: f.uuid,
                    folderType: f.folder_type,
                    name,
                    emailCount: f.email_count,
                    unreadCount: f.unread_count,
                };
            })
        );
    }

    // ── Emails ──

    async listEmails(folder = 'inbox', limit = 20, offset = 0): Promise<ListEmailsOutput> {
        const result = await this.callTool('list_emails', { folder, limit, offset });
        return result.data as ListEmailsOutput;
    }

    async readEmail(emailUuid: string): Promise<ReadEmailOutput> {
        const result = await this.callTool('read_email', { email_uuid: emailUuid });
        return result.data as ReadEmailOutput;
    }

    async readEmailDecrypted(emailUuid: string): Promise<DecryptedEmail> {
        this.ensureVaultKey();
        this.ensurePrivateKeys();

        const encrypted = await this.readEmail(emailUuid);
        try {
            return await decryptEmail(
                encrypted as unknown as EncryptedEmail,
                this.masterKey!,
                this.privateKeys!
            );
        } catch (error) {
            throw new McpDecryptionError(
                `Failed to decrypt email ${emailUuid}: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    // ── Email Actions ──

    async markRead(emailUuid: string): Promise<void> {
        await this.callTool('mark_read', { email_uuid: emailUuid });
    }

    async markUnread(emailUuid: string): Promise<void> {
        await this.callTool('mark_unread', { email_uuid: emailUuid });
    }

    async moveEmail(emailUuid: string, targetFolder: string): Promise<void> {
        await this.callTool('move_email', { email_uuid: emailUuid, target_folder: targetFolder });
    }

    async deleteEmail(emailUuid: string): Promise<void> {
        await this.callTool('delete_email', { email_uuid: emailUuid });
    }

    // ── Send/Reply/Forward ──

    async sendEmail(params: SendEmailInput): Promise<SendEmailOutput> {
        const result = await this.callTool('send_email', params as unknown as Record<string, unknown>);
        return result.data as SendEmailOutput;
    }

    async replyEmail(params: ReplyEmailInput): Promise<ReplyEmailOutput> {
        const result = await this.callTool('reply_email', params as unknown as Record<string, unknown>);
        return result.data as ReplyEmailOutput;
    }

    async forwardEmail(params: ForwardEmailInput): Promise<ForwardEmailOutput> {
        const result = await this.callTool('forward_email', params as unknown as Record<string, unknown>);
        return result.data as ForwardEmailOutput;
    }

    // ── Drafts ──

    async saveDraft(params: SaveDraftInput): Promise<SaveDraftOutput> {
        const result = await this.callTool('save_draft', params as unknown as Record<string, unknown>);
        return result.data as SaveDraftOutput;
    }

    async listDrafts(limit = 20, offset = 0): Promise<ListDraftsOutput> {
        const result = await this.callTool('list_drafts', { limit, offset });
        return result.data as ListDraftsOutput;
    }

    async getDraft(draftId: string): Promise<unknown> {
        const result = await this.callTool('get_draft', { draft_id: draftId });
        return result.data;
    }

    async deleteDraft(draftId: string): Promise<void> {
        await this.callTool('delete_draft', { draft_id: draftId });
    }

    // ── DEA Management ──

    async listDeas(): Promise<DeaInfo[]> {
        const result = await this.callTool('list_deas');
        return (result.data as ListDeasOutput).deas;
    }

    async getDea(deaUid: string): Promise<DeaInfo> {
        const result = await this.callTool('get_dea', { dea_uid: deaUid });
        return result.data as DeaInfo;
    }

    async createDea(params: CreateDeaInput): Promise<CreateDeaOutput> {
        const result = await this.callTool('create_dea', params as unknown as Record<string, unknown>);
        return result.data as CreateDeaOutput;
    }

    async updateDea(params: UpdateDeaInput): Promise<UpdateDeaOutput> {
        const result = await this.callTool('update_dea', params as unknown as Record<string, unknown>);
        return result.data as UpdateDeaOutput;
    }

    async deleteDea(deaUid: string): Promise<void> {
        await this.callTool('delete_dea', { dea_uid: deaUid });
    }

    // ── Shared Folders ──

    async listSharedFolders(direction: 'incoming' | 'outgoing' | 'both' = 'both'): Promise<ListSharedFoldersOutput> {
        const result = await this.callTool('list_shared_folders', { direction });
        return result.data as ListSharedFoldersOutput;
    }

    async shareFolder(params: ShareFolderInput): Promise<ShareFolderOutput> {
        const result = await this.callTool('share_folder', params as unknown as Record<string, unknown>);
        return result.data as ShareFolderOutput;
    }

    async revokeShare(shareUuid: string): Promise<RevokeShareOutput> {
        const result = await this.callTool('revoke_share', { share_uuid: shareUuid });
        return result.data as RevokeShareOutput;
    }

    async updateSharePermissions(params: UpdateSharePermissionsInput): Promise<UpdateSharePermissionsOutput> {
        const result = await this.callTool('update_share_permissions', params as unknown as Record<string, unknown>);
        return result.data as UpdateSharePermissionsOutput;
    }

    async getRecipientKeys(recipientUsername: string): Promise<GetRecipientKeysOutput> {
        const result = await this.callTool('get_recipient_keys', { recipient_username: recipientUsername });
        return result.data as GetRecipientKeysOutput;
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

    // ── Private Helpers ──

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
