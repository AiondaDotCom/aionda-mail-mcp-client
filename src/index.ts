/**
 * @aiondadotcom/mail-mcp-client
 *
 * TypeScript MCP client for Aionda Mail — E2E encrypted email access for AI agents
 *
 * @example
 * ```typescript
 * import { AiondaMailClient } from '@aiondadotcom/mail-mcp-client';
 *
 * const client = new AiondaMailClient({
 *     apiKey: 'tma_...',
 *     vaultKey: '...',           // optional: hex-encoded 32-byte master key
 *     vaultPrivateKeys: '...',   // optional: hex-encoded x25519+mlkem private keys
 *     endpoint: 'https://trashmail.com',
 * });
 *
 * await client.connect();
 * const emails = await client.listEmails('inbox', 10);
 * const decrypted = await client.readEmailDecrypted('email-uuid');
 * await client.disconnect();
 * ```
 */

// Main client
export { AiondaMailClient } from './client';
export type { AiondaMailClientOptions } from './client';

// Transport & Session
export { McpTransport } from './transport';
export type { TransportOptions } from './transport';
export { McpSession } from './session';

// Events
export { AiondaEventClient } from './events';
export type { AiondaEventClientOptions } from './events';

// Errors
export {
    McpError,
    McpAuthError,
    McpRateLimitError,
    McpSessionExpiredError,
    McpToolError,
    McpDecryptionError,
} from './errors';

// Constants
export {
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_NAME,
    MCP_ENDPOINT_PATH,
    SESSION_TTL_MS,
} from './constants';

// Types
export type {
    JsonRpcRequest,
    JsonRpcNotification,
    JsonRpcResponse,
    JsonRpcError,
    McpInitializeResult,
    McpToolDefinition,
    McpToolResult,
} from './types';

export type {
    ListFoldersInput, ListFoldersOutput,
    ListEmailsInput, ListEmailsOutput,
    ReadEmailInput, ReadEmailOutput,
    MarkReadInput, MarkReadOutput,
    MarkUnreadInput, MarkUnreadOutput,
    MoveEmailInput, MoveEmailOutput,
    DeleteEmailInput, DeleteEmailOutput,
    ListDeasInput, ListDeasOutput, DeaInfo,
    GetDeaInput, GetDeaOutput,
    SendEmailInput, SendEmailOutput,
    ReplyEmailInput, ReplyEmailOutput,
    ForwardEmailInput, ForwardEmailOutput,
    SaveDraftInput, SaveDraftOutput,
    ListDraftsInput, ListDraftsOutput,
    GetDraftInput, GetDraftOutput,
    CreateDeaInput, CreateDeaOutput,
    UpdateDeaInput, UpdateDeaOutput,
    DeleteDeaInput, DeleteDeaOutput,
    ListSharedFoldersInput, ListSharedFoldersOutput,
    ShareFolderInput, ShareFolderOutput,
    RevokeShareInput, RevokeShareOutput,
    UpdateSharePermissionsInput, UpdateSharePermissionsOutput,
    GetRecipientKeysInput, GetRecipientKeysOutput,
    SharedFolderPermissions, SharedFolderRolePreset,
    IncomingShare, OutgoingShare,
    EventTopic,
    EventSubscribeInput, EventSubscribeOutput,
    GetMissedEventsInput, GetMissedEventsOutput, EncryptedEventEntry,
} from './types';

export type {
    EventType,
    EncryptedEventPayload,
    DecryptedEvent,
    EmailReceivedEventData,
    NotificationEventData,
    EventSubscription,
    MissedEventsOutput,
    EventHandler,
} from './types/events';

export type {
    EncryptedEmail,
    EncryptedAttachment,
    DecryptedEmail,
    DecryptedAttachmentMeta,
    DecryptedAttachment,
} from './types/email';

export type {
    EncryptedFolder,
    DecryptedFolder,
} from './types/folder';

export { ErrorCodes } from './types/errors';

// Crypto (for advanced usage)
export {
    decryptEmail,
    decryptSharedFolderKey,
    decryptAesGcm,
    decryptPhpAesGcm,
    hybridDecapsulate,
    deriveFolderKey,
    decompress,
    isBucketPadded,
    unpadFromBucket,
    decodeMimeEncodedWords,
    extractMessageId,
    extractReplyTo,
    fromHex,
    toHex,
    fromBase64,
    toBase64,
} from './crypto';
export type { VaultPrivateKeys } from './crypto';
