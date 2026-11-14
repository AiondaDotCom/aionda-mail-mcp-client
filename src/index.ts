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
 *     apiKey: process.env.AIONDA_MCP_KEY!,     // tmmcp_… or tma_…
 *     vaultKey: process.env.AIONDA_VAULT_KEY!, // tmv_…
 *     endpoint: 'https://mail.aionda.com',
 * });
 *
 * await client.connect();
 * const page = await client.listEmailPage({ folder: 'inbox', after: 'start' });
 * const decrypted = await client.readEmailDecrypted(page.emails[0].uuid);
 * await client.disconnect();
 * ```
 */

// Main client
export { AiondaMailClient } from './client.js';
export { parseToolResult } from './client.js';
export type {
    AiondaMailClientOptions,
    EmailPageOptions,
    EmailPage,
    UndecryptableEmail,
    ReplyToEmailOptions,
    ForwardEmailToOptions,
} from './client.js';
export type { DecryptedAttachmentWithEmail } from './crypto/attachment-decryptor.js';

// Transport & Session
export { McpTransport } from './transport.js';
export type { TransportOptions } from './transport.js';
export { McpSession } from './session.js';

// Events
export { AiondaEventClient } from './events.js';
export type { AiondaEventClientOptions } from './events.js';

// Errors
export {
    McpError,
    McpAuthError,
    McpRateLimitError,
    McpSessionExpiredError,
    McpToolError,
    McpDecryptionError,
    McpTransportError,
    McpIntegrationError,
    McpKeyUnusableError,
    McpKeySuspendedError,
    McpKeyRotatedError,
    McpKeyLimitError,
    McpSourceAddressDeniedError,
    McpFolderNotAllowedError,
    McpOutsideTimeWindowError,
    McpSenderNotAllowedError,
    McpSendLimitReachedError,
    McpToolNotAllowedError,
    McpIdempotencyConflictError,
    McpCursorInvalidError,
    McpKeyAdminError,
    McpLimitAboveAccountError,
    McpKeyCompanyManagedError,
    McpLimitLoosenedError,
    McpIntegrationErrorCodes,
    mcpErrorFromCode,
    mcpErrorFromJsonRpc,
    isRetryableMcpError,
} from './errors.js';

// Constants
export {
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_NAME,
    MCP_ENDPOINT_PATH,
    SESSION_TTL_MS,
} from './constants.js';

// Types
export type {
    JsonRpcRequest,
    JsonRpcNotification,
    JsonRpcResponse,
    JsonRpcError,
    McpInitializeResult,
    McpToolDefinition,
    McpToolResult,
} from './types/index.js';

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
    OutgoingAttachment, IdempotencyOption,
    McpKeyLimits, McpKeyInfo, ListMcpKeysOutput,
    McpKeyAccessLogEntry, McpKeyAlert, McpKeyAccessLogOutput,
    ListEmployeeMcpKeysOutput,
} from './types/index.js';

export type {
    EventType,
    EncryptedEventPayload,
    DecryptedEvent,
    EmailReceivedEventData,
    NotificationEventData,
    EventSubscription,
    MissedEventsOutput,
    EventHandler,
} from './types/events.js';

export type {
    EncryptedEmail,
    EncryptedAttachment,
    DecryptedEmail,
    DecryptedAttachmentMeta,
    DecryptedAttachment,
} from './types/email.js';

export type {
    EncryptedFolder,
    DecryptedFolder,
} from './types/folder.js';

export { ErrorCodes } from './types/errors.js';

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
} from './crypto/index.js';
export type { VaultPrivateKeys } from './crypto/index.js';
