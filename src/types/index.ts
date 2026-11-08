/**
 * Types barrel export
 */
export type {
    JsonRpcRequest,
    JsonRpcNotification,
    JsonRpcResponse,
    JsonRpcError,
    McpInitializeResult,
    McpToolDefinition,
    McpPropertySchema,
    McpToolResult,
} from './mcp-protocol';

export type {
    ListFoldersInput, ListFoldersOutput, EncryptedFolderInfo,
    ListEmailsInput, ListEmailsOutput, EncryptedEmailSummary,
    ReadEmailInput, ReadEmailOutput, EncryptedAttachmentInfo,
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
    ListDraftsInput, ListDraftsOutput, DraftInfo,
    GetDraftInput, GetDraftOutput,
    DeleteDraftInput, DeleteDraftOutput,
    CreateDeaInput, CreateDeaOutput,
    UpdateDeaInput, UpdateDeaOutput,
    DeleteDeaInput, DeleteDeaOutput,
    SharedFolderPermissions, SharedFolderRolePreset,
    IncomingShare, OutgoingShare,
    ListSharedFoldersInput, ListSharedFoldersOutput,
    ShareFolderInput, ShareFolderOutput,
    RevokeShareInput, RevokeShareOutput,
    UpdateSharePermissionsInput, UpdateSharePermissionsOutput,
    GetRecipientKeysInput, GetRecipientKeysOutput,
    EventTopic,
    EventSubscribeInput, EventSubscribeOutput,
    GetMissedEventsInput, GetMissedEventsOutput, EncryptedEventEntry,
} from './tools';

export type {
    EncryptedEmail,
    EncryptedAttachment,
    DecryptedEmail,
    DecryptedAttachmentMeta,
    DecryptedAttachment,
} from './email';

export type {
    EncryptedFolder,
    DecryptedFolder,
} from './folder';

export type {
    EventType,
    EncryptedEventPayload,
    DecryptedEvent,
    EmailReceivedEventData,
    NotificationEventData,
    EventSubscription,
    MissedEventsOutput,
    EventHandler,
} from './events';

export { ErrorCodes } from './errors';
export type { ErrorCode } from './errors';
