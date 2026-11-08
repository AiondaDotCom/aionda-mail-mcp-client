/**
 * Crypto barrel export
 */
export { decryptAesGcm, decryptPhpAesGcm, decryptClientAesGcm } from './aes-gcm';
export { deriveFolderKey, deriveEncryptionKey } from './key-derivation';
export { decompress, isGzipCompressed, isZlibCompressed, decompressGzip, decompressZlib } from './decompression';
export { isBucketPadded, unpadFromBucket } from './bucket-padding';
export { hybridDecapsulate } from './hybrid-kem';
export { decodeMimeEncodedWords, extractMessageId, extractReplyTo } from './mime-decoder';
export { decryptEmail } from './email-decryptor';
export type { VaultPrivateKeys } from './email-decryptor';
export { decryptSharedFolderKey } from './shared-folder-key';
export { fromHex, toHex, fromBase64, toBase64 } from './encoding';
// Aufgaben-Modul — // #f1c8f3f1
export {
    generateTaskKey,
    wrapTaskKey,
    unwrapTaskKey,
    encryptTaskField,
    decryptTaskField,
    normalizeSteps,
    parseSteps,
    TASKS_HKDF_INFO,
    LEGACY_HKDF_INFO,
    TASK_WRAP_VERSION,
} from './tasks-crypto';
export type { TaskStep } from './tasks-crypto';
// Signierter Postfach-Schlüsselwechsel (#658912ef, docs/VAULT_SCHLUESSELWECHSEL_SIGNATUR.md)
export {
    fingerprintPreimage,
    fingerprintFull,
    formatFingerprint,
    normalizeLogin,
    transitionRecord,
    installRecord,
    seedAad,
    FINGERPRINT_DOMAIN,
    INSTALL_TAG,
    INSTALL_VERSION,
    INSTALL_CONTEXT,
    SEED_AAD_TAG,
    TRANSITION_TAG,
    TRANSITION_VERSION,
    TRANSITION_CONTEXT,
    TRANSITION_REASON,
    TRANSITION_REASON_NAMES,
} from './key-transition';
export type { TransitionReason, TransitionRecordInput, InstallRecordInput } from './key-transition';
// Umschlag des Master Keys für den MCP-Zugang echter Menschen (Vertrag 13.09.2026)
export {
    unwrapMasterKey,
    deriveWrappingKey,
    masterKeyAad,
    MCP_MASTER_KEY_AAD_PREFIX,
    WRAPPED_MASTER_KEY_LENGTH,
} from './mcp-master-key';
