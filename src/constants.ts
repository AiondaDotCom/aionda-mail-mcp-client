/**
 * Protocol Constants
 */

export const MCP_PROTOCOL_VERSION = '2025-03-26';
export const MCP_SERVER_NAME = 'Aionda Mail';
export const MCP_ENDPOINT_PATH = '/mcp';

export const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export const RATE_LIMIT_DEFAULT_RETRY_MS = 60000;

export const WRAPPED_KEY_VERSION_HYBRID_KEM = 1;
export const X25519_PUBLIC_KEY_LENGTH = 32;
export const MLKEM_CIPHERTEXT_LENGTH = 1568;
export const AES_GCM_NONCE_LENGTH = 12;
export const AES_GCM_TAG_LENGTH = 16;
export const AES_256_KEY_LENGTH = 32;

export const GZIP_MAGIC = new Uint8Array([0x1f, 0x8b]);
export const ZLIB_MAGIC = 0x78;
export const BUCKET_PADDING_MAGIC = new Uint8Array([0xde, 0xad]);

export const PADDING_BUCKETS = [
    256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216,
];

export const MASTER_KEY_MARKER = '__MASTER_KEY_ENCRYPTED__';
export const MASTER_KEY_MARKER_HEX = '5f5f4d41535445525f4b45595f454e435259505445445f5f';

export const HKDF_INFO_HYBRID_KEM = 'trashmail-hybrid-kem-v1';
export const HKDF_INFO_FOLDER_KEY = 'trashmail-folder-key-v1';
