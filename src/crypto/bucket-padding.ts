/**
 * Bucket Padding Removal (0xDEAD)
 *
 * Format: MAGIC (2 bytes) || length (4 bytes big-endian) || data || random_padding
 * Prevents CRIME/BREACH-style compression side-channel attacks.
 */

const PADDED_MAGIC = new Uint8Array([0xde, 0xad]);

const PADDING_BUCKETS = [
    256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216,
];

export function isBucketPadded(data: Uint8Array): boolean {
    return data.length >= 6 && data[0] === PADDED_MAGIC[0] && data[1] === PADDED_MAGIC[1];
}

function isValidBucketSize(size: number): boolean {
    if (PADDING_BUCKETS.includes(size)) return true;
    if (size > 16777216 && size % 1048576 === 0) return true;
    return false;
}

/**
 * Remove bucket padding from data
 */
export function unpadFromBucket(paddedData: Uint8Array): Uint8Array {
    if (!isBucketPadded(paddedData)) return paddedData;
    if (!isValidBucketSize(paddedData.length)) return paddedData;

    const dataLen = (paddedData[2] << 24) |
                    (paddedData[3] << 16) |
                    (paddedData[4] << 8) |
                    paddedData[5];

    if (dataLen < 0 || dataLen > paddedData.length - 6) return paddedData;

    return paddedData.slice(6, 6 + dataLen);
}

/**
 * Full decompression pipeline: unpad → decompress
 */
export { decompress } from './decompression';
