/**
 * Gzip/Zlib decompression using Node.js zlib
 */
import { gunzip, inflate } from 'node:zlib';
import { promisify } from 'node:util';

const gunzipAsync = promisify(gunzip);
const inflateAsync = promisify(inflate);

const GZIP_MAGIC = new Uint8Array([0x1f, 0x8b]);
const ZLIB_MAGIC = 0x78;

export function isGzipCompressed(data: Uint8Array): boolean {
    return data.length >= 2 && data[0] === GZIP_MAGIC[0] && data[1] === GZIP_MAGIC[1];
}

export function isZlibCompressed(data: Uint8Array): boolean {
    if (data.length < 2) return false;
    return data[0] === ZLIB_MAGIC &&
        (data[1] === 0x01 || data[1] === 0x5e || data[1] === 0x9c || data[1] === 0xda);
}

export async function decompressGzip(data: Uint8Array): Promise<Uint8Array> {
    const result = await gunzipAsync(Buffer.from(data));
    return new Uint8Array(result);
}

export async function decompressZlib(data: Uint8Array): Promise<Uint8Array> {
    const result = await inflateAsync(Buffer.from(data));
    return new Uint8Array(result);
}

/**
 * Auto-detect and decompress data if needed
 */
export async function decompress(data: Uint8Array): Promise<Uint8Array> {
    if (isGzipCompressed(data)) {
        try {
            return await decompressGzip(data);
        } catch {
            return data;
        }
    }

    if (isZlibCompressed(data)) {
        try {
            return await decompressZlib(data);
        } catch {
            return data;
        }
    }

    return data;
}
