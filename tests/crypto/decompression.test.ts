import { describe, it, expect } from 'vitest';
import { gzip, deflate } from 'node:zlib';
import { promisify } from 'node:util';
import { decompress, isGzipCompressed, isZlibCompressed } from '../../src/crypto/decompression';

const gzipAsync = promisify(gzip);
const deflateAsync = promisify(deflate);

describe('Decompression', () => {
    it('detects gzip magic bytes', () => {
        expect(isGzipCompressed(new Uint8Array([0x1f, 0x8b, 0x08]))).toBe(true);
        expect(isGzipCompressed(new Uint8Array([0x00, 0x00]))).toBe(false);
    });

    it('detects zlib magic bytes', () => {
        expect(isZlibCompressed(new Uint8Array([0x78, 0x9c]))).toBe(true);
        expect(isZlibCompressed(new Uint8Array([0x78, 0xda]))).toBe(true);
        expect(isZlibCompressed(new Uint8Array([0x78, 0x01]))).toBe(true);
        expect(isZlibCompressed(new Uint8Array([0x00, 0x00]))).toBe(false);
    });

    it('decompresses gzip data', async () => {
        const original = Buffer.from('Hello, compressed world!');
        const compressed = await gzipAsync(original);
        const result = await decompress(new Uint8Array(compressed));
        expect(new TextDecoder().decode(result)).toBe('Hello, compressed world!');
    });

    it('decompresses zlib data', async () => {
        const original = Buffer.from('Zlib compressed data');
        const compressed = await deflateAsync(original);
        const result = await decompress(new Uint8Array(compressed));
        expect(new TextDecoder().decode(result)).toBe('Zlib compressed data');
    });

    it('passes through non-compressed data', async () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const result = await decompress(data);
        expect(result).toEqual(data);
    });
});
