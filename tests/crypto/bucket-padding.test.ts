import { describe, it, expect } from 'vitest';
import { isBucketPadded, unpadFromBucket } from '../../src/crypto/bucket-padding';

describe('Bucket Padding', () => {
    it('detects 0xDEAD magic bytes', () => {
        const padded = new Uint8Array([0xde, 0xad, 0, 0, 0, 5, 1, 2, 3, 4, 5]);
        expect(isBucketPadded(padded)).toBe(true);
    });

    it('rejects non-padded data', () => {
        const data = new Uint8Array([0x1f, 0x8b, 0, 0, 0, 5, 1, 2, 3, 4, 5]);
        expect(isBucketPadded(data)).toBe(false);
    });

    it('unpads data from valid bucket size (256)', () => {
        const originalData = new Uint8Array([10, 20, 30, 40, 50]);
        const padded = new Uint8Array(256);
        padded[0] = 0xde;
        padded[1] = 0xad;
        padded[2] = 0;
        padded[3] = 0;
        padded[4] = 0;
        padded[5] = 5; // data length
        padded.set(originalData, 6);
        // Rest is random padding (zeros are fine for test)

        const result = unpadFromBucket(padded);
        expect(result).toEqual(originalData);
    });

    it('returns original if not a valid bucket size', () => {
        // 100 bytes is NOT a valid bucket size
        const data = new Uint8Array(100);
        data[0] = 0xde;
        data[1] = 0xad;
        data[2] = 0;
        data[3] = 0;
        data[4] = 0;
        data[5] = 10;

        const result = unpadFromBucket(data);
        // Should return original because 100 is not a valid bucket size
        expect(result).toEqual(data);
    });

    it('handles non-padded data passthrough', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const result = unpadFromBucket(data);
        expect(result).toEqual(data);
    });

    it('validates data length against bucket size', () => {
        const padded = new Uint8Array(512);
        padded[0] = 0xde;
        padded[1] = 0xad;
        // Length = 200 (valid, < 512 - 6)
        padded[2] = 0;
        padded[3] = 0;
        padded[4] = 0;
        padded[5] = 200;
        // Fill with test data
        for (let i = 6; i < 206; i++) padded[i] = i % 256;

        const result = unpadFromBucket(padded);
        expect(result.length).toBe(200);
    });
});
