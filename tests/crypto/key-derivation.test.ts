import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';
import { deriveFolderKey } from '../../src/crypto/key-derivation';

describe('Key Derivation', () => {
    it('derives deterministic folder key', async () => {
        const masterKey = new Uint8Array(32);
        webcrypto.getRandomValues(masterKey);

        const key1 = await deriveFolderKey(masterKey, 'folder-uuid-123');
        const key2 = await deriveFolderKey(masterKey, 'folder-uuid-123');

        expect(key1).toEqual(key2);
        expect(key1.length).toBe(32);
    });

    it('different folders produce different keys', async () => {
        const masterKey = new Uint8Array(32);
        webcrypto.getRandomValues(masterKey);

        const key1 = await deriveFolderKey(masterKey, 'folder-a');
        const key2 = await deriveFolderKey(masterKey, 'folder-b');

        expect(key1).not.toEqual(key2);
    });

    it('different master keys produce different folder keys', async () => {
        const mk1 = new Uint8Array(32);
        const mk2 = new Uint8Array(32);
        webcrypto.getRandomValues(mk1);
        webcrypto.getRandomValues(mk2);

        const key1 = await deriveFolderKey(mk1, 'same-folder');
        const key2 = await deriveFolderKey(mk2, 'same-folder');

        expect(key1).not.toEqual(key2);
    });
});
