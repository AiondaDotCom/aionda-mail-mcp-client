/**
 * Ränder der Krypto-Bausteine: Markererkennung, beschädigte Kapseln,
 * Fallback zwischen den Feldformaten, Polsterung, Kompression, Kodierung,
 * Schlüsselableitung, Umschlag mit falscher Schlüssellänge, Zeichensätze.
 */
import { webcrypto } from 'node:crypto';
import { deflateSync, gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';

import { decryptVaultData, encryptVaultData } from '../../src/crypto/aes-gcm';
import { isBucketPadded, unpadFromBucket } from '../../src/crypto/bucket-padding';
import { decompress } from '../../src/crypto/decompression';
import {
    decryptFieldBytes, decryptWrappedKey, isClientEncrypted, parseWrappedKey, resolveContentKey,
} from '../../src/crypto/email-decryptor';
import { fromBase64, fromHex, toHex } from '../../src/crypto/encoding';
import { hybridEncapsulate } from '../../src/crypto/hybrid-kem';
import { deriveEmailKey, deriveEncryptionKey } from '../../src/crypto/key-derivation';
import { decodeMimeEncodedWords } from '../../src/crypto/mime-decoder';
import { packWrappedKeyForRecipient } from '../../src/crypto/wrapped-key-pack';
import { aesGcmRaw, clientFieldHex, makeVault, phpFieldHex, rnd, utf8 } from '../helpers/vault';

describe('email-decryptor', () => {
    it('isClientEncrypted erkennt alle Marker des Master-Key-Wegs, aber keine KEM-Kapsel', () => {
        for (const w of ['', '__MASTER_KEY_ENCRYPTED__', '5f5f4d41535445525f4b45595f454e435259505445445f5f',
            '000000000000000000000000', '00ff', '__DERIVED_KEY_ENCRYPTED__']) {
            expect(isClientEncrypted(w)).toBe(true);
        }
        expect(isClientEncrypted('01' + 'ab'.repeat(40))).toBe(false);
        expect(isClientEncrypted('kein-hex')).toBe(false);
    });

    it('Kapsel einer unbekannten Version wird abgelehnt', () => {
        expect(() => parseWrappedKey(new Uint8Array([2, 0, 0]))).toThrow('Unsupported wrapped key version: 2');
    });

    it('Kapsel ohne Nutzdaten und Kapsel mit falscher Schlüssellänge werden abgelehnt', async () => {
        const v = await makeVault();
        const kurz = parseWrappedKey(new Uint8Array([1, ...rnd(32 + 1568 + 12 + 16)]));
        await expect(decryptWrappedKey(kurz, v.privateKeys)).rejects.toThrow('Encrypted key too short: 16 bytes');

        const falscheLaenge = await packWrappedKeyForRecipient(rnd(16), v.publicKeys.x25519, v.publicKeys.mlkem);
        await expect(decryptWrappedKey(parseWrappedKey(falscheLaenge), v.privateKeys))
            .rejects.toThrow('Invalid ephemeral key length: 16 (expected 32)');
    });

    it('Kapsel mit gepolstertem und komprimiertem Schlüssel wird ausgepackt', async () => {
        const v = await makeVault();
        const mailKey = rnd(32);
        const gz = new Uint8Array(gzipSync(mailKey));
        const padded = new Uint8Array(256);
        padded.set([0xde, 0xad, 0, 0, 0, gz.length]);
        padded.set(gz, 6);
        const pack = await packWrappedKeyForRecipient(padded, v.publicKeys.x25519, v.publicKeys.mlkem);
        const res = await resolveContentKey(toHex(pack), 'm1', v.masterKey, v.privateKeys);
        expect(res).toMatchObject({ source: 'kem', clientEncrypted: false });
        expect(toHex(res.key)).toBe(toHex(mailKey));
    });

    it('decryptFieldBytes probiert das zweite Format und meldet sonst den ERSTEN Fehler', async () => {
        const key = rnd(32);
        expect(new TextDecoder().decode(await decryptFieldBytes(fromHex(await phpFieldHex('php', key)), key, true))).toBe('php');
        expect(new TextDecoder().decode(await decryptFieldBytes(fromHex(await clientFieldHex('client', key)), key, false))).toBe('client');
        await expect(decryptFieldBytes(fromHex(await phpFieldHex('x', rnd(32))), key, true)).rejects.toThrow();
    });
});

describe('Polsterung, Kompression, Kodierung', () => {
    it('Polsterung jenseits 16 MiB (Vielfaches von 1 MiB) wird erkannt; zu große Längenangabe nicht', () => {
        const big = new Uint8Array(17 * 1048576);
        big.set([0xde, 0xad, 0, 0, 0, 3, 7, 8, 9]);
        expect(Array.from(unpadFromBucket(big))).toEqual([7, 8, 9]);

        const luege = new Uint8Array(256);
        luege.set([0xde, 0xad, 0, 0, 1, 0]);
        expect(isBucketPadded(luege)).toBe(true);
        expect(unpadFromBucket(luege)).toBe(luege);
    });

    it('beschädigte gzip- bzw. zlib-Daten kommen unverändert zurück, gültige werden entpackt', async () => {
        const gz = new Uint8Array([0x1f, 0x8b, 1, 2, 3]);
        const zl = new Uint8Array([0x78, 0x9c, 1, 2, 3]);
        expect(await decompress(gz)).toBe(gz);
        expect(await decompress(zl)).toBe(zl);
        expect(new TextDecoder().decode(await decompress(new Uint8Array(deflateSync(utf8('zlib')))))).toBe('zlib');
    });

    it('fromBase64 nimmt base64url ohne Auffüllung und mit Leerraum', () => {
        expect(Array.from(fromBase64('-_8'))).toEqual([0xfb, 0xff]);
        expect(Array.from(fromBase64('AQ ID\n'))).toEqual([1, 2, 3]);
    });
});

describe('Schlüsselableitung', () => {
    it('deriveEncryptionKey öffnet, was encryptVaultData (Version 2) verpackt hat', async () => {
        const m = rnd(32);
        const blob = await encryptVaultData(utf8('Kontakt'), m);
        const key = await deriveEncryptionKey(m, blob.slice(1, 33));
        const plain = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(33, 45) }, key, blob.slice(45));
        expect(new TextDecoder().decode(plain)).toBe('Kontakt');
        expect(new TextDecoder().decode(await decryptVaultData(blob, m))).toBe('Kontakt');
    });

    it('deriveEmailKey ohne Mail-UUID ist ein Fehler, kein leerer info-Wert', async () => {
        await expect(deriveEmailKey(rnd(32), '')).rejects.toThrow('deriveEmailKey ohne Mail-UUID aufgerufen');
    });
});

describe('MIME-Zeichensätze', () => {
    it('ISO-8859-1, Windows-1252 und unbekannte Zeichensätze', () => {
        expect(decodeMimeEncodedWords('=?ISO-8859-1?Q?M=FCller?=')).toBe('Müller');
        expect(decodeMimeEncodedWords('=?latin1?B?' + Buffer.from([0x47, 0x72, 0xfc, 0xdf]).toString('base64') + '?=')).toBe('Grüß');
        expect(decodeMimeEncodedWords('=?windows-1252?Q?=80_Preis?=')).toBe('€ Preis');
        expect(decodeMimeEncodedWords('=?x-gibt-es-nicht?Q?abc?=')).toBe('abc');
    });
});

describe('Hybrid-KEM-Kapsel öffnet sich nur beim Empfänger', () => {
    it('falscher Empfänger bekommt einen anderen Schlüssel (implizite Ablehnung), AES-GCM scheitert dann laut', async () => {
        const a = await makeVault();
        const b = await makeVault();
        const kem = await hybridEncapsulate(a.publicKeys.x25519, a.publicKeys.mlkem);
        const iv = rnd(12);
        const sealed = await aesGcmRaw(kem.sharedSecret, iv, utf8('nur für a'));
        const pack = new Uint8Array([1, ...kem.x25519Ciphertext, ...kem.mlKemCiphertext, ...iv, ...sealed.slice(-16), ...sealed.slice(0, -16)]);
        await expect(decryptWrappedKey(parseWrappedKey(pack), b.privateKeys)).rejects.toThrow();
    });
});
