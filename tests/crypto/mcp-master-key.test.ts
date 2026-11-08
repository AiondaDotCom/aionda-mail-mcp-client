/**
 * Umschlag des Master Keys – Known-Answer-Test gegen kat/mcp-menschenschluessel.json
 *
 * Zwei Wege je Vektor:
 *   1. eine UNABHÄNGIGE Nachrechnung mit rohem WebCrypto (kein Produktivcode),
 *      die den erwarteten Blob aus den Eingaben erzeugt – belegt, dass die
 *      Datei stimmt;
 *   2. die echte Lesefunktion unwrapMasterKey(), die den Blob öffnen muss.
 *
 * Dieselbe Datei prüfen der Web-Manager und der Swift-Core.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { McpDecryptionError } from '../../src/errors';
import {
    MCP_MASTER_KEY_AAD_PREFIX, WRAPPED_MASTER_KEY_LENGTH,
    deriveWrappingKey, masterKeyAad, unwrapMasterKey,
} from '../../src/crypto/mcp-master-key';

interface KatCase {
    name: string;
    vault_key_utf8: string;
    key_uuid: string;
    aad_utf8: string;
    aad: string;
    wrapping_key: string;
    master_key: string;
    iv: string;
    ciphertext: string;
    tag: string;
    wrapped_master_key: string;
}
interface ApiKeyCase { name: string; api_key_utf8: string; api_key_hash: string; key_prefix: string }
interface NegativeCase { name: string; vault_key_utf8: string; key_uuid: string; wrapped_master_key: string; expect: string }
interface KatFile { cases: KatCase[]; api_key_cases: ApiKeyCase[]; negative_cases: NegativeCase[] }

const KAT_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'kat', 'mcp-menschenschluessel.json');
const kat = JSON.parse(readFileSync(KAT_PATH, 'utf8')) as KatFile;

const hex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g)!.map(x => parseInt(x, 16)));
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Unabhängige Nachrechnung – bewusst ohne Produktivcode. */
async function wrapIndependently(c: KatCase): Promise<string> {
    const K = new Uint8Array(await webcrypto.subtle.digest('SHA-256', utf8(c.vault_key_utf8)));
    const key = await webcrypto.subtle.importKey('raw', K, 'AES-GCM', false, ['encrypt']);
    const ctTag = new Uint8Array(await webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv: fromHex(c.iv), additionalData: utf8('aionda-mcp-master-key-v1:' + c.key_uuid.toLowerCase()) },
        key,
        fromHex(c.master_key)
    ));
    return c.iv + hex(ctTag);
}

describe('KAT mcp-menschenschluessel.json', () => {
    it('hat Fälle in allen drei Gruppen (sonst misst dieser Test nichts)', () => {
        expect(kat.cases.length).toBeGreaterThanOrEqual(3);
        expect(kat.api_key_cases.length).toBeGreaterThanOrEqual(1);
        expect(kat.negative_cases.length).toBeGreaterThanOrEqual(3);
    });

    for (const c of kat.cases) {
        it(`${c.name}: unabhängige WebCrypto-Rechnung erzeugt den erwarteten Blob`, async () => {
            expect(await wrapIndependently(c)).toBe(c.wrapped_master_key);
            expect(c.wrapped_master_key).toBe(c.iv + c.ciphertext + c.tag);
            expect(c.wrapped_master_key.length / 2).toBe(WRAPPED_MASTER_KEY_LENGTH);
            expect(hex(utf8(c.aad_utf8))).toBe(c.aad);
            expect(c.aad_utf8).toBe(MCP_MASTER_KEY_AAD_PREFIX + c.key_uuid.toLowerCase());
        });

        it(`${c.name}: die Produktivfunktion öffnet den Blob zu M`, async () => {
            expect(hex(await deriveWrappingKey(c.vault_key_utf8))).toBe(c.wrapping_key);
            expect(hex(masterKeyAad(c.key_uuid))).toBe(c.aad);
            const M = await unwrapMasterKey(fromHex(c.wrapped_master_key), c.vault_key_utf8, c.key_uuid);
            expect(hex(M)).toBe(c.master_key);
        });
    }

    for (const c of kat.api_key_cases) {
        it(`${c.name}: SHA-256 des tmmcp_-Textes und Präfix`, async () => {
            const digest = new Uint8Array(await webcrypto.subtle.digest('SHA-256', utf8(c.api_key_utf8)));
            expect(hex(digest)).toBe(c.api_key_hash);
            expect(c.api_key_utf8.substring(0, 12)).toBe(c.key_prefix);
            expect(c.api_key_utf8).toMatch(/^tmmcp_[A-Za-z0-9_-]{43}$/);
        });
    }

    for (const c of kat.negative_cases) {
        it(`${c.name}: bricht hart ab (${c.expect})`, async () => {
            expect(c.expect).toBe('auth_failure');
            await expect(unwrapMasterKey(fromHex(c.wrapped_master_key), c.vault_key_utf8, c.key_uuid))
                .rejects.toBeInstanceOf(McpDecryptionError);
        });
    }
});

describe('unwrapMasterKey – Bauform', () => {
    const g = kat.cases[0];

    it('falsches tmv_ bricht ab und liefert NIE SHA-256(tmv_) als Ersatz', async () => {
        const falsch = g.vault_key_utf8.slice(0, -2) + 'zz';
        let ergebnis: Uint8Array | null = null;
        let fehler: unknown = null;
        try {
            ergebnis = await unwrapMasterKey(fromHex(g.wrapped_master_key), falsch, g.key_uuid);
        } catch (e) {
            fehler = e;
        }
        expect(ergebnis).toBeNull();
        expect(fehler).toBeInstanceOf(McpDecryptionError);
        expect((fehler as Error).message).toMatch(/AIONDA_VAULT_KEY does not match/);
    });

    it('UUID in Grossbuchstaben ergibt dieselbe AAD', async () => {
        const M = await unwrapMasterKey(fromHex(g.wrapped_master_key), g.vault_key_utf8, g.key_uuid.toUpperCase());
        expect(hex(M)).toBe(g.master_key);
    });

    it('lehnt einen Text ohne tmv_-Präfix ab', async () => {
        await expect(deriveWrappingKey('tma_' + g.vault_key_utf8.slice(4))).rejects.toBeInstanceOf(McpDecryptionError);
    });

    it('lehnt eine kaputte UUID ab, bevor gerechnet wird', async () => {
        await expect(unwrapMasterKey(fromHex(g.wrapped_master_key), g.vault_key_utf8, 'keine-uuid'))
            .rejects.toThrow(/not a UUID/);
    });
});
