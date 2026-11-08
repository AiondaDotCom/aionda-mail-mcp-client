/**
 * Bootstrap des Proxys gegen einen nachgebauten Server – der Umschlag des
 * Master Keys (Mensch) und der alte SHA-256-Weg (KI-Mitarbeiter).
 *
 * Der Server ist eine fetch-Attrappe, die Krypto ist echt: der private
 * Schlüssel wird mit dem echten M verschlüsselt, der Umschlag mit dem echten
 * tmv_. Was hier festgenagelt wird:
 *   - Mensch, webcrypto-Layout: privater Schlüssel kommt an
 *   - falsches tmv_: Start bricht ab, kein „decryption disabled"
 *   - KI-Mitarbeiter, php-Layout: unverändert
 *   - privater Schlüssel passt nicht zum Master Key: Abbruch
 *   - get_vault_keys ohne Schlüssel: Abbruch
 */
import { webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('tesseract.js', () => {
    throw new Error('tesseract.js wird im Test nicht geladen');
});

import { McpDecryptingProxy } from '../src/proxy';

const hex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const rnd = (n: number): Uint8Array => webcrypto.getRandomValues(new Uint8Array(n));
const b64url = (b: Uint8Array): string => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const KEY_UUID = '0f3c4c5e-7a1b-4d2e-9f80-1a2b3c4d5e6f';
const PRIVATE_KEY_LEN = 32 + 3168;

async function sha256(b: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await webcrypto.subtle.digest('SHA-256', b));
}

async function aesGcm(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    const k = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    return new Uint8Array(await webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv, ...(aad ? { additionalData: aad } : {}) }, k, plaintext
    ));
}

interface ServerMaterial {
    vaultKeyText: string;
    masterKey: Uint8Array;
    privateKey: Uint8Array;
    keys: Record<string, unknown>;
}

/** Mensch: M zufällig, Umschlag mit tmv_, privater Schlüssel im webcrypto-Layout. */
async function humanMaterial(): Promise<ServerMaterial> {
    const vaultKeyText = 'tmv_' + b64url(rnd(32));
    const masterKey = rnd(32);
    const privateKey = rnd(PRIVATE_KEY_LEN);

    const K = await sha256(utf8(vaultKeyText));
    const wrapIv = rnd(12);
    const wrapped = new Uint8Array([...wrapIv, ...await aesGcm(K, wrapIv, masterKey, utf8('aionda-mcp-master-key-v1:' + KEY_UUID))]);

    const pkIv = rnd(12);
    const encPriv = await aesGcm(masterKey, pkIv, privateKey); // ct || tag

    return {
        vaultKeyText, masterKey, privateKey,
        keys: {
            wrapped_master_key: hex(wrapped),
            mcp_key_uuid: KEY_UUID,
            encrypted_private_key: hex(encPriv),
            private_key_iv: hex(pkIv),
            private_key_layout: 'webcrypto',
            crypto_version: 2,
            x25519_public_key: hex(rnd(32)),
            mlkem_public_key: hex(rnd(64)),
        },
    };
}

/** KI-Mitarbeiter: M = SHA-256(tmv_), privater Schlüssel im php-Layout (nonce || tag || ct). */
async function aiMaterial(): Promise<ServerMaterial> {
    const vaultKeyText = 'tmv_' + b64url(rnd(32));
    const masterKey = await sha256(utf8(vaultKeyText));
    const privateKey = rnd(PRIVATE_KEY_LEN);
    const iv = rnd(12);
    const ctTag = await aesGcm(masterKey, iv, privateKey);
    const ct = ctTag.slice(0, ctTag.length - 16);
    const tag = ctTag.slice(ctTag.length - 16);
    const phpBlob = new Uint8Array([...iv, ...tag, ...ct]);
    return {
        vaultKeyText, masterKey, privateKey,
        keys: {
            wrapped_master_key: null,
            mcp_key_uuid: null,
            encrypted_private_key: hex(phpBlob),
            private_key_iv: hex(iv),
            private_key_layout: 'php',
            crypto_version: 2,
            x25519_public_key: hex(rnd(32)),
            mlkem_public_key: hex(rnd(64)),
        },
    };
}

function toolText(payload: unknown): unknown {
    return { content: [{ type: 'text', text: JSON.stringify(payload) }] };
}

/** fetch-Attrappe: antwortet je nach Methode/Werkzeug. */
function installServer(keys: Record<string, unknown> | { error: string }): { calls: string[] } {
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string }) => {
        const req = JSON.parse(init.body) as { id?: number; method: string; params?: { name?: string } };
        calls.push(req.params?.name ?? req.method);
        let body: unknown = { jsonrpc: '2.0', id: req.id, result: {} };
        if (req.method === 'tools/call' && req.params?.name === 'get_vault_keys') {
            body = 'error' in keys
                ? { jsonrpc: '2.0', id: req.id, error: { code: 61, message: keys.error } }
                : { jsonrpc: '2.0', id: req.id, result: toolText({ success: true, data: keys }) };
        }
        if (req.method === 'tools/call' && req.params?.name === 'get_default_signature') {
            body = { jsonrpc: '2.0', id: req.id, result: toolText({ success: true, data: { has_signature: false } }) };
        }
        return {
            headers: { get: (name: string) => (name === 'Mcp-Session-Id' ? 'test-session' : null) },
            json: async () => body,
        };
    }));
    return { calls };
}

function privateKeysOf(proxy: McpDecryptingProxy): { x25519PrivateKey: Uint8Array; mlKemPrivateKey: Uint8Array } | null {
    return (proxy as unknown as { privateKeys: { x25519PrivateKey: Uint8Array; mlKemPrivateKey: Uint8Array } | null }).privateKeys;
}
function masterKeyOf(proxy: McpDecryptingProxy): Uint8Array | null {
    return (proxy as unknown as { masterKey: Uint8Array | null }).masterKey;
}

describe('McpDecryptingProxy.bootstrap – Umschlag des Master Keys', () => {
    let stderr: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    });
    afterEach(() => {
        vi.unstubAllGlobals();
        stderr.mockRestore();
    });

    it('Mensch, webcrypto-Layout: Umschlag geht auf, privater Schlüssel liegt vor', async () => {
        const m = await humanMaterial();
        const server = installServer(m.keys);
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tmmcp_x', vaultKey: m.vaultKeyText });

        await proxy.bootstrap();

        expect(hex(masterKeyOf(proxy)!)).toBe(hex(m.masterKey));
        const pk = privateKeysOf(proxy);
        expect(pk).not.toBeNull();
        expect(hex(pk!.x25519PrivateKey)).toBe(hex(m.privateKey.slice(0, 32)));
        expect(hex(pk!.mlKemPrivateKey)).toBe(hex(m.privateKey.slice(32)));
        expect(server.calls).toEqual(['initialize', 'notifications/initialized', 'get_vault_keys', 'get_default_signature']);
    });

    it('falsches tmv_: Start bricht ab – kein „decryption disabled", kein Rückfall auf SHA-256(tmv_)', async () => {
        const m = await humanMaterial();
        installServer(m.keys);
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tmmcp_x', vaultKey: 'tmv_' + b64url(rnd(32)) });

        await expect(proxy.bootstrap()).rejects.toThrow(/AIONDA_VAULT_KEY does not match/);
        expect(masterKeyOf(proxy)).toBeNull();
        expect(privateKeysOf(proxy)).toBeNull();
        const meldungen = stderr.mock.calls.map(c => String(c[0])).join('');
        expect(meldungen).not.toMatch(/decryption disabled/);
    });

    it('KI-Mitarbeiter, php-Layout: M = SHA-256(tmv_), Weg unverändert', async () => {
        const m = await aiMaterial();
        installServer(m.keys);
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tma_x', vaultKey: m.vaultKeyText });

        await proxy.bootstrap();

        expect(hex(masterKeyOf(proxy)!)).toBe(hex(m.masterKey));
        expect(hex(privateKeysOf(proxy)!.mlKemPrivateKey)).toBe(hex(m.privateKey.slice(32)));
    });

    it('privater Schlüssel passt nicht zum Master Key: Abbruch mit klarer Meldung', async () => {
        const m = await humanMaterial();
        const fremd = await humanMaterial();
        // Umschlag von m, privater Schlüssel von fremd (mit anderem M verschlüsselt)
        installServer({ ...m.keys, encrypted_private_key: fremd.keys.encrypted_private_key, private_key_iv: fremd.keys.private_key_iv });
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tmmcp_x', vaultKey: m.vaultKeyText });

        await expect(proxy.bootstrap()).rejects.toThrow(/Vault private key could not be decrypted \(layout=webcrypto\)/);
        expect(privateKeysOf(proxy)).toBeNull();
    });

    it('Umschlag ohne mcp_key_uuid: Abbruch statt Raten', async () => {
        const m = await humanMaterial();
        installServer({ ...m.keys, mcp_key_uuid: null });
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tmmcp_x', vaultKey: m.vaultKeyText });
        await expect(proxy.bootstrap()).rejects.toThrow(/without mcp_key_uuid/);
    });

    it('get_vault_keys ohne Schlüssel (Zugang abgelehnt): Abbruch', async () => {
        installServer({ error: 'Dein MCP-Zugang ist am 2026-01-01T00:00:00Z abgelaufen.' });
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tmmcp_x', vaultKey: 'tmv_' + b64url(rnd(32)) });
        await expect(proxy.bootstrap()).rejects.toThrow(/get_vault_keys failed: Dein MCP-Zugang ist am/);
    });

    it('webcrypto-Layout ohne IV: Abbruch', async () => {
        const m = await humanMaterial();
        installServer({ ...m.keys, private_key_iv: null });
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tmmcp_x', vaultKey: m.vaultKeyText });
        await expect(proxy.bootstrap()).rejects.toThrow(/private_key_iv missing/);
    });
});
