/**
 * Bootstrap-Ränder und die Standardsignatur.
 *
 * Die Signatur liegt beim Server unter dem Master Key verschlüsselt
 * (WebCrypto-Format, IV getrennt). Der Proxy lädt sie beim Start und hängt
 * sie je nach Schalter an neue Mails bzw. an Antworten an. Außerdem werden
 * die OCR-Modelle im Hintergrund vorgeladen.
 */
import { webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const tess = vi.hoisted(() => ({ createWorker: vi.fn(), terminate: vi.fn() }));
vi.mock('tesseract.js', () => ({ createWorker: tess.createWorker }));

import { McpDecryptingProxy } from '../src/proxy';
import { toBase64, toHex } from '../src/crypto/encoding';
import { aesGcmRaw, fakeServer, rnd, toolCall, utf8, type ServerCall, type ToolHandler } from './helpers/vault';

const settle = (): Promise<void> => new Promise(r => setTimeout(r, 10));

let stderr: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
    stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    tess.createWorker.mockReset();
    tess.terminate.mockReset();
    tess.createWorker.mockResolvedValue({ terminate: tess.terminate });
});
// Das Vorladen der OCR-Modelle läuft im Hintergrund; erst abwarten, dann stderr freigeben.
afterEach(async () => { await settle(); vi.unstubAllGlobals(); stderr.mockRestore(); });

const log = (): string => stderr.mock.calls.map(c => String(c[0])).join('');

/** KI-Mitarbeiter-Material: M = SHA-256(tmv_), privater Schlüssel im php-Layout. */
async function aiKeys(opts: { privateKeyLength?: number; publicKeys?: boolean } = {}) {
    const vaultKey = 'tmv_' + toHex(rnd(16));
    const masterKey = new Uint8Array(await webcrypto.subtle.digest('SHA-256', utf8(vaultKey)));
    const iv = rnd(12);
    const ctTag = await aesGcmRaw(masterKey, iv, rnd(opts.privateKeyLength ?? 3200));
    const php = new Uint8Array([...iv, ...ctTag.slice(-16), ...ctTag.slice(0, -16)]);
    const keys: Record<string, unknown> = { encrypted_private_key: toHex(php), private_key_layout: 'php' };
    if (opts.publicKeys !== false) {
        keys.x25519_public_key = toHex(rnd(32));
        keys.mlkem_public_key = toHex(rnd(1568));
    }
    return { vaultKey, masterKey, keys };
}

async function signature(masterKey: Uint8Array, html: string, flags: { neu: boolean; antwort: boolean }) {
    const iv = rnd(12);
    return {
        success: true,
        data: {
            has_signature: true, auto_insert_new: flags.neu, auto_insert_reply: flags.antwort,
            encrypted_content_html: toBase64(await aesGcmRaw(masterKey, iv, utf8(html))), iv: toBase64(iv),
        },
    };
}

async function boot(vaultKey: string, handler: ToolHandler): Promise<{ proxy: McpDecryptingProxy; calls: ServerCall[] }> {
    const calls = fakeServer(handler);
    const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tma_x', vaultKey });
    await proxy.bootstrap();
    return { proxy, calls };
}

describe('Standardsignatur', () => {
    it('neue Mails, Weiterleitungen und Entwürfe bekommen sie, Antworten nicht (Schalter)', async () => {
        const m = await aiKeys();
        const sig = await signature(m.masterKey, '<p>Gruß, Max</p>', { neu: true, antwort: false });
        const { proxy, calls } = await boot(m.vaultKey, (name) => (name === 'get_vault_keys' ? { data: m.keys } : name === 'get_default_signature' ? sig : { ok: true }));

        for (const tool of ['send_email', 'forward_email', 'save_draft', 'reply_email']) {
            await proxy.handleRequest(toolCall(tool, { body: 'Hallo' }));
        }

        const bodies = Object.fromEntries(calls.filter(c => c.args.body).map(c => [c.name, c.args.body]));
        expect(bodies).toEqual({
            send_email: 'Hallo<br><br><p>Gruß, Max</p>',
            forward_email: 'Hallo<br><br><p>Gruß, Max</p>',
            save_draft: 'Hallo<br><br><p>Gruß, Max</p>',
            reply_email: 'Hallo',
        });
        expect(log()).toMatch(/Signature loaded \(16 chars, new=true, reply=false\)/);
    });

    it('nur für Antworten eingeschaltet: Antwort bekommt sie, neue Mail nicht', async () => {
        const m = await aiKeys();
        const sig = await signature(m.masterKey, '-- Max', { neu: false, antwort: true });
        const { proxy, calls } = await boot(m.vaultKey, (name) => (name === 'get_vault_keys' ? { data: m.keys } : name === 'get_default_signature' ? sig : {}));
        await proxy.handleRequest(toolCall('reply_email', { body: 'Danke' }));
        await proxy.handleRequest(toolCall('send_email', { body: 'Neu' }));
        expect(calls.find(c => c.name === 'reply_email')!.args.body).toBe('Danke<br><br>-- Max');
        expect(calls.find(c => c.name === 'send_email')!.args.body).toBe('Neu');
    });

    it('nicht entschlüsselbare Signatur: Start gelingt, angehängt wird nichts', async () => {
        const m = await aiKeys();
        const sig = await signature(rnd(32), 'fremd', { neu: true, antwort: true });
        const { proxy, calls } = await boot(m.vaultKey, (name) => (name === 'get_vault_keys' ? { data: m.keys } : name === 'get_default_signature' ? sig : {}));
        await proxy.handleRequest(toolCall('send_email', { body: 'Hallo' }));
        expect(calls.find(c => c.name === 'send_email')!.args.body).toBe('Hallo');
        expect(log()).toMatch(/Failed to load signature/);
    });

    it('keine Signatur hinterlegt: Meldung, nichts angehängt', async () => {
        const m = await aiKeys();
        const { proxy, calls } = await boot(m.vaultKey, (name) => (name === 'get_vault_keys' ? { data: m.keys } : { has_signature: false }));
        await proxy.handleRequest(toolCall('send_email', { body: 'Hallo' }));
        expect(calls.find(c => c.name === 'send_email')!.args.body).toBe('Hallo');
        expect(log()).toMatch(/No default signature configured/);
    });
});

describe('Bootstrap-Ränder', () => {
    it('lädt die OCR-Modelle im Hintergrund vor und gibt den Worker wieder frei', async () => {
        const m = await aiKeys();
        await boot(m.vaultKey, (name) => (name === 'get_vault_keys' ? { data: m.keys } : {}));
        await settle();
        expect(tess.createWorker).toHaveBeenCalledWith('deu+eng');
        expect(tess.terminate).toHaveBeenCalledTimes(1);
        expect(log()).toMatch(/OCR models pre-loaded \(deu\+eng\)/);
    });

    it('scheitert das Vorladen, läuft der Proxy trotzdem (nur Meldung)', async () => {
        tess.createWorker.mockRejectedValue(new Error('kein Netz'));
        const m = await aiKeys();
        await boot(m.vaultKey, (name) => (name === 'get_vault_keys' ? { data: m.keys } : {}));
        await settle();
        expect(log()).toMatch(/OCR model pre-load failed: kein Netz/);
    });

    it('öffentliche Schlüssel werden für die Neukapselung gemerkt, fehlen sie, bleibt das Feld leer', async () => {
        const mit = await aiKeys();
        const a = await boot(mit.vaultKey, (name) => (name === 'get_vault_keys' ? { data: mit.keys } : {}));
        const pub = (a.proxy as unknown as { publicKeys: { x25519: Uint8Array } | null }).publicKeys;
        expect(toHex(pub!.x25519)).toBe(mit.keys.x25519_public_key);

        const ohne = await aiKeys({ publicKeys: false });
        const b = await boot(ohne.vaultKey, (name) => (name === 'get_vault_keys' ? ohne.keys : {}));
        expect((b.proxy as unknown as { publicKeys: unknown }).publicKeys).toBeNull();
    });

    it('initialize scheitert: Abbruch mit Servermeldung', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({
            headers: { get: () => null }, json: async () => ({ jsonrpc: '2.0', id: 0, error: { code: 61, message: 'Invalid API key' } }),
        })));
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tma_x', vaultKey: 'tmv_x' });
        await expect(proxy.bootstrap()).rejects.toThrow('MCP initialize failed: Invalid API key');
    });

    it('get_vault_keys ohne privaten Schlüssel: die Meldung des Servers geht mit', async () => {
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tma_x', vaultKey: 'tmv_x' });
        fakeServer(() => ({ success: false, msg: 'Vault ist nicht eingerichtet' }));
        await expect(proxy.bootstrap()).rejects.toThrow('get_vault_keys returned no encrypted_private_key: Vault ist nicht eingerichtet');
        fakeServer(() => ({ __raw: { content: [] } }));
        await expect(proxy.bootstrap()).rejects.toThrow('get_vault_keys returned no encrypted_private_key: vault not configured or access denied');
    });

    it('zu kurzer privater Schlüssel: Abbruch mit Längenangabe', async () => {
        const m = await aiKeys({ privateKeyLength: 100 });
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tma_x', vaultKey: m.vaultKey });
        fakeServer((name) => (name === 'get_vault_keys' ? { data: m.keys } : {}));
        await expect(proxy.bootstrap()).rejects.toThrow('Vault private key has 100 bytes, expected 3200');
    });
});
