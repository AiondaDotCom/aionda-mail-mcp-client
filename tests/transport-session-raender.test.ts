/**
 * Ränder von Transport und Sitzung: Zeitüberschreitung, Netzfehler,
 * Ratenbegrenzung ohne Retry-After, JSON-RPC-Fehler, Benachrichtigungen,
 * Ablauf der Sitzung nach 24 h – und die Fehlerklassen selbst.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import { McpTransport } from '../src/transport';
import { McpSession } from '../src/session';
import {
    McpDecryptionError, McpError, McpRateLimitError, McpSessionExpiredError, McpToolError,
} from '../src/errors';
import { SESSION_TTL_MS } from '../src/constants';
import { ErrorCodes } from '../src/types/errors';

afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

const ok = (body: unknown, headers: Record<string, string> = {}) =>
    ({ status: 200, headers: new Headers(headers), json: async () => body });

describe('McpTransport', () => {
    it('Zeitüberschreitung bricht die Anfrage ab und meldet -32000', async () => {
        vi.stubGlobal('fetch', vi.fn((_u: string, init: { signal: AbortSignal }) => new Promise((_res, rej) => {
            init.signal.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')));
        })));
        const t = new McpTransport({ endpoint: 'https://x.test/mcp', apiKey: 'k', timeout: 5 });
        const err = await t.request('ping').catch(e => e);
        expect(err).toBeInstanceOf(McpError);
        expect(err).toMatchObject({ message: 'Request timeout', code: -32000 });
    });

    it('Netzfehler wird zu „Transport error“ mit -32603, auch ohne Error-Objekt', async () => {
        vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new TypeError('fetch failed')).mockRejectedValueOnce('aus'));
        const t = new McpTransport({ endpoint: 'https://x.test/mcp', apiKey: 'k' });
        await expect(t.request('ping')).rejects.toMatchObject({ message: 'Transport error: fetch failed', code: -32603 });
        await expect(t.request('ping')).rejects.toMatchObject({ message: 'Transport error: aus', code: -32603 });
    });

    it('429 ohne Retry-After: 60 s Wartezeit', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 429, headers: new Headers(), json: async () => ({}) }));
        const err = await new McpTransport({ endpoint: 'https://x.test/mcp', apiKey: 'k' }).request('ping').catch(e => e);
        expect(err).toBeInstanceOf(McpRateLimitError);
        expect(err.retryAfterMs).toBe(60000);
    });

    it('JSON-RPC-Fehler mit Code und Daten', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok({ jsonrpc: '2.0', id: 1, error: { code: 43, message: 'Email not found', data: { uuid: 'm1' } } })));
        await expect(new McpTransport({ endpoint: 'https://x.test/mcp', apiKey: 'k' }).request('tools/call', {}))
            .rejects.toMatchObject({ message: 'Email not found', code: 43, data: { uuid: 'm1' } });
    });

    it('Sitzungskennung: gesetzt, mitgesendet, auch bei Benachrichtigungen; Netzfehler bei notify wird geschluckt', async () => {
        const fetch = vi.fn().mockResolvedValue(ok({ jsonrpc: '2.0', id: 1, result: {} }));
        vi.stubGlobal('fetch', fetch);
        const t = new McpTransport({ endpoint: 'https://x.test/mcp', apiKey: 'k' });
        expect(t.getSessionId()).toBeNull();
        t.setSessionId('s-9');
        expect(t.getSessionId()).toBe('s-9');

        await t.notify('notifications/initialized', { a: 1 });
        await t.notify('notifications/x');
        const [, init] = fetch.mock.calls[0];
        expect(init.headers['Mcp-Session-Id']).toBe('s-9');
        expect(JSON.parse(init.body)).toEqual({ jsonrpc: '2.0', method: 'notifications/initialized', params: { a: 1 } });
        expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ jsonrpc: '2.0', method: 'notifications/x' });

        fetch.mockRejectedValueOnce(new Error('weg'));
        await expect(t.notify('notifications/y')).resolves.toBeUndefined();
    });
});

describe('McpSession', () => {
    it('läuft nach 24 h ab: Aufruf wirft und die Sitzung gilt als nicht mehr initialisiert', async () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok({ jsonrpc: '2.0', id: 1, result: { protocolVersion: '2025-03-26' } })));
        const s = new McpSession(new McpTransport({ endpoint: 'https://x.test/mcp', apiKey: 'k' }));

        expect(s.isExpired()).toBe(true);
        expect(s.getInitResult()).toBeNull();
        await s.initialize();
        expect(s.getInitResult()).toEqual({ protocolVersion: '2025-03-26' });
        expect(s.isExpired()).toBe(false);

        vi.setSystemTime(new Date(Date.now() + SESSION_TTL_MS + 1));
        expect(s.isExpired()).toBe(true);
        await expect(s.callTool('list_emails')).rejects.toThrow('Session expired. Call initialize() again.');
        expect(s.isInitialized()).toBe(false);
        await expect(s.ping()).rejects.toBeInstanceOf(McpSessionExpiredError);
    });
});

describe('Fehlerklassen', () => {
    it('tragen Name, Code und Zusatzfelder', () => {
        const tool = new McpToolError('send_email', 'Versand fehlgeschlagen', 39);
        expect(tool).toBeInstanceOf(McpError);
        expect(tool).toMatchObject({ name: 'McpToolError', toolName: 'send_email', code: 39, message: 'Versand fehlgeschlagen' });
        expect(new McpDecryptionError()).toMatchObject({ name: 'McpDecryptionError', code: 77, message: 'Decryption failed' });
        expect(new McpRateLimitError()).toMatchObject({ code: 429, retryAfterMs: 60000 });
        expect(new McpSessionExpiredError()).toMatchObject({ code: -32000, message: 'Session expired' });
        // Die Codes der Klassen entsprechen der Servertabelle.
        expect(ErrorCodes.DECRYPTION_FAILED).toBe(new McpDecryptionError().code);
        expect(ErrorCodes.AUTHENTICATION_ERROR).toBe(61);
    });
});
