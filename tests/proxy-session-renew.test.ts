/**
 * Sitzung verloren → einmal neu anmelden und wiederholen (#c2fb3967)
 *
 * Gemessen 08.11.2026: Der Server hält höchstens 10 Sitzungen je MCP-Schlüssel
 * und schließt bei der elften die älteste. Der Proxy reichte danach jeden
 * Aufruf als „Invalid or expired session“ an den Agenten durch.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('tesseract.js', () => ({ default: {}, createWorker: vi.fn() }));

import { McpDecryptingProxy } from '../src/proxy';

interface Req { id?: number; method: string; params?: { name?: string } }

function installServer(opts: { dropFirstToolCall: boolean; initFails?: boolean }): { calls: string[]; sessions: (string | null)[] } {
    const calls: string[] = [];
    const sessions: (string | null)[] = [];
    let generation = 0;
    let dropped = false;
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string; headers: Record<string, string> }) => {
        const req = JSON.parse(init.body) as Req;
        calls.push(req.params?.name ?? req.method);
        sessions.push(init.headers['Mcp-Session-Id'] ?? null);
        let body: unknown = { jsonrpc: '2.0', id: req.id, result: { content: [{ type: 'text', text: '{"ok":true}' }] } };
        if (req.method === 'initialize') {
            generation++;
            if (opts.initFails && generation > 1) {
                body = { jsonrpc: '2.0', id: req.id, error: { code: -32001, message: 'Unauthorized' } };
            }
        } else if (req.method === 'tools/call' && opts.dropFirstToolCall && !dropped) {
            dropped = true;
            body = { jsonrpc: '2.0', id: req.id, error: { code: -32000, message: 'Invalid or expired session' } };
        }
        const sid = `session-${generation}`;
        return { headers: { get: (n: string) => (n === 'Mcp-Session-Id' ? sid : null) }, json: async () => body };
    }));
    return { calls, sessions };
}

function forward(proxy: McpDecryptingProxy, req: Req): Promise<{ result?: unknown; error?: { code: number; message: string } }> {
    return (proxy as unknown as { forwardToServer(r: Req): Promise<{ result?: unknown; error?: { code: number; message: string } }> })
        .forwardToServer(req);
}

describe('McpDecryptingProxy – verlorene Sitzung', () => {
    let stderr: ReturnType<typeof vi.spyOn>;
    beforeEach(() => { stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true); });
    afterEach(() => { vi.unstubAllGlobals(); stderr.mockRestore(); });

    it('meldet sich einmal neu an und wiederholt den Aufruf mit der neuen Sitzung', async () => {
        const server = installServer({ dropFirstToolCall: true });
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tmmcp_x', vaultKey: 'tmv_x' });
        await forward(proxy, { jsonrpc: '2.0', id: 0, method: 'initialize' } as Req);

        const resp = await forward(proxy, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'list_emails' } } as Req);

        expect(resp.error).toBeUndefined();
        expect(server.calls).toEqual(['initialize', 'list_emails', 'initialize', 'notifications/initialized', 'list_emails']);
        expect(server.sessions.at(-1)).toBe('session-2');
    });

    it('schweigt, wenn die Sitzung gültig ist (kein zweites initialize)', async () => {
        const server = installServer({ dropFirstToolCall: false });
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tmmcp_x', vaultKey: 'tmv_x' });
        await forward(proxy, { jsonrpc: '2.0', id: 0, method: 'initialize' } as Req);

        await forward(proxy, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'list_emails' } } as Req);

        expect(server.calls).toEqual(['initialize', 'list_emails']);
    });

    it('scheitert die Neuanmeldung, kommt der ursprüngliche Fehler zurück - keine Schleife', async () => {
        const server = installServer({ dropFirstToolCall: true, initFails: true });
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tmmcp_x', vaultKey: 'tmv_x' });
        await forward(proxy, { jsonrpc: '2.0', id: 0, method: 'initialize' } as Req);

        const resp = await forward(proxy, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'list_emails' } } as Req);

        expect(resp.error?.code).toBe(-32000);
        expect(server.calls).toEqual(['initialize', 'list_emails', 'initialize']);
    });
});
