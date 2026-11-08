import { describe, it, expect, vi, beforeEach } from 'vitest';
import { McpSession } from '../src/session';
import { McpTransport } from '../src/transport';
import { McpSessionExpiredError } from '../src/errors';

describe('McpSession', () => {
    let transport: McpTransport;

    beforeEach(() => {
        transport = new McpTransport({
            endpoint: 'https://example.com/mcp',
            apiKey: 'tma_test',
        });
    });

    it('initializes session', async () => {
        const headers = new Headers();
        headers.set('Mcp-Session-Id', 'session-abc');
        const mockFetch = vi.fn()
            .mockResolvedValueOnce({
                status: 200,
                headers,
                json: () => Promise.resolve({
                    jsonrpc: '2.0',
                    id: 1,
                    result: {
                        protocolVersion: '2025-03-26',
                        capabilities: { tools: {} },
                        serverInfo: { name: 'Aionda Mail', version: '1.0.0' },
                    },
                }),
            })
            .mockResolvedValueOnce({ status: 204, headers: new Headers() });
        vi.stubGlobal('fetch', mockFetch);

        const session = new McpSession(transport);
        const result = await session.initialize();

        expect(result.protocolVersion).toBe('2025-03-26');
        expect(result.serverInfo.name).toBe('Aionda Mail');
        expect(session.isInitialized()).toBe(true);

        vi.unstubAllGlobals();
    });

    it('throws if calling tools before init', async () => {
        const session = new McpSession(transport);
        await expect(session.listTools()).rejects.toThrow(McpSessionExpiredError);
    });

    it('destroy resets session', async () => {
        const headers = new Headers();
        headers.set('Mcp-Session-Id', 'session-def');
        const mockFetch = vi.fn()
            .mockResolvedValueOnce({
                status: 200,
                headers,
                json: () => Promise.resolve({
                    jsonrpc: '2.0', id: 1,
                    result: {
                        protocolVersion: '2025-03-26',
                        capabilities: { tools: {} },
                        serverInfo: { name: 'Test', version: '1.0.0' },
                    },
                }),
            })
            .mockResolvedValue({ status: 204, headers: new Headers() });
        vi.stubGlobal('fetch', mockFetch);

        const session = new McpSession(transport);
        await session.initialize();
        expect(session.isInitialized()).toBe(true);

        session.destroy();
        expect(session.isInitialized()).toBe(false);

        vi.unstubAllGlobals();
    });
});
