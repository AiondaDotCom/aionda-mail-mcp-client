import { describe, it, expect, vi } from 'vitest';
import { McpTransport } from '../src/transport';
import { McpAuthError, McpRateLimitError } from '../src/errors';

describe('McpTransport', () => {
    it('sends JSON-RPC 2.0 request with auth header', async () => {
        const mockFetch = vi.fn().mockResolvedValue({
            status: 200,
            headers: new Headers(),
            json: () => Promise.resolve({
                jsonrpc: '2.0',
                id: 1,
                result: { test: true },
            }),
        });
        vi.stubGlobal('fetch', mockFetch);

        const transport = new McpTransport({
            endpoint: 'https://example.com/mcp',
            apiKey: 'tma_test_key',
        });

        const response = await transport.request('test_method', { foo: 'bar' });

        expect(mockFetch).toHaveBeenCalledOnce();
        const [url, options] = mockFetch.mock.calls[0];
        expect(url).toBe('https://example.com/mcp');
        expect(options.method).toBe('POST');
        expect(options.headers['Authorization']).toBe('Bearer tma_test_key');

        const body = JSON.parse(options.body);
        expect(body.jsonrpc).toBe('2.0');
        expect(body.method).toBe('test_method');
        expect(body.params).toEqual({ foo: 'bar' });

        expect(response.result).toEqual({ test: true });

        vi.unstubAllGlobals();
    });

    it('stores session ID from response header', async () => {
        const headers = new Headers();
        headers.set('Mcp-Session-Id', 'session-123');
        const mockFetch = vi.fn().mockResolvedValue({
            status: 200,
            headers,
            json: () => Promise.resolve({ jsonrpc: '2.0', id: 1, result: {} }),
        });
        vi.stubGlobal('fetch', mockFetch);

        const transport = new McpTransport({
            endpoint: 'https://example.com/mcp',
            apiKey: 'tma_test',
        });

        await transport.request('initialize');
        expect(transport.getSessionId()).toBe('session-123');

        vi.unstubAllGlobals();
    });

    it('throws McpAuthError on 401', async () => {
        const mockFetch = vi.fn().mockResolvedValue({
            status: 401,
            headers: new Headers(),
            json: () => Promise.resolve({}),
        });
        vi.stubGlobal('fetch', mockFetch);

        const transport = new McpTransport({
            endpoint: 'https://example.com/mcp',
            apiKey: 'tma_bad',
        });

        await expect(transport.request('test')).rejects.toThrow(McpAuthError);

        vi.unstubAllGlobals();
    });

    it('throws McpRateLimitError on 429', async () => {
        const headers = new Headers();
        headers.set('Retry-After', '30');
        const mockFetch = vi.fn().mockResolvedValue({
            status: 429,
            headers,
            json: () => Promise.resolve({}),
        });
        vi.stubGlobal('fetch', mockFetch);

        const transport = new McpTransport({
            endpoint: 'https://example.com/mcp',
            apiKey: 'tma_test',
        });

        try {
            await transport.request('test');
        } catch (error) {
            expect(error).toBeInstanceOf(McpRateLimitError);
            expect((error as McpRateLimitError).retryAfterMs).toBe(30000);
        }

        vi.unstubAllGlobals();
    });

    it('auto-increments request IDs', async () => {
        const mockFetch = vi.fn().mockResolvedValue({
            status: 200,
            headers: new Headers(),
            json: () => Promise.resolve({ jsonrpc: '2.0', id: 1, result: {} }),
        });
        vi.stubGlobal('fetch', mockFetch);

        const transport = new McpTransport({
            endpoint: 'https://example.com/mcp',
            apiKey: 'tma_test',
        });

        await transport.request('a');
        await transport.request('b');

        const body1 = JSON.parse(mockFetch.mock.calls[0][1].body);
        const body2 = JSON.parse(mockFetch.mock.calls[1][1].body);
        expect(body2.id).toBe(body1.id + 1);

        vi.unstubAllGlobals();
    });
});
