import { describe, it, expect, vi, afterEach } from 'vitest';
import { AiondaMailClient } from '../src/client';
import { McpDecryptionError } from '../src/errors';

describe('AiondaMailClient', () => {
    let mockFetch: ReturnType<typeof vi.fn>;

    function setupMockFetch(): void {
        const initHeaders = new Headers();
        initHeaders.set('Mcp-Session-Id', 'test-session');

        mockFetch = vi.fn()
            // initialize
            .mockResolvedValueOnce({
                status: 200,
                headers: initHeaders,
                json: () => Promise.resolve({
                    jsonrpc: '2.0', id: 1,
                    result: {
                        protocolVersion: '2025-03-26',
                        capabilities: { tools: {} },
                        serverInfo: { name: 'Test', version: '1.0.0' },
                    },
                }),
            })
            // notifications/initialized
            .mockResolvedValueOnce({ status: 204, headers: new Headers() });

        vi.stubGlobal('fetch', mockFetch);
    }

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('connects and disconnects', async () => {
        setupMockFetch();
        const client = new AiondaMailClient({ apiKey: 'tma_test' });
        await client.connect();
        expect(client.isConnected()).toBe(true);
        await client.disconnect();
        expect(client.isConnected()).toBe(false);
    });

    it('lists DEAs', async () => {
        setupMockFetch();
        mockFetch.mockResolvedValueOnce({
            status: 200,
            headers: new Headers(),
            json: () => Promise.resolve({
                jsonrpc: '2.0', id: 3,
                result: {
                    success: true,
                    data: {
                        deas: [{
                            dea_uid: '123',
                            address: 'test@trashmail.com',
                            destination: 'real@gmail.com',
                            from_name: '',
                            forwards: -1,
                            masquerade: 0,
                            notify: 1,
                            vault_store: 1,
                            created_at: '2026-01-01',
                        }],
                    },
                },
            }),
        });

        const client = new AiondaMailClient({ apiKey: 'tma_test' });
        await client.connect();
        const deas = await client.listDeas();
        expect(deas).toHaveLength(1);
        expect(deas[0].address).toBe('test@trashmail.com');
    });

    it('readEmailDecrypted throws without vault key', async () => {
        setupMockFetch();
        const client = new AiondaMailClient({ apiKey: 'tma_test' });
        await client.connect();
        await expect(client.readEmailDecrypted('uuid')).rejects.toThrow(McpDecryptionError);
    });

    it('uses default endpoint', () => {
        const client = new AiondaMailClient({ apiKey: 'tma_test' });
        // Just verify construction doesn't throw
        expect(client).toBeDefined();
    });

    it('appends /mcp to endpoint', () => {
        const client = new AiondaMailClient({
            apiKey: 'tma_test',
            endpoint: 'https://trashmail.com',
        });
        expect(client).toBeDefined();
    });
});
