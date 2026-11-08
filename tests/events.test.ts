import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AiondaEventClient } from '../src/events';
import type { AiondaMailClient } from '../src/client';
import type { VaultPrivateKeys } from '../src/crypto/email-decryptor';

// Stub EventSource for Node.js (browser-only API)
class MockEventSource {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSED = 2;
    readonly CONNECTING = 0;
    readonly OPEN = 1;
    readonly CLOSED = 2;
    readyState = MockEventSource.CLOSED;
    onmessage: ((event: MessageEvent) => void) | null = null;
    onerror: (() => void) | null = null;
    onopen: (() => void) | null = null;
    url: string;
    withCredentials = false;
    constructor(url: string) { this.url = url; }
    close(): void { this.readyState = MockEventSource.CLOSED; }
    addEventListener(): void { /* stub */ }
    removeEventListener(): void { /* stub */ }
    dispatchEvent(): boolean { return false; }
}

// Mock AiondaMailClient
function createMockClient(): AiondaMailClient {
    return {
        callTool: vi.fn().mockResolvedValue({
            data: {
                subscription_id: 'sub-123',
                mercure_url: 'https://example.com/.well-known/mercure',
                subscriber_jwt: 'eyJhbGciOiJIUzI1NiJ9.test.token',
                topics: ['email.received.12345'],
            },
        }),
    } as unknown as AiondaMailClient;
}

function createMockKeys(): VaultPrivateKeys {
    return {
        x25519PrivateKey: new Uint8Array(32),
        mlKemPrivateKey: new Uint8Array(3168),
    };
}

describe('AiondaEventClient', () => {
    let client: AiondaEventClient;
    let mockMailClient: AiondaMailClient;

    beforeEach(() => {
        vi.stubGlobal('EventSource', MockEventSource);
        mockMailClient = createMockClient();
        client = new AiondaEventClient(mockMailClient, createMockKeys());
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('should register and unregister event handlers', () => {
        const handler = vi.fn();
        client.on('email.received', handler);

        // Verify handler is registered (internal state)
        expect(() => client.off('email.received', handler)).not.toThrow();
    });

    it('should not be connected before connect() is called', () => {
        expect(client.connected).toBe(false);
    });

    it('should disconnect cleanly', () => {
        client.disconnect();
        expect(client.connected).toBe(false);
    });

    it('should accept multiple handlers for same event type', () => {
        const handler1 = vi.fn();
        const handler2 = vi.fn();

        client.on('email.received', handler1);
        client.on('email.received', handler2);

        // Remove one, verify no error
        client.off('email.received', handler1);
        expect(() => client.off('email.received', handler2)).not.toThrow();
    });

    it('should handle removing non-existent handler gracefully', () => {
        const handler = vi.fn();
        // Should not throw even if handler was never registered
        expect(() => client.off('email.received', handler)).not.toThrow();
    });

    it('should construct with custom options', () => {
        const customClient = new AiondaEventClient(
            mockMailClient,
            createMockKeys(),
            {
                reconnectDelay: 5000,
                maxReconnectDelay: 120000,
                missedEventsLimit: 50,
            }
        );
        expect(customClient.connected).toBe(false);
    });
});
