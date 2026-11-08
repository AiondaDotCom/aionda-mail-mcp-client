/**
 * Real-time Event Client (SSE/Mercure)
 *
 * Subscribes to E2E encrypted Mercure events via Server-Sent Events.
 * Events are decrypted client-side using Hybrid KEM (X25519 + ML-KEM-1024).
 *
 * NOTE: This module uses the EventSource API. In Node.js >=18 with
 * --experimental-fetch, you may need a polyfill like 'eventsource'.
 * In Node.js 22+, EventSource is available natively.
 *
 * @example
 * ```typescript
 * import { AiondaMailClient } from '@aiondadotcom/mail-mcp-client';
 * import { AiondaEventClient } from '@aiondadotcom/mail-mcp-client/events';
 *
 * const mail = new AiondaMailClient({ apiKey: 'tma_...', vaultPrivateKeys: '...' });
 * await mail.connect();
 *
 * const events = new AiondaEventClient(mail);
 * events.on('email.received', (event) => {
 *     console.log('New email:', event.data.email_uuid);
 * });
 * await events.connect(['email.received', 'notification.new']);
 *
 * // Later:
 * events.disconnect();
 * ```
 */
import { webcrypto } from 'node:crypto';
import { hybridDecapsulate } from './crypto/hybrid-kem';
import { fromBase64 } from './crypto/encoding';
import { decompress } from './crypto/decompression';
import { McpDecryptionError } from './errors';
import type { AiondaMailClient } from './client';
import type { VaultPrivateKeys } from './crypto/email-decryptor';
import type {
    EventType,
    EncryptedEventPayload,
    DecryptedEvent,
    EventSubscription,
    MissedEventsOutput,
    EventHandler,
} from './types/events';

/** Options for the event client */
export interface AiondaEventClientOptions {
    /** Reconnect delay in ms (default: 3000) */
    reconnectDelay?: number;
    /** Max reconnect delay in ms (default: 60000) */
    maxReconnectDelay?: number;
    /** Max missed events to fetch on reconnect (default: 100) */
    missedEventsLimit?: number;
}

export class AiondaEventClient {
    private client: AiondaMailClient;
    private privateKeys: VaultPrivateKeys;
    private handlers = new Map<EventType, Set<EventHandler>>();
    private eventSource: EventSource | null = null;
    private subscription: EventSubscription | null = null;
    private lastEventId: string | null = null;
    private reconnectDelay: number;
    private maxReconnectDelay: number;
    private missedEventsLimit: number;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    private currentReconnectDelay: number;
    private isConnecting = false;
    private isDisconnected = false;

    constructor(
        client: AiondaMailClient,
        privateKeys: VaultPrivateKeys,
        options: AiondaEventClientOptions = {}
    ) {
        this.client = client;
        this.privateKeys = privateKeys;
        this.reconnectDelay = options.reconnectDelay ?? 3000;
        this.maxReconnectDelay = options.maxReconnectDelay ?? 60000;
        this.missedEventsLimit = options.missedEventsLimit ?? 100;
        this.currentReconnectDelay = this.reconnectDelay;
    }

    /**
     * Register an event handler for a specific event type.
     */
    on<T = unknown>(type: EventType, handler: EventHandler<T>): void {
        if (!this.handlers.has(type)) {
            this.handlers.set(type, new Set());
        }
        this.handlers.get(type)!.add(handler as EventHandler);
    }

    /**
     * Remove an event handler.
     */
    off<T = unknown>(type: EventType, handler: EventHandler<T>): void {
        this.handlers.get(type)?.delete(handler as EventHandler);
    }

    /**
     * Connect to the Mercure hub and start receiving events.
     *
     * @param topics - Event types to subscribe to
     */
    async connect(topics: EventType[]): Promise<void> {
        if (this.isConnecting) return;
        this.isConnecting = true;
        this.isDisconnected = false;

        try {
            // Subscribe via MCP tool to get Mercure URL + JWT
            this.subscription = await this.subscribe(topics);

            // Open EventSource connection
            this.openEventSource();

            // Fetch missed events if we have a lastEventId
            if (this.lastEventId) {
                await this.fetchMissedEvents();
            }
        } finally {
            this.isConnecting = false;
        }
    }

    /**
     * Disconnect from the event stream.
     */
    disconnect(): void {
        this.isDisconnected = true;
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }
        this.subscription = null;
    }

    /**
     * Whether the event client is currently connected.
     */
    get connected(): boolean {
        return this.eventSource?.readyState === EventSource.OPEN;
    }

    /**
     * Fetch events that were missed while disconnected.
     */
    async fetchMissedEvents(): Promise<DecryptedEvent[]> {
        const result = await this.client.callTool('get_missed_events', {
            last_event_id: this.lastEventId ?? '',
            limit: this.missedEventsLimit,
        });
        const data = result.data as MissedEventsOutput;

        const decrypted: DecryptedEvent[] = [];
        for (const encEvent of data.events) {
            try {
                const event = await this.decryptEvent(encEvent);
                decrypted.push(event);
                this.dispatch(event);
            } catch {
                // Skip events that can't be decrypted (e.g. different key epoch)
            }
        }
        return decrypted;
    }

    // ── Private ──

    private async subscribe(topics: EventType[]): Promise<EventSubscription> {
        const result = await this.client.callTool('event_subscribe', {
            topics,
        });
        return result.data as EventSubscription;
    }

    private openEventSource(): void {
        if (!this.subscription) return;

        const url = new URL(this.subscription.mercure_url);
        for (const topic of this.subscription.topics) {
            url.searchParams.append('topic', topic);
        }

        // EventSource with authorization via URL parameter (Mercure convention)
        url.searchParams.set('authorization', this.subscription.subscriber_jwt);

        if (this.lastEventId) {
            url.searchParams.set('Last-Event-ID', this.lastEventId);
        }

        this.eventSource = new EventSource(url.toString());

        this.eventSource.onmessage = async (event: MessageEvent) => {
            if (event.lastEventId) {
                this.lastEventId = event.lastEventId;
            }

            try {
                const payload: EncryptedEventPayload = JSON.parse(event.data);
                const decrypted = await this.decryptEvent(payload);
                this.currentReconnectDelay = this.reconnectDelay; // Reset on success
                this.dispatch(decrypted);
            } catch {
                // Skip malformed events
            }
        };

        this.eventSource.onerror = () => {
            if (this.isDisconnected) return;
            this.eventSource?.close();
            this.eventSource = null;
            this.scheduleReconnect();
        };

        this.eventSource.onopen = () => {
            this.currentReconnectDelay = this.reconnectDelay;
        };
    }

    private scheduleReconnect(): void {
        if (this.isDisconnected || this.reconnectTimer) return;

        this.reconnectTimer = setTimeout(async () => {
            this.reconnectTimer = null;
            if (this.isDisconnected) return;

            try {
                await this.connect(
                    this.subscription?.topics.map(t =>
                        t.replace(/\.\d+$/, '') as EventType
                    ) ?? []
                );
            } catch {
                // Exponential backoff
                this.currentReconnectDelay = Math.min(
                    this.currentReconnectDelay * 2,
                    this.maxReconnectDelay
                );
                this.scheduleReconnect();
            }
        }, this.currentReconnectDelay);
    }

    private async decryptEvent(payload: EncryptedEventPayload): Promise<DecryptedEvent> {
        // Hybrid KEM decapsulation to get shared secret
        const sharedSecret = await hybridDecapsulate(
            fromBase64(payload.x25519_ephemeral),
            fromBase64(payload.mlkem_ciphertext),
            this.privateKeys.x25519PrivateKey,
            this.privateKeys.mlKemPrivateKey
        );

        // Import shared secret as AES-GCM key
        const aesKey = await webcrypto.subtle.importKey(
            'raw',
            sharedSecret,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        // Decrypt: encrypted is base64(nonce(12) || tag(16) || ciphertext)
        const encryptedData = fromBase64(payload.encrypted);
        const nonce = encryptedData.slice(0, 12);
        const tag = encryptedData.slice(12, 28);
        const ciphertext = encryptedData.slice(28);

        // Reorder: PHP format (nonce||tag||ct) → WebCrypto (ct||tag)
        const reordered = new Uint8Array(ciphertext.length + tag.length);
        reordered.set(ciphertext, 0);
        reordered.set(tag, ciphertext.length);

        let decryptedBuf: ArrayBuffer;
        try {
            decryptedBuf = await webcrypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce },
                aesKey,
                reordered
            );
        } catch {
            throw new McpDecryptionError('Failed to decrypt event payload');
        }

        // Decompress if needed (gzip/zlib detection)
        let plainBytes: Uint8Array = new Uint8Array(decryptedBuf);
        try {
            const decompressed = await decompress(plainBytes);
            plainBytes = new Uint8Array(decompressed);
        } catch {
            // Not compressed, use as-is
        }

        const json = new TextDecoder().decode(plainBytes);
        const data = JSON.parse(json);

        return {
            type: data.type as EventType,
            data: data.data ?? data,
            timestamp: payload.timestamp,
            eventId: data.event_id,
        };
    }

    private dispatch(event: DecryptedEvent): void {
        const handlers = this.handlers.get(event.type);
        if (!handlers) return;
        for (const handler of handlers) {
            try {
                handler(event);
            } catch {
                // Don't let handler errors break the event loop
            }
        }
    }
}
