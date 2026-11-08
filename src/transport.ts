/**
 * HTTP JSON-RPC 2.0 Transport
 *
 * Low-level transport for MCP server communication.
 * Sends JSON-RPC 2.0 requests over HTTP POST.
 */
import { McpError, McpAuthError, McpRateLimitError } from './errors';
import type { JsonRpcRequest, JsonRpcNotification, JsonRpcResponse } from './types/mcp-protocol';

export interface TransportOptions {
    /** MCP server endpoint URL (e.g. https://trashmail.com/mcp) */
    endpoint: string;
    /** Bearer token (tma_* API key) */
    apiKey: string;
    /** Request timeout in ms (default: 30000) */
    timeout?: number;
}

export class McpTransport {
    private endpoint: string;
    private apiKey: string;
    private timeout: number;
    private nextId = 1;
    private sessionId: string | null = null;

    constructor(options: TransportOptions) {
        this.endpoint = options.endpoint;
        this.apiKey = options.apiKey;
        this.timeout = options.timeout ?? 30000;
    }

    /**
     * Set the MCP session ID (from initialize response header)
     */
    setSessionId(sessionId: string): void {
        this.sessionId = sessionId;
    }

    /**
     * Get current session ID
     */
    getSessionId(): string | null {
        return this.sessionId;
    }

    /**
     * Send a JSON-RPC request and wait for response
     */
    async request(method: string, params?: Record<string, unknown>): Promise<JsonRpcResponse> {
        const id = this.nextId++;
        const body: JsonRpcRequest = {
            jsonrpc: '2.0',
            id,
            method,
            ...(params !== undefined ? { params } : {}),
        };

        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
        };

        if (this.sessionId) {
            headers['Mcp-Session-Id'] = this.sessionId;
        }

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const response = await fetch(this.endpoint, {
                method: 'POST',
                headers,
                body: JSON.stringify(body),
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            // Extract session ID from response header
            const newSessionId = response.headers.get('Mcp-Session-Id');
            if (newSessionId) {
                this.sessionId = newSessionId;
            }

            // Handle HTTP errors
            if (response.status === 401) {
                throw new McpAuthError('Invalid API key');
            }
            if (response.status === 429) {
                const retryAfter = response.headers.get('Retry-After');
                const retryMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : 60000;
                throw new McpRateLimitError('Rate limit exceeded', retryMs);
            }

            const json = await response.json() as JsonRpcResponse;

            if (json.error) {
                throw new McpError(json.error.message, json.error.code, json.error.data);
            }

            return json;
        } catch (error) {
            clearTimeout(timeoutId);

            if (error instanceof McpError) throw error;

            if (error instanceof DOMException && error.name === 'AbortError') {
                throw new McpError('Request timeout', -32000);
            }

            throw new McpError(
                `Transport error: ${error instanceof Error ? error.message : String(error)}`,
                -32603
            );
        }
    }

    /**
     * Send a JSON-RPC notification (no response expected)
     */
    async notify(method: string, params?: Record<string, unknown>): Promise<void> {
        const body: JsonRpcNotification = {
            jsonrpc: '2.0',
            method,
            ...(params !== undefined ? { params } : {}),
        };

        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
        };

        if (this.sessionId) {
            headers['Mcp-Session-Id'] = this.sessionId;
        }

        try {
            await fetch(this.endpoint, {
                method: 'POST',
                headers,
                body: JSON.stringify(body),
            });
        } catch {
            // Notifications are fire-and-forget
        }
    }
}
