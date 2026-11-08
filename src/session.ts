/**
 * MCP Session Lifecycle Manager
 *
 * Handles: initialize → notifications/initialized → ping → destroy
 */
import { McpTransport } from './transport';
import { McpSessionExpiredError } from './errors';
import { MCP_PROTOCOL_VERSION, SESSION_TTL_MS } from './constants';
import type { McpInitializeResult, McpToolDefinition } from './types/mcp-protocol';

export class McpSession {
    private transport: McpTransport;
    private initialized = false;
    private initResult: McpInitializeResult | null = null;
    private createdAt: number = 0;

    constructor(transport: McpTransport) {
        this.transport = transport;
    }

    /**
     * Initialize the MCP session
     *
     * Sends initialize request, stores session ID from response header,
     * then sends notifications/initialized.
     */
    async initialize(): Promise<McpInitializeResult> {
        const response = await this.transport.request('initialize', {
            protocolVersion: MCP_PROTOCOL_VERSION,
            capabilities: {},
            clientInfo: {
                name: '@aiondadotcom/mail-mcp-client',
                version: '0.1.0',
            },
        });

        this.initResult = response.result as McpInitializeResult;
        this.initialized = true;
        this.createdAt = Date.now();

        // Send initialized notification
        await this.transport.notify('notifications/initialized');

        return this.initResult;
    }

    /**
     * List available tools
     */
    async listTools(): Promise<McpToolDefinition[]> {
        this.ensureInitialized();
        const response = await this.transport.request('tools/list');
        const result = response.result as { tools: McpToolDefinition[] };
        return result.tools;
    }

    /**
     * Call a tool
     */
    async callTool(name: string, args: Record<string, unknown> = {}): Promise<unknown> {
        this.ensureInitialized();
        const response = await this.transport.request('tools/call', { name, arguments: args });
        return response.result;
    }

    /**
     * Send ping to keep session alive
     */
    async ping(): Promise<void> {
        this.ensureInitialized();
        await this.transport.request('ping');
    }

    /**
     * Check if session is expired
     */
    isExpired(): boolean {
        if (!this.initialized) return true;
        return Date.now() - this.createdAt > SESSION_TTL_MS;
    }

    /**
     * Check if session is initialized
     */
    isInitialized(): boolean {
        return this.initialized;
    }

    /**
     * Get the initialization result
     */
    getInitResult(): McpInitializeResult | null {
        return this.initResult;
    }

    /**
     * Destroy the session (client-side cleanup)
     */
    destroy(): void {
        this.initialized = false;
        this.initResult = null;
        this.createdAt = 0;
    }

    private ensureInitialized(): void {
        if (!this.initialized) {
            throw new McpSessionExpiredError('Session not initialized. Call initialize() first.');
        }
        if (this.isExpired()) {
            this.initialized = false;
            throw new McpSessionExpiredError('Session expired. Call initialize() again.');
        }
    }
}
