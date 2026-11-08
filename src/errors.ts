/**
 * MCP Error Hierarchy
 */

export class McpError extends Error {
    public readonly code: number;
    public readonly data?: unknown;

    constructor(message: string, code: number, data?: unknown) {
        super(message);
        this.name = 'McpError';
        this.code = code;
        this.data = data;
    }
}

export class McpAuthError extends McpError {
    constructor(message = 'Authentication failed') {
        super(message, 61);
        this.name = 'McpAuthError';
    }
}

export class McpRateLimitError extends McpError {
    public readonly retryAfterMs: number;

    constructor(message = 'Rate limit exceeded', retryAfterMs = 60000) {
        super(message, 429);
        this.name = 'McpRateLimitError';
        this.retryAfterMs = retryAfterMs;
    }
}

export class McpSessionExpiredError extends McpError {
    constructor(message = 'Session expired') {
        super(message, -32000);
        this.name = 'McpSessionExpiredError';
    }
}

export class McpToolError extends McpError {
    public readonly toolName: string;

    constructor(toolName: string, message: string, code: number) {
        super(message, code);
        this.name = 'McpToolError';
        this.toolName = toolName;
    }
}

export class McpDecryptionError extends McpError {
    constructor(message = 'Decryption failed') {
        super(message, 77);
        this.name = 'McpDecryptionError';
    }
}
