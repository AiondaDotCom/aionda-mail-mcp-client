/**
 * JSON-RPC 2.0 + MCP Protocol Types
 * @aiondadotcom/mail-mcp-client
 */

export interface JsonRpcRequest {
    jsonrpc: '2.0';
    id: number | string;
    method: string;
    params?: Record<string, unknown>;
}

export interface JsonRpcNotification {
    jsonrpc: '2.0';
    method: string;
    params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
    jsonrpc: '2.0';
    id: number | string | null;
    result?: unknown;
    error?: JsonRpcError;
}

export interface JsonRpcError {
    code: number;
    message: string;
    data?: unknown;
}

export interface McpInitializeResult {
    protocolVersion: string;
    capabilities: {
        tools?: Record<string, never>;
    };
    serverInfo: {
        name: string;
        version: string;
    };
    instructions?: string;
}

export interface McpToolDefinition {
    name: string;
    description: string;
    inputSchema: {
        type: 'object';
        properties: Record<string, McpPropertySchema>;
        required?: string[];
    };
}

export interface McpPropertySchema {
    type: string;
    description?: string;
    default?: unknown;
}

export interface McpToolResult {
    success: boolean;
    data?: unknown;
    error_code?: number;
    msg?: string;
}
