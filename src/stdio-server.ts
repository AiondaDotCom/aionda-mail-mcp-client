/**
 * stdio JSON-RPC Server
 *
 * Reads JSON-RPC requests from stdin (line-delimited),
 * forwards through McpDecryptingProxy, writes responses to stdout.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */
import { McpDecryptingProxy } from './proxy';
import type { ProxyConfig } from './proxy';

interface JsonRpcRequest {
    jsonrpc: '2.0';
    id?: number | string;
    method: string;
    params?: Record<string, unknown>;
}

/**
 * Start the stdio MCP proxy server.
 *
 * Reads env vars:
 *   AIONDA_API_KEY   - tma_* API key (required)
 *   AIONDA_VAULT_KEY - tmv_* vault key (required for decryption)
 *   AIONDA_ENDPOINT  - Server URL (default: https://mail.aionda.com)
 */
export async function startStdioServer(): Promise<void> {
    const apiKey = process.env['AIONDA_API_KEY'];
    const vaultKey = process.env['AIONDA_VAULT_KEY'];
    const endpoint = process.env['AIONDA_ENDPOINT'] || 'https://mail.aionda.com';

    if (!apiKey) {
        process.stderr.write('[aionda-mail-mcp] Error: AIONDA_API_KEY environment variable is required\n');
        process.exit(1);
    }

    if (!vaultKey) {
        process.stderr.write('[aionda-mail-mcp] Error: AIONDA_VAULT_KEY environment variable is required\n');
        process.exit(1);
    }

    const config: ProxyConfig = { endpoint, apiKey, vaultKey };
    const proxy = new McpDecryptingProxy(config);

    process.stderr.write(`[aionda-mail-mcp] Connecting to ${endpoint}/mcp ...\n`);

    try {
        await proxy.bootstrap();
    } catch (err) {
        process.stderr.write(`[aionda-mail-mcp] Bootstrap failed: ${err}\n`);
        process.exit(1);
    }

    process.stderr.write('[aionda-mail-mcp] Ready — listening on stdio\n');

    let pendingRequests = 0;
    let stdinEnded = false;

    function maybeExit(): void {
        if (stdinEnded && pendingRequests === 0) {
            process.stderr.write('[aionda-mail-mcp] stdin closed, shutting down\n');
            process.exit(0);
        }
    }

    // Read line-delimited JSON-RPC from stdin
    let buffer = '';

    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk: string) => {
        buffer += chunk;

        // Process complete lines
        let newlineIdx: number;
        while ((newlineIdx = buffer.indexOf('\n')) !== -1) {
            const line = buffer.slice(0, newlineIdx).trim();
            buffer = buffer.slice(newlineIdx + 1);

            if (!line) continue;

            pendingRequests++;
            processLine(proxy, line).finally(() => {
                pendingRequests--;
                maybeExit();
            });
        }
    });

    process.stdin.on('end', () => {
        stdinEnded = true;
        maybeExit();
    });
}

async function processLine(proxy: McpDecryptingProxy, line: string): Promise<void> {
    let request: JsonRpcRequest;
    try {
        request = JSON.parse(line) as JsonRpcRequest;
    } catch {
        const errorResponse = {
            jsonrpc: '2.0' as const,
            id: null,
            error: { code: -32700, message: 'Parse error' },
        };
        writeResponse(errorResponse);
        return;
    }

    // Notifications (no id) — forward but don't return response
    if (request.id === undefined && request.id !== 0) {
        try {
            await proxy.handleRequest(request);
        } catch {
            // Notifications are fire-and-forget
        }
        return;
    }

    try {
        const response = await proxy.handleRequest(request);
        writeResponse(response);
    } catch (err) {
        const errorResponse = {
            jsonrpc: '2.0' as const,
            id: request.id,
            error: {
                code: -32603,
                message: err instanceof Error ? err.message : String(err),
            },
        };
        writeResponse(errorResponse);
    }
}

function writeResponse(response: unknown): void {
    process.stdout.write(JSON.stringify(response) + '\n');
}
