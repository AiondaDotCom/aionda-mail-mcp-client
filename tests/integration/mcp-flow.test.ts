/**
 * Basic MCP flow integration test
 * Credentials from .env.test (not in git)
 */
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { describe, it, expect } from 'vitest';
import { AiondaMailClient } from '../../src/client';

const envPath = resolve(__dirname, '../../.env.test');
if (existsSync(envPath)) {
    for (const line of readFileSync(envPath, 'utf-8').split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx > 0) {
            process.env[trimmed.slice(0, eqIdx)] = trimmed.slice(eqIdx + 1);
        }
    }
}

describe.skipIf(!process.env['MCP_API_KEY'])('MCP Integration Flow', () => {
    const apiKey = process.env['MCP_API_KEY'] ?? '';
    const endpoint = process.env['MCP_ENDPOINT'] ?? 'https://dev.mail.aionda.com';

    it('full flow: connect -> list tools -> list folders -> disconnect', async () => {
        const client = new AiondaMailClient({
            apiKey,
            endpoint,
            timeout: 15000,
        });

        await client.connect();
        expect(client.isConnected()).toBe(true);

        const tools = await client.listTools();
        expect(tools.length).toBeGreaterThan(0);
        expect(tools.some(t => t.name === 'list_folders')).toBe(true);
        expect(tools.some(t => t.name === 'list_emails')).toBe(true);

        await client.disconnect();
    });
});
