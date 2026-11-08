/**
 * stdio-Server: liest zeilenweise JSON-RPC von stdin, reicht es durch den
 * Proxy und schreibt die Antworten nach stdout.
 *
 * Der Proxy ist eine Attrappe; stdin/stdout/exit werden über Spione
 * beobachtet. Geprüft wird, was auf stdout landet und wann der Prozess endet.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const proxyCtl = vi.hoisted(() => ({
    bootstrap: vi.fn(),
    handleRequest: vi.fn(),
    configs: [] as unknown[],
}));
vi.mock('../src/proxy', () => ({
    McpDecryptingProxy: class {
        constructor(config: unknown) { proxyCtl.configs.push(config); }
        bootstrap(): Promise<void> { return proxyCtl.bootstrap(); }
        handleRequest(r: unknown): Promise<unknown> { return proxyCtl.handleRequest(r); }
    },
}));

import { startStdioServer } from '../src/stdio-server';

class ExitCalled extends Error {
    constructor(public code: number | undefined) { super(`exit ${code}`); }
}

let stdinHandlers: Record<string, (arg?: unknown) => void>;
let stdout: string[];
let stderr: string[];
let exitCodes: (number | undefined)[];
let exitThrows: boolean;
const env = { ...process.env };

beforeEach(() => {
    stdinHandlers = {};
    stdout = [];
    stderr = [];
    exitCodes = [];
    exitThrows = false;
    proxyCtl.configs = [];
    proxyCtl.bootstrap.mockReset().mockResolvedValue(undefined);
    proxyCtl.handleRequest.mockReset();
    vi.spyOn(process.stdin, 'setEncoding').mockImplementation(() => process.stdin);
    vi.spyOn(process.stdin, 'on').mockImplementation(((ev: string, fn: (arg?: unknown) => void) => {
        stdinHandlers[ev] = fn;
        return process.stdin;
    }) as never);
    vi.spyOn(process.stdout, 'write').mockImplementation(((s: string) => { stdout.push(s); return true; }) as never);
    vi.spyOn(process.stderr, 'write').mockImplementation(((s: string) => { stderr.push(s); return true; }) as never);
    vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
        exitCodes.push(code);
        if (exitThrows) throw new ExitCalled(code);
    }) as never);
    process.env.AIONDA_API_KEY = 'tma_test';
    process.env.AIONDA_VAULT_KEY = 'tmv_test';
    delete process.env.AIONDA_ENDPOINT;
});
afterEach(() => {
    vi.restoreAllMocks();
    process.env = { ...env };
});

const tick = (): Promise<void> => new Promise(r => setTimeout(r, 0));
const lines = (): unknown[] => stdout.join('').split('\n').filter(Boolean).map(l => JSON.parse(l));

describe('startStdioServer', () => {
    it('fehlender API-Schlüssel oder Vault-Schlüssel: Meldung und Exit 1, kein Proxy', async () => {
        exitThrows = true;
        delete process.env.AIONDA_API_KEY;
        await expect(startStdioServer()).rejects.toThrow(ExitCalled);
        expect(stderr.join('')).toContain('AIONDA_API_KEY environment variable is required');

        process.env.AIONDA_API_KEY = 'tma_test';
        delete process.env.AIONDA_VAULT_KEY;
        await expect(startStdioServer()).rejects.toThrow(ExitCalled);
        expect(stderr.join('')).toContain('AIONDA_VAULT_KEY environment variable is required');
        expect(exitCodes).toEqual([1, 1]);
        expect(proxyCtl.configs).toHaveLength(0);
    });

    it('Bootstrap scheitert: Meldung mit Grund, Exit 1', async () => {
        exitThrows = true;
        proxyCtl.bootstrap.mockRejectedValue(new Error('get_vault_keys failed: abgelaufen'));
        await expect(startStdioServer()).rejects.toThrow(ExitCalled);
        expect(stderr.join('')).toContain('Bootstrap failed: Error: get_vault_keys failed: abgelaufen');
        expect(exitCodes).toEqual([1]);
    });

    it('reicht Zeilen durch den Proxy, setzt geteilte Zeilen zusammen und beantwortet Fehler je id', async () => {
        process.env.AIONDA_ENDPOINT = 'https://dev.example';
        proxyCtl.handleRequest.mockImplementation(async (r: { id?: number; method: string }) => {
            if (r.method === 'boom') throw new Error('kaputt');
            if (r.method === 'boom2') throw 'nur Text';
            return { jsonrpc: '2.0', id: r.id, result: { echo: r.method } };
        });

        await startStdioServer();
        expect(proxyCtl.configs).toEqual([{ endpoint: 'https://dev.example', apiKey: 'tma_test', vaultKey: 'tmv_test' }]);
        expect(stderr.join('')).toContain('Connecting to https://dev.example/mcp');

        stdinHandlers.data!('{"jsonrpc":"2.0","id":1,"method":"tools/li');
        await tick();
        expect(proxyCtl.handleRequest).not.toHaveBeenCalled();
        stdinHandlers.data!('st"}\n\n   \n{"jsonrpc":"2.0","id":0,"method":"ping"}\nnicht json\n');
        stdinHandlers.data!('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
        stdinHandlers.data!('{"jsonrpc":"2.0","id":7,"method":"boom"}\n{"jsonrpc":"2.0","id":8,"method":"boom2"}\n');
        await tick();

        expect(proxyCtl.handleRequest.mock.calls.map(c => (c[0] as { method: string }).method))
            .toEqual(['tools/list', 'ping', 'notifications/initialized', 'boom', 'boom2']);
        expect(lines()).toEqual(expect.arrayContaining([
            { jsonrpc: '2.0', id: 1, result: { echo: 'tools/list' } },
            { jsonrpc: '2.0', id: 0, result: { echo: 'ping' } },
            { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
            { jsonrpc: '2.0', id: 7, error: { code: -32603, message: 'kaputt' } },
            { jsonrpc: '2.0', id: 8, error: { code: -32603, message: 'nur Text' } },
        ]));
        // Benachrichtigung: keine Antwort.
        expect(lines()).toHaveLength(5);
    });

    it('Standard-Endpunkt; scheiternde Benachrichtigung bleibt stumm; Ende von stdin wartet auf offene Anfragen', async () => {
        let release!: (v: unknown) => void;
        proxyCtl.handleRequest.mockImplementation((r: { id?: number }) => {
            if (r.id === undefined) return Promise.reject(new Error('egal'));
            return new Promise(res => { release = res; });
        });
        await startStdioServer();
        expect(proxyCtl.configs[0]).toMatchObject({ endpoint: 'https://mail.aionda.com' });

        stdinHandlers.data!('{"jsonrpc":"2.0","method":"notifications/x"}\n{"jsonrpc":"2.0","id":3,"method":"slow"}\n');
        stdinHandlers.end!();
        await tick();
        expect(exitCodes).toEqual([]);
        expect(stdout).toEqual([]);

        release({ jsonrpc: '2.0', id: 3, result: 'fertig' });
        await tick();
        expect(lines()).toEqual([{ jsonrpc: '2.0', id: 3, result: 'fertig' }]);
        expect(exitCodes).toEqual([0]);
        expect(stderr.join('')).toContain('stdin closed, shutting down');
    });

    it('stdin endet ohne offene Anfragen: sofort Exit 0', async () => {
        await startStdioServer();
        stdinHandlers.end!();
        expect(exitCodes).toEqual([0]);
    });
});
