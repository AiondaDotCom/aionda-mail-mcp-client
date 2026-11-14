/**
 * Fehlerklassen für die Server-Codes 194–206 (trashmail #359, #360).
 *
 * Die Tabelle unten ist aus includes/config.php des Servers abgelesen
 * (define ERROR_CODE_MCP_*), nicht erraten. Jede Zeile prüft Klasse,
 * Oberklasse, Code und ob ein Wiederholen sinnvoll ist.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
    McpAuthError,
    McpCursorInvalidError,
    McpError,
    McpFolderNotAllowedError,
    McpIdempotencyConflictError,
    McpIntegrationError,
    McpIntegrationErrorCodes,
    McpKeyAdminError,
    McpKeyCompanyManagedError,
    McpKeyLimitError,
    McpKeyRotatedError,
    McpKeySuspendedError,
    McpKeyUnusableError,
    McpLimitAboveAccountError,
    McpLimitLoosenedError,
    McpOutsideTimeWindowError,
    McpRateLimitError,
    McpSendLimitReachedError,
    McpSenderNotAllowedError,
    McpSourceAddressDeniedError,
    McpToolError,
    McpToolNotAllowedError,
    McpTransportError,
    isRetryableMcpError,
    mcpErrorFromCode,
    mcpErrorFromJsonRpc,
} from '../src/errors';
import { ErrorCodes } from '../src/types/errors';
import { McpTransport } from '../src/transport';
import { AiondaMailClient } from '../src/client';
import { toHex } from '../src/crypto/encoding';
import { clientFieldHex, derivedEmail, makeVault, rnd } from './helpers/vault';
import { deriveEmailKey } from '../src/crypto/key-derivation';

type Ctor = new (...args: never[]) => McpError;

const TABELLE: [number, Ctor, Ctor, boolean][] = [
    [194, McpKeySuspendedError, McpKeyUnusableError, false],
    [195, McpSourceAddressDeniedError, McpKeyLimitError, false],
    [196, McpFolderNotAllowedError, McpKeyLimitError, false],
    [197, McpOutsideTimeWindowError, McpKeyLimitError, false],
    [198, McpSenderNotAllowedError, McpKeyLimitError, false],
    [199, McpSendLimitReachedError, McpKeyLimitError, true],
    [200, McpToolNotAllowedError, McpKeyLimitError, false],
    [201, McpIdempotencyConflictError, McpIntegrationError, false],
    [202, McpCursorInvalidError, McpIntegrationError, false],
    [203, McpKeyRotatedError, McpKeyUnusableError, false],
    [204, McpLimitAboveAccountError, McpKeyAdminError, false],
    [205, McpKeyCompanyManagedError, McpKeyAdminError, false],
    [206, McpLimitLoosenedError, McpKeyAdminError, false],
];

describe('mcpErrorFromCode', () => {
    it.each(TABELLE)('Code %i → %o', (code, Klasse, Ober, retryable) => {
        const err = mcpErrorFromCode(code, `Meldung ${code}`, 'send_email', { error_code: code });
        expect(err).toBeInstanceOf(Klasse);
        expect(err).toBeInstanceOf(Ober);
        expect(err).toBeInstanceOf(McpIntegrationError);
        expect(err.code).toBe(code);
        expect(err.message).toBe(`Meldung ${code}`);
        expect((err as McpIntegrationError).toolName).toBe('send_email');
        expect((err as McpIntegrationError).retryable).toBe(retryable);
        expect(isRetryableMcpError(err)).toBe(retryable);
        expect(err.name).toBe(Klasse.name);
        // Standardmeldung ohne Argumente
        const blank = new (Klasse as unknown as new () => McpIntegrationError)();
        expect(blank.code).toBe(code);
        expect(blank.message.length).toBeGreaterThan(0);
    });

    it('Codes in beiden Tabellen sind dieselben', () => {
        const c = McpIntegrationErrorCodes;
        expect(Object.values(c)).toEqual([194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206]);
        expect(ErrorCodes.MCP_KEY_SUSPENDED).toBe(c.KEY_SUSPENDED);
        expect(ErrorCodes.MCP_KEY_ROTATED).toBe(c.KEY_ROTATED);
        expect(ErrorCodes.MCP_LIMIT_LOOSENED).toBe(c.LIMIT_LOOSENED);
    });

    it('Gesperrt und abgelöst sind voneinander und von vorübergehenden Fehlern unterscheidbar', () => {
        const gesperrt = mcpErrorFromCode(194, 'x');
        const abgeloest = mcpErrorFromCode(203, 'x');
        const grenze = mcpErrorFromCode(199, 'x');
        expect(gesperrt).not.toBeInstanceOf(McpKeyRotatedError);
        expect(abgeloest).not.toBeInstanceOf(McpKeySuspendedError);
        expect(grenze).not.toBeInstanceOf(McpKeyUnusableError);
        expect([gesperrt, abgeloest, grenze].map(isRetryableMcpError)).toEqual([false, false, true]);
    });

    it('Anmeldesperre 78 und Anmeldefehler 61; unbekannte Codes bleiben allgemein', () => {
        expect(mcpErrorFromCode(78, 'Too many authentication failures')).toBeInstanceOf(McpRateLimitError);
        expect(isRetryableMcpError(mcpErrorFromCode(78, 'x'))).toBe(true);
        expect(mcpErrorFromCode(61, 'Invalid API key')).toBeInstanceOf(McpAuthError);
        const mitWerkzeug = mcpErrorFromCode(43, 'Email not found', 'read_email');
        expect(mitWerkzeug).toBeInstanceOf(McpToolError);
        expect((mitWerkzeug as McpToolError).toolName).toBe('read_email');
        const ohne = mcpErrorFromCode(43, 'Email not found', undefined, { a: 1 });
        expect(ohne.constructor).toBe(McpError);
        expect(ohne.data).toEqual({ a: 1 });
        expect(isRetryableMcpError(ohne)).toBe(false);
        expect(isRetryableMcpError(new Error('x'))).toBe(false);
        expect(isRetryableMcpError(new McpTransportError('weg'))).toBe(true);
        expect(new McpTransportError('weg').code).toBe(-32603);
    });

    it('201: in_progress aus data zählt, unbekannter Wortlaut gilt als „anderer Auftrag“', () => {
        expect(new McpIdempotencyConflictError('irgendwas', 'send_email', { in_progress: true }).inProgress).toBe(true);
        expect(new McpIdempotencyConflictError('irgendwas').inProgress).toBe(false);
        expect(new McpIdempotencyConflictError().retryable).toBe(false);
    });
});

describe('mcpErrorFromJsonRpc', () => {
    it('mit data.error_code: typisiert; ohne: McpError mit JSON-RPC-Code', () => {
        const tor = mcpErrorFromJsonRpc({ code: -32000, message: 'This MCP key may not be used from source address 1.2.3.4.', data: { error_code: 195 } });
        expect(tor).toBeInstanceOf(McpSourceAddressDeniedError);
        const sitzung = mcpErrorFromJsonRpc({ code: -32000, message: 'Invalid or expired session' });
        expect(sitzung.constructor).toBe(McpError);
        expect(sitzung.code).toBe(-32000);
        expect(mcpErrorFromJsonRpc({ code: -32602 }).message).toBe('Server error -32602');
        expect(mcpErrorFromJsonRpc({ code: -32000, message: 'x', data: { error_code: 'nein' } }).code).toBe(-32000);
    });
});

describe('McpTransport (Altbetrieb)', () => {
    afterEach(() => vi.unstubAllGlobals());

    it('Ablehnung am Schlüsseltor wird typisiert, mit Werkzeugname bei tools/call', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({
            status: 200, headers: new Headers(),
            json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'This MCP key is suspended', data: { error_code: 194 } } }),
        })));
        const t = new McpTransport({ endpoint: 'https://x/mcp', apiKey: 'tmmcp_x' });
        const err = await t.request('tools/call', { name: 'list_emails' }).catch(e => e);
        expect(err).toBeInstanceOf(McpKeySuspendedError);
        expect(err.toolName).toBe('list_emails');
        const ohne = await t.request('tools/list').catch(e => e);
        expect(ohne).toBeInstanceOf(McpKeySuspendedError);
        expect(ohne.toolName).toBeUndefined();
        const leer = await t.request('tools/call').catch(e => e);
        expect(leer.toolName).toBe('');
    });

    it('Zeitüberschreitung und Netzfehler werden McpTransportError (wiederholbar)', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => { throw new DOMException('aborted', 'AbortError'); }));
        const t = new McpTransport({ endpoint: 'https://x/mcp', apiKey: 'k' });
        const zeit = await t.request('ping').catch(e => e);
        expect(zeit).toBeInstanceOf(McpTransportError);
        expect(zeit.code).toBe(-32000);
        vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('fetch failed'); }));
        const netz = await t.request('ping').catch(e => e);
        expect(netz).toBeInstanceOf(McpTransportError);
        expect(isRetryableMcpError(netz)).toBe(true);
    });
});

describe('AiondaMailClient im Altbetrieb (Hex-Master-Key)', () => {
    afterEach(() => vi.unstubAllGlobals());

    function legacyServer(handler: (name: string, args: Record<string, unknown>) => unknown): { name: string; args: Record<string, unknown> }[] {
        const sent: { name: string; args: Record<string, unknown> }[] = [];
        vi.stubGlobal('fetch', vi.fn(async (_u: string, init: { body: string }) => {
            const req = JSON.parse(init.body);
            if (req.method === 'tools/call') sent.push({ name: req.params.name, args: req.params.arguments });
            const result = req.method === 'tools/call'
                ? { content: [{ type: 'text', text: JSON.stringify(handler(req.params.name, req.params.arguments)) }] }
                : { protocolVersion: '2025-03-26' };
            return { status: 200, headers: new Headers({ 'Mcp-Session-Id': 's' }), json: async () => ({ jsonrpc: '2.0', id: req.id, result }) };
        }));
        return sent;
    }

    it('listEmailPage, getAttachmentDecrypted und Werkzeugfehler auch ohne tmv_', async () => {
        const vault = await makeVault();
        const { email } = await derivedEmail(vault, 'm1', { subject: 'Alt', from: 'a', to: 'b' });
        const mailKey = await deriveEmailKey(vault.masterKey, 'm1');
        const att = {
            uuid: 'a1', email_uuid: 'm1', wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await clientFieldHex('x.txt', mailKey), encrypted_content: await clientFieldHex('inhalt', mailKey),
        };
        const sent = legacyServer((name) => name === 'list_emails'
            ? { emails: [email], limit: 50, has_more: false, next_cursor: 'm1' }
            : name === 'get_attachment' ? att : {});
        const client = new AiondaMailClient({
            apiKey: 'tma_x', endpoint: 'https://x',
            vaultKey: toHex(vault.masterKey),
            vaultPrivateKeys: toHex(new Uint8Array([...vault.privateKeys.x25519PrivateKey, ...vault.privateKeys.mlKemPrivateKey])),
        });
        await client.connect();
        const page = await client.listEmailPage({ folder: 'sent', after: 'start' });
        expect(page.emails[0].subject).toBe('Alt');
        expect(sent[0]).toEqual({ name: 'list_emails', args: { folder: 'sent', after: 'start', limit: 50 } });
        const a = await client.getAttachmentDecrypted('a1');
        expect(new TextDecoder().decode(a.content)).toBe('inhalt');
        expect(a.mimetype).toBe('application/octet-stream');

        const ohneSchluessel = new AiondaMailClient({ apiKey: 'tma_x', vaultKey: toHex(rnd(32)) });
        await expect(ohneSchluessel.listEmailPage()).rejects.toThrow('Vault private keys not provided');
    });
});
