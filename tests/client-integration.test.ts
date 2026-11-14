/**
 * AiondaMailClient als Bibliothek in einer Server-Integration (Feldwerk):
 * tmv_-Betrieb über den Proxy-Motor, Zeiger-Sync, Idempotenz, entschlüsselte
 * Anhänge, Antworten, Schlüsselverwaltung und die typisierten Fehler 194–206.
 *
 * Der Server ist eine fetch-Attrappe in der ECHTEN Antwortform
 * (`{content: [{type: 'text', text}]}`, Fehler als `isError` bzw. JSON-RPC-
 * Fehler mit `data.error_code`, wie McpServerService.php sie baut). Die Krypto
 * ist echt.
 */
import { webcrypto } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('tesseract.js', () => {
    throw new Error('tesseract.js wird im Test nicht geladen');
});

import { AiondaMailClient, parseToolResult } from '../src/client';
import {
    McpCursorInvalidError,
    McpDecryptionError,
    McpError,
    McpFolderNotAllowedError,
    McpIdempotencyConflictError,
    McpKeyRotatedError,
    McpKeySuspendedError,
    McpKeyUnusableError,
    McpSendLimitReachedError,
    McpToolError,
    McpToolNotAllowedError,
    McpTransportError,
    isRetryableMcpError,
} from '../src/errors';
import { McpDecryptingProxy } from '../src/proxy';
import { toBase64, toHex } from '../src/crypto/encoding';
import {
    clientFieldHex, derivedEmail, fakeServer, makeVault, payloadOf, rnd, toolCall, utf8,
    type ServerCall, type ToolHandler, type Vault,
} from './helpers/vault';
import { deriveEmailKey } from '../src/crypto/key-derivation';

const KEY_UUID = '0f3c4c5e-7a1b-4d2e-9f80-1a2b3c4d5e6f';
const b64url = (b: Uint8Array): string => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function aesGcm(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    const k = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    return new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv, ...(aad ? { additionalData: aad } : {}) }, k, plaintext));
}

/** get_vault_keys eines Menschen (tmmcp_ + tmv_) für dieses Postfach. */
async function personalKeyMaterial(vault: Vault): Promise<{ vaultKeyText: string; keys: Record<string, unknown> }> {
    const vaultKeyText = 'tmv_' + b64url(rnd(32));
    const K = new Uint8Array(await webcrypto.subtle.digest('SHA-256', utf8(vaultKeyText)));
    const wrapIv = rnd(12);
    const wrapped = new Uint8Array([...wrapIv, ...await aesGcm(K, wrapIv, vault.masterKey, utf8('aionda-mcp-master-key-v1:' + KEY_UUID))]);
    const pkIv = rnd(12);
    const priv = new Uint8Array([...vault.privateKeys.x25519PrivateKey, ...vault.privateKeys.mlKemPrivateKey]);
    return {
        vaultKeyText,
        keys: {
            wrapped_master_key: toHex(wrapped),
            mcp_key_uuid: KEY_UUID,
            encrypted_private_key: toHex(await aesGcm(vault.masterKey, pkIv, priv)),
            private_key_iv: toHex(pkIv),
            private_key_layout: 'webcrypto',
            x25519_public_key: toHex(vault.publicKeys.x25519),
            mlkem_public_key: toHex(vault.publicKeys.mlkem),
        },
    };
}

/** Werkzeugfehler wie McpServerService: isError + {error, error_code, message}. */
const toolError = (code: number, message: string): { __raw: unknown } => ({
    __raw: { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: true, error_code: code, message }) }] },
});
/** Ablehnung am Schlüsseltor: JSON-RPC-Fehler -32000 mit data.error_code. */
const gateError = (code: number, message: string): { __error: { code: number; message: string; data: unknown } } => ({
    __error: { code: -32000, message, data: { error_code: code } },
});

let vault: Vault;
let material: { vaultKeyText: string; keys: Record<string, unknown> };
let stderr: ReturnType<typeof vi.spyOn>;

beforeAll(async () => {
    vault = await makeVault();
    material = await personalKeyMaterial(vault);
});
beforeEach(() => { stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true); });
afterEach(() => { vi.unstubAllGlobals(); stderr.mockRestore(); });

/** Server, der get_vault_keys/get_default_signature beantwortet und den Rest an `handler` gibt. */
function server(handler: ToolHandler = () => ({})): ServerCall[] {
    return fakeServer((name, args) => {
        if (name === 'get_vault_keys') return material.keys;
        if (name === 'get_default_signature') return { has_signature: false };
        return handler(name, args);
    });
}

async function connectedClient(handler?: ToolHandler): Promise<{ client: AiondaMailClient; calls: ServerCall[] }> {
    const calls = server(handler);
    const client = new AiondaMailClient({ apiKey: 'tmmcp_test', vaultKey: material.vaultKeyText, endpoint: 'https://mail.example' });
    await client.connect();
    return { client, calls };
}

const toolCalls = (calls: ServerCall[], name: string): ServerCall[] => calls.filter(c => c.method === 'tools/call' && c.name === name);

describe('tmv_-Betrieb: Anmeldung', () => {
    it('connect entsperrt das Postfach über den Proxy-Motor, ohne OCR-Vorladen', async () => {
        const { client, calls } = await connectedClient();
        expect(client.isConnected()).toBe(true);
        expect(calls.map(c => c.name ?? c.method)).toEqual(['initialize', 'notifications/initialized', 'get_vault_keys', 'get_default_signature']);
        expect(calls[0].headers.Authorization).toBe('Bearer tmmcp_test');
        const log = stderr.mock.calls.map(c => String(c[0])).join('');
        expect(log).not.toMatch(/OCR/);
        await client.disconnect();
        expect(client.isConnected()).toBe(false);
    });

    it('gesperrter Schlüssel (194): initialize geht durch, connect wirft McpKeySuspendedError – nicht wiederholbar', async () => {
        fakeServer((name) => name === 'get_vault_keys'
            ? gateError(194, 'This MCP key is suspended (since 2026-11-14 10:00:00 UTC). The account owner can lift the suspension.')
            : {});
        const client = new AiondaMailClient({ apiKey: 'tmmcp_test', vaultKey: material.vaultKeyText, endpoint: 'https://mail.example' });
        const err = await client.connect().catch(e => e);
        expect(err).toBeInstanceOf(McpKeySuspendedError);
        expect(err).toBeInstanceOf(McpKeyUnusableError);
        expect(err.code).toBe(194);
        expect(err.retryable).toBe(false);
        expect(isRetryableMcpError(err)).toBe(false);
        expect(err.message).toMatch(/^get_vault_keys failed: This MCP key is suspended/);
        expect(client.isConnected()).toBe(false);
    });

    it('abgelöster Schlüssel (203): McpKeyRotatedError, unterscheidbar von der Sperre', async () => {
        fakeServer((name) => name === 'get_vault_keys' ? gateError(203, 'This MCP key was replaced by a new key and has expired. Use the new key.') : {});
        const client = new AiondaMailClient({ apiKey: 'tmmcp_test', vaultKey: material.vaultKeyText, endpoint: 'https://mail.example' });
        const err = await client.connect().catch(e => e);
        expect(err).toBeInstanceOf(McpKeyRotatedError);
        expect(err).not.toBeInstanceOf(McpKeySuspendedError);
        expect(err.retryable).toBe(false);
    });

    it('falsches tmv_: McpDecryptionError; Netzfehler: McpTransportError (wiederholbar)', async () => {
        server();
        const falsch = new AiondaMailClient({ apiKey: 'tmmcp_test', vaultKey: 'tmv_' + b64url(rnd(32)), endpoint: 'https://mail.example' });
        await expect(falsch.connect()).rejects.toBeInstanceOf(McpDecryptionError);

        vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('fetch failed'); }));
        const netz = await new AiondaMailClient({ apiKey: 'tmmcp_test', vaultKey: material.vaultKeyText }).connect().catch(e => e);
        expect(netz).toBeInstanceOf(McpTransportError);
        expect(isRetryableMcpError(netz)).toBe(true);

        vi.stubGlobal('fetch', vi.fn(async () => { throw new DOMException('The operation timed out.', 'TimeoutError'); }));
        const zeit = await new AiondaMailClient({ apiKey: 'tmmcp_test', vaultKey: material.vaultKeyText }).connect().catch(e => e);
        expect(zeit).toBeInstanceOf(McpTransportError);
        expect(zeit.message).toBe('Request timeout');
    });

    it('jede Serveranfrage trägt die Zeitgrenze', async () => {
        const fetchSpy = vi.fn(async (_u: string, init: { body: string; signal?: AbortSignal }) => {
            const req = JSON.parse(init.body);
            expect(init.signal).toBeInstanceOf(AbortSignal);
            const result = req.params?.name === 'get_vault_keys'
                ? { content: [{ type: 'text', text: JSON.stringify(material.keys) }] }
                : { content: [{ type: 'text', text: '{}' }] };
            return { headers: { get: () => null }, json: async () => ({ jsonrpc: '2.0', id: req.id, result }) };
        });
        vi.stubGlobal('fetch', fetchSpy);
        await new AiondaMailClient({ apiKey: 'tmmcp_test', vaultKey: material.vaultKeyText, timeout: 1234 }).connect();
        expect(fetchSpy).toHaveBeenCalled();
    });

    it('tmv_ zusammen mit vaultPrivateKeys ist ein Bedienfehler', () => {
        expect(() => new AiondaMailClient({ apiKey: 'x', vaultKey: 'tmv_abc', vaultPrivateKeys: '00' })).toThrow(McpDecryptionError);
    });

    it('vor connect: entschlüsselnde Methoden werfen statt Geheimtext zu liefern', async () => {
        server();
        const client = new AiondaMailClient({ apiKey: 'tmmcp_test', vaultKey: material.vaultKeyText });
        await expect(client.listEmailPage()).rejects.toThrow('Vault is locked. Call connect() first.');
        await expect(client.readEmailDecrypted('m')).rejects.toBeInstanceOf(McpDecryptionError);
        await expect(client.getAttachmentDecrypted('a')).rejects.toBeInstanceOf(McpDecryptionError);
        await expect(client.listFoldersDecrypted()).rejects.toBeInstanceOf(McpDecryptionError);
    });

    it('ping, listTools, callTool laufen über den Proxy', async () => {
        const { client, calls } = await connectedClient((name) => (name === 'list_deas' ? { deas: [] } : {}));
        await client.ping();
        expect(calls.at(-1)!.method).toBe('ping');
        // tools/list liefert die Attrappe als {} → Werkzeugliste fehlt; nur der Weg zählt hier
        await client.listTools().catch(() => undefined);
        expect(calls.at(-1)!.method).toBe('tools/list');
        const raw = await client.callTool('list_deas');
        expect(parseToolResult('list_deas', raw)).toEqual({ deas: [] });
    });
});

describe('Zeiger-Sync (list_emails mit after)', () => {
    async function mails(n: number, prefix: string): Promise<Record<string, unknown>[]> {
        return Promise.all(Array.from({ length: n }, async (_x, i) =>
            (await derivedEmail(vault, `${prefix}-${i}`, { subject: `Betreff ${prefix}-${i}`, from: 'kunde@example.com', to: 'personal@aionda.com' })).email));
    }

    it('listEmailPage entschlüsselt, reicht next_cursor/has_more durch und nennt Unentschlüsselbares getrennt', async () => {
        const ok = await mails(2, 'm');
        const { email: fremd } = await derivedEmail(await makeVault(), 'm-fremd', { subject: 'x', from: 'y', to: 'z' });
        const { client, calls } = await connectedClient((name) => name === 'list_emails'
            ? { success: true, emails: [...ok, fremd], limit: 50, has_more: true, next_cursor: 'm-fremd', order: 'arrival_asc' }
            : {});

        const page = await client.listEmailPage({ folder: 'inbox' });
        expect(toolCalls(calls, 'list_emails')[0].args).toEqual({ folder: 'inbox', after: 'start', limit: 50 });
        expect(page.emails.map(e => e.subject)).toEqual(['Betreff m-0', 'Betreff m-1']);
        expect(page.failed).toHaveLength(1);
        expect(page.failed[0]).toMatchObject({ uuid: 'm-fremd', receivedAt: '2026-01-02T03:04:05Z' });
        expect(page.nextCursor).toBe('m-fremd');
        expect(page.hasMore).toBe(true);
    });

    it('iterateEmailPages läuft vom Zeiger bis has_more=false und gibt jeden Zeiger weiter', async () => {
        const seiten: Record<string, Record<string, unknown>> = {
            'c0': { emails: await mails(2, 'a'), limit: 2, has_more: true, next_cursor: 'a-1' },
            'a-1': { emails: await mails(1, 'b'), limit: 2, has_more: false, next_cursor: 'b-0' },
        };
        const { client, calls } = await connectedClient((name, args) => (name === 'list_emails' ? seiten[args.after as string] : {}));

        const gesehen: string[] = [];
        for await (const page of client.iterateEmailPages({ folder: 'folder:abc', after: 'c0', limit: 2 })) {
            gesehen.push(...page.emails.map(e => e.uuid), `→${page.nextCursor}`);
        }
        expect(gesehen).toEqual(['a-0', 'a-1', '→a-1', 'b-0', '→b-0']);
        expect(toolCalls(calls, 'list_emails').map(c => c.args)).toEqual([
            { folder: 'folder:abc', after: 'c0', limit: 2 },
            { folder: 'folder:abc', after: 'a-1', limit: 2 },
        ]);
    });

    it('Server ignoriert after (alter Server, Offset-Antwort): Fehler statt stiller Offset-Seite', async () => {
        const { client } = await connectedClient((name) => (name === 'list_emails'
            ? { emails: [], total: 0, offset: 0, limit: 50, hasMore: false } : {}));
        await expect(client.listEmailPage()).rejects.toThrow(/Server ignored "after"/);
    });

    it('has_more ohne Fortschritt bricht ab statt endlos zu laufen', async () => {
        const { client } = await connectedClient((name) => (name === 'list_emails'
            ? { emails: [], limit: 50, has_more: true, next_cursor: 'start' } : {}));
        const it = client.iterateEmailPages();
        await it.next();
        await expect(it.next()).rejects.toThrow(/Cursor did not advance/);
    });

    it('unbekannter Zeiger (202) wird McpCursorInvalidError', async () => {
        const { client } = await connectedClient((name) => (name === 'list_emails'
            ? toolError(202, 'Cursor "x" is unknown for this mailbox (the email no longer exists). Start again with after="start"; deliveries are deduplicated by email uuid on your side.')
            : {}));
        const err = await client.listEmailPage({ after: '11111111-1111-4111-8111-111111111111' }).catch(e => e);
        expect(err).toBeInstanceOf(McpCursorInvalidError);
        expect(err.toolName).toBe('list_emails');
        expect(err.retryable).toBe(false);
    });

    it('Ordnergrenze (196) bei list_emails wird McpFolderNotAllowedError', async () => {
        const { client } = await connectedClient((name) => (name === 'list_emails'
            ? toolError(196, 'Folder "spam" is not allowed for this MCP key (allowed: inbox, sent).') : {}));
        const err = await client.listEmailPage({ folder: 'spam' }).catch(e => e);
        expect(err).toBeInstanceOf(McpFolderNotAllowedError);
        expect(err.code).toBe(196);
    });

    it('listEmails mit Optionen sendet after und gibt die Serverfelder unverändert zurück', async () => {
        const { client, calls } = await connectedClient((name) => (name === 'list_emails'
            ? { emails: [], limit: 10, has_more: false, next_cursor: 'start' } : {}));
        const out = await client.listEmails({ folder: 'sent', after: 'start', limit: 10 });
        expect(toolCalls(calls, 'list_emails')[0].args).toEqual({ folder: 'sent', after: 'start', limit: 10 });
        expect(out).toMatchObject({ has_more: false, next_cursor: 'start' });
    });
});


describe('Lesen, Anhänge, Verschieben', () => {
    it('readEmailDecrypted und getAttachmentDecrypted (im Speicher, keine Datei)', async () => {
        const mailUuid = 'mail-anhang';
        const attUuid = 'att-' + toHex(rnd(4));
        const mailKey = await deriveEmailKey(vault.masterKey, mailUuid);
        const inhalt = utf8('%PDF-1.4 Rechnung');
        const { email } = await derivedEmail(vault, mailUuid, { subject: 'Rechnung', from: 'a@example.com', to: 'b@example.com', body: '<p>Hallo</p>' }, {
            has_attachments: true, attachment_count: 1,
            attachments: [{
                uuid: attUuid, size_bytes: inhalt.length, wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__', ephemeral_key_iv: '',
                encrypted_filename: await clientFieldHex('rechnung.pdf', mailKey),
                encrypted_mimetype: await clientFieldHex('application/pdf', mailKey),
            }],
        });
        const att = {
            uuid: attUuid, email_uuid: mailUuid, wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await clientFieldHex('rechnung.pdf', mailKey),
            encrypted_mimetype: await clientFieldHex('application/pdf', mailKey),
            encrypted_content: await clientFieldHex(inhalt, mailKey),
        };
        const { client, calls } = await connectedClient((name) => (name === 'read_email' ? email : name === 'get_attachment' ? att : {}));

        const mail = await client.readEmailDecrypted(mailUuid);
        expect(mail).toMatchObject({ subject: 'Rechnung', body: '<p>Hallo</p>' });
        expect(mail.attachments).toEqual([{ uuid: attUuid, filename: 'rechnung.pdf', mimetype: 'application/pdf', sizeBytes: inhalt.length }]);

        const dec = await client.getAttachmentDecrypted(attUuid);
        expect(toolCalls(calls, 'get_attachment')[0].args).toEqual({ attachment_uuid: attUuid });
        expect(dec).toMatchObject({ uuid: attUuid, emailUuid: mailUuid, filename: 'rechnung.pdf', mimetype: 'application/pdf', sizeBytes: inhalt.length });
        expect(new TextDecoder().decode(dec.content)).toBe('%PDF-1.4 Rechnung');
        expect(existsSync(join(tmpdir(), 'aionda-mail-attachments', attUuid))).toBe(false);
    });

    it('Anhang, der nicht aufgeht: McpDecryptionError mit Anhangs-UUID', async () => {
        const fremdKey = rnd(32);
        const { client } = await connectedClient((name) => (name === 'get_attachment' ? {
            uuid: 'att-x', email_uuid: 'm-x', wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: 'ab'.repeat(40), encrypted_content: toHex(fremdKey),
        } : name === 'read_email' ? { uuid: 'm-x' } : {}));
        await expect(client.getAttachmentDecrypted('att-x')).rejects.toThrow(/^Failed to decrypt attachment att-x: /);
    });

    it('moveEmail meldet eine Grenzverletzung, statt sie zu verschlucken', async () => {
        const { client, calls } = await connectedClient((name) => (name === 'move_email'
            ? toolError(200, 'Tool move_email is not allowed for this MCP key.') : {}));
        const err = await client.moveEmail('m1', 'folder-uuid').catch(e => e);
        expect(toolCalls(calls, 'move_email')[0].args).toEqual({ email_uuid: 'm1', target_folder: 'folder-uuid' });
        expect(err).toBeInstanceOf(McpToolNotAllowedError);
    });

    it('listFoldersDecrypted im tmv_-Betrieb nimmt die vom Proxy entschlüsselten Namen', async () => {
        const { encryptPhpAesGcm } = await import('../src/crypto/aes-gcm');
        const name = toBase64(await encryptPhpAesGcm(utf8('Feldwerk'), vault.masterKey));
        // Form wie McpToolsService::toolListFolders (trashmail) bei Ordnergrenze inbox+sent.
        const { client } = await connectedClient((n) => (n === 'list_folders' ? {
            system_folders: [
                { name: 'inbox', type: 'system', email_count: 5, unread_count: 0 },
                { name: 'sent', type: 'system', email_count: 1, unread_count: 0 },
            ],
            custom_folders: [{ uuid: 'f1', encrypted_name: name, parent_uuid: null, color: null, sort_order: 0, email_count: 2, unread_count: 1 }],
            shared_folders: { incoming: [], outgoing: [] },
            note: 'n',
        } : {}));
        expect(await client.listFoldersDecrypted()).toEqual([
            { uuid: 'inbox', folderType: 'inbox', name: 'inbox', emailCount: 5, unreadCount: 0 },
            { uuid: 'sent', folderType: 'sent', name: 'sent', emailCount: 1, unreadCount: 0 },
            { uuid: 'f1', folderType: 'custom', name: 'Feldwerk', emailCount: 2, unreadCount: 1 },
        ]);
    });
});

describe('Versand: Idempotenz, Anhänge, Antworten', () => {
    it('sendEmail: idempotencyKey wird idempotency_key; Bytes-Anhang geht als Base64 durch den Proxy', async () => {
        const { client, calls } = await connectedClient((name) => (name === 'send_email'
            ? { message_id: '<1@aionda.com>', sent: true, idempotent_replay: true } : {}));
        const out = await client.sendEmail({
            from_identity: 'personal@aionda.com', to: 'kunde@example.com', subject: 'Angebot', body: '<p>Hi</p>', lang: 'de',
            idempotencyKey: 'feldwerk-job-42',
            attachments: [{ filename: 'angebot.pdf', content: utf8('PDF'), mimetype: 'application/pdf' }],
        });
        expect(out).toEqual({ message_id: '<1@aionda.com>', sent: true, idempotent_replay: true });
        const args = toolCalls(calls, 'send_email')[0].args;
        expect(args.idempotency_key).toBe('feldwerk-job-42');
        expect(args).not.toHaveProperty('idempotencyKey');
        expect(args.attachments).toEqual([{ filename: 'angebot.pdf', content: toBase64(utf8('PDF')), mimetype: 'application/pdf', size: 3 }]);
    });

    it('ungültiger idempotencyKey wird lokal abgelehnt – es geht nichts an den Server', async () => {
        const { client, calls } = await connectedClient();
        const vorher = calls.length;
        for (const key of ['', 'mit leerzeichen', 'x'.repeat(129), 'ümlaut']) {
            await expect(client.sendEmail({ from_identity: 'a', to: 'b', subject: 's', body: 'b', idempotencyKey: key })).rejects.toThrow(/1-128 printable ASCII/);
        }
        expect(calls.length).toBe(vorher);
    });

    it('Idempotenzkonflikt (201): anderer Auftrag = nicht wiederholen, „in Arbeit“ = wiederholen', async () => {
        let msg = '';
        const { client } = await connectedClient((name) => (name === 'send_email' ? toolError(201, msg) : {}));
        const p = { from_identity: 'a', to: 'b', subject: 's', body: 'b', lang: 'de', idempotencyKey: 'k1' };

        msg = 'idempotency_key was already used for a different request within 24 h; nothing was sent';
        const anders = await client.sendEmail(p).catch(e => e);
        expect(anders).toBeInstanceOf(McpIdempotencyConflictError);
        expect(anders.inProgress).toBe(false);
        expect(isRetryableMcpError(anders)).toBe(false);

        msg = 'A request with this idempotency_key is still in progress; nothing was sent again';
        const laeuft = await client.sendEmail(p).catch(e => e);
        expect(laeuft.inProgress).toBe(true);
        expect(isRetryableMcpError(laeuft)).toBe(true);

        msg = 'idempotency_key changed state concurrently; nothing was sent, retry';
        expect((await client.sendEmail(p).catch(e => e)).inProgress).toBe(true);
    });

    it('Versandgrenze (199) ist wiederholbar, mit Werkzeugname', async () => {
        const { client } = await connectedClient((name) => (name === 'send_email'
            ? toolError(199, 'Send limit of this MCP key reached (5 per hour). Nothing was sent.') : {}));
        const err = await client.sendEmail({ from_identity: 'a', to: 'b', subject: 's', body: 'b', lang: 'de' }).catch(e => e);
        expect(err).toBeInstanceOf(McpSendLimitReachedError);
        expect(err.toolName).toBe('send_email');
        expect(isRetryableMcpError(err)).toBe(true);
    });

    it('Schlüssel mitten im Betrieb gesperrt: JSON-RPC-Fehler am Tor wird McpKeySuspendedError', async () => {
        const { client } = await connectedClient((name) => (name === 'send_email' ? gateError(194, 'This MCP key is suspended') : {}));
        const err = await client.sendEmail({ from_identity: 'a', to: 'b', subject: 's', body: 'b', lang: 'de' }).catch(e => e);
        expect(err).toBeInstanceOf(McpKeySuspendedError);
        expect(err.toolName).toBe('send_email');
    });

    it('replyToEmail füllt original_from (Reply-To), Betreff und Message-ID aus der entschlüsselten Mail', async () => {
        const headers = 'Message-ID: <orig-1@example.com>\r\nReply-To: antwort@example.com\r\n';
        const { email } = await derivedEmail(vault, 'm-orig', { subject: 'Frage', from: 'kunde@example.com', to: 'personal@aionda.com', body: 'Wie?', headers });
        const { client, calls } = await connectedClient((name) => (name === 'read_email' ? email
            : name === 'reply_email' ? { message_id: '<r@aionda.com>', replied_to: 'antwort@example.com' } : {}));

        const out = await client.replyToEmail('m-orig', { body: '<p>So.</p>', lang: 'de', idempotencyKey: 'r-1', cc: 'chef@example.com' });
        expect(out.message_id).toBe('<r@aionda.com>');
        expect(toolCalls(calls, 'reply_email')[0].args).toEqual({
            email_uuid: 'm-orig', body: '<p>So.</p>', lang: 'de',
            original_from: 'antwort@example.com', original_subject: 'Frage', original_message_id: 'orig-1@example.com', // ohne <>, der Server setzt sie (VaultSendEmailService)
            cc: 'chef@example.com', idempotency_key: 'r-1',
        });
    });

    it('replyToEmail ohne Reply-To nimmt From; Überschreibungen werden durchgereicht', async () => {
        const { email } = await derivedEmail(vault, 'm-2', { subject: 'Hallo', from: 'kunde@example.com', to: 'x@aionda.com', body: 'b' });
        const { client, calls } = await connectedClient((name) => (name === 'read_email' ? email : name === 'reply_email' ? { message_id: 'm' } : {}));
        await client.replyToEmail('m-2', {
            body: 'b', lang: 'en', to: 'anders@example.com', subject: 'Re: anders', fromIdentity: 'personal@aionda.com',
            attachments: [{ file_path: '/nicht/da.pdf' }],
        }).catch(() => undefined);
        await client.replyToEmail('m-2', { body: 'b', lang: 'en' });
        const args = toolCalls(calls, 'reply_email').at(-1)!.args;
        expect(args).toMatchObject({ original_from: 'kunde@example.com', original_subject: 'Hallo' });
        expect(args).not.toHaveProperty('original_message_id');
    });

    it('forwardEmailTo nimmt Betreff und Text der entschlüsselten Mail', async () => {
        const { email } = await derivedEmail(vault, 'm-f', { subject: 'Bericht', from: 'a@example.com', to: 'b@example.com', body: '<p>Inhalt</p>' });
        const { client, calls } = await connectedClient((name) => (name === 'read_email' ? email : name === 'forward_email' ? { message_id: 'f' } : {}));
        await client.forwardEmailTo('m-f', { to: 'team@example.com', lang: 'de', body: 'FYI', fromIdentity: 'personal@aionda.com', idempotencyKey: 'f-1' });
        expect(toolCalls(calls, 'forward_email')[0].args).toEqual({
            email_uuid: 'm-f', to: 'team@example.com', lang: 'de', original_subject: 'Bericht', original_body: '<p>Inhalt</p>',
            body: 'FYI', from_identity: 'personal@aionda.com', idempotency_key: 'f-1',
        });

        const { email: ohneHtml } = await derivedEmail(vault, 'm-t', { subject: 'S', from: 'a', to: 'b', bodyText: 'nur Text' });
        const { client: c2, calls: calls2 } = await connectedClient((name) => (name === 'read_email' ? ohneHtml : { message_id: 'f' }));
        await c2.forwardEmailTo('m-t', { to: 't@example.com', lang: 'de', attachments: [{ filename: 'a.txt', content: 'QQ==' }] });
        expect(toolCalls(calls2, 'forward_email')[0].args).toMatchObject({ original_body: 'nur Text', attachments: [{ filename: 'a.txt', content: 'QQ==', mimetype: 'application/octet-stream', size: 1 }] });

        const { email: leer } = await derivedEmail(vault, 'm-l', { subject: 'S', from: 'a', to: 'b' });
        const { client: c3, calls: calls3 } = await connectedClient((name) => (name === 'read_email' ? leer : { message_id: 'f' }));
        await c3.forwardEmailTo('m-l', { to: 't@example.com', lang: 'de' });
        expect(toolCalls(calls3, 'forward_email')[0].args.original_body).toBe('');
    });
});

describe('MCP-Schlüsselverwaltung', () => {
    it('jede Methode ruft ihr Werkzeug mit den Serverfeldern auf', async () => {
        const key = { key_uuid: KEY_UUID, kind: 'personal', name: 'Feldwerk', suspended: false };
        const { client, calls } = await connectedClient((name) => {
            if (name === 'list_mcp_keys') return { keys: [key] };
            if (name === 'get_mcp_key_access_log') return { entries: [], alerts: [] };
            if (name === 'list_employee_mcp_keys') return { employee_uuid: 'e1', keys: [key] };
            return key;
        });
        const limits = { allowed_folders: ['inbox', 'sent'], max_age_days: 30, max_sends_per_day: 10, allowed_source_ips: ['203.0.113.7'] };

        expect(await client.listMcpKeys()).toEqual([key]);
        expect(await client.getMcpKeyLimits()).toEqual(key);
        await client.getMcpKeyLimits(KEY_UUID);
        await client.setMcpKeyLimits(KEY_UUID, limits);
        await client.suspendMcpKey();
        await client.suspendMcpKey(KEY_UUID, false);
        expect(await client.getMcpKeyAccessLog(KEY_UUID)).toEqual({ entries: [], alerts: [] });
        await client.getMcpKeyAccessLog(KEY_UUID, 20);
        expect((await client.listEmployeeMcpKeys('e1')).keys).toEqual([key]);
        await client.setEmployeeMcpKeyLimits('e1', KEY_UUID, { max_sends_per_hour: 2 });
        await client.suspendEmployeeMcpKey('e1', KEY_UUID);
        await client.suspendEmployeeMcpKey('e1', KEY_UUID, false);

        const admin = calls.filter(c => c.method === 'tools/call' && !['get_vault_keys', 'get_default_signature'].includes(c.name!));
        expect(admin.map(c => [c.name, c.args])).toEqual([
            ['list_mcp_keys', {}],
            ['get_mcp_key_limits', {}],
            ['get_mcp_key_limits', { key_uuid: KEY_UUID }],
            ['set_mcp_key_limits', { ...limits, key_uuid: KEY_UUID }],
            ['suspend_mcp_key', { suspended: true }],
            ['suspend_mcp_key', { key_uuid: KEY_UUID, suspended: false }],
            ['get_mcp_key_access_log', { key_uuid: KEY_UUID }],
            ['get_mcp_key_access_log', { key_uuid: KEY_UUID, limit: 20 }],
            ['list_employee_mcp_keys', { employee_uuid: 'e1' }],
            ['set_employee_mcp_key_limits', { max_sends_per_hour: 2, employee_uuid: 'e1', key_uuid: KEY_UUID }],
            ['suspend_employee_mcp_key', { employee_uuid: 'e1', key_uuid: KEY_UUID, suspended: true }],
            ['suspend_employee_mcp_key', { employee_uuid: 'e1', key_uuid: KEY_UUID, suspended: false }],
        ]);
    });

    it('Verwaltungsfehler 204/205/206 kommen typisiert an', async () => {
        let code = 204;
        const { client } = await connectedClient(() => toolError(code, `Fehler ${code}`));
        const { McpLimitAboveAccountError, McpKeyCompanyManagedError, McpLimitLoosenedError, McpKeyAdminError } = await import('../src/errors');
        const e204 = await client.setMcpKeyLimits(KEY_UUID, { max_sends_per_day: 100 }).catch(e => e);
        expect(e204).toBeInstanceOf(McpLimitAboveAccountError);
        code = 205;
        expect(await client.setMcpKeyLimits(KEY_UUID, {}).catch(e => e)).toBeInstanceOf(McpKeyCompanyManagedError);
        code = 206;
        const e206 = await client.setEmployeeMcpKeyLimits('e1', KEY_UUID, {}).catch(e => e);
        expect(e206).toBeInstanceOf(McpLimitLoosenedError);
        expect(e206).toBeInstanceOf(McpKeyAdminError);
        expect(e206.retryable).toBe(false);
    });
});

describe('stdio-Proxy reicht die neuen Werkzeuge unverändert durch', () => {
    it.each([
        ['list_mcp_keys', {}],
        ['get_mcp_key_limits', { key_uuid: KEY_UUID }],
        ['set_mcp_key_limits', { key_uuid: KEY_UUID, allowed_folders: ['inbox'], max_sends_per_day: 5 }],
        ['suspend_mcp_key', { suspended: true }],
        ['get_mcp_key_access_log', { key_uuid: KEY_UUID, limit: 10 }],
        ['list_employee_mcp_keys', { employee_uuid: 'e1' }],
        ['set_employee_mcp_key_limits', { employee_uuid: 'e1', key_uuid: KEY_UUID, max_sends_per_hour: 1 }],
        ['suspend_employee_mcp_key', { employee_uuid: 'e1', key_uuid: KEY_UUID, suspended: false }],
    ])('%s', async (name, args) => {
        const antwort = { keys: [{ key_uuid: KEY_UUID, limits: { allowed_folders: ['inbox'] } }], entries: [] };
        const calls = server(() => antwort);
        const proxy = new McpDecryptingProxy({ endpoint: 'https://mail.example', apiKey: 'tmmcp_x', vaultKey: material.vaultKeyText });
        await proxy.bootstrap();
        const resp = await proxy.handleRequest(toolCall(name, args, 7));
        expect(toolCalls(calls, name)[0].args).toEqual(args);
        expect(resp.id).toBe(7);
        expect(payloadOf(resp)).toEqual(antwort);
    });

    it('event_subscribe mit Ordnergrenze: Fehler 200 kommt unverändert bei der KI an', async () => {
        server((name) => (name === 'event_subscribe' ? toolError(200, 'Tool event_subscribe is not available for a key with a folder or time limit.') : {}));
        const proxy = new McpDecryptingProxy({ endpoint: 'https://mail.example', apiKey: 'tmmcp_x', vaultKey: material.vaultKeyText });
        await proxy.bootstrap();
        const resp = await proxy.handleRequest(toolCall('event_subscribe', { topics: ['email.received'] }));
        expect((resp.result as { isError?: boolean }).isError).toBe(true);
        expect(payloadOf(resp)).toMatchObject({ error: true, error_code: 200 });
    });
});

describe('parseToolResult', () => {
    it('ohne Textinhalt: McpToolError; Fehler ohne JSON: Text als Meldung, Code 1', () => {
        expect(() => parseToolResult('x', { content: [] } as never)).toThrow(McpToolError);
        expect(() => parseToolResult('x', undefined)).toThrow(/x: server returned no JSON text content/);
        expect(() => parseToolResult('x', { content: [{ type: 'text', text: 'kein json' }] } as never)).toThrow(McpToolError);
        const err = (() => { try { parseToolResult('x', { isError: true, content: [{ type: 'text', text: 'kaputt' }] } as never); } catch (e) { return e; } })() as McpError;
        expect(err).toBeInstanceOf(McpToolError);
        expect(err.code).toBe(1);
        expect(err.message).toBe('kaputt');
        const msg = (() => { try { parseToolResult('x', { isError: true, content: [{ type: 'text', text: JSON.stringify({ msg: 'alt' }) }] } as never); } catch (e) { return e; } })() as McpError;
        expect(msg.message).toBe('alt');
        const leer = (() => { try { parseToolResult('x', { isError: true } as never); } catch (e) { return e; } })() as McpError;
        expect(leer.message).toBe('Tool execution failed');
    });
});
