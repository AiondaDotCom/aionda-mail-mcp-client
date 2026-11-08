/**
 * search_emails im Proxy: Die Suche läuft vollständig lokal über
 * entschlüsselte Mails (Zero Knowledge) – Betreff/Absender/Empfänger, dann
 * Text der Mail und PDF-Anhänge (Textebene, sonst OCR).
 *
 * pdfjs-dist und tesseract.js sind Attrappen, die den Inhalt der
 * tatsächlich entschlüsselten und abgelegten Datei lesen. Was sie finden,
 * stammt also aus der Entschlüsselung, nicht aus der Attrappe.
 */
import { readFileSync } from 'node:fs';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const ocr = vi.hoisted(() => ({ recognize: vi.fn(), terminate: vi.fn() }));
vi.mock('tesseract.js', () => ({ createWorker: vi.fn(async () => ocr) }));
vi.mock('pdfjs-dist/legacy/build/pdf.mjs', () => ({
    getDocument: ({ data }: { data: Uint8Array }) => {
        const text = new TextDecoder().decode(data);
        if (text.startsWith('KAPUTT')) return { promise: Promise.reject(new Error('Invalid PDF structure')) };
        // „SCAN…“ steht für ein gescanntes PDF ohne Textebene.
        const seiten = text.startsWith('SCAN') ? ['', ''] : [text.slice(0, 10), text.slice(10)];
        return {
            promise: Promise.resolve({
                numPages: seiten.length,
                getPage: async (p: number) => ({ getTextContent: async () => ({ items: [{ str: seiten[p - 1] }] }) }),
            }),
        };
    },
}));

import { McpDecryptingProxy, throwOnServerError } from '../src/proxy';
import {
    derivedEmail, fakeServer, makeVault, payloadOf, phpFieldHex, toolCall, unlock, type Vault,
} from './helpers/vault';

let vault: Vault;
beforeAll(async () => { vault = await makeVault(); });

let stderr: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
    stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    ocr.recognize.mockReset();
    ocr.terminate.mockReset();
    ocr.recognize.mockImplementation(async (path: string) => ({ data: { text: readFileSync(path, 'utf8').replace(/^SCAN/, '') } }));
});
afterEach(() => { vi.unstubAllGlobals(); stderr.mockRestore(); });

function newProxy(): McpDecryptingProxy {
    const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tma_x', vaultKey: 'tmv_x' });
    unlock(proxy, vault);
    return proxy;
}

async function search(proxy: McpDecryptingProxy, args: Record<string, unknown>) {
    const resp = await proxy.handleRequest(toolCall('search_emails', args, 11));
    return { data: payloadOf(resp), isError: (resp.result as { isError?: boolean }).isError === true, id: resp.id };
}

describe('search_emails: Kopfzeilen', () => {
    it('durchsucht ohne Ordnerangabe System-, eigene und geteilte Ordner; Treffer aus entschlüsselten Feldern', async () => {
        const a = (await derivedEmail(vault, 'a', { subject: 'Steuerbescheid 2025', from: 'amt@example.com', to: 'me@example.com' })).email;
        const b = (await derivedEmail(vault, 'b', { subject: 'Hallo', from: 'Steuerberater@example.com', to: 'me@example.com' })).email;
        const c = (await derivedEmail(vault, 'c', { subject: 'Frage', from: 'x@example.com', to: 'steuer@example.com' })).email;
        const d = (await derivedEmail(vault, 'd', { subject: 'Urlaub', from: 'y@example.com', to: 'me@example.com' })).email;
        const byFolder: Record<string, unknown[]> = { inbox: [a], sent: [b], 'folder:c1': [c], 'folder:s1': [d] };
        const calls = fakeServer((name, args) => {
            if (name === 'list_folders') return { custom_folders: [{ uuid: 'c1' }], shared_folders: { incoming: [{ folder_uuid: 's1' }] } };
            return { emails: byFolder[String(args.folder)] ?? [] };
        });

        const { data, isError, id } = await search(newProxy(), { query: '  STEUER ' });

        expect(isError).toBe(false);
        expect(id).toBe(11);
        expect(calls.filter(c2 => c2.name === 'list_emails').map(c2 => c2.args.folder))
            .toEqual(['inbox', 'sent', 'drafts', 'spam', 'trash', 'folder:c1', 'folder:s1']);
        expect(data).toMatchObject({ query: 'steuer', total_searched: 4, total_matched: 3 });
        expect((data.results as Record<string, unknown>[]).map(r => [r.uuid, r.match_field, r.folder, r.subject])).toEqual([
            ['a', 'subject', 'inbox', 'Steuerbescheid 2025'],
            ['b', 'from', 'sent', 'Hallo'],
            ['c', 'to', 'folder:c1', 'Frage'],
        ]);
        expect(JSON.stringify(data)).not.toContain('encrypted_');
    });

    it('limit beendet die Suche, weitere Ordner werden nicht mehr geholt', async () => {
        const mails = await Promise.all([1, 2, 3].map(async i => (await derivedEmail(vault, `m${i}`, { subject: 'Treffer', from: 'f', to: 't' })).email));
        const calls = fakeServer(() => ({ emails: mails }));
        const { data } = await search(newProxy(), { query: 'treffer', folders: ['inbox', 'sent'], limit: 2 });
        expect(data.total_matched).toBe(2);
        expect(calls.map(c => c.args.folder)).toEqual(['inbox']);
    });

    it('ohne Suchbegriff: Fehler, kein Serveraufruf', async () => {
        const calls = fakeServer(() => ({}));
        const { data, isError } = await search(newProxy(), { query: '   ' });
        expect(isError).toBe(true);
        expect(data).toEqual({ error: true, message: 'query is required' });
        expect(calls).toHaveLength(0);
    });

    it('Serverfehler bei list_folders kommt mit seiner Meldung zurück', async () => {
        fakeServer(() => ({ __error: { code: 61, message: 'Invalid API key' } }));
        const { data, isError } = await search(newProxy(), { query: 'x' });
        expect(isError).toBe(true);
        expect(data.message).toBe('Search failed: Invalid API key');
    });
});

describe('search_emails: Inhalt und PDF-Anhänge', () => {
    it('findet im Text, in der PDF-Textebene und per OCR im gescannten PDF; Bildanhänge werden nicht gelesen', async () => {
        const mk = async (uuid: string, body: string, atts: { uuid: string; name: string; mime: string; content: string }[]) => {
            const { email, mailKey } = await derivedEmail(vault, uuid, { subject: 'Post', from: 'f@example.com', to: 't@example.com', bodyText: body }, { has_attachments: true });
            const listed = { ...email };
            delete listed.encrypted_body_text;
            const full = { ...email, attachments: await Promise.all(atts.map(async a => ({
                uuid: a.uuid, size_bytes: a.content.length, wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
                encrypted_filename: await phpFieldHex(a.name, mailKey), encrypted_mimetype: await phpFieldHex(a.mime, mailKey),
            }))) };
            const attResp = await Promise.all(atts.map(async a => ({
                uuid: a.uuid, email_uuid: uuid, wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
                encrypted_filename: await phpFieldHex(a.name, mailKey), encrypted_mimetype: await phpFieldHex(a.mime, mailKey),
                encrypted_content: await phpFieldHex(a.content, mailKey),
            })));
            return { listed, full, attResp };
        };
        const mails = [
            await mk('body', 'Die Lohnsteuer ist fällig', []),
            await mk('pdf', 'nichts', [{ uuid: 'p1', name: 'beleg.pdf', mime: 'application/pdf', content: 'Rechnung: Lohnsteuer 2025' }]),
            await mk('scan', 'nichts', [{ uuid: 'p2', name: 'scan.pdf', mime: 'application/pdf', content: 'SCAN Lohnsteuer' }]),
            await mk('ohne', 'nichts', [
                { uuid: 'p3', name: 'kaputt.pdf', mime: 'application/pdf', content: 'KAPUTT' },
                { uuid: 'p4', name: 'anderes.pdf', mime: 'application/pdf', content: 'Speiseplan der Kantine' },
                { uuid: 'i1', name: 'foto.png', mime: 'image/png', content: 'Lohnsteuer im Bild' },
            ]),
        ];
        const byUuid = new Map(mails.map(m => [String(m.listed.uuid), m]));
        const atts = new Map(mails.flatMap(m => m.attResp.map(a => [a.uuid, a] as const)));
        const calls = fakeServer((name, args) => {
            if (name === 'list_emails') return { emails: mails.map(m => m.listed) };
            if (name === 'read_email') return byUuid.get(String(args.email_uuid))!.full;
            if (name === 'get_attachment') return atts.get(String(args.attachment_uuid));
            throw new Error(name);
        });

        const { data } = await search(newProxy(), { query: 'lohnsteuer', folders: ['inbox'] });

        expect((data.results as Record<string, unknown>[]).map(r => [r.uuid, r.match_field])).toEqual([
            ['body', 'body'],
            ['pdf', 'attachment:beleg.pdf'],
            ['scan', 'attachment:scan.pdf (OCR)'],
        ]);
        expect(calls.filter(c => c.name === 'get_attachment').map(c => c.args.attachment_uuid)).toEqual(['p1', 'p2', 'p3', 'p4']);
        expect(ocr.terminate).toHaveBeenCalledTimes(1);
    });

    it('scheitert die OCR, ist es kein Treffer, die Suche läuft weiter', async () => {
        ocr.recognize.mockRejectedValue(new Error('OCR kaputt'));
        const { email, mailKey } = await derivedEmail(vault, 'scan', { subject: 'Post', from: 'f', to: 't', bodyText: 'nichts' }, { has_attachments: true });
        const full = { ...email, attachments: [{ uuid: 'p', size_bytes: 1, wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('s.pdf', mailKey), encrypted_mimetype: await phpFieldHex('application/pdf', mailKey) }] };
        const att = { uuid: 'p', email_uuid: 'scan', wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('s.pdf', mailKey), encrypted_content: await phpFieldHex('SCAN x', mailKey) };
        fakeServer((name) => (name === 'list_emails' ? { emails: [email] } : name === 'read_email' ? full : att));

        const { data, isError } = await search(newProxy(), { query: 'x-y-z', folders: ['inbox'] });
        expect(isError).toBe(false);
        expect(data.total_matched).toBe(0);
        expect(ocr.terminate).toHaveBeenCalledTimes(1);
    });

    // Fehler im Produktivcode: searchEmailContent() überspringt jeden Anhang,
    // der kein application/pdf ist (`continue`), BEVOR der Zweig „Also search
    // image attachments via OCR“ erreicht wird. Der OCR-Zweig für Bilder ist
    // damit unerreichbar; ein Bildanhang wird nie gelesen.
    it.fails('Bildanhänge werden per OCR durchsucht (Zweig ist unerreichbar)', async () => {
        const { email, mailKey } = await derivedEmail(vault, 'bild', { subject: 'Post', from: 'f', to: 't', bodyText: 'nichts' }, { has_attachments: true });
        const full = { ...email, attachments: [{ uuid: 'i', size_bytes: 1, wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('foto.png', mailKey), encrypted_mimetype: await phpFieldHex('image/png', mailKey) }] };
        const att = { uuid: 'i', email_uuid: 'bild', wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('foto.png', mailKey), encrypted_content: await phpFieldHex('Lohnsteuer im Bild', mailKey) };
        fakeServer((name) => (name === 'list_emails' ? { emails: [email] } : name === 'read_email' ? full : att));

        const { data } = await search(newProxy(), { query: 'lohnsteuer', folders: ['inbox'] });
        expect((data.results as Record<string, unknown>[])[0]?.match_field).toBe('attachment:foto.png');
    });

    it('nicht lesbare Mailantwort zählt als kein Treffer', async () => {
        const { email } = await derivedEmail(vault, 'x', { subject: 'Post', from: 'f', to: 't' }, { has_attachments: true });
        fakeServer((name) => (name === 'list_emails' ? { emails: [email] } : { __raw: { content: [{ type: 'text', text: 'kein json' }] } }));
        const { data } = await search(newProxy(), { query: 'irgendwas', folders: ['inbox'] });
        expect(data.total_matched).toBe(0);
    });
});

describe('throwOnServerError', () => {
    it('Meldung des Servers, sonst Code; fehlendes Ergebnis ist ein Fehler; gültige Antwort geht durch', () => {
        expect(() => throwOnServerError({ jsonrpc: '2.0', error: { code: 42, message: '' } })).toThrow('Server error 42');
        expect(() => throwOnServerError({ jsonrpc: '2.0' })).toThrow('Server returned no result');
        expect(() => throwOnServerError({ jsonrpc: '2.0', result: { content: [] } })).not.toThrow();
    });
});

describe('search_emails: nicht entschlüsselbarer PDF-Anhang', () => {
    it('wird übersprungen, ohne die Suche abzubrechen', async () => {
        const { email, mailKey } = await derivedEmail(vault, 'p', { subject: 'Post', from: 'f', to: 't', bodyText: 'nichts' }, { has_attachments: true });
        const full = { ...email, attachments: [{ uuid: 'a', size_bytes: 1, wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('a.pdf', mailKey), encrypted_mimetype: await phpFieldHex('application/pdf', mailKey) }] };
        const fremd = (await makeVault()).masterKey;
        const att = { uuid: 'a', email_uuid: 'p', wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('a.pdf', fremd), encrypted_content: await phpFieldHex('Treffer', fremd) };
        const calls = fakeServer((name) => (name === 'list_emails' ? { emails: [email] } : name === 'read_email' ? full : att));

        const { data, isError } = await search(newProxy(), { query: 'treffer', folders: ['inbox'] });
        expect(isError).toBe(false);
        expect(data.total_matched).toBe(0);
        expect(calls.map(c => c.name)).toEqual(['list_emails', 'read_email', 'get_attachment', 'read_email']);
    });
});
