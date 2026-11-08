/**
 * export_email_pdf im Proxy: Mail lokal entschlüsseln, als HTML ablegen und
 * mit Chrome headless in ein PDF drucken.
 *
 * Chrome ist eine Attrappe (execSync), die die PDF-Datei an den verlangten
 * Pfad schreibt; existsSync ist steuerbar, damit die Suche nach Chrome nicht
 * vom Rechner abhängt. Geprüft wird das erzeugte HTML (entschlüsselte Felder,
 * maskierte Kopfzeilen, eingebettete Bilder) und die Antwort an den Agenten.
 */
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const fsCtl = vi.hoisted(() => ({ existing: new Set<string>() }));
vi.mock('node:fs', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:fs')>();
    const existsSync = (p: string): boolean => (String(p).includes('hrom') ? fsCtl.existing.has(String(p)) : actual.existsSync(p));
    return { ...actual, default: { ...actual, existsSync }, existsSync };
});
const exec = vi.hoisted(() => ({ execSync: vi.fn() }));
vi.mock('node:child_process', async (importOriginal) => ({ ...await importOriginal<object>(), execSync: exec.execSync }));
vi.mock('tesseract.js', () => ({ createWorker: vi.fn() }));

import { McpDecryptingProxy } from '../src/proxy';
import { derivedEmail, fakeServer, makeVault, payloadOf, phpFieldHex, toolCall, unlock, type Vault } from './helpers/vault';

let vault: Vault;
beforeAll(async () => { vault = await makeVault(); });

let stderr: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
    stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    fsCtl.existing.clear();
    exec.execSync.mockReset();
    exec.execSync.mockImplementation((cmd: string) => {
        if (cmd.startsWith('which')) return '/opt/fake/chrome\n';
        const m = /--print-to-pdf="([^"]+)"/.exec(cmd);
        if (m) writeFileSync(m[1], '%PDF-1.7 attrappe');
        return '';
    });
});
afterEach(() => { vi.unstubAllGlobals(); stderr.mockRestore(); });

function newProxy(withKeys = true): McpDecryptingProxy {
    const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tma_x', vaultKey: 'tmv_x' });
    if (withKeys) unlock(proxy, vault);
    return proxy;
}

async function exportPdf(proxy: McpDecryptingProxy, args: Record<string, unknown>) {
    const resp = await proxy.handleRequest(toolCall('export_email_pdf', args, 4));
    return { data: payloadOf(resp), isError: (resp.result as { isError?: boolean }).isError === true };
}

const uid = (): string => `exp-${Math.random().toString(16).slice(2)}`;

describe('export_email_pdf', () => {
    it('entschlüsselt die Mail, maskiert die Kopfzeilen und druckt über Chrome (Fund per which)', async () => {
        const uuid = uid();
        const { email } = await derivedEmail(vault, uuid, {
            subject: 'Angebot <b>"neu"</b> / 2026', from: 'shop & co <shop@example.com>', to: 'me@example.com', body: '<p>Inhalt</p>',
        });
        const calls = fakeServer(() => email);

        const { data, isError } = await exportPdf(newProxy(), { email_uuid: uuid });

        expect(isError).toBe(false);
        expect(calls.map(c => [c.name, c.args])).toEqual([['read_email', { email_uuid: uuid }]]);
        const pdfPath = String(data.file_path);
        expect(pdfPath).toMatch(new RegExp(`aionda-mail-exports/${uuid}/Angebot _b__neu___b_ _ 2026\\.pdf$`));
        expect(data).toMatchObject({ subject: 'Angebot <b>"neu"</b> / 2026', from: 'shop & co <shop@example.com>', to: 'me@example.com', date: '2026-01-02T03:04:05Z', note: `PDF exported to ${pdfPath}` });
        expect(data.file_size_bytes).toBe('%PDF-1.7 attrappe'.length);

        const html = readFileSync(join(tmpdir(), 'aionda-mail-exports', uuid, 'email.html'), 'utf8');
        expect(html).toContain('<h1>Angebot &lt;b&gt;&quot;neu&quot;&lt;/b&gt; / 2026</h1>');
        expect(html).toContain('<strong>From:</strong> shop &amp; co &lt;shop@example.com&gt;');
        expect(html).toContain('<div class="body"><p>Inhalt</p></div>');

        const chrome = String(exec.execSync.mock.calls[1][0]);
        expect(chrome).toContain('"/opt/fake/chrome" --headless');
        expect(chrome).toContain(`file://${join(tmpdir(), 'aionda-mail-exports', uuid, 'email.html')}`);
    });

    it('nimmt einen vorhandenen Chrome-Pfad direkt; ohne HTML-Teil den Textteil; ohne Betreff einen Platzhalter', async () => {
        fsCtl.existing.add('/usr/bin/chromium');
        const uuid = uid();
        fakeServer(() => ({ uuid, body_text: 'nur Text', subject: '' }));
        const { data } = await exportPdf(newProxy(false), { email_uuid: uuid });
        expect(String(data.file_path)).toMatch(/\(No subject\)\.pdf$/);
        expect(exec.execSync).toHaveBeenCalledTimes(1);
        expect(String(exec.execSync.mock.calls[0][0])).toMatch(/^"\/usr\/bin\/chromium" --headless/);
        expect(readFileSync(join(tmpdir(), 'aionda-mail-exports', uuid, 'email.html'), 'utf8')).toContain('<div class="body">nur Text</div>');
    });

    it('ohne Chrome: Fehler mit dem Pfad des abgelegten HTML', async () => {
        exec.execSync.mockImplementation(() => { throw new Error('not found'); });
        const uuid = uid();
        fakeServer(() => ({ uuid, subject: 'S', body: 'B' }));
        const { data, isError } = await exportPdf(newProxy(false), { email_uuid: uuid });
        expect(isError).toBe(true);
        expect(data).toEqual({
            error: true, message: 'Chrome/Chromium not found. Install Google Chrome for PDF export.',
            html_path: join(tmpdir(), 'aionda-mail-exports', uuid, 'email.html'),
        });
    });

    it('Chrome bricht ab: „PDF export failed“ mit Grund', async () => {
        fsCtl.existing.add('/usr/bin/google-chrome');
        exec.execSync.mockImplementation(() => { throw new Error('Timeout nach 15 s'); });
        fakeServer(() => ({ uuid: 'x', subject: 'S' }));
        const { data, isError } = await exportPdf(newProxy(false), { email_uuid: uid() });
        expect(isError).toBe(true);
        expect(data.message).toBe('PDF export failed: Timeout nach 15 s');
    });

    it('ohne email_uuid, nicht entschlüsselbar oder nicht gefunden: Fehler ohne Druckversuch', async () => {
        fakeServer(() => ({}));
        expect((await exportPdf(newProxy(), {})).data).toEqual({ error: true, message: 'email_uuid is required' });

        const fremd = await makeVault();
        const { email } = await derivedEmail(fremd, 'm-x', { subject: 's', from: 'f', to: 't' });
        fakeServer(() => email);
        const bad = await exportPdf(newProxy(), { email_uuid: 'm-x' });
        expect(bad.isError).toBe(true);
        expect(String(bad.data.message)).toMatch(/^Failed to read email: .+/);
        expect(bad.data.message).not.toBe('Failed to read email: not found');

        fakeServer(() => ({ __raw: { content: [] } }));
        expect((await exportPdf(newProxy(), { email_uuid: 'm-y' })).data.message).toBe('Failed to read email: not found');
        expect(exec.execSync).not.toHaveBeenCalled();
    });

    it('ersetzt cid:-Bilder durch eingebettete Daten-URLs (nur Bildanhänge werden geholt)', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'cid-'));
        const png = join(dir, 'logo.png');
        writeFileSync(png, Buffer.from([0x89, 0x50, 0x4e, 0x47]));
        const uuid = uid();
        const calls = fakeServer((name, args) => {
            if (name === 'read_email') return {
                uuid, subject: 'Logo', body: '<img src="cid:logo.1@example"><img src="CID:logo.1@example">',
                attachments: [
                    { uuid: 'a-img', content_id: '<logo.1@example>', mimetype: 'image/png' },
                    { uuid: 'a-pdf', contentId: 'doc', mimetype: 'application/pdf' },
                    { uuid: 'a-weg', content_id: 'weg', mimetype: 'image/gif' },
                ],
            };
            return args.attachment_uuid === 'a-img' ? { file_path: png } : { file_path: join(dir, 'fehlt.gif') };
        });

        await exportPdf(newProxy(false), { email_uuid: uuid });

        const html = readFileSync(join(tmpdir(), 'aionda-mail-exports', uuid, 'email.html'), 'utf8');
        expect(html).toContain('<img src="data:image/png;base64,iVBORw=="><img src="data:image/png;base64,iVBORw==">');
        expect(calls.filter(c => c.name === 'get_attachment').map(c => c.args.attachment_uuid)).toEqual(['a-img', 'a-weg']);
    });

    // Fehler im Produktivcode (Befund): Nach der Entschlüsselung tragen die
    // Anhangsmetadaten nur uuid/filename/mimetype/sizeBytes (decryptEmail).
    // Ein content_id, das der Server am Anhang mitliefert, geht dabei verloren
    // – die cid:-Ersetzung oben greift deshalb bei verschlüsselten Mails nie.
    it.fails('bettet cid:-Bilder auch bei einer verschlüsselten Mail ein', async () => {
        const uuid = uid();
        const { email, mailKey } = await derivedEmail(vault, uuid, { subject: 'Logo', from: 'f', to: 't', body: '<img src="cid:logo@x">' });
        email.attachments = [{
            uuid: 'a-img', size_bytes: 4, content_id: '<logo@x>', wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('logo.png', mailKey), encrypted_mimetype: await phpFieldHex('image/png', mailKey),
        }];
        const att = { uuid: 'a-img', email_uuid: uuid, wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('logo.png', mailKey), encrypted_content: await phpFieldHex(new Uint8Array([1, 2, 3]), mailKey) };
        fakeServer((name) => (name === 'read_email' ? email : att));

        await exportPdf(newProxy(), { email_uuid: uuid });

        const html = readFileSync(join(tmpdir(), 'aionda-mail-exports', uuid, 'email.html'), 'utf8');
        expect(html).toContain('data:image/png;base64,AQID');
    });
});
