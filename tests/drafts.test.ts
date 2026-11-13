/**
 * Entwürfe über den Proxy (persönlicher Schlüssel): lokal verschlüsselt,
 * Server sieht nur `encrypted_content`, Fortschreiben behält Nutzer-Ergänzungen.
 * HTTP-Gegenstelle als Attrappe; das Gegenstück auf dem Server prüft
 * tests/unit/Api/Services/McpEntwurfMenschTest.php gegen die echte Datenbank.
 *
 * Fehltrefferzahl: 0 am 13.11.2026 auf dem sauberen Baum.
 */
import { webcrypto } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { McpDecryptingProxy } from '../src/proxy';
import { decryptDraft, encryptDraft, mergeDraft, parseAddresses } from '../src/drafts';
import { toHex } from '../src/crypto/encoding';
import type { JsonRpcRequest } from '../src/types/mcp-protocol';

const schluessel = () => webcrypto.getRandomValues(new Uint8Array(32));

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('Entwurfsformat', () => {
    it('liest einen Entwurf im Format des Web-Composers (WebCrypto, iv_hex:ct_hex)', async () => {
        const key = schluessel();
        const iv  = webcrypto.getRandomValues(new Uint8Array(12));
        const aes = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
        const klar = JSON.stringify({ subject: 'Web', body: '<p>x</p>', to: [{ email: 'a@example.com' }] });
        const ct  = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, new TextEncoder().encode(klar)));
        const inhalt = await decryptDraft(`${toHex(iv)}:${toHex(ct)}`, key);
        expect(inhalt.subject).toBe('Web');
        expect(inhalt.to).toEqual([{ email: 'a@example.com' }]);
    });

    it('schreibt iv_hex(24):ct_hex und lehnt den falschen Schlüssel ab', async () => {
        const key = schluessel();
        const geheim = await encryptDraft({ subject: 's', body: 'b' }, key);
        expect(geheim).toMatch(/^[0-9a-f]{24}:[0-9a-f]{32,}$/);
        expect((await decryptDraft(geheim, key)).body).toBe('b');
        await expect(decryptDraft(geheim, schluessel())).rejects.toThrow();
    });

    it('zerlegt Adressen in allen Schreibweisen und wirft bei Unlesbarem', () => {
        expect(parseAddresses('a@x.de, "Jendrik S" <j@y.de>; b@z.de', 'to')).toEqual([
            { email: 'a@x.de' }, { email: 'j@y.de', name: 'Jendrik S' }, { email: 'b@z.de' },
        ]);
        expect(parseAddresses([{ email: 'c@x.de', name: '' }], 'cc')).toEqual([{ email: 'c@x.de' }]);
        expect(parseAddresses('', 'bcc')).toEqual([]);
        expect(() => parseAddresses('kein Empfänger', 'to')).toThrow(/to/);
    });

    it('ändert beim Fortschreiben nur übergebene Felder und behält Anhänge', () => {
        const bisher = {
            subject: 'Alt', body: 'alt', to: [{ email: 'a@x.de' }], priority: 'high',
            attachments: [{ name: 'nutzer.pdf', size: 1, type: 'application/pdf', content: 'AA==' }],
        };
        const neu = mergeDraft(bisher, { body: 'neu' }, [{ name: 'ki.txt', size: 1, type: 'text/plain', content: 'AQ==' }]);
        expect(neu.subject).toBe('Alt');
        expect(neu.body).toBe('neu');
        expect(neu.to).toEqual([{ email: 'a@x.de' }]);
        expect(neu.priority).toBe('high');
        expect(neu.attachments?.map(a => a.name)).toEqual(['nutzer.pdf', 'ki.txt']);
        expect(() => mergeDraft({}, {}, [])).toThrow(/subject or body/);
    });
});

describe('Proxy save_draft mit persönlichem Schlüssel', () => {
    function aufbau() {
        const key = schluessel();
        const ablage = new Map<string, string>();
        const anServer: { name: string; args: Record<string, unknown> }[] = [];
        vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
        vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string }) => {
            const req = JSON.parse(init.body) as JsonRpcRequest;
            const name = req.params?.name as string;
            const args = (req.params?.arguments ?? {}) as Record<string, unknown>;
            anServer.push({ name, args });
            let data: unknown;
            if (name === 'save_draft') {
                const id = (args.draft_id as string) ?? `draft-${ablage.size + 1}`;
                ablage.set(id, args.encrypted_content as string);
                data = { draft_id: id, saved: true };
            } else if (name === 'get_draft') {
                const geheim = ablage.get(args.draft_id as string);
                data = geheim ? { draft_id: args.draft_id, encrypted_content: geheim, updated_at: 'jetzt' }
                    : { error: true, message: 'Draft not found' };
            } else if (name === 'list_drafts') {
                data = { drafts: [...ablage].map(([draft_id, encrypted_content]) => ({ draft_id, encrypted_content })) };
            }
            return { headers: { get: () => null }, json: async () => ({ jsonrpc: '2.0', id: req.id, result: { content: [{ type: 'text', text: JSON.stringify(data) }] } }) };
        }));
        const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'fixture', vaultKey: 'fixture' });
        Object.assign(proxy as unknown as Record<string, unknown>, {
            masterKey: key, personalKey: true,
            signatureHtml: '<p>-- Signatur</p>', signatureAutoInsertNew: true,
        });
        const rufe = async (name: string, args: Record<string, unknown>) => {
            const r = await proxy.handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
            return JSON.parse((r.result as { content: { text: string }[] }).content[0].text) as Record<string, unknown>;
        };
        return { key, ablage, anServer, rufe };
    }

    it('schickt dem Server nur Geheimtext, den der macOS-Client lesen kann', async () => {
        const { key, ablage, anServer, rufe } = aufbau();
        const r = await rufe('save_draft', {
            to: 'jendrik@example.com', from_identity: 'ich@example.com',
            subject: 'Kanzleikosten', body: '<div>Tabelle</div>', lang: 'de',
        });
        expect(r.draft_id).toBe('draft-1');
        const gesendet = anServer.find(a => a.name === 'save_draft')!.args;
        expect(Object.keys(gesendet)).toEqual(['encrypted_content']);
        const inhalt = await decryptDraft(ablage.get('draft-1')!, key);
        expect(inhalt.subject).toBe('Kanzleikosten');
        expect(inhalt.to).toEqual([{ email: 'jendrik@example.com' }]);
        expect(inhalt.from_identity).toBe('ich@example.com');
        expect(inhalt.body).toContain('-- Signatur');
    });

    it('schreibt einen Entwurf fort, ohne Nutzer-Anhänge oder Signatur doppelt anzufassen', async () => {
        const { key, ablage, rufe } = aufbau();
        ablage.set('d-1', await encryptDraft({
            subject: 'Vom Nutzer', body: '<p>Entwurf</p><p>-- Signatur</p>', to: [{ email: 'a@x.de' }],
            attachments: [{ name: 'nutzer.pdf', size: 2, type: 'application/pdf', content: 'AAA=' }],
        }, key));
        await rufe('save_draft', { draft_id: 'd-1', body: '<p>Überarbeitet</p><p>-- Signatur</p>' });
        const inhalt = await decryptDraft(ablage.get('d-1')!, key);
        expect(inhalt.subject).toBe('Vom Nutzer');
        expect(inhalt.body).toBe('<p>Überarbeitet</p><p>-- Signatur</p>');
        expect(inhalt.attachments?.map(a => a.name)).toEqual(['nutzer.pdf']);
        expect(ablage.size).toBe(1);
    });

    it('liefert get_draft und list_drafts entschlüsselt, ohne Anhang-Nutzdaten', async () => {
        const { key, ablage, rufe } = aufbau();
        ablage.set('d-1', await encryptDraft({
            subject: 'S', body: 'B', to: [{ email: 'a@x.de', name: 'A' }],
            attachments: [{ name: 'n.pdf', size: 2, type: 'application/pdf', content: 'AAA=' }],
        }, key));
        const einzeln = await rufe('get_draft', { draft_id: 'd-1' });
        expect(einzeln).toMatchObject({ draft_id: 'd-1', subject: 'S', body: 'B', to: 'A <a@x.de>' });
        expect(einzeln.encrypted_content).toBeUndefined();
        expect(einzeln.attachments).toEqual([{ name: 'n.pdf', size: 2, type: 'application/pdf' }]);
        const liste = await rufe('list_drafts', {});
        expect((liste.drafts as Record<string, unknown>[])[0]).toMatchObject({ subject: 'S' });
    });

    it('meldet einen unbekannten Entwurf als Fehler und speichert nichts', async () => {
        const { ablage, anServer, rufe } = aufbau();
        const r = await rufe('save_draft', { draft_id: 'gibt-es-nicht', body: 'x' });
        expect(r.error).toBe(true);
        expect(String(r.message)).toContain('Draft not found');
        expect(anServer.some(a => a.name === 'save_draft')).toBe(false);
        expect(ablage.size).toBe(0);
    });
});
