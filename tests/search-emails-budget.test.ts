/**
 * search_emails im Proxy — #30209ea3
 *
 * Gemessen 04.11.2026: zwei Suchen lösten über 1000 Serveraufrufe aus
 * (624× read_email, 258× get_attachment), rissen die Grenze von 500
 * Aufrufen je Minute, und die Suche meldete danach nur
 * „Cannot read properties of undefined (reading 'content')“.
 *
 * Festgenagelt wird:
 *   - die Inhaltssuche liest höchstens SEARCH_CONTENT_CHECK_BUDGET Mails
 *   - der Rest wird gezählt und im Ergebnis genannt
 *   - ein Serverfehler (Ratenbegrenzung) kommt mit seiner Meldung zurück
 *     — beim Auflisten UND beim Lesen einer Mail
 *   - Gegenprobe: unter dem Budget wird jede Mail mit Anhang gelesen
 *
 * Der Server ist eine fetch-Attrappe; der Proxy läuft ohne Master Key, die
 * Antworten sind also Klartext (Entschlüsselung ist hier nicht die Frage).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('tesseract.js', () => {
    throw new Error('tesseract.js wird im Test nicht geladen');
});

import { McpDecryptingProxy, SEARCH_CONTENT_CHECK_BUDGET } from '../src/proxy';

type Call = { name: string; args: Record<string, unknown> };

function toolText(payload: unknown): unknown {
    return { content: [{ type: 'text', text: JSON.stringify(payload) }] };
}

function emails(n: number) {
    return Array.from({ length: n }, (_, i) => ({
        uuid: `mail-${i}`,
        subject: `Betreff ${i}`,
        from: 'absender@example.com',
        to: 'empfaenger@example.com',
        has_attachments: true,
    }));
}

/** Attrappe: list_emails liefert `count` Mails mit Anhang, read_email einen Text ohne Treffer. */
function fakeServer(count: number, opts: { rateLimitOn?: string } = {}) {
    const calls: Call[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string }) => {
        const req = JSON.parse(init.body);
        const name = req.params?.name as string;
        calls.push({ name, args: req.params?.arguments ?? {} });
        let body: unknown;
        if (name === opts.rateLimitOn) {
            body = { jsonrpc: '2.0', id: req.id, error: { code: -32000, message: 'Rate limit exceeded: max 500 tool calls per minute' } };
        } else if (name === 'list_emails') {
            body = { jsonrpc: '2.0', id: req.id, result: toolText({ emails: emails(count) }) };
        } else if (name === 'read_email') {
            body = { jsonrpc: '2.0', id: req.id, result: toolText({ body_text: 'nichts Passendes', attachments: [] }) };
        } else {
            throw new Error(`unerwarteter Aufruf ${name}`);
        }
        return { headers: { get: () => null }, json: async () => body } as unknown as Response;
    }));
    return calls;
}

async function search(args: Record<string, unknown>) {
    const proxy = new McpDecryptingProxy({ endpoint: 'https://example.invalid', apiKey: 'x', vaultKey: '' } as never);
    const resp = await proxy.handleRequest({
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'search_emails', arguments: args },
    });
    const result = resp.result as { content: { text: string }[]; isError?: boolean };
    return { data: JSON.parse(result.content[0].text), isError: result.isError === true };
}

afterEach(() => vi.unstubAllGlobals());

describe('search_emails: Budget der Inhaltssuche', () => {
    it('liest höchstens SEARCH_CONTENT_CHECK_BUDGET Mails und nennt den Rest', async () => {
        const calls = fakeServer(50);
        const { data, isError } = await search({ query: 'gibt-es-nicht', folders: ['inbox', 'sent', 'spam'] });

        expect(isError).toBe(false);
        const reads = calls.filter(c => c.name === 'read_email').length;
        expect(reads).toBe(SEARCH_CONTENT_CHECK_BUDGET);
        expect(data.total_searched).toBe(150);
        expect(data.content_search_skipped).toBe(150 - SEARCH_CONTENT_CHECK_BUDGET);
        expect(data.note).toContain(String(SEARCH_CONTENT_CHECK_BUDGET));
    });

    it('Gegenprobe: unter dem Budget wird jede Mail mit Anhang gelesen, kein Hinweis', async () => {
        const calls = fakeServer(SEARCH_CONTENT_CHECK_BUDGET - 1);
        const { data } = await search({ query: 'gibt-es-nicht', folders: ['inbox'] });

        expect(calls.filter(c => c.name === 'read_email').length).toBe(SEARCH_CONTENT_CHECK_BUDGET - 1);
        expect(data.content_search_skipped).toBeUndefined();
    });
});

describe('search_emails: Serverfehler kommen mit ihrer Meldung zurück', () => {
    it('Ratenbegrenzung bei list_emails', async () => {
        fakeServer(5, { rateLimitOn: 'list_emails' });
        const { data, isError } = await search({ query: 'x', folders: ['inbox'] });

        expect(isError).toBe(true);
        expect(data.message).toBe('Search failed: Rate limit exceeded: max 500 tool calls per minute');
    });

    it('Ratenbegrenzung bei read_email bricht ab, statt als „kein Treffer“ weiterzulaufen', async () => {
        const calls = fakeServer(5, { rateLimitOn: 'read_email' });
        const { data, isError } = await search({ query: 'gibt-es-nicht', folders: ['inbox'] });

        expect(isError).toBe(true);
        expect(data.message).toContain('Rate limit exceeded');
        expect(calls.filter(c => c.name === 'read_email').length).toBe(1);
    });
});
