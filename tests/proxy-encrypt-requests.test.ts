/**
 * Proxy: Klartext des Agenten wird vor dem Versand verschlüsselt
 * (Zero Knowledge) und Dateianhänge werden von der Platte geladen.
 *
 * Geprüft wird, was tatsächlich beim Server ankommt: Die Attrappe zeichnet
 * jede Anfrage auf, und der Test entschlüsselt die Felder mit dem echten
 * Master Key wieder. Klartext darf in der Anfrage nicht mehr vorkommen.
 */
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('tesseract.js', () => ({ createWorker: vi.fn() }));

import { McpDecryptingProxy } from '../src/proxy';
import { decryptClientAesGcm, decryptPhpAesGcm, decryptVaultData } from '../src/crypto/aes-gcm';
import { fromBase64, toBase64 } from '../src/crypto/encoding';
import { decryptTaskField, encryptTaskField, generateTaskKey, unwrapTaskKey, wrapTaskKey } from '../src/crypto/tasks-crypto';
import { fakeServer, makeVault, toolCall, unlock, type ServerCall, type Vault } from './helpers/vault';

let vault: Vault;
beforeAll(async () => { vault = await makeVault(); });

let stderr: ReturnType<typeof vi.spyOn>;
beforeEach(() => { stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true); });
afterEach(() => { vi.unstubAllGlobals(); stderr.mockRestore(); });

function newProxy(withKeys = true): McpDecryptingProxy {
    const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tma_x', vaultKey: 'tmv_x' });
    if (withKeys) unlock(proxy, vault);
    return proxy;
}

const dec = (b: Uint8Array): string => new TextDecoder().decode(b);
const sent = (calls: ServerCall[], name: string): Record<string, unknown> => {
    const c = calls.find(x => x.name === name);
    if (!c) throw new Error(`${name} wurde nicht gesendet`);
    return c.args;
};

describe('create_folder', () => {
    it('verschlüsselt den Ordnernamen mit dem Master Key, der Klartext geht nicht raus', async () => {
        const calls = fakeServer(() => ({ success: true }));
        await newProxy().handleRequest(toolCall('create_folder', { name: 'Steuer 2026', parent: 'p1' }));

        const args = sent(calls, 'create_folder');
        expect(args).not.toHaveProperty('name');
        expect(args.parent).toBe('p1');
        expect(dec(await decryptPhpAesGcm(fromBase64(String(args.encrypted_name)), vault.masterKey))).toBe('Steuer 2026');
    });

    it('ohne Master Key wird nichts verändert', async () => {
        const calls = fakeServer(() => ({ success: true }));
        await newProxy(false).handleRequest(toolCall('create_folder', { name: 'Klartext' }));
        expect(sent(calls, 'create_folder')).toEqual({ name: 'Klartext' });
    });
});

describe('Kalendertermine', () => {
    async function openField(args: Record<string, unknown>, field: string): Promise<string> {
        const eventKey = await decryptVaultData(fromBase64(String(args.wrapped_key)), vault.masterKey);
        return dec(await decryptClientAesGcm(fromBase64(String(args[field])), eventKey));
    }

    it('create_event: Titel, Beschreibung, Ort unter einem neuen Terminschlüssel', async () => {
        const calls = fakeServer(() => ({ success: true }));
        await newProxy().handleRequest(toolCall('create_event', {
            calendar_uuid: 'cal-1', title: 'Zahnarzt', description: 'Kontrolle', location: 'Praxis', start_time: 's',
        }));

        const args = sent(calls, 'create_event');
        expect(args).not.toHaveProperty('title');
        expect(args).not.toHaveProperty('description');
        expect(args).not.toHaveProperty('location');
        expect(args).toMatchObject({ calendar_uuid: 'cal-1', start_time: 's' });
        expect(await openField(args, 'encrypted_title')).toBe('Zahnarzt');
        expect(await openField(args, 'encrypted_description')).toBe('Kontrolle');
        expect(await openField(args, 'encrypted_location')).toBe('Praxis');
    });

    it('Klartext in den encrypted_*-Feldern (so steht es im Schema) wird ebenfalls verschlüsselt', async () => {
        const calls = fakeServer(() => ({ success: true }));
        await newProxy().handleRequest(toolCall('create_event', { encrypted_title: 'Meeting' }));
        const args = sent(calls, 'create_event');
        expect(args.encrypted_title).not.toBe('Meeting');
        expect(await openField(args, 'encrypted_title')).toBe('Meeting');
    });

    it('update_event: nur Beschreibung bzw. nur Ort bekommen einen Schlüssel, calendar_uuid fällt weg', async () => {
        const calls = fakeServer(() => ({ success: true }));
        const proxy = newProxy();
        await proxy.handleRequest(toolCall('update_event', { event_uuid: 'e1', calendar_uuid: 'cal-1', description: 'neu' }));
        await proxy.handleRequest(toolCall('update_event', { event_uuid: 'e2', location: 'Ort' }));

        const [a, b] = calls.filter(c => c.name === 'update_event').map(c => c.args);
        expect(a).not.toHaveProperty('calendar_uuid');
        expect(await openField(a, 'encrypted_description')).toBe('neu');
        expect(await openField(b, 'encrypted_location')).toBe('Ort');
    });

    it('create_event ohne Titel und update_event ohne Textfelder gehen unverändert raus', async () => {
        const calls = fakeServer(() => ({ success: true }));
        const proxy = newProxy();
        await proxy.handleRequest(toolCall('create_event', { description: 'nur Beschreibung' }));
        await proxy.handleRequest(toolCall('update_event', { event_uuid: 'e1', calendar_uuid: 'cal-1', start_time: 's' }));
        expect(calls[0].args).toEqual({ description: 'nur Beschreibung' });
        expect(calls[1].args).toEqual({ event_uuid: 'e1', calendar_uuid: 'cal-1', start_time: 's' });
    });
});

describe('Aufgaben', () => {
    it('create_task: eigener Aufgabenschlüssel, alle Textfelder verschlüsselt, Schritte normalisiert', async () => {
        const calls = fakeServer(() => ({ success: true }));
        await newProxy().handleRequest(toolCall('create_task', {
            list_uuid: 'l1', title: 'Steuer', notes: 'bis Freitag', steps: ['Belege', { title: 'Senden', completed: true }],
            metadata: { prio: 1 },
        }));

        const args = sent(calls, 'create_task');
        for (const k of ['title', 'notes', 'steps', 'metadata']) expect(args).not.toHaveProperty(k);
        const key = await unwrapTaskKey(fromBase64(String(args.wrapped_key)), vault.masterKey);
        expect(await decryptTaskField(String(args.encrypted_title), key, 'title')).toBe('Steuer');
        expect(await decryptTaskField(String(args.encrypted_notes), key, 'notes')).toBe('bis Freitag');
        expect(JSON.parse(await decryptTaskField(String(args.encrypted_steps), key, 'steps'))).toEqual([
            { id: 'step-0', title: 'Belege', completed: false },
            { id: 'step-1', title: 'Senden', completed: true },
        ]);
        expect(JSON.parse(await decryptTaskField(String(args.encrypted_metadata), key, 'metadata'))).toEqual({ prio: 1 });
        expect(args.list_uuid).toBe('l1');
    });

    it('create_task ohne Titel scheitert laut und sendet nichts', async () => {
        const calls = fakeServer(() => ({ success: true }));
        await expect(newProxy().handleRequest(toolCall('create_task', { notes: 'x' }))).rejects.toThrow('create_task requires a title');
        expect(calls).toHaveLength(0);
    });

    it('update_task: verschlüsselt mit dem BESTEHENDEN Aufgabenschlüssel, leere Felder werden null', async () => {
        const taskKey = generateTaskKey();
        const wrapped = toBase64(await wrapTaskKey(taskKey, vault.masterKey));
        const calls = fakeServer((name) => (name === 'list_tasks'
            ? { tasks: [{ uuid: 'other' }, { uuid: 't1', wrapped_key: wrapped }] }
            : { success: true }));

        await newProxy().handleRequest(toolCall('update_task', { task_uuid: 't1', title: 'Neu', notes: '', steps: [], metadata: null }));

        expect(calls.map(c => c.name)).toEqual(['list_tasks', 'update_task']);
        expect(calls[0].args).toEqual({ filter: 'all', include_completed: true, limit: 500 });
        const args = sent(calls, 'update_task');
        expect(args).not.toHaveProperty('wrapped_key');
        expect(await decryptTaskField(String(args.encrypted_title), taskKey, 'title')).toBe('Neu');
        expect(args.encrypted_notes).toBeNull();
        expect(args.encrypted_steps).toBeNull();
        expect(args.encrypted_metadata).toBeNull();
    });

    it('update_task: gefüllte Notizen, Schritte und Metadaten', async () => {
        const taskKey = generateTaskKey();
        const wrapped = toBase64(await wrapTaskKey(taskKey, vault.masterKey));
        const calls = fakeServer((name) => (name === 'list_tasks' ? { tasks: [{ uuid: 't1', wrapped_key: wrapped }] } : {}));

        await newProxy().handleRequest(toolCall('update_task', { task_uuid: 't1', notes: 'N', steps: ['a'], metadata: { x: 1 } }));

        const args = sent(calls, 'update_task');
        expect(args).not.toHaveProperty('encrypted_title');
        expect(await decryptTaskField(String(args.encrypted_notes), taskKey, 'notes')).toBe('N');
        expect(JSON.parse(await decryptTaskField(String(args.encrypted_steps), taskKey, 'steps'))).toEqual([{ id: 'step-0', title: 'a', completed: false }]);
        expect(JSON.parse(await decryptTaskField(String(args.encrypted_metadata), taskKey, 'metadata'))).toEqual({ x: 1 });
    });

    it('update_task ohne Textfelder: kein Nachladen, unverändert', async () => {
        const calls = fakeServer(() => ({}));
        await newProxy().handleRequest(toolCall('update_task', { task_uuid: 't1', is_completed: true }));
        expect(calls.map(c => c.name)).toEqual(['update_task']);
        expect(calls[0].args).toEqual({ task_uuid: 't1', is_completed: true });
    });

    it('update_task ohne task_uuid oder mit unbekannter Aufgabe scheitert, statt neu zu verschlüsseln', async () => {
        const calls = fakeServer((name) => (name === 'list_tasks' ? { tasks: [] } : {}));
        const proxy = newProxy();
        await expect(proxy.handleRequest(toolCall('update_task', { title: 'x' }))).rejects.toThrow('update_task requires task_uuid');
        await expect(proxy.handleRequest(toolCall('update_task', { task_uuid: 'weg', title: 'x' })))
            .rejects.toThrow('update_task: task weg not found - cannot re-encrypt fields');
        fakeServer(() => ({ __raw: { content: [] } }));
        await expect(proxy.handleRequest(toolCall('update_task', { task_uuid: 'weg', title: 'x' }))).rejects.toThrow(/not found/);
        expect(calls.filter(c => c.name === 'update_task')).toHaveLength(0);
    });

    it('create_task_list: Name mit eigenem Listenschlüssel; ohne Namen Abbruch', async () => {
        const calls = fakeServer(() => ({}));
        const proxy = newProxy();
        await proxy.handleRequest(toolCall('create_task_list', { name: 'Einkauf' }));
        const args = sent(calls, 'create_task_list');
        expect(args).not.toHaveProperty('name');
        const key = await unwrapTaskKey(fromBase64(String(args.wrapped_key)), vault.masterKey);
        expect(await decryptTaskField(String(args.encrypted_name), key, 'list-name')).toBe('Einkauf');

        await expect(proxy.handleRequest(toolCall('create_task_list', {}))).rejects.toThrow('create_task_list requires a name');
    });

    it('bestehende Aufgabe aus dem Web bleibt nach update_task lesbar (unveränderte Felder)', async () => {
        const taskKey = generateTaskKey();
        const wrapped = toBase64(await wrapTaskKey(taskKey, vault.masterKey));
        const alteNotiz = await encryptTaskField('alte Notiz', taskKey, 'notes');
        const calls = fakeServer((name) => (name === 'list_tasks' ? { tasks: [{ uuid: 't1', wrapped_key: wrapped, encrypted_notes: alteNotiz }] } : {}));
        await newProxy().handleRequest(toolCall('update_task', { task_uuid: 't1', title: 'Neu' }));
        const args = sent(calls, 'update_task');
        // Der Schlüssel ist derselbe – die alte Notiz geht weiter auf.
        expect(await decryptTaskField(alteNotiz, taskKey, 'notes')).toBe('alte Notiz');
        expect(await decryptTaskField(String(args.encrypted_title), taskKey, 'title')).toBe('Neu');
        expect(args).not.toHaveProperty('encrypted_notes');
    });
});

describe('Dateianhänge', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-anhang-'));
    const pdf = join(dir, 'rechnung.pdf');
    const unbekannt = join(dir, 'daten.xyz');
    writeFileSync(pdf, '%PDF-1.4 test');
    writeFileSync(unbekannt, Buffer.from([1, 2, 3]));

    it('attachment_path (Text) wird geladen, base64-kodiert, Typ aus der Endung', async () => {
        const calls = fakeServer(() => ({ success: true }));
        await newProxy().handleRequest(toolCall('send_email', { to: 'a@example.com', body: 'x', attachment_path: pdf }));
        const args = sent(calls, 'send_email');
        expect(args).not.toHaveProperty('attachment_path');
        expect(args.attachments).toEqual([{
            filename: 'rechnung.pdf', content: Buffer.from('%PDF-1.4 test').toString('base64'),
            mimetype: 'application/pdf', size: 13,
        }]);
    });

    it('attachment_paths (Liste): eigener Name/Typ bleibt, unbekannte Endung wird octet-stream, fehlende Datei wird übersprungen', async () => {
        const calls = fakeServer(() => ({ success: true }));
        await newProxy().handleRequest(toolCall('reply_email', {
            email_uuid: 'm1', body: 'x',
            attachment_paths: [pdf, unbekannt, join(dir, 'gibt-es-nicht.txt'), { file_path: pdf, filename: 'umbenannt.bin', mimetype: 'x/y' }],
        }));
        const atts = sent(calls, 'reply_email').attachments as Record<string, unknown>[];
        expect(atts.map(a => [a.filename, a.mimetype, a.size])).toEqual([
            ['rechnung.pdf', 'application/pdf', 13],
            ['daten.xyz', 'application/octet-stream', 3],
            ['umbenannt.bin', 'x/y', 13],
        ]);
        expect(stderr.mock.calls.map(c => String(c[0])).join('')).toMatch(/Failed to read attachment .*gibt-es-nicht\.txt/);
    });

    it('lässt sich kein einziger Anhang laden, wird NICHT ohne Anhang gesendet', async () => {
        const calls = fakeServer(() => ({ success: true }));
        await expect(newProxy().handleRequest(toolCall('forward_email', {
            email_uuid: 'm1', attachments: [{ file_path: join(dir, 'weg.pdf') }, { filename: 'ohne-pfad' }],
        }))).rejects.toThrow('All attachments failed to load. Check file paths and permissions.');
        expect(calls).toHaveLength(0);
    });

    it('bei anderen Werkzeugen werden Anhangsparameter nicht angefasst', async () => {
        const calls = fakeServer(() => ({}));
        await newProxy().handleRequest(toolCall('save_draft', { attachment_path: pdf }));
        expect(sent(calls, 'save_draft')).toEqual({ attachment_path: pdf });
    });
});
