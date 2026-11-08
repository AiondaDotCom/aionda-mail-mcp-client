/**
 * Proxy: Antworten des Servers werden lokal entschlüsselt, bevor sie den
 * Agenten erreichen.
 *
 * Der Server ist eine fetch-Attrappe; jedes verschlüsselte Feld wird hier mit
 * echter Krypto erzeugt (Hybrid-KEM-Kapsel, AES-GCM im Server- bzw.
 * Clientformat, HKDF-abgeleitete Schlüssel). Geprüft wird, was beim Agenten
 * ankommt.
 */
import { existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('tesseract.js', () => ({ createWorker: vi.fn() }));

import { McpDecryptingProxy } from '../src/proxy';
import { encryptPhpAesGcm, encryptVaultData } from '../src/crypto/aes-gcm';
import { toBase64, toHex } from '../src/crypto/encoding';
import { hybridEncapsulate } from '../src/crypto/hybrid-kem';
import { encryptTaskField, generateTaskKey, wrapTaskKey } from '../src/crypto/tasks-crypto';
import {
    aesGcmRaw, clientFieldB64, derivedEmail, fakeServer, incomingShare, kemEmail, makeVault,
    payloadOf, phpFieldHex, rewrapForFolder, rnd, toolCall, unlock, utf8, type Vault,
} from './helpers/vault';

let vault: Vault;
beforeAll(async () => { vault = await makeVault(); });

let stderr: ReturnType<typeof vi.spyOn>;
beforeEach(() => { stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true); });
afterEach(() => { vi.unstubAllGlobals(); stderr.mockRestore(); });

function newProxy(withKeys = true): McpDecryptingProxy {
    const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test/mcp', apiKey: 'tma_x', vaultKey: 'tmv_x' });
    if (withKeys) unlock(proxy, vault);
    return proxy;
}

/** Bucket-Padding wie im Server: 0xDEAD || u32 Länge || Daten || Füllung bis 256. */
function bucketPad(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(256);
    out.set([0xde, 0xad, 0, 0, (data.length >> 8) & 0xff, data.length & 0xff]);
    out.set(data, 6);
    out.set(rnd(256 - 6 - data.length), 6 + data.length);
    return out;
}

describe('list_emails', () => {
    it('entschlüsselt KEM- und HKDF-Mails, eine kaputte Mail wird als solche gemeldet', async () => {
        const kem = await kemEmail(vault, 'm-kem', { subject: '=?UTF-8?B?w4RyZ2VyIG1pdCBVbWxhdXQ=?=', from: 'alice@example.com', to: 'bob@example.com' });
        const der = await derivedEmail(vault, 'm-der', { subject: 'Abgeleitet', from: 'carol@example.com', to: 'dave@example.com' });
        const fremd = await kemEmail(await makeVault(), 'm-fremd', { subject: 'geheim', from: 'x', to: 'y' });
        fakeServer(() => ({ emails: [kem.email, der.email, fremd.email], total: 3 }));

        const resp = await newProxy().handleRequest(toolCall('list_emails', { folder: 'inbox' }));
        const data = payloadOf(resp) as { emails: Record<string, unknown>[]; total: number };

        expect(data.total).toBe(3);
        expect(data.emails[0]).toMatchObject({
            uuid: 'm-kem', subject: 'Ärger mit Umlaut', from: 'alice@example.com', to: 'bob@example.com',
            size_bytes: 1234, is_starred: true, received_at: '2026-01-02T03:04:05Z', thread_id: 'thread-1',
        });
        expect(data.emails[0]).not.toHaveProperty('encrypted_subject');
        expect(data.emails[1]).toMatchObject({ uuid: 'm-der', subject: 'Abgeleitet', from: 'carol@example.com' });
        expect(data.emails[2]).toMatchObject({ uuid: 'm-fremd', subject: '[Decryption failed]', from: '[encrypted]' });
        expect(String(data.emails[2].decryption_error)).not.toBe('');
        expect(JSON.stringify(data)).not.toContain('geheim');
    });

    it('ohne Schlüssel bleibt die Antwort unverändert (kein Entschlüsselungsversuch)', async () => {
        const kem = await kemEmail(vault, 'm1', { subject: 's', from: 'f', to: 't' });
        fakeServer(() => ({ emails: [kem.email] }));
        const resp = await newProxy(false).handleRequest(toolCall('list_emails'));
        expect((payloadOf(resp).emails as unknown[])[0]).toEqual(kem.email);
    });

    it('Mail aus einem geteilten Ordner: Mailschlüssel kommt über den Ordnerschlüssel', async () => {
        const owner = await makeVault();
        const folderKey = rnd(32);
        const { email, mailKey } = await kemEmail(owner, 'm-shared', { subject: 'Aus dem Teamordner', from: 'owner@example.com', to: 'team@example.com' });
        Object.assign(email, { folder_uuid: 'folder-1', ...await rewrapForFolder(mailKey, folderKey) });
        const share = await incomingShare(vault, folderKey, { folder_uuid: 'folder-1', share_uuid: 'share-1' });
        const calls = fakeServer((name) => {
            if (name === 'list_folders') return { folders: [], shared_folders: { incoming: [share] } };
            return { emails: [email] };
        });

        const proxy = newProxy();
        const first = payloadOf(await proxy.handleRequest(toolCall('list_emails', { folder: 'folder:folder-1' })));
        const second = payloadOf(await proxy.handleRequest(toolCall('list_emails', { folder: 'folder:folder-1' })));

        expect((first.emails as Record<string, unknown>[])[0].subject).toBe('Aus dem Teamordner');
        expect((second.emails as Record<string, unknown>[])[0].subject).toBe('Aus dem Teamordner');
        // Die Freigaben werden einmal geholt und danach aus dem Zwischenspeicher genommen.
        expect(calls.filter(c => c.name === 'list_folders')).toHaveLength(1);
    });

    it('geteilter Ordner, aber Ordnerschlüssel passt nicht: Mail wird als nicht entschlüsselbar gemeldet', async () => {
        const folderKey = rnd(32);
        const { email, mailKey } = await kemEmail(await makeVault(), 'm-x', { subject: 's', from: 'f', to: 't' });
        Object.assign(email, { folder_uuid: 'folder-1', ...await rewrapForFolder(mailKey, rnd(32)) });
        const share = await incomingShare(vault, folderKey, { folder_uuid: 'folder-1' });
        fakeServer((name) => name === 'list_folders'
            ? { shared_folders: { incoming: [share] } }
            : { emails: [email] });

        const data = payloadOf(await newProxy().handleRequest(toolCall('list_emails')));
        expect((data.emails as Record<string, unknown>[])[0].subject).toBe('[Decryption failed]');
        expect(stderr.mock.calls.map(c => String(c[0])).join('')).toMatch(/Shared folder key decryption failed/);
    });
});

describe('read_email', () => {
    it('entschlüsselt Inhalt, Kopfzeilen und Anhangsmetadaten', async () => {
        const headers = 'Message-ID: <abc@example.com>\r\nReply-To: antwort@example.com\r\n';
        const { email, mailKey } = await kemEmail(vault, 'm-full', {
            subject: 'Rechnung', from: 'shop@example.com', to: 'me@example.com',
            body: '<p>Hallo</p>', bodyText: 'Hallo', headers,
        }, { has_attachments: true, attachment_count: 1, signature_status: 'valid' });
        email.attachments = [{
            uuid: 'att-1', size_bytes: 10,
            wrapped_ephemeral_key: email.wrapped_ephemeral_key,
            encrypted_filename: await phpFieldHex('=?UTF-8?Q?R=C3=BCckseite.pdf?=', mailKey),
            encrypted_mimetype: await phpFieldHex('application/pdf', mailKey),
            ephemeral_key_iv: '',
        }];
        fakeServer(() => email);

        const data = payloadOf(await newProxy().handleRequest(toolCall('read_email', { email_uuid: 'm-full' })));

        expect(data).toMatchObject({
            uuid: 'm-full', subject: 'Rechnung', from: 'shop@example.com', to: 'me@example.com',
            body: '<p>Hallo</p>', body_text: 'Hallo', headers,
            message_id: 'abc@example.com', reply_to: 'antwort@example.com', signature_status: 'valid',
            has_attachments: true, attachment_count: 1,
        });
        expect(data.attachments).toEqual([{ uuid: 'att-1', filename: 'Rückseite.pdf', mimetype: 'application/pdf', sizeBytes: 10 }]);
    });

    it('nicht entschlüsselbar: Agent bekommt eine klare Meldung statt Chiffrat', async () => {
        const { email } = await kemEmail(await makeVault(), 'm-bad', { subject: 'x', from: 'y', to: 'z', body: 'GEHEIMER INHALT' });
        fakeServer(() => email);
        const data = payloadOf(await newProxy().handleRequest(toolCall('read_email', { email_uuid: 'm-bad' })));
        expect(data.subject).toBe('[Decryption failed]');
        expect(String(data.body)).toMatch(/^\[Decryption failed: .*could not be decrypted with the current vault keys/);
        expect(data).not.toHaveProperty('encrypted_body');
    });
});

describe('list_folders', () => {
    it('entschlüsselt Ordnernamen (auch gepolstert und komprimiert), kaputte bleiben, Freigaben werden gemerkt', async () => {
        const plain = toBase64(await encryptPhpAesGcm(utf8('Projekte'), vault.masterKey));
        const packed = toBase64(await encryptPhpAesGcm(bucketPad(new Uint8Array(gzipSync(utf8('Steuer 2026')))), vault.masterKey));
        const broken = toBase64(rnd(40));
        const share = { folder_uuid: 'shared-1', share_uuid: 's-1' };
        const calls = fakeServer((name) => name === 'list_folders'
            ? { folders: [
                { uuid: 'f1', encrypted_name: plain },
                { uuid: 'f2', encrypted_name: packed },
                { uuid: 'f3', encrypted_name: broken },
                { uuid: 'f4', folder_type: 'inbox' },
            ], shared_folders: { incoming: [share] } }
            : { emails: [] });

        const proxy = newProxy();
        const data = payloadOf(await proxy.handleRequest(toolCall('list_folders')));
        const folders = data.folders as Record<string, unknown>[];

        expect(folders[0]).toEqual({ uuid: 'f1', name: 'Projekte' });
        expect(folders[1]).toEqual({ uuid: 'f2', name: 'Steuer 2026' });
        expect(folders[2]).toEqual({ uuid: 'f3', encrypted_name: broken });
        expect(folders[3]).toEqual({ uuid: 'f4', folder_type: 'inbox' });
        expect((proxy as unknown as { cachedIncomingShares: unknown[] }).cachedIncomingShares).toEqual([share]);
        expect(calls).toHaveLength(1);
    });
});

describe('Kalender', () => {
    it('list_calendars: Kalenderschlüssel aus dem Umschlag, Name im Client-, Beschreibung im Serverformat', async () => {
        const calKey = rnd(32);
        const cal = {
            uuid: 'cal-1', color: '#f00', is_default: true, event_count: 3, sort_order: 1,
            created_at: 'c', updated_at: 'u',
            encrypted_calendar_key: toBase64(await encryptVaultData(calKey, vault.masterKey)),
            encrypted_name: await clientFieldB64('Familie', calKey),
            encrypted_description: toBase64(await encryptPhpAesGcm(utf8('Geburtstage'), calKey)),
        };
        const kurzerSchluessel = { uuid: 'cal-2', encrypted_calendar_key: toBase64(await encryptVaultData(rnd(16), vault.masterKey)) };
        const fremd = { uuid: 'cal-3', encrypted_calendar_key: toBase64(await encryptVaultData(calKey, rnd(32))) };
        const unlesbarerName = {
            uuid: 'cal-4',
            encrypted_calendar_key: toBase64(await encryptVaultData(calKey, vault.masterKey)),
            encrypted_name: toBase64(rnd(50)),
        };
        const ohne = { uuid: 'cal-5', name: 'unverschlüsselt' };
        fakeServer(() => ({ calendars: [cal, kurzerSchluessel, fremd, unlesbarerName, ohne] }));

        const data = payloadOf(await newProxy().handleRequest(toolCall('list_calendars')));
        const cals = data.calendars as Record<string, unknown>[];

        expect(cals[0]).toEqual({
            uuid: 'cal-1', name: 'Familie', description: 'Geburtstage', color: '#f00', is_default: true,
            event_count: 3, sort_order: 1, created_at: 'c', updated_at: 'u',
        });
        expect(cals[1]).toEqual(kurzerSchluessel);
        expect(cals[2]).toEqual(fremd);
        expect(cals[3]).toMatchObject({ uuid: 'cal-4', name: 'cal-4', description: null });
        expect(cals[4]).toEqual(ohne);
    });

    it('calendars werden nur bei list_calendars angefasst', async () => {
        const cal = { uuid: 'cal-1', encrypted_calendar_key: 'xyz' };
        fakeServer(() => ({ calendars: [cal] }));
        const data = payloadOf(await newProxy().handleRequest(toolCall('some_other_tool')));
        expect(data.calendars).toEqual([cal]);
    });

    it('list_events: alle Felder, Teilnehmer als JSON, kaputtes JSON wird null', async () => {
        const eventKey = rnd(32);
        const evt = {
            uuid: 'e1', calendar_uuid: 'cal-1', start_time: 's', end_time: 'e', is_all_day: false,
            status: 'confirmed', is_private: false, calendar_color: '#0f0', created_at: 'c', updated_at: 'u',
            wrapped_key: toBase64(await encryptVaultData(eventKey, vault.masterKey)),
            encrypted_title: await clientFieldB64('Zahnarzt', eventKey),
            encrypted_description: await clientFieldB64('Kontrolle', eventKey),
            encrypted_location: await clientFieldB64('Hauptstraße 1', eventKey),
            encrypted_attendees: await clientFieldB64(JSON.stringify([{ email: 'a@example.com' }]), eventKey),
            encrypted_metadata: await clientFieldB64('{kein json', eventKey),
        };
        const ohneTitel = {
            uuid: 'e2', wrapped_key: toBase64(await encryptVaultData(eventKey, vault.masterKey)),
            encrypted_title: toBase64(rnd(40)),
            encrypted_metadata: await clientFieldB64('{"farbe":"rot"}', eventKey),
            encrypted_attendees: await clientFieldB64('kaputt', eventKey),
        };
        const kaputt = { uuid: 'e3', wrapped_key: toBase64(rnd(60)) };
        const kurz = { uuid: 'e4', wrapped_key: toBase64(await encryptVaultData(rnd(8), vault.masterKey)) };
        fakeServer(() => ({ events: [evt, ohneTitel, kaputt, kurz, { uuid: 'e5' }] }));

        const data = payloadOf(await newProxy().handleRequest(toolCall('list_shared_events')));
        const events = data.events as Record<string, unknown>[];

        expect(events[0]).toEqual({
            uuid: 'e1', calendar_uuid: 'cal-1', title: 'Zahnarzt', description: 'Kontrolle',
            location: 'Hauptstraße 1', attendees: [{ email: 'a@example.com' }], metadata: null,
            start_time: 's', end_time: 'e', is_all_day: false, status: 'confirmed', is_private: false,
            calendar_color: '#0f0', created_at: 'c', updated_at: 'u',
        });
        expect(events[1]).toMatchObject({ uuid: 'e2', title: '[encrypted]', metadata: { farbe: 'rot' }, attendees: null });
        expect(events[2]).toEqual(kaputt);
        expect(events[3]).toEqual(kurz);
        expect(events[4]).toEqual({ uuid: 'e5' });
    });

    it('list_shared_calendars: Anzeigename über die KEM-Kapsel, ohne Kapsel Eigentümer / UUID', async () => {
        const kem = await hybridEncapsulate(vault.publicKeys.x25519, vault.publicKeys.mlkem);
        const nonce = rnd(12);
        const sc = {
            share_uuid: 'sh-1', calendar_uuid: 'cal-9', owner_username: 'chef', calendar_color: '#00f',
            can_read: true, can_create: false, can_edit: false, can_delete: false, can_invite: false, can_manage: false,
            role_preset: 'viewer', event_count: 4,
            encrypted_display_name: toBase64(await aesGcmRaw(kem.sharedSecret, nonce, utf8('Urlaubsplan'))),
            x25519_ephemeral: toBase64(kem.x25519Ciphertext),
            mlkem_ciphertext: toBase64(new Uint8Array(kem.mlKemCiphertext)),
            display_name_nonce: toBase64(nonce),
        };
        const kaputt = { ...sc, share_uuid: 'sh-2', display_name_nonce: toBase64(rnd(12)) };
        fakeServer(() => ({ incoming: [sc, kaputt, { share_uuid: 'sh-3', owner_username: 'x', calendar_uuid: 'c3' }] }));

        const data = payloadOf(await newProxy().handleRequest(toolCall('list_shared_calendars')));
        const incoming = data.incoming as Record<string, unknown>[];

        expect(incoming[0]).toEqual({
            share_uuid: 'sh-1', calendar_uuid: 'cal-9', name: 'chef / Urlaubsplan', owner: 'chef',
            calendar_color: '#00f', can_read: true, can_create: false, can_edit: false, can_delete: false,
            can_invite: false, can_manage: false, role_preset: 'viewer', event_count: 4,
        });
        expect(incoming[1].name).toBe('chef / cal-9');
        expect(incoming[2].name).toBe('x / c3');
    });
});

describe('Aufgaben', () => {
    it('list_tasks: Titel, Notizen, Schritte, Metadaten; kaputte Schritte kippen die Aufgabe nicht', async () => {
        const taskKey = generateTaskKey();
        const wrapped = toBase64(await wrapTaskKey(taskKey, vault.masterKey));
        const task = {
            uuid: 't1', list_uuid: 'l1', due_date: 'd', reminder_time: null, is_important: true, is_completed: false,
            completed_at: null, my_day_date: null, linked_email_uuid: 'm1', position: 2, created_at: 'c', updated_at: 'u',
            wrapped_key: wrapped,
            encrypted_title: await encryptTaskField('Steuer machen', taskKey, 'title'),
            encrypted_notes: await encryptTaskField('bis Freitag', taskKey, 'notes'),
            encrypted_steps: await encryptTaskField(JSON.stringify(['Belege', { title: 'Abschicken', completed: true }]), taskKey, 'steps'),
            encrypted_metadata: await encryptTaskField('{"prio":1}', taskKey, 'metadata'),
        };
        const kaputteSchritte = {
            uuid: 't2', wrapped_key: wrapped,
            encrypted_steps: await encryptTaskField('{kaputt', taskKey, 'steps'),
            encrypted_metadata: await encryptTaskField('{kaputt', taskKey, 'metadata'),
        };
        const fremd = { uuid: 't3', wrapped_key: toBase64(await wrapTaskKey(taskKey, rnd(32))) };
        fakeServer(() => ({ tasks: [task, kaputteSchritte, fremd, { uuid: 't4' }] }));

        const data = payloadOf(await newProxy().handleRequest(toolCall('list_tasks')));
        const tasks = data.tasks as Record<string, unknown>[];

        expect(tasks[0]).toEqual({
            uuid: 't1', list_uuid: 'l1', title: 'Steuer machen', notes: 'bis Freitag',
            steps: [
                { id: 'step-0', title: 'Belege', completed: false },
                { id: 'step-1', title: 'Abschicken', completed: true },
            ],
            metadata: { prio: 1 }, due_date: 'd', reminder_time: null, is_important: true, is_completed: false,
            completed_at: null, my_day_date: null, linked_email_uuid: 'm1', position: 2, created_at: 'c', updated_at: 'u',
        });
        expect(tasks[1]).toMatchObject({ uuid: 't2', title: '[encrypted]', steps: [], metadata: null });
        expect(tasks[2]).toEqual(fremd);
        expect(tasks[3]).toEqual({ uuid: 't4' });
    });

    it('list_task_lists: Name mit eigenem Listenschlüssel, ohne Namen die UUID', async () => {
        const listKey = generateTaskKey();
        const wrapped = toBase64(await wrapTaskKey(listKey, vault.masterKey));
        const encName = await encryptTaskField('Einkauf', listKey, 'list-name');
        fakeServer(() => ({ lists: [
            { uuid: 'l1', wrapped_key: wrapped, encrypted_name: encName, position: 0, is_default: true, task_count: 5, created_at: 'c', updated_at: 'u' },
            { uuid: 'l2', wrapped_key: wrapped },
            { uuid: 'l3', wrapped_key: toBase64(rnd(80)) },
            { uuid: 'l4' },
        ] }));

        const data = payloadOf(await newProxy().handleRequest(toolCall('list_task_lists')));
        const lists = data.lists as Record<string, unknown>[];

        expect(lists[0]).toEqual({ uuid: 'l1', name: 'Einkauf', position: 0, is_default: true, task_count: 5, created_at: 'c', updated_at: 'u' });
        expect(lists[1]).toMatchObject({ uuid: 'l2', name: 'l2' });
        expect(lists[2]).toHaveProperty('wrapped_key');
        expect(lists[3]).toEqual({ uuid: 'l4' });
    });
});

describe('get_attachment', () => {
    it('entschlüsselt Name, Typ und Inhalt und legt die Datei ohne Pfadausbruch ab', async () => {
        const { email, mailKey } = await kemEmail(vault, 'm-att', { subject: 's', from: 'f', to: 't' });
        const inhalt = utf8('%PDF-1.4 Inhalt der Rechnung');
        const attUuid = `att-${toHex(rnd(4))}`;
        const att = {
            uuid: attUuid, email_uuid: 'm-att',
            wrapped_ephemeral_key: email.wrapped_ephemeral_key,
            encrypted_filename: await phpFieldHex('../böse:datei.pdf', mailKey),
            encrypted_mimetype: await phpFieldHex('application/pdf', mailKey),
            encrypted_content: await phpFieldHex(inhalt, mailKey),
        };
        fakeServer(() => att);

        const data = payloadOf(await newProxy().handleRequest(toolCall('get_attachment', { attachment_uuid: attUuid })));

        expect(data).toMatchObject({ uuid: attUuid, email_uuid: 'm-att', filename: '../böse:datei.pdf', mimetype: 'application/pdf', file_size_bytes: inhalt.length });
        const filePath = String(data.file_path);
        expect(filePath).toMatch(new RegExp(`aionda-mail-attachments/${attUuid}/\\.\\._böse_datei\\.pdf$`));
        expect(readFileSync(filePath)).toEqual(Buffer.from(inhalt));
        expect(data.note).toBe(`File saved to ${filePath}. Use the Read tool to view the file content.`);
    });

    it('Anhang aus einem geteilten Ordner: eigener Schlüssel scheitert, der Ordnerschlüssel öffnet ihn', async () => {
        const owner = await makeVault();
        const folderKey = rnd(32);
        const { email, mailKey } = await kemEmail(owner, 'm-team', { subject: 's', from: 'f', to: 't' });
        Object.assign(email, { folder_uuid: 'tf', ...await rewrapForFolder(mailKey, folderKey) });
        const share = await incomingShare(vault, folderKey, { folder_uuid: 'tf' });
        const attUuid = `att-${toHex(rnd(4))}`;
        const att = {
            uuid: attUuid, email_uuid: 'm-team',
            // Der Server legt kein Material für den Empfänger an den Anhang.
            wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('plan.txt', mailKey),
            encrypted_content: await phpFieldHex('Teaminhalt', mailKey),
        };
        const calls = fakeServer((name) => {
            if (name === 'get_attachment') return att;
            if (name === 'read_email') return { data: email };
            return { shared_folders: { incoming: [share] } };
        });

        const data = payloadOf(await newProxy().handleRequest(toolCall('get_attachment', { attachment_uuid: attUuid })));

        expect(data).toMatchObject({ filename: 'plan.txt', mimetype: 'application/octet-stream' });
        expect(readFileSync(String(data.file_path), 'utf8')).toBe('Teaminhalt');
        expect(calls.map(c => c.name)).toEqual(['get_attachment', 'read_email', 'list_folders']);
    });

    it('weder eigener noch Ordnerschlüssel: Antwort bleibt verschlüsselt, keine Datei', async () => {
        const fremd = rnd(32);
        const attUuid = `att-${toHex(rnd(4))}`;
        const att = {
            uuid: attUuid, email_uuid: 'm-weg', wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('x.txt', fremd),
            encrypted_content: await phpFieldHex('x', fremd),
        };
        fakeServer((name) => (name === 'get_attachment' ? att : { error: true, msg: 'not found' }));

        const data = payloadOf(await newProxy().handleRequest(toolCall('get_attachment', { attachment_uuid: attUuid })));

        expect(data).toEqual(att);
        expect(stderr.mock.calls.map(c => String(c[0])).join('')).toMatch(/Attachment decryption failed/);
    });

    it('Antwort ohne encrypted_content wird nicht angefasst, es entsteht keine Datei', async () => {
        const { email, mailKey } = await kemEmail(vault, 'm-meta', { subject: 's', from: 'f', to: 't' });
        const attUuid = `att-${toHex(rnd(4))}`;
        const encMime = await phpFieldHex('text/plain', mailKey);
        fakeServer(() => ({
            uuid: attUuid, email_uuid: 'm-meta', wrapped_ephemeral_key: email.wrapped_ephemeral_key,
            encrypted_content: '', encrypted_mimetype: encMime,
        }));
        const resp = await newProxy().handleRequest(toolCall('get_attachment', { attachment_uuid: attUuid }));
        const data = payloadOf(resp);
        expect(data).toMatchObject({ encrypted_content: '' });
        expect(existsSync(join(tmpdir(), 'aionda-mail-attachments', attUuid))).toBe(false);
    });
});

describe('Durchreichen ohne Eingriff', () => {
    it('Nicht-JSON, fehlender Textinhalt, Fehlerantworten und andere Methoden bleiben unverändert', async () => {
        const proxy = newProxy();

        fakeServer(() => ({ __raw: { content: [{ type: 'text', text: 'kein json' }] } }));
        expect((await proxy.handleRequest(toolCall('list_emails'))).result).toEqual({ content: [{ type: 'text', text: 'kein json' }] });

        fakeServer(() => ({ __raw: { content: [{ type: 'image', text: '' }] } }));
        expect((await proxy.handleRequest(toolCall('list_emails'))).result).toEqual({ content: [{ type: 'image', text: '' }] });

        fakeServer(() => ({ __raw: { isError: false } }));
        expect((await proxy.handleRequest(toolCall('list_emails'))).result).toEqual({ isError: false });

        fakeServer(() => ({ ok: true }));
        expect(payloadOf(await proxy.handleRequest(toolCall('mark_read')))).toEqual({ ok: true });

        fakeServer(() => ({ __error: { code: 59, message: 'not found' } }));
        expect((await proxy.handleRequest(toolCall('read_email'))).error).toEqual({ code: 59, message: 'not found' });

        const calls = fakeServer(() => ({}));
        const resp = await proxy.handleRequest({ jsonrpc: '2.0', id: 9, method: 'tools/list' });
        expect(resp).toEqual({ jsonrpc: '2.0', id: 9, result: {} });
        expect(calls[0]).toMatchObject({ method: 'tools/list', headers: { Authorization: 'Bearer tma_x' } });
    });

    it('Benachrichtigungen ohne id liefern keinen Inhalt zurück', async () => {
        fakeServer(() => ({}));
        const resp = await newProxy().handleRequest({ jsonrpc: '2.0', method: 'notifications/initialized' });
        expect(resp).toEqual({ jsonrpc: '2.0' });
    });

    it('Endpunkt ohne /mcp bekommt den Pfad angehängt, mit /mcp bleibt er', async () => {
        const calls: string[] = [];
        vi.stubGlobal('fetch', vi.fn(async (url: string) => {
            calls.push(url);
            return { headers: { get: () => null }, json: async () => ({ jsonrpc: '2.0', id: 1, result: {} }) };
        }));
        await new McpDecryptingProxy({ endpoint: 'https://a.test', apiKey: 'k', vaultKey: 'v' }).handleRequest({ jsonrpc: '2.0', id: 1, method: 'ping' });
        await new McpDecryptingProxy({ endpoint: 'https://b.test/mcp', apiKey: 'k', vaultKey: 'v' }).handleRequest({ jsonrpc: '2.0', id: 1, method: 'ping' });
        expect(calls).toEqual(['https://a.test/mcp', 'https://b.test/mcp']);
    });
});

describe('Ränder der Schlüsselsuche', () => {
    it('rewrapped_key ohne passende Freigabe oder ohne Ordner: der eigene Schlüssel öffnet die Mail', async () => {
        const a = await kemEmail(vault, 'm-a', { subject: 'Eigene A', from: 'f', to: 't' });
        Object.assign(a.email, { folder_uuid: 'unbekannt', rewrapped_key: 'eA==', key_nonce: 'eA==' });
        const b = await kemEmail(vault, 'm-b', { subject: 'Eigene B', from: 'f', to: 't' });
        Object.assign(b.email, { folder_uuid: null, rewrapped_key: 'eA==', key_nonce: 'eA==' });
        const calls = fakeServer((name) => (name === 'list_folders' ? { shared_folders: { incoming: [{ folder_uuid: 'anderer' }] } } : { emails: [a.email, b.email] }));

        const data = payloadOf(await newProxy().handleRequest(toolCall('list_emails')));

        expect((data.emails as Record<string, unknown>[]).map(e => e.subject)).toEqual(['Eigene A', 'Eigene B']);
        expect(calls.filter(c => c.name === 'list_folders')).toHaveLength(1);
    });

    it('gepolsterter Kalendername wird ausgepackt', async () => {
        const calKey = rnd(32);
        const name = bucketPad(utf8('Team'));
        const cal = {
            uuid: 'c', encrypted_calendar_key: toBase64(await encryptVaultData(calKey, vault.masterKey)),
            encrypted_name: toBase64(await encryptPhpAesGcm(name, calKey)),
        };
        fakeServer(() => ({ calendars: [cal] }));
        const data = payloadOf(await newProxy().handleRequest(toolCall('list_calendars')));
        expect((data.calendars as Record<string, unknown>[])[0].name).toBe('Team');
    });

    it('Anhang aus geteiltem Ordner, aber die Mail ist nicht lesbar: bleibt verschlüsselt', async () => {
        const attUuid = `att-${toHex(rnd(4))}`;
        const att = {
            uuid: attUuid, email_uuid: 'm-q', wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
            encrypted_filename: await phpFieldHex('x', rnd(32)), encrypted_content: await phpFieldHex('x', rnd(32)),
        };
        const calls = fakeServer((name) => (name === 'get_attachment' ? att : { __raw: { content: [] } }));
        const data = payloadOf(await newProxy().handleRequest(toolCall('get_attachment', { attachment_uuid: attUuid })));
        expect(data).toEqual(att);
        expect(calls.map(c => c.name)).toEqual(['get_attachment', 'read_email']);
    });
});
