/**
 * AiondaMailClient: jede Methode ruft das richtige Werkzeug mit den richtigen
 * Argumenten und gibt `data` zurück; die entschlüsselnden Methoden öffnen
 * Ordnernamen, Mails und Ordnerschlüssel mit echtem Schlüsselmaterial.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { AiondaMailClient } from '../src/client';
import { McpDecryptionError, McpSessionExpiredError } from '../src/errors';
import { toHex } from '../src/crypto/encoding';
import { derivedEmail, incomingShare, makeVault, phpFieldHex, rnd, type Vault } from './helpers/vault';

interface Sent { url: string; method: string; name?: string; args?: Record<string, unknown>; session?: string }

/** Server-Attrappe: tools/call antwortet mit `{ data: handler(name, args) }`. */
function server(handler: (name: string, args: Record<string, unknown>) => unknown = () => ({})): Sent[] {
    const sent: Sent[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: { body: string; headers: Record<string, string> }) => {
        const req = JSON.parse(init.body);
        sent.push({ url, method: req.method, name: req.params?.name, args: req.params?.arguments, session: init.headers['Mcp-Session-Id'] });
        const result = req.method === 'tools/call'
            ? { data: handler(req.params.name, req.params.arguments) }
            : req.method === 'tools/list' ? { tools: [{ name: 'list_emails' }] } : { protocolVersion: '2025-03-26' };
        return { status: 200, headers: new Headers({ 'Mcp-Session-Id': 'sid-1' }), json: async () => ({ jsonrpc: '2.0', id: req.id, result }) };
    }));
    return sent;
}

let vault: Vault;
beforeAll(async () => { vault = await makeVault(); });
afterEach(() => vi.unstubAllGlobals());

const keyOpts = (v: Vault) => ({
    vaultKey: toHex(v.masterKey),
    vaultPrivateKeys: toHex(new Uint8Array([...v.privateKeys.x25519PrivateKey, ...v.privateKeys.mlKemPrivateKey])),
});

async function connected(handler?: Parameters<typeof server>[0], withKeys = false) {
    const sent = server(handler);
    const client = new AiondaMailClient({ apiKey: 'tma_x', endpoint: 'https://mail.example/mcp', ...(withKeys ? keyOpts(vault) : {}) });
    await client.connect();
    return { client, sent };
}

describe('Werkzeug-Wrapper', () => {
    it('jede Methode sendet ihr Werkzeug mit ihren Argumenten und liefert data', async () => {
        const { client, sent } = await connected((name, args) => ({ tool: name, args, deas: [{ dea_uid: 'd1' }] }));

        const cases: [() => Promise<unknown>, string, Record<string, unknown>][] = [
            [() => client.listFolders(), 'list_folders', {}],
            [() => client.listEmails(), 'list_emails', { folder: 'inbox', limit: 20, offset: 0 }],
            [() => client.listEmails('sent', 5, 10), 'list_emails', { folder: 'sent', limit: 5, offset: 10 }],
            [() => client.readEmail('m1'), 'read_email', { email_uuid: 'm1' }],
            [() => client.sendEmail({ to: 'a@x', subject: 's', body: 'b' } as never), 'send_email', { to: 'a@x', subject: 's', body: 'b' }],
            [() => client.replyEmail({ email_uuid: 'm1', body: 'b' } as never), 'reply_email', { email_uuid: 'm1', body: 'b' }],
            [() => client.forwardEmail({ email_uuid: 'm1', to: 'c@x' } as never), 'forward_email', { email_uuid: 'm1', to: 'c@x' }],
            [() => client.saveDraft({ subject: 's' } as never), 'save_draft', { subject: 's' }],
            [() => client.listDrafts(), 'list_drafts', { limit: 20, offset: 0 }],
            [() => client.getDraft('d1'), 'get_draft', { draft_id: 'd1' }],
            [() => client.getDea('d1'), 'get_dea', { dea_uid: 'd1' }],
            [() => client.createDea({ name: 'n' } as never), 'create_dea', { name: 'n' }],
            [() => client.updateDea({ dea_uid: 'd1' } as never), 'update_dea', { dea_uid: 'd1' }],
            [() => client.listSharedFolders(), 'list_shared_folders', { direction: 'both' }],
        ];
        for (const [call, name, args] of cases) {
            const out = await call() as Record<string, unknown>;
            expect(sent.at(-1)).toMatchObject({ method: 'tools/call', name, args, session: 'sid-1' });
            expect(out).toMatchObject({ tool: name, args });
        }

        expect(await client.listDeas()).toEqual([{ dea_uid: 'd1' }]);
        expect(sent.at(-1)).toMatchObject({ name: 'list_deas', args: {} });

        const voids: [() => Promise<void>, string, Record<string, unknown>][] = [
            [() => client.markRead('m1'), 'mark_read', { email_uuid: 'm1' }],
            [() => client.markUnread('m1'), 'mark_unread', { email_uuid: 'm1' }],
            [() => client.moveEmail('m1', 'archive'), 'move_email', { email_uuid: 'm1', target_folder: 'archive' }],
            [() => client.deleteEmail('m1'), 'delete_email', { email_uuid: 'm1' }],
            [() => client.deleteDraft('d1'), 'delete_draft', { draft_id: 'd1' }],
            [() => client.deleteDea('d1'), 'delete_dea', { dea_uid: 'd1' }],
        ];
        for (const [call, name, args] of voids) {
            expect(await call()).toBeUndefined();
            expect(sent.at(-1)).toMatchObject({ name, args });
        }
        expect(sent[0].url).toBe('https://mail.example/mcp');
    });

    it('listTools, ping und isConnected; nach disconnect wirft jeder Aufruf', async () => {
        const { client, sent } = await connected();
        expect(await client.listTools()).toEqual([{ name: 'list_emails' }]);
        await client.ping();
        expect(sent.map(s => s.method)).toEqual(['initialize', 'notifications/initialized', 'tools/list', 'ping']);
        expect(client.isConnected()).toBe(true);

        await client.disconnect();
        expect(client.isConnected()).toBe(false);
        await expect(client.listFolders()).rejects.toBeInstanceOf(McpSessionExpiredError);
    });
});

describe('Entschlüsselnde Methoden', () => {
    it('listFoldersDecrypted: Namen mit dem Master Key, kaputte und fehlende fallen auf folder_type zurück', async () => {
        const name = await phpFieldHex('Projekte', vault.masterKey);
        const { client } = await connected(() => ({ folders: [
            { uuid: 'f1', folder_type: 'custom', encrypted_name: name, email_count: 3, unread_count: 1 },
            { uuid: 'f2', folder_type: 'custom', encrypted_name: toHex(rnd(40)), email_count: 0, unread_count: 0 },
            { uuid: 'f3', folder_type: 'inbox', email_count: 9, unread_count: 2 },
        ] }), true);

        expect(await client.listFoldersDecrypted()).toEqual([
            { uuid: 'f1', folderType: 'custom', name: 'Projekte', emailCount: 3, unreadCount: 1 },
            { uuid: 'f2', folderType: 'custom', name: 'custom', emailCount: 0, unreadCount: 0 },
            { uuid: 'f3', folderType: 'inbox', name: 'inbox', emailCount: 9, unreadCount: 2 },
        ]);
    });

    it('readEmailDecrypted: öffnet die Mail; fremde Mail wird zu McpDecryptionError mit UUID', async () => {
        const { email } = await derivedEmail(vault, 'm-ok', { subject: 'Hallo', from: 'a@example.com', to: 'b@example.com', body: 'Text' });
        const { email: fremd } = await derivedEmail(await makeVault(), 'm-fremd', { subject: 'x', from: 'y', to: 'z' });
        const { client } = await connected((_n, args) => (args.email_uuid === 'm-ok' ? email : fremd), true);

        const mail = await client.readEmailDecrypted('m-ok');
        expect(mail).toMatchObject({ uuid: 'm-ok', subject: 'Hallo', from: 'a@example.com', to: 'b@example.com', body: 'Text' });

        const err = await client.readEmailDecrypted('m-fremd').catch(e => e);
        expect(err).toBeInstanceOf(McpDecryptionError);
        expect(err.message).toMatch(/^Failed to decrypt email m-fremd: /);
    });

    it('decryptSharedFolderKey öffnet den Ordnerschlüssel einer eingehenden Freigabe', async () => {
        const folderKey = rnd(32);
        const share = await incomingShare(vault, folderKey);
        const client = new AiondaMailClient({ apiKey: 'tma_x', ...keyOpts(vault) });
        expect(toHex(await client.decryptSharedFolderKey(share as never))).toBe(toHex(folderKey));
    });

    it('ohne Schlüssel: klare Fehlermeldung statt Chiffrat', async () => {
        const nurMaster = new AiondaMailClient({ apiKey: 'tma_x', vaultKey: toHex(vault.masterKey) });
        await expect(nurMaster.readEmailDecrypted('m1')).rejects.toThrow('Vault private keys not provided');
        await expect(new AiondaMailClient({ apiKey: 'tma_x' }).listFoldersDecrypted()).rejects.toThrow('Vault key not provided');
        await expect(nurMaster.decryptSharedFolderKey({} as never)).rejects.toThrow('Vault private keys not provided');
    });
});
