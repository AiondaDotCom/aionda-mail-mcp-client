/**
 * Proxy: Mails zwischen dem eigenen Postfach und geteilten Ordnern.
 *
 * move_email aus einem geteilten Ordner ist serverseitig unmöglich (anderes
 * Postfach). Der Proxy kopiert stattdessen und kapselt den Mailschlüssel neu
 * für die eigenen öffentlichen Schlüssel. deliver_to_shared_folder macht den
 * umgekehrten Weg: Mailschlüssel mit dem Ordnerschlüssel verpacken und eine
 * Kapsel für den Eigentümer beilegen.
 *
 * Alle Kapseln werden im Test mit den echten privaten Schlüsseln geöffnet.
 */
import { webcrypto } from 'node:crypto';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('tesseract.js', () => ({ createWorker: vi.fn() }));

import { McpDecryptingProxy } from '../src/proxy';
import { resolveContentKey } from '../src/crypto/email-decryptor';
import { fromBase64, toBase64, toHex } from '../src/crypto/encoding';
import { packWrappedKeyHex } from '../src/crypto/wrapped-key-pack';
import {
    fakeServer, incomingShare, kemEmail, makeVault, payloadOf, rewrapForFolder, rnd, toolCall, unlock,
    type ToolHandler, type Vault,
} from './helpers/vault';

let me: Vault;
let owner: Vault;
beforeAll(async () => { me = await makeVault(); owner = await makeVault(); });

let stderr: ReturnType<typeof vi.spyOn>;
beforeEach(() => { stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true); });
afterEach(() => { vi.unstubAllGlobals(); stderr.mockRestore(); });

function newProxy(withPublicKeys = true): McpDecryptingProxy {
    const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test', apiKey: 'tma_x', vaultKey: 'tmv_x' });
    unlock(proxy, me, withPublicKeys);
    return proxy;
}

async function aesOpen(key: Uint8Array, nonce: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const k = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, k, data));
}

describe('move_email', () => {
    it('normaler Umzug im eigenen Postfach: genau ein Aufruf, Antwort unverändert', async () => {
        const calls = fakeServer(() => ({ success: true, moved: 1 }));
        const resp = await newProxy().handleRequest(toolCall('move_email', { email_uuid: 'm1', target_folder: 'archive' }, 5));
        expect(payloadOf(resp)).toEqual({ success: true, moved: 1 });
        expect(resp.id).toBe(5);
        expect(calls.map(c => c.name)).toEqual(['move_email']);
    });

    it('Fehler ohne Bezug zu geteilten Ordnern wird unverändert gemeldet, kein Kopierversuch', async () => {
        const calls = fakeServer(() => ({ success: false, msg: 'target folder is full' }));
        const resp = await newProxy().handleRequest(toolCall('move_email', { email_uuid: 'm1', target_folder: 'x' }));
        expect(payloadOf(resp).msg).toBe('target folder is full');
        expect(calls.map(c => c.name)).toEqual(['move_email']);
    });

    it('Mail aus geteiltem Ordner: wird kopiert, der neue Schlüssel öffnet sich mit dem EIGENEN privaten Schlüssel', async () => {
        const folderKey = rnd(32);
        const { email, mailKey } = await kemEmail(owner, 'm-team', { subject: 's', from: 'f', to: 't' });
        const ordnerMail = { ...email, ...await rewrapForFolder(mailKey, folderKey) };
        const shares = [
            await incomingShare(me, rnd(32), { folder_uuid: 'leer', share_uuid: 'sh-0' }),
            await incomingShare(me, folderKey, { folder_uuid: 'team', share_uuid: 'sh-1' }),
        ];
        const calls = fakeServer((name, args) => {
            if (name === 'move_email') return { __raw: { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: true, message: 'Email not found' }) }] } };
            if (name === 'list_folders') return { shared_folders: { incoming: shares } };
            if (name === 'list_emails') return { emails: args.folder === 'folder:team' ? [{ uuid: 'anders' }, ordnerMail] : [] };
            return { success: true, copied: true };
        });

        const resp = await newProxy().handleRequest(toolCall('move_email', { email_uuid: 'm-team', target_folder: 'inbox' }, 42));

        expect(payloadOf(resp)).toEqual({ success: true, copied: true });
        expect(calls.map(c => c.name)).toEqual(['move_email', 'list_folders', 'list_emails', 'list_emails', 'copy_from_shared_folder']);
        const copy = calls.at(-1)!;
        expect(copy.id).toBe(42);
        expect(copy.args).toMatchObject({ email_uuid: 'm-team', target_folder: 'inbox' });
        const neu = await resolveContentKey(String(copy.args.new_wrapped_ephemeral_key), 'm-team', me.masterKey, me.privateKeys);
        expect(neu.source).toBe('kem');
        expect(toHex(neu.key)).toBe(toHex(mailKey));
    });

    it('Mail in keinem geteilten Ordner: ursprünglicher Fehler kommt zurück', async () => {
        const share = await incomingShare(me, rnd(32), { folder_uuid: 'team' });
        const calls = fakeServer((name) => {
            if (name === 'move_email') return { success: false, msg: 'permission denied' };
            if (name === 'list_folders') return { shared_folders: { incoming: [share] } };
            return { emails: [] };
        });
        const resp = await newProxy().handleRequest(toolCall('move_email', { email_uuid: 'm1', target_folder: 'inbox' }));
        expect(payloadOf(resp)).toEqual({ success: false, msg: 'permission denied' });
        expect(calls.map(c => c.name)).not.toContain('copy_from_shared_folder');
        expect(stderr.mock.calls.map(c => String(c[0])).join('')).toMatch(/Cross-vault copy failed: Email not found in any shared folder/);
    });

    it('gefundene Mail ohne rewrapped_key wird nicht kopiert', async () => {
        const share = await incomingShare(me, rnd(32), { folder_uuid: 'team' });
        const calls = fakeServer((name) => {
            if (name === 'move_email') return { error: true, msg: 'move-out not allowed' };
            if (name === 'list_folders') return { shared_folders: { incoming: [share] } };
            return { emails: [{ uuid: 'm1' }] };
        });
        const resp = await newProxy().handleRequest(toolCall('move_email', { email_uuid: 'm1', target_folder: 'inbox' }));
        expect(payloadOf(resp).msg).toBe('move-out not allowed');
        expect(calls.map(c => c.name)).not.toContain('copy_from_shared_folder');
    });

    it('ohne eigene öffentliche Schlüssel oder ohne Ziel: gewöhnlicher Durchlauf', async () => {
        const calls = fakeServer(() => ({ success: false, msg: 'not found' }));
        await newProxy(false).handleRequest(toolCall('move_email', { email_uuid: 'm1', target_folder: 'x' }));
        await newProxy().handleRequest(toolCall('move_email', { email_uuid: 'm1' }));
        expect(calls.map(c => c.name)).toEqual(['move_email', 'move_email']);
    });
});

describe('deliver_to_shared_folder', () => {
    async function setup(over: { share?: Record<string, unknown>; handler?: ToolHandler; wrapped?: string } = {}) {
        const folderKey = rnd(32);
        const mailKey = rnd(32);
        const wrapped = over.wrapped ?? await packWrappedKeyHex(mailKey, me.publicKeys.x25519, me.publicKeys.mlkem);
        const share = await incomingShare(me, folderKey, {
            share_uuid: 'sh-1', folder_uuid: 'team', can_move_in: true, owner_username: 'chef', ...over.share,
        });
        const calls = fakeServer(over.handler ?? ((name) => {
            if (name === 'list_folders') return { shared_folders: { incoming: [share] } };
            if (name === 'get_email_key') return { wrapped_ephemeral_key: wrapped };
            if (name === 'get_recipient_keys') return { x25519_public_key: toBase64(owner.publicKeys.x25519), mlkem_public_key: toBase64(owner.publicKeys.mlkem) };
            return { success: true, delivered: true };
        }));
        return { calls, folderKey, mailKey };
    }

    it('verpackt den Mailschlüssel für den Ordner und kapselt ihn für den Eigentümer', async () => {
        const { calls, folderKey, mailKey } = await setup();

        const resp = await newProxy().handleRequest(toolCall('deliver_to_shared_folder', { email_uuid: 'm1', share_uuid: 'sh-1' }, 7));

        expect(payloadOf(resp)).toEqual({ success: true, delivered: true });
        expect(calls.map(c => c.name)).toEqual(['list_folders', 'get_email_key', 'get_recipient_keys', 'deliver_to_shared_folder']);
        expect(calls[2].args).toEqual({ recipient_username: 'chef' });
        const args = calls[3].args;
        expect(calls[3].id).toBe(7);
        expect(args).toMatchObject({ email_uuid: 'm1', share_uuid: 'sh-1' });
        // Ordnerempfänger: rewrapped_key geht mit dem Ordnerschlüssel auf.
        const ausOrdner = await aesOpen(folderKey, fromBase64(String(args.key_nonce)), fromBase64(String(args.rewrapped_key)));
        expect(toHex(ausOrdner)).toBe(toHex(mailKey));
        // Eigentümer: owner_wrapped_key geht mit SEINEM privaten Schlüssel auf.
        const fuerEigentuemer = await resolveContentKey(String(args.owner_wrapped_key), 'm1', owner.masterKey, owner.privateKeys);
        expect(toHex(fuerEigentuemer.key)).toBe(toHex(mailKey));
    });

    async function fehler(over: Parameters<typeof setup>[0]): Promise<{ msg: string; names: (string | undefined)[] }> {
        const { calls } = await setup(over);
        const resp = await newProxy().handleRequest(toolCall('deliver_to_shared_folder', { email_uuid: 'm1', share_uuid: 'sh-1' }, 3));
        expect((resp.result as { isError?: boolean }).isError).toBe(true);
        expect(resp.id).toBe(3);
        return { msg: String(payloadOf(resp).message), names: calls.map(c => c.name) };
    }

    it('Altmail unter dem Master Key wird NICHT geteilt (sonst bekäme der Ordner das ganze Postfach)', async () => {
        const r = await fehler({ wrapped: '__MASTER_KEY_ENCRYPTED__' });
        expect(r.msg).toMatch(/^Proxy crypto failed: This e-mail is still encrypted with the vault master key/);
        expect(r.names).not.toContain('deliver_to_shared_folder');
    });

    it('unbekannte Freigabe, fehlendes Einliefer-Recht, fehlender Eigentümer, fehlende Schlüssel: Abbruch mit Grund', async () => {
        expect((await fehler({ share: { share_uuid: 'anders' } })).msg).toBe('Proxy crypto failed: Shared folder not found');
        expect((await fehler({ share: { can_move_in: false } })).msg).toBe('Proxy crypto failed: No move-in permission on this shared folder');
        expect((await fehler({ share: { owner_username: '' } })).msg).toBe('Proxy crypto failed: Shared folder has no owner_username');

        const share = await incomingShare(me, rnd(32), { share_uuid: 'sh-1', can_move_in: true, owner_username: 'chef' });
        const ohneKey = await fehler({ handler: (name) => (name === 'list_folders' ? { shared_folders: { incoming: [share] } } : {}) });
        expect(ohneKey.msg).toBe('Proxy crypto failed: Failed to get email key');

        const wrapped = await packWrappedKeyHex(rnd(32), me.publicKeys.x25519, me.publicKeys.mlkem);
        const ohneOwnerKeys = await fehler({
            handler: (name) => {
                if (name === 'list_folders') return { shared_folders: { incoming: [share] } };
                if (name === 'get_email_key') return { wrapped_ephemeral_key: wrapped };
                return { x25519_public_key: 'nur-einer' };
            },
        });
        expect(ohneOwnerKeys.msg).toBe('Proxy crypto failed: Failed to get public keys of folder owner "chef"');
        expect(ohneOwnerKeys.names).not.toContain('deliver_to_shared_folder');
    });

    it('ohne email_uuid/share_uuid geht die Anfrage unverändert an den Server', async () => {
        const calls = fakeServer(() => ({ error: true, msg: 'missing parameter' }));
        const resp = await newProxy().handleRequest(toolCall('deliver_to_shared_folder', { email_uuid: 'm1' }));
        expect(payloadOf(resp).msg).toBe('missing parameter');
        expect(calls.map(c => [c.name, c.args])).toEqual([['deliver_to_shared_folder', { email_uuid: 'm1' }]]);
    });
});
