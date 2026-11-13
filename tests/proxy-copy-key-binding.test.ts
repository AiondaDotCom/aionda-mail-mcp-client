/**
 * #53a45a9d: Echter KEM-Umschlag im Proxy, HTTP-Gegenstelle als Attrappe.
 * Fehltrefferzahl: 0 am 09.11.2026 (2 Tests). Ohne Bindungsfelder: 2 Failures;
 * nach Rückkehr wieder 2 bestanden. Echte HTTP-Abnahme zusätzlich auf Dev.
 */
import { webcrypto } from 'node:crypto';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { McpDecryptingProxy } from '../src/proxy';
import { hybridEncapsulate, hybridDecapsulate } from '../src/crypto/hybrid-kem';
import { fromHex, toHex, toBase64 } from '../src/crypto/encoding';
import type { JsonRpcResponse } from '../src/types/mcp-protocol';
import type { VaultPrivateKeys } from '../src/crypto/email-decryptor';

interface CopyProbe {
    publicKeys: { x25519: Uint8Array; mlkem: Uint8Array };
    privateKeys: VaultPrivateKeys;
    cachedIncomingShares: Record<string, unknown>[];
    doCrossVaultCopy(email: string, folder: string, id: number): Promise<JsonRpcResponse>;
}
const random = (length: number) => webcrypto.getRandomValues(new Uint8Array(length));
async function encrypt(key: Uint8Array, iv: Uint8Array, value: Uint8Array): Promise<Uint8Array> {
    const aes = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    return new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, value));
}
async function fixture() {
    const x = await webcrypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const xPub = new Uint8Array(await webcrypto.subtle.exportKey('raw', x.publicKey));
    const xPriv = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', x.privateKey)).slice(-32);
    const m = ml_kem1024.keygen();
    const publicKeys = { x25519: xPub, mlkem: m.publicKey };
    const privateKeys = { x25519PrivateKey: xPriv, mlKemPrivateKey: m.secretKey };
    const folderKey = random(32), emailKey = random(32), folderIv = random(12), emailIv = random(12);
    const kem = await hybridEncapsulate(xPub, m.publicKey);
    return { publicKeys, privateKeys, emailKey,
        share: { folder_uuid: 'fixture-folder', encrypted_folder_key: toBase64(await encrypt(kem.sharedSecret, folderIv, folderKey)),
            x25519_ephemeral: toBase64(kem.x25519Ciphertext), mlkem_ciphertext: toBase64(kem.mlKemCiphertext), key_nonce: toBase64(folderIv) },
        email: { uuid: 'fixture-email', rewrapped_key: toBase64(await encrypt(folderKey, emailIv, emailKey)), key_nonce: toBase64(emailIv) } };
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('MCP copy target binding', () => {
    for (const rejected of [false, true]) {
        it(rejected ? 'preserves stable key-change rejection and never logs success' : 'binds the actual encapsulation keys and produces a readable envelope', async () => {
            const f = await fixture();
            const log = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
            let captured: Record<string, string> | null = null;
            const reply = { jsonrpc: '2.0' as const, id: 7, result: { isError: rejected, content: [{ type: 'text', text: JSON.stringify(rejected
                ? { error: true, error_code: 193, message: 'Restart the MCP client and retry. Nothing was copied.' }
                : { new_email_uuid: 'copy-uuid' }) }] } };
            vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string }) => {
                const request = JSON.parse(init.body) as { params: { name: string; arguments: Record<string,string> } };
                if (request.params.name === 'copy_from_shared_folder') captured = request.params.arguments;
                return { headers: { get: () => null }, json: async () => request.params.name === 'copy_from_shared_folder'
                    ? reply : { result: { content: [{ type: 'text', text: JSON.stringify({ emails: [f.email] }) }] } } };
            }));
            const proxy = new McpDecryptingProxy({ endpoint: 'https://example.test/mcp', apiKey: 'fixture', vaultKey: 'fixture' });
            const probe = proxy as unknown as CopyProbe;
            probe.publicKeys = f.publicKeys; probe.privateKeys = f.privateKeys; probe.cachedIncomingShares = [f.share];
            const response = await probe.doCrossVaultCopy('fixture-email', 'inbox', 7);
            expect(response).toEqual(reply);
            expect(captured).not.toBeNull();
            const args = captured as unknown as Record<string,string>;
            expect(args.target_x25519_public_key).toBe(toHex(f.publicKeys.x25519));
            expect(args.target_mlkem_public_key).toBe(toHex(f.publicKeys.mlkem));
            const p = fromHex(args.new_wrapped_ephemeral_key);
            const secret = await hybridDecapsulate(p.slice(1,33), p.slice(33,1601), f.privateKeys.x25519PrivateKey, f.privateKeys.mlKemPrivateKey);
            const aes = await webcrypto.subtle.importKey('raw', secret, 'AES-GCM', false, ['decrypt']);
            const key = new Uint8Array(await webcrypto.subtle.decrypt({name:'AES-GCM',iv:p.slice(1601,1613)}, aes,
                new Uint8Array([...p.slice(1629), ...p.slice(1613,1629)])));
            expect(key).toEqual(f.emailKey);
            const messages = log.mock.calls.map(call => String(call[0])).join('');
            expect(messages.includes('copy complete')).toBe(!rejected);
        });
    }
});
