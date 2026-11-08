/**
 * Gemeinsame Testhilfen: echtes Schlüsselmaterial und eine fetch-Attrappe.
 *
 * Alles hier ist echte Krypto (X25519 + ML-KEM-1024, AES-256-GCM, HKDF) –
 * die Tests entschlüsseln also mit denselben Bausteinen, die der Server bzw.
 * der Web-Client beim Verschlüsseln benutzen. Nur der Transport ist nachgebaut.
 */
import { webcrypto } from 'node:crypto';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { vi } from 'vitest';

import { encryptClientAesGcm, encryptPhpAesGcm } from '../../src/crypto/aes-gcm';
import { toBase64, toHex } from '../../src/crypto/encoding';
import { hybridEncapsulate } from '../../src/crypto/hybrid-kem';
import { deriveEmailKey } from '../../src/crypto/key-derivation';
import { packWrappedKeyHex } from '../../src/crypto/wrapped-key-pack';
import type { VaultPrivateKeys } from '../../src/crypto/email-decryptor';
import type { McpDecryptingProxy } from '../../src/proxy';

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const rnd = (n: number): Uint8Array => webcrypto.getRandomValues(new Uint8Array(n));

export interface Vault {
    masterKey: Uint8Array;
    privateKeys: VaultPrivateKeys;
    publicKeys: { x25519: Uint8Array; mlkem: Uint8Array };
}

/** Vollständiges Postfach: Master Key + Hybrid-KEM-Schlüsselpaar. */
export async function makeVault(): Promise<Vault> {
    const pair = await webcrypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']) as unknown as {
        publicKey: Parameters<typeof webcrypto.subtle.exportKey>[1];
        privateKey: Parameters<typeof webcrypto.subtle.exportKey>[1];
    };
    const pub = new Uint8Array(await webcrypto.subtle.exportKey('raw', pair.publicKey));
    const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', pair.privateKey));
    const kem = ml_kem1024.keygen();
    return {
        masterKey: rnd(32),
        privateKeys: { x25519PrivateKey: pkcs8.slice(pkcs8.length - 32), mlKemPrivateKey: kem.secretKey },
        publicKeys: { x25519: pub, mlkem: kem.publicKey },
    };
}

/** Serverformat: nonce(12) || tag(16) || ciphertext, hex. */
export async function phpFieldHex(text: string | Uint8Array, key: Uint8Array): Promise<string> {
    return toHex(await encryptPhpAesGcm(typeof text === 'string' ? utf8(text) : text, key));
}

/** Clientformat: iv(12) || ciphertext || tag(16), hex. */
export async function clientFieldHex(text: string | Uint8Array, key: Uint8Array): Promise<string> {
    return toHex(await encryptClientAesGcm(typeof text === 'string' ? utf8(text) : text, key));
}

/** Clientformat, base64 (Kalender, Ordnernamen im Browser). */
export async function clientFieldB64(text: string, key: Uint8Array): Promise<string> {
    return toBase64(await encryptClientAesGcm(utf8(text), key));
}

/** AES-GCM, WebCrypto-Ausgabe ciphertext || tag (Nonce getrennt). */
export async function aesGcmRaw(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    const k = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    return new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, plaintext));
}

export interface MailText {
    subject: string;
    from: string;
    to: string;
    body?: string;
    bodyText?: string;
    headers?: string;
}

function baseEmail(uuid: string): Record<string, unknown> {
    return {
        uuid,
        dea_id: 7,
        ephemeral_key_iv: '',
        size_bytes: 1234,
        has_attachments: false,
        attachment_count: 0,
        is_read: false,
        is_starred: true,
        is_deleted: false,
        folder_type: 'inbox',
        folder_uuid: null,
        received_at: '2026-01-02T03:04:05Z',
        thread_id: 'thread-1',
    };
}

/** Eingehende Mail, vom Server mit einem Hybrid-KEM-gekapselten Mailschlüssel verschlüsselt. */
export async function kemEmail(
    vault: Vault, uuid: string, text: MailText, extra: Record<string, unknown> = {}
): Promise<{ email: Record<string, unknown>; mailKey: Uint8Array }> {
    const mailKey = rnd(32);
    const email: Record<string, unknown> = {
        ...baseEmail(uuid),
        wrapped_ephemeral_key: await packWrappedKeyHex(mailKey, vault.publicKeys.x25519, vault.publicKeys.mlkem),
        encrypted_subject: await phpFieldHex(text.subject, mailKey),
        encrypted_from: await phpFieldHex(text.from, mailKey),
        encrypted_to: await phpFieldHex(text.to, mailKey),
        ...extra,
    };
    if (text.body !== undefined) email.encrypted_body = await phpFieldHex(text.body, mailKey);
    if (text.bodyText !== undefined) email.encrypted_body_text = await phpFieldHex(text.bodyText, mailKey);
    if (text.headers !== undefined) email.encrypted_headers = await phpFieldHex(text.headers, mailKey);
    return { email, mailKey };
}

/** Mail mit abgeleitetem Schlüssel (HKDF(Master Key, UUID)), Clientformat. */
export async function derivedEmail(
    vault: Vault, uuid: string, text: MailText, extra: Record<string, unknown> = {}
): Promise<{ email: Record<string, unknown>; mailKey: Uint8Array }> {
    const mailKey = await deriveEmailKey(vault.masterKey, uuid);
    const email: Record<string, unknown> = {
        ...baseEmail(uuid),
        wrapped_ephemeral_key: '__DERIVED_KEY_ENCRYPTED__',
        encrypted_subject: await clientFieldHex(text.subject, mailKey),
        encrypted_from: await clientFieldHex(text.from, mailKey),
        encrypted_to: await clientFieldHex(text.to, mailKey),
        ...extra,
    };
    if (text.body !== undefined) email.encrypted_body = await clientFieldHex(text.body, mailKey);
    if (text.bodyText !== undefined) email.encrypted_body_text = await clientFieldHex(text.bodyText, mailKey);
    if (text.headers !== undefined) email.encrypted_headers = await clientFieldHex(text.headers, mailKey);
    return { email, mailKey };
}

/** Eingehende Freigabe: Ordnerschlüssel für den Empfänger gekapselt (wie der Web-Client). */
export async function incomingShare(
    recipient: Vault, folderKey: Uint8Array, extra: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
    const kem = await hybridEncapsulate(recipient.publicKeys.x25519, recipient.publicKeys.mlkem);
    const nonce = rnd(12);
    return {
        encrypted_folder_key: toBase64(await aesGcmRaw(kem.sharedSecret, nonce, folderKey)),
        x25519_ephemeral: toBase64(kem.x25519Ciphertext),
        mlkem_ciphertext: toBase64(new Uint8Array(kem.mlKemCiphertext)),
        key_nonce: toBase64(nonce),
        ...extra,
    };
}

/** Mailschlüssel mit dem Ordnerschlüssel verpackt (rewrapped_key / key_nonce einer Ordnermail). */
export async function rewrapForFolder(mailKey: Uint8Array, folderKey: Uint8Array): Promise<{ rewrapped_key: string; key_nonce: string }> {
    const nonce = rnd(12);
    return { rewrapped_key: toBase64(await aesGcmRaw(folderKey, nonce, mailKey)), key_nonce: toBase64(nonce) };
}

/** Den Proxy mit Schlüsseln bestücken, ohne den Bootstrap durchzuspielen. */
export function unlock(proxy: McpDecryptingProxy, vault: Vault, withPublicKeys = true): void {
    const p = proxy as unknown as Record<string, unknown>;
    p.masterKey = vault.masterKey;
    p.privateKeys = vault.privateKeys;
    if (withPublicKeys) p.publicKeys = vault.publicKeys;
}

export function toolText(payload: unknown): { content: { type: string; text: string }[] } {
    return { content: [{ type: 'text', text: JSON.stringify(payload) }] };
}

export interface ServerCall {
    method: string;
    name?: string;
    args: Record<string, unknown>;
    id?: number | string;
    headers: Record<string, string>;
}

export type ToolHandler = (name: string, args: Record<string, unknown>) =>
    unknown | { __error: { code: number; message: string } } | { __raw: unknown };

/**
 * fetch-Attrappe für den MCP-Server. Der Handler liefert die Nutzlast eines
 * Werkzeugs (wird als Textinhalt verpackt), `{__error}` für einen JSON-RPC-Fehler
 * oder `{__raw}` für ein unverändertes `result`.
 */
export function fakeServer(handler: ToolHandler): ServerCall[] {
    const calls: ServerCall[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string; headers: Record<string, string> }) => {
        const req = JSON.parse(init.body) as { id?: number | string; method: string; params?: { name?: string; arguments?: Record<string, unknown> } };
        const name = req.params?.name;
        const args = req.params?.arguments ?? {};
        calls.push({ method: req.method, name, args, id: req.id, headers: init.headers });
        let body: unknown = { jsonrpc: '2.0', id: req.id, result: {} };
        if (req.method === 'tools/call' && name) {
            const out = handler(name, args) as Record<string, unknown> | undefined;
            if (out && typeof out === 'object' && '__error' in out) {
                body = { jsonrpc: '2.0', id: req.id, error: out.__error };
            } else if (out && typeof out === 'object' && '__raw' in out) {
                body = { jsonrpc: '2.0', id: req.id, result: out.__raw };
            } else {
                body = { jsonrpc: '2.0', id: req.id, result: toolText(out ?? {}) };
            }
        }
        return { headers: { get: (h: string) => (h === 'Mcp-Session-Id' ? 'sess-1' : null) }, json: async () => body };
    }));
    return calls;
}

/** Erstes Textelement einer Werkzeugantwort als JSON. */
export function payloadOf(resp: { result?: unknown }): Record<string, unknown> {
    const r = resp.result as { content: { text: string }[] };
    return JSON.parse(r.content[0].text) as Record<string, unknown>;
}

export function toolCall(name: string, args: Record<string, unknown> = {}, id: number | string = 1): {
    jsonrpc: '2.0'; id: number | string; method: string; params: Record<string, unknown>;
} {
    return { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } };
}
