/**
 * MCP Decrypting Proxy
 *
 * Thin pass-through proxy between AI (stdio) and Aionda Mail MCP server (HTTPS).
 * Forwards all requests 1:1. Only intercepts responses that contain encrypted
 * fields (encrypted_subject, encrypted_body, etc.) and decrypts them locally.
 *
 * New tools added on the server are automatically available — the proxy
 * doesn't need to know about them.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */
import { webcrypto } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { decryptEmail, decryptFieldBytes, resolveContentKey } from './crypto/email-decryptor';
import { decryptAesGcm, decryptPhpAesGcm, decryptClientAesGcm, encryptPhpAesGcm, decryptVaultData, encryptVaultData } from './crypto/aes-gcm';
import { decompress } from './crypto/decompression';
import { isBucketPadded, unpadFromBucket } from './crypto/bucket-padding';
import { fromBase64, fromHex, toBase64, toHex } from './crypto/encoding';
import { hybridDecapsulate } from './crypto/hybrid-kem';
import { decryptSharedFolderKey } from './crypto/shared-folder-key';
import { packWrappedKeyHex } from './crypto/wrapped-key-pack';
import { unwrapMasterKey } from './crypto/mcp-master-key';
import { decryptDraft, draftForAi, encryptDraft, mergeDraft } from './drafts';
import type { DraftAttachment, DraftContent } from './drafts';
import {
    decryptTaskField,
    encryptTaskField,
    generateTaskKey,
    normalizeSteps,
    parseSteps,
    unwrapTaskKey,
    wrapTaskKey,
} from './crypto/tasks-crypto';
import type { VaultPrivateKeys } from './crypto/email-decryptor';
import type { EncryptedEmail } from './types/email';

// ── Types ──

interface JsonRpcRequest {
    jsonrpc: '2.0';
    id?: number | string;
    method: string;
    params?: Record<string, unknown>;
}

interface JsonRpcResponse {
    jsonrpc: '2.0';
    id?: number | string;
    result?: unknown;
    error?: { code: number; message: string; data?: unknown };
}

interface McpContent {
    type: string;
    text: string;
}

interface McpToolResult {
    content?: McpContent[];
    isError?: boolean;
}

export interface ProxyConfig {
    /** Aionda Mail MCP server URL */
    endpoint: string;
    /** API key (tma_*) */
    apiKey: string;
    /** Vault key (tmv_*) for deriving master key */
    vaultKey: string;
}

// ── Proxy ──

/** Höchstzahl Mails, deren Inhalt/Anhänge eine search_emails-Suche liest — #30209ea3 */
export const SEARCH_CONTENT_CHECK_BUDGET = 30;

/** Wirft die Fehlermeldung des Servers, statt sie als leeres Ergebnis durchzureichen — #30209ea3 */
export function throwOnServerError(response: JsonRpcResponse): void {
    if (response.error) {
        throw new Error(response.error.message || `Server error ${response.error.code}`);
    }
    if (!response.result) {
        throw new Error('Server returned no result');
    }
}

export class McpDecryptingProxy {
    private endpoint: string;
    private apiKey: string;
    private masterKey: Uint8Array | null = null;
    /** Persönlicher Schlüssel eines Menschen: Server kennt den Hauptschlüssel nicht. */
    private personalKey = false;
    private privateKeys: VaultPrivateKeys | null = null;
    private sessionId: string | null = null;
    private vaultKey: string;

    // Own vault public keys (for re-wrapping ephemeral keys)
    private publicKeys: { x25519: Uint8Array; mlkem: Uint8Array } | null = null;

    // Cached shared folder data (from list_folders)
    private cachedIncomingShares: Record<string, unknown>[] = [];

    // Signature auto-append (loaded once during bootstrap)
    private signatureHtml: string | null = null;
    private signatureAutoInsertNew = false;
    private signatureAutoInsertReply = false;

    constructor(config: ProxyConfig) {
        this.endpoint = config.endpoint.endsWith('/mcp')
            ? config.endpoint
            : config.endpoint + '/mcp';
        this.apiKey = config.apiKey;
        this.vaultKey = config.vaultKey;
    }

    /**
     * Bootstrap: Sitzung aufbauen, Schlüssel vom Server holen, Master Key
     * bestimmen, privaten Schlüssel entschlüsseln.
     *
     * Zwei Sorten Konten laufen hier durch, und AIONDA_VAULT_KEY heisst in
     * beiden Fällen tmv_…:
     *
     *   KI-Mitarbeiter   M = SHA-256(utf8(tmv_))         (kein Umschlag)
     *   Mensch           M = Umschlag(wrapped_master_key) mit K = SHA-256(tmv_)
     *                    und AAD = "aionda-mcp-master-key-v1:" + mcp_key_uuid
     *
     * 🚩 Jeder Fehlschlag bricht den Start ab. Hier stand vorher
     *    „get_vault_keys not available — decryption disabled" als WARNUNG,
     *    und ein Mensch bekam danach jede Mail als „[Decryption failed]" –
     *    das ist ein stiller Rückfall, kein Betriebszustand.
     */
    async bootstrap(): Promise<void> {
        // 1. Initialize MCP session
        const initResp = await this.forwardToServer({
            jsonrpc: '2.0', id: 0, method: 'initialize',
            params: {
                protocolVersion: '2025-03-26',
                capabilities: {},
                clientInfo: { name: '@aiondadotcom/mail-mcp-client', version: '0.16.0' },
            },
        });

        if (initResp.error) {
            throw new Error(`MCP initialize failed: ${initResp.error.message}`);
        }

        // 2. Send initialized notification
        await this.forwardToServer({ jsonrpc: '2.0', method: 'notifications/initialized' });

        // 3. Fetch encrypted private keys via get_vault_keys tool
        const keysResp = await this.forwardToServer({
            jsonrpc: '2.0', id: 0, method: 'tools/call',
            params: { name: 'get_vault_keys', arguments: {} },
        });
        if (keysResp.error) {
            throw new Error(`get_vault_keys failed: ${keysResp.error.message}`);
        }

        const keysRaw  = this.parseToolContent(keysResp);
        const keysData = ((keysRaw?.data as Record<string, unknown> | undefined) ?? keysRaw) as Record<string, unknown> | null;
        if (!keysData || typeof keysData.encrypted_private_key !== 'string' || keysData.encrypted_private_key === '') {
            const grund = typeof keysData?.msg === 'string' ? keysData.msg : 'vault not configured or access denied';
            throw new Error(`get_vault_keys returned no encrypted_private_key: ${grund}`);
        }

        // 4. Master Key
        const wrapped = keysData.wrapped_master_key;
        if (typeof wrapped === 'string' && wrapped !== '') {
            const keyUuid = keysData.mcp_key_uuid;
            if (typeof keyUuid !== 'string' || keyUuid === '') {
                throw new Error('get_vault_keys returned wrapped_master_key without mcp_key_uuid');
            }
            // Wirft McpDecryptionError bei falschem tmv_, falscher UUID, Schaden.
            this.masterKey = await unwrapMasterKey(fromHex(wrapped), this.vaultKey, keyUuid);
            this.personalKey = true;
            process.stderr.write('[proxy] Personal MCP key: master key unwrapped\n');
        } else {
            // KI-Mitarbeiter: derselbe Text, direkt als Master Key.
            const vaultKeyBytes = new TextEncoder().encode(this.vaultKey);
            const hashBuffer = await webcrypto.subtle.digest('SHA-256', vaultKeyBytes);
            this.masterKey = new Uint8Array(hashBuffer);
        }

        // 5. Privaten Schlüssel nach Ablageformat entschlüsseln
        //    php        nonce(12) || tag(16) || ciphertext   (KI-Mitarbeiter, AesGcmService)
        //    webcrypto  ciphertext || tag(16), IV in private_key_iv (Mensch, Browser)
        const layout     = keysData.private_key_layout === 'webcrypto' ? 'webcrypto' : 'php';
        const encPrivKey = fromHex(keysData.encrypted_private_key);
        let decrypted: Uint8Array;
        try {
            if (layout === 'webcrypto') {
                if (typeof keysData.private_key_iv !== 'string' || keysData.private_key_iv === '') {
                    throw new Error('private_key_iv missing for webcrypto layout');
                }
                decrypted = await decryptAesGcm(encPrivKey, this.masterKey, fromHex(keysData.private_key_iv));
            } else {
                decrypted = await decryptPhpAesGcm(encPrivKey, this.masterKey);
            }
        } catch (e) {
            throw new Error(
                `Vault private key could not be decrypted (layout=${layout}): ${(e as Error).message}. `
                + 'AIONDA_VAULT_KEY does not belong to this account.'
            );
        }

        const X25519_LEN = 32;
        const MLKEM_LEN  = 3168;
        if (decrypted.length < X25519_LEN + MLKEM_LEN) {
            throw new Error(`Vault private key has ${decrypted.length} bytes, expected ${X25519_LEN + MLKEM_LEN}`);
        }
        this.privateKeys = {
            x25519PrivateKey: decrypted.slice(0, X25519_LEN),
            mlKemPrivateKey: decrypted.slice(X25519_LEN),
        };
        // Cache public keys for re-wrapping (cross-vault copy)
        if (keysData.x25519_public_key && keysData.mlkem_public_key) {
            this.publicKeys = {
                x25519: fromHex(keysData.x25519_public_key as string),
                mlkem: fromHex(keysData.mlkem_public_key as string),
            };
        }
        process.stderr.write(`[proxy] Vault unlocked — private keys decrypted (layout=${layout})\n`);

        // 6. Load and decrypt default signature for auto-append
        await this.loadSignature();

        // 7. Pre-load OCR models in background (one-time download, ~15MB)
        this.preloadOcrModels();
    }

    /**
     * Pre-load tesseract.js OCR models so they're ready when needed.
     * Runs in background — doesn't block bootstrap.
     */
    private preloadOcrModels(): void {
        import('tesseract.js').then(async ({ createWorker }) => {
            try {
                const worker = await createWorker('deu+eng');
                await worker.terminate();
                process.stderr.write('[proxy] OCR models pre-loaded (deu+eng)\n');
            } catch (e) {
                process.stderr.write(`[proxy] OCR model pre-load failed: ${(e as Error).message}\n`);
            }
        }).catch(() => {
            // tesseract.js not available — OCR disabled
        });
    }

    /**
     * Handle a JSON-RPC request from stdio, forward to server, decrypt if needed
     */
    async handleRequest(request: JsonRpcRequest): Promise<JsonRpcResponse> {
        // Encrypt plaintext fields before forwarding (Zero-Knowledge)
        if (request.method === 'tools/call') {
            // Intercept move_email for cross-vault moves (shared folder → own vault)
            const toolName = (request.params?.name as string) || '';
            if (toolName === 'move_email') {
                const crossVaultResult = await this.maybeCrossVaultMove(request);
                if (crossVaultResult) return crossVaultResult;
            }

            // Intercept export_email_pdf: render email as PDF client-side
            if (toolName === 'export_email_pdf') {
                return this.handleExportEmailPdf(request);
            }

            // Intercept search_emails: runs entirely client-side (Zero Knowledge)
            if (toolName === 'search_emails') {
                return this.handleSearchEmails(request);
            }

            // Intercept deliver_to_shared_folder: re-wrap ephemeral key with folder key
            if (toolName === 'deliver_to_shared_folder') {
                const deliverResult = await this.handleDeliverToSharedFolder(request);
                if (deliverResult) return deliverResult;
            }

            // Entwürfe eines Menschen verschlüsselt der Proxy selbst - der
            // Server kennt seinen Hauptschlüssel nicht (Zero Knowledge).
            if (toolName === 'save_draft' && this.personalKey) {
                return this.handleSavePersonalDraft(request);
            }

            request = await this.maybeEncryptRequest(request);
        }

        // Forward to server
        const response = await this.forwardToServer(request);

        // Cache shared folder data from list_folders responses
        if (request.method === 'tools/call' && response.result && !response.error) {
            const toolName = (request.params?.name as string) || '';
            if (toolName === 'list_folders') {
                this.cacheSharedFolders(response);
            }
            return {
                ...response,
                result: await this.maybeDecryptResult(response.result as McpToolResult, toolName),
            };
        }

        return response;
    }

    /**
     * Encrypt plaintext request fields before forwarding to server.
     * Transforms AI-friendly plaintext args into encrypted fields the server expects.
     */
    private async maybeEncryptRequest(request: JsonRpcRequest): Promise<JsonRpcRequest> {
        if (!this.masterKey) return request;

        const toolName = (request.params?.name as string) || '';
        const args = (request.params?.arguments as Record<string, unknown>) || {};

        // Auto-append signature to outgoing emails
        if (typeof args.body === 'string') {
            const fortschreiben = toolName === 'save_draft' && typeof args.draft_id === 'string' && args.draft_id !== '';
            if (['send_email', 'forward_email', 'save_draft'].includes(toolName) && this.signatureAutoInsertNew && !fortschreiben) {
                args.body = this.appendSignature(args.body);
            } else if (toolName === 'reply_email' && this.signatureAutoInsertReply) {
                args.body = this.appendSignature(args.body);
            }
        }

        // Normalize attachment parameters (accept attachment_paths, attachment_path as aliases)
        if (['send_email', 'reply_email', 'forward_email'].includes(toolName)) {
            if (!args.attachments && (args.attachment_paths || args.attachment_path)) {
                const paths = args.attachment_paths || args.attachment_path;
                if (typeof paths === 'string') {
                    // Single path as string → convert to array
                    args.attachments = [{ file_path: paths }];
                } else if (Array.isArray(paths)) {
                    // Array of strings → convert to array of objects
                    args.attachments = (paths as string[]).map(p =>
                        typeof p === 'string' ? { file_path: p } : p
                    );
                }
                delete args.attachment_paths;
                delete args.attachment_path;
            }
        }

        // Read file attachments from disk and convert to base64
        if (['send_email', 'reply_email', 'forward_email'].includes(toolName) && Array.isArray(args.attachments)) {
            args.attachments = await this.loadAttachmentFiles(args.attachments as Record<string, unknown>[]);
        }

        if (toolName === 'create_folder' && typeof args.name === 'string') {
            const plaintext = new TextEncoder().encode(args.name);
            const encrypted = await encryptPhpAesGcm(plaintext, this.masterKey);
            const { name: _removed, ...rest } = args;
            return {
                ...request,
                params: {
                    ...request.params,
                    arguments: { ...rest, encrypted_name: toBase64(encrypted) },
                },
            };
        }

        // Calendar event encryption (create_event, update_event)
        if ((toolName === 'create_event' || toolName === 'update_event') && this.masterKey) {
            const encArgs = await this.encryptCalendarEventArgs(toolName, args);
            return {
                ...request,
                params: { ...request.params, arguments: encArgs },
            };
        }

        // Aufgaben-Verschluesselung (create_task, update_task, create_task_list) - // #f1c8f3f1
        if ((toolName === 'create_task' || toolName === 'update_task') && this.masterKey) {
            const encArgs = await this.encryptTaskArgs(toolName, args);
            return {
                ...request,
                params: { ...request.params, arguments: encArgs },
            };
        }

        if (toolName === 'create_task_list' && this.masterKey) {
            const encArgs = await this.encryptTaskListArgs(args);
            return {
                ...request,
                params: { ...request.params, arguments: encArgs },
            };
        }

        return request;
    }

    /**
     * Forward a JSON-RPC request to the remote Aionda Mail MCP server
     */
    /** JSON-RPC-Fehlercode des Servers für eine ungültige oder abgelaufene Sitzung. */
    private static readonly SESSION_INVALID_CODE = -32000;

    /**
     * Anfrage an den Server; bei verlorener Sitzung einmal neu anmelden und wiederholen.
     *
     * 🚩 Gemessen 08.11.2026: Der Server hält höchstens 10 Sitzungen je
     * MCP-Schlüssel (McpSessionService::MAX_SESSIONS_PER_EMP) und schließt bei
     * der elften die ÄLTESTE. Ein zweiter Rechner, ein Testlauf oder ein Neustart
     * an anderer Stelle verdrängt so die Sitzung eines laufenden Agenten - und
     * jeder weitere Aufruf endete mit „Invalid or expired session“, bis man den
     * Agenten neu startete. Nach 24 h läuft die Sitzung ohnehin ab.
     * Die Schlüssel bleiben dabei im Speicher; neu ist nur die Sitzungskennung.
     */
    private async forwardToServer(request: JsonRpcRequest): Promise<JsonRpcResponse> {
        const response = await this.sendToServer(request);
        if (request.method === 'initialize' || !this.isSessionLost(response)) {
            return response;
        }

        process.stderr.write('[proxy] MCP session lost, re-initializing once\n');
        this.sessionId = null;
        const initResp = await this.sendToServer({
            jsonrpc: '2.0', id: 0, method: 'initialize',
            params: {
                protocolVersion: '2025-03-26',
                capabilities: {},
                clientInfo: { name: '@aiondadotcom/mail-mcp-client', version: '0.16.0' },
            },
        });
        if (initResp.error) {
            return response;
        }
        await this.sendToServer({ jsonrpc: '2.0', method: 'notifications/initialized' });
        return this.sendToServer(request);
    }

    /**
     * Ist das die Antwort „Sitzung ungültig oder abgelaufen“?
     */
    private isSessionLost(response: JsonRpcResponse): boolean {
        const error = response.error;
        return !!error
            && error.code === McpDecryptingProxy.SESSION_INVALID_CODE
            && /session/i.test(error.message ?? '');
    }

    private async sendToServer(request: JsonRpcRequest): Promise<JsonRpcResponse> {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
        };
        if (this.sessionId) {
            headers['Mcp-Session-Id'] = this.sessionId;
        }

        const resp = await fetch(this.endpoint, {
            method: 'POST',
            headers,
            body: JSON.stringify(request),
        });

        // Capture session ID
        const newSessionId = resp.headers.get('Mcp-Session-Id');
        if (newSessionId) {
            this.sessionId = newSessionId;
        }

        // Notifications have no body
        if (!request.id && request.id !== 0) {
            return { jsonrpc: '2.0' };
        }

        return await resp.json() as JsonRpcResponse;
    }


    /**
     * Anhänge von der Platte lesen: {file_path, filename?, mimetype?} →
     * {filename, content(Base64), mimetype, size}. Wirft, wenn keiner lesbar ist.
     */
    private async loadAttachmentFiles(
        attachments: Record<string, unknown>[]
    ): Promise<{ filename: string; content: string; mimetype: string; size: number }[]> {
        const processedAttachments: { filename: string; content: string; mimetype: string; size: number }[] = [];
        for (const att of attachments) {
            const filePath = att.file_path as string;
            if (!filePath) continue;

            try {
                const fileData = readFileSync(filePath);
                const { basename, extname } = await import('node:path');
                const filename = (att.filename as string) || basename(filePath);
                const ext = extname(filename).toLowerCase();

                // Detect mimetype from extension
                const mimeMap: Record<string, string> = {
                    '.pdf': 'application/pdf', '.doc': 'application/msword',
                    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    '.xls': 'application/vnd.ms-excel',
                    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    '.ppt': 'application/vnd.ms-powerpoint',
                    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
                    '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
                    '.txt': 'text/plain', '.csv': 'text/csv', '.html': 'text/html',
                    '.zip': 'application/zip', '.gz': 'application/gzip',
                };
                const mimetype = (att.mimetype as string) || mimeMap[ext] || 'application/octet-stream';

                processedAttachments.push({
                    filename,
                    content: fileData.toString('base64'),
                    mimetype,
                    size: fileData.length,
                });

                process.stderr.write(`[proxy] Attachment loaded: ${filename} (${fileData.length} bytes)\n`);
            } catch (e) {
                process.stderr.write(`[proxy] Failed to read attachment ${filePath}: ${(e as Error).message}\n`);
            }
        }
        if (processedAttachments.length === 0 && attachments.length > 0) {
            // All attachments failed to load — refuse to send without them
            throw new Error('All attachments failed to load. Check file paths and permissions.');
        }
        return processedAttachments;
    }

    /**
     * save_draft mit persönlichem Schlüssel: Entwurf lokal bauen,
     * verschlüsseln, nur `encrypted_content` (+ draft_id) an den Server.
     *
     * Mit draft_id wird der bestehende Entwurf geholt, entschlüsselt und nur
     * in den übergebenen Feldern geändert - so geht nichts verloren, was der
     * Nutzer inzwischen im Client ergänzt hat (Anhänge, Empfänger, Text).
     */
    private async handleSavePersonalDraft(request: JsonRpcRequest): Promise<JsonRpcResponse> {
        const id   = request.id ?? null;
        const args = { ...((request.params?.arguments as Record<string, unknown>) || {}) };
        const fehler = (message: string): JsonRpcResponse => ({
            jsonrpc: '2.0', id,
            result: { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: true, message }) }] },
        } as JsonRpcResponse);

        if (!this.masterKey) return fehler('Vault is locked: draft cannot be encrypted');

        const draftId = typeof args.draft_id === 'string' && args.draft_id !== '' ? args.draft_id : null;

        try {
            let bisher: DraftContent = {};
            if (draftId) {
                const alt = await this.forwardToServer({
                    jsonrpc: '2.0', id: 0, method: 'tools/call',
                    params: { name: 'get_draft', arguments: { draft_id: draftId } },
                });
                const altDaten = this.parseToolContent(alt);
                if (alt.error || !altDaten || altDaten.error || typeof altDaten.encrypted_content !== 'string') {
                    // Grund des Servers weitergeben, nicht pauschal „not found" (CLAUDE.md, Punkt 7).
                    const grund = alt.error?.message
                        ?? (typeof altDaten?.message === 'string' ? altDaten.message : 'no encrypted_content returned');
                    return fehler(`Draft ${draftId} could not be loaded: ${grund}`);
                }
                bisher = await decryptDraft(altDaten.encrypted_content, this.masterKey);
            }

            // Anhänge: dieselben Aliase wie bei send_email
            const anhangListe = args.attachments ?? args.attachment_paths ?? args.attachment_path;
            let neueAnhaenge: DraftAttachment[] = [];
            if (anhangListe !== undefined) {
                const liste = (Array.isArray(anhangListe) ? anhangListe : [anhangListe]).map(a =>
                    typeof a === 'string' ? { file_path: a } : (a as Record<string, unknown>));
                neueAnhaenge = (await this.loadAttachmentFiles(liste)).map(a => ({
                    id: webcrypto.randomUUID().toUpperCase(),
                    name: a.filename, size: a.size, type: a.mimetype, content: a.content,
                }));
            }

            let body = args.body;
            if (!draftId && typeof body === 'string' && this.signatureAutoInsertNew) {
                body = this.appendSignature(body);
            }

            const inhalt = mergeDraft(bisher, {
                subject: args.subject, body, to: args.to, cc: args.cc, bcc: args.bcc,
                from_identity: args.from_identity,
            }, neueAnhaenge, new Date(),
                args.clear_fields === undefined ? [] : Array.isArray(args.clear_fields) ? args.clear_fields : [args.clear_fields]);

            const encrypted_content = await encryptDraft(inhalt, this.masterKey);
            const antwort = await this.forwardToServer({
                ...request,
                params: {
                    ...request.params,
                    arguments: draftId ? { encrypted_content, draft_id: draftId } : { encrypted_content },
                },
            });
            process.stderr.write(`[proxy] save_draft: encrypted locally (${draftId ? 'update' : 'new'})\n`);
            return antwort;
        } catch (e) {
            return fehler(`Draft not saved: ${(e as Error).message}`);
        }
    }

    /** Entwurf für die KI lesbar machen; bei Fehler Grund statt Geheimtext. */
    private async tryDecryptDraft(draft: Record<string, unknown>): Promise<Record<string, unknown>> {
        if (!this.masterKey || typeof draft.encrypted_content !== 'string') return draft;
        try {
            return draftForAi(draft, await decryptDraft(draft.encrypted_content, this.masterKey));
        } catch (e) {
            const { encrypted_content: _geheim, ...rest } = draft;
            return { ...rest, decrypt_error: (e as Error).message };
        }
    }

    /**
     * Inspect a tool result and decrypt encrypted fields if found
     */
    private async maybeDecryptResult(result: McpToolResult, toolName: string): Promise<McpToolResult> {
        if (!result.content || !this.masterKey) return result;

        const textContent = result.content.find(c => c.type === 'text');
        if (!textContent) return result;

        let data: Record<string, unknown>;
        try {
            data = JSON.parse(textContent.text);
        } catch {
            return result;
        }

        let modified = false;

        // Decrypt email lists (list_emails)
        if (data.emails && Array.isArray(data.emails)) {
            data.emails = await Promise.all(
                (data.emails as EncryptedEmail[]).map(e => this.tryDecryptEmailSummary(e))
            );
            modified = true;
        }

        // Decrypt single email (read_email)
        if (data.encrypted_subject && data.uuid) {
            data = await this.tryDecryptFullEmail(data as unknown as EncryptedEmail);
            modified = true;
        }

        // Decrypt attachment and save to disk (get_attachment)
        if (toolName === 'get_attachment' && data.encrypted_content && data.uuid) {
            data = await this.tryDecryptAttachment(data);
            modified = true;
        }

        // Entwürfe entschlüsseln (list_drafts, get_draft)
        if (toolName === 'list_drafts' && Array.isArray(data.drafts)) {
            data.drafts = await Promise.all(
                (data.drafts as Record<string, unknown>[]).map(d => this.tryDecryptDraft(d))
            );
            modified = true;
        }
        if (toolName === 'get_draft' && typeof data.encrypted_content === 'string') {
            data = await this.tryDecryptDraft(data);
            modified = true;
        }

        // Decrypt folder names (list_folders)
        if (data.folders && Array.isArray(data.folders)) {
            data.folders = await Promise.all(
                (data.folders as Record<string, unknown>[]).map(f => this.tryDecryptFolder(f))
            );
            modified = true;
        }

        // Decrypt calendar list (list_calendars)
        process.stderr.write(`[proxy] maybeDecryptResult toolName=${toolName} keys: ${Object.keys(data).join(',')}\n`);
        if (data.calendars && Array.isArray(data.calendars) && toolName === 'list_calendars') {
            process.stderr.write(`[proxy] Decrypting ${(data.calendars as unknown[]).length} calendars\n`);
            data.calendars = await Promise.all(
                (data.calendars as Record<string, unknown>[]).map(c => this.tryDecryptCalendar(c))
            );
            modified = true;
        }

        // Decrypt calendar events (list_events, list_shared_events)
        if (data.events && Array.isArray(data.events) && (toolName === 'list_events' || toolName === 'list_shared_events')) {
            data.events = await Promise.all(
                (data.events as Record<string, unknown>[]).map(e => this.tryDecryptCalendarEvent(e))
            );
            modified = true;
        }

        // Decrypt tasks (list_tasks) - // #f1c8f3f1
        if (toolName === 'list_tasks' && data.tasks && Array.isArray(data.tasks)) {
            data.tasks = await Promise.all(
                (data.tasks as Record<string, unknown>[]).map(t => this.tryDecryptTask(t))
            );
            modified = true;
        }

        // Decrypt task lists (list_task_lists) - // #f1c8f3f1
        if (toolName === 'list_task_lists' && data.lists && Array.isArray(data.lists)) {
            data.lists = await Promise.all(
                (data.lists as Record<string, unknown>[]).map(l => this.tryDecryptTaskList(l))
            );
            modified = true;
        }

        // Decrypt shared calendars (list_shared_calendars)
        if (toolName === 'list_shared_calendars' && data.incoming && Array.isArray(data.incoming)) {
            data.incoming = await Promise.all(
                (data.incoming as Record<string, unknown>[]).map(sc => this.tryDecryptSharedCalendar(sc))
            );
            modified = true;
        }

        if (modified) {
            return {
                ...result,
                content: result.content.map(c =>
                    c === textContent ? { ...c, text: JSON.stringify(data) } : c
                ),
            };
        }

        return result;
    }

    /**
     * Decrypt email summary fields (subject, from, to)
     */
    private async tryDecryptEmailSummary(email: EncryptedEmail): Promise<Record<string, unknown>> {
        if (!this.masterKey || !this.privateKeys) return email as unknown as Record<string, unknown>;
        try {
            // For shared folder emails, decrypt ephemeral key via folder key
            const ephKey = await this.getSharedFolderEphemeralKey(email as unknown as Record<string, unknown>);
            const decrypted = await decryptEmail(email, this.masterKey, this.privateKeys, ephKey ?? undefined);
            return {
                uuid: decrypted.uuid,
                subject: decrypted.subject,
                from: decrypted.from,
                to: decrypted.to,
                size_bytes: decrypted.sizeBytes,
                has_attachments: decrypted.hasAttachments,
                attachment_count: decrypted.attachmentCount,
                is_read: decrypted.isRead,
                is_starred: decrypted.isStarred,
                is_deleted: decrypted.isDeleted,
                folder_type: decrypted.folderType,
                folder_uuid: decrypted.folderUuid,
                received_at: email.received_at,
                thread_id: decrypted.threadId,
            };
        } catch (err) {
            process.stderr.write(`[proxy] Decrypt email summary ${email.uuid} failed: ${err}\n`);
            // Return minimal info without encrypted garbage
            return {
                uuid: email.uuid,
                subject: '[Decryption failed]',
                from: '[encrypted]',
                to: '[encrypted]',
                decryption_error: (err as Error).message,
                is_read: email.is_read,
                folder_type: email.folder_type,
                folder_uuid: email.folder_uuid,
                received_at: email.received_at,
                has_attachments: email.has_attachments,
            };
        }
    }

    /**
     * Decrypt full email (read_email response)
     */
    private async tryDecryptFullEmail(email: EncryptedEmail): Promise<Record<string, unknown>> {
        if (!this.masterKey || !this.privateKeys) return email as unknown as Record<string, unknown>;
        try {
            const ephKey = await this.getSharedFolderEphemeralKey(email as unknown as Record<string, unknown>);
            const decrypted = await decryptEmail(email, this.masterKey, this.privateKeys, ephKey ?? undefined);
            return {
                uuid: decrypted.uuid,
                subject: decrypted.subject,
                from: decrypted.from,
                to: decrypted.to,
                body: decrypted.body,
                body_text: decrypted.bodyText,
                headers: decrypted.headers,
                size_bytes: decrypted.sizeBytes,
                has_attachments: decrypted.hasAttachments,
                attachment_count: decrypted.attachmentCount,
                attachments: decrypted.attachments,
                is_read: decrypted.isRead,
                is_starred: decrypted.isStarred,
                is_deleted: decrypted.isDeleted,
                folder_type: decrypted.folderType,
                folder_uuid: decrypted.folderUuid,
                received_at: email.received_at,
                thread_id: decrypted.threadId,
                message_id: decrypted.messageId,
                reply_to: decrypted.replyTo,
                signature_status: decrypted.signatureStatus,
            };
        } catch (err) {
            process.stderr.write(`[proxy] Decrypt full email ${email.uuid} failed: ${err}\n`);
            return {
                uuid: email.uuid,
                subject: '[Decryption failed]',
                from: '[encrypted]',
                to: '[encrypted]',
                body: `[Decryption failed: ${(err as Error).message}. The email content is encrypted and could not be decrypted with the current vault keys.]`,
                decryption_error: (err as Error).message,
                is_read: email.is_read,
                folder_type: email.folder_type,
                folder_uuid: email.folder_uuid,
                received_at: email.received_at,
                has_attachments: email.has_attachments,
            };
        }
    }

    /**
     * Decrypt folder name
     */
    private async tryDecryptFolder(folder: Record<string, unknown>): Promise<Record<string, unknown>> {
        if (!this.masterKey || !folder.encrypted_name) return folder;
        try {
            const encName = fromBase64(folder.encrypted_name as string);
            let plaintext = await decryptPhpAesGcm(encName, this.masterKey);
            if (isBucketPadded(plaintext)) plaintext = unpadFromBucket(plaintext);
            plaintext = await decompress(plaintext);
            const name = new TextDecoder().decode(plaintext);
            return { ...folder, name, encrypted_name: undefined };
        } catch {
            return folder;
        }
    }

    /**
     * Decrypt a calendar entry (list_calendars response item)
     */
    private async tryDecryptCalendar(cal: Record<string, unknown>): Promise<Record<string, unknown>> {
        if (!this.masterKey || !cal.encrypted_calendar_key) return cal;
        try {
            // Calendar key is encrypted with Master Key (browser encryptData format)
            const encCalKey = fromBase64(cal.encrypted_calendar_key as string);
            const calKey = await decryptVaultData(encCalKey, this.masterKey);
            if (!calKey || calKey.length !== 32) return cal;

            let name = cal.uuid as string;
            let description: string | null = null;

            if (cal.encrypted_name) {
                const decrypted = await this.decryptFieldWithKey(calKey, cal.encrypted_name as string);
                if (decrypted) name = decrypted;
            }
            if (cal.encrypted_description) {
                description = await this.decryptFieldWithKey(calKey, cal.encrypted_description as string);
            }

            return {
                uuid: cal.uuid,
                name,
                description,
                color: cal.color,
                is_default: cal.is_default,
                event_count: cal.event_count,
                sort_order: cal.sort_order,
                created_at: cal.created_at,
                updated_at: cal.updated_at,
            };
        } catch (err) {
            process.stderr.write(`[proxy] Decrypt calendar failed: ${err}\n`);
            return cal;
        }
    }

    /**
     * Decrypt a calendar event entry (list_events response item)
     */
    private async tryDecryptCalendarEvent(evt: Record<string, unknown>): Promise<Record<string, unknown>> {
        if (!this.masterKey || !evt.wrapped_key) return evt;
        try {
            // Event key is wrapped with Calendar Key or Master Key (browser encryptData format)
            const wrappedData = fromBase64(evt.wrapped_key as string);
            const eventKey = await decryptVaultData(wrappedData, this.masterKey);
            if (!eventKey || eventKey.length !== 32) return evt;

            let title = '[encrypted]';
            let description: string | null = null;
            let location: string | null = null;
            let attendees: unknown = null;
            let metadata: unknown = null;

            if (evt.encrypted_title) title = await this.decryptFieldWithKey(eventKey, evt.encrypted_title as string) ?? title;
            if (evt.encrypted_description) description = await this.decryptFieldWithKey(eventKey, evt.encrypted_description as string);
            if (evt.encrypted_location) location = await this.decryptFieldWithKey(eventKey, evt.encrypted_location as string);
            if (evt.encrypted_attendees) {
                const raw = await this.decryptFieldWithKey(eventKey, evt.encrypted_attendees as string);
                if (raw) try { attendees = JSON.parse(raw); } catch { /* ignore */ }
            }
            if (evt.encrypted_metadata) {
                const raw = await this.decryptFieldWithKey(eventKey, evt.encrypted_metadata as string);
                if (raw) try { metadata = JSON.parse(raw); } catch { /* ignore */ }
            }

            return {
                uuid: evt.uuid,
                calendar_uuid: evt.calendar_uuid,
                title,
                description,
                location,
                attendees,
                metadata,
                start_time: evt.start_time,
                end_time: evt.end_time,
                is_all_day: evt.is_all_day,
                status: evt.status,
                is_private: evt.is_private,
                calendar_color: evt.calendar_color,
                created_at: evt.created_at,
                updated_at: evt.updated_at,
            };
        } catch (err) {
            process.stderr.write(`[proxy] Decrypt calendar event failed: ${err}\n`);
            return evt;
        }
    }

    /**
     * Decrypt a shared calendar entry (list_shared_calendars response item)
     */
    private async tryDecryptSharedCalendar(sc: Record<string, unknown>): Promise<Record<string, unknown>> {
        if (!this.masterKey || !this.privateKeys) return sc;
        let displayName = `${sc.owner_username} / ${sc.calendar_uuid}`;
        try {
            if (sc.encrypted_display_name && sc.x25519_ephemeral && sc.mlkem_ciphertext && sc.display_name_nonce) {
                const sharedSecret = await hybridDecapsulate(
                    fromBase64(sc.x25519_ephemeral as string),
                    fromBase64(sc.mlkem_ciphertext as string),
                    this.privateKeys.x25519PrivateKey,
                    this.privateKeys.mlKemPrivateKey
                );
                const { webcrypto } = await import('node:crypto');
                const aesKey = await webcrypto.subtle.importKey('raw', sharedSecret, 'AES-GCM', false, ['decrypt']);
                const decBuf = await webcrypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: fromBase64(sc.display_name_nonce as string) },
                    aesKey,
                    fromBase64(sc.encrypted_display_name as string)
                );
                displayName = `${sc.owner_username} / ${new TextDecoder().decode(decBuf)}`;
            }
        } catch (err) {
            process.stderr.write(`[proxy] Shared calendar name decrypt failed: ${err}\n`);
        }
        return {
            share_uuid: sc.share_uuid,
            calendar_uuid: sc.calendar_uuid,
            name: displayName,
            owner: sc.owner_username,
            calendar_color: sc.calendar_color,
            can_read: sc.can_read, can_create: sc.can_create, can_edit: sc.can_edit,
            can_delete: sc.can_delete, can_invite: sc.can_invite, can_manage: sc.can_manage,
            role_preset: sc.role_preset,
            event_count: sc.event_count,
        };
    }

    /**
     * Unwrap a Hybrid KEM wrapped key (version 1 format)
     */
    private async unwrapHybridKemKey(data: Uint8Array): Promise<Uint8Array | null> {
        if (!this.privateKeys) return null;
        const version = data[0];
        if (version !== 1) {
            process.stderr.write(`[proxy] Unsupported wrapped key version: ${version}\n`);
            return null;
        }
        const x25519Ct = data.slice(1, 33);
        const mlKemCt = data.slice(33, 33 + 1568);
        const iv = data.slice(33 + 1568, 33 + 1568 + 12);
        const encryptedKey = data.slice(33 + 1568 + 12);

        const sharedSecret = await hybridDecapsulate(
            x25519Ct, mlKemCt,
            this.privateKeys.x25519PrivateKey, this.privateKeys.mlKemPrivateKey
        );

        // PHP format: tag(16) || ciphertext → reorder to WebCrypto: ciphertext || tag
        const TAG_LENGTH = 16;
        const tag = encryptedKey.slice(0, TAG_LENGTH);
        const ciphertext = encryptedKey.slice(TAG_LENGTH);
        const reordered = new Uint8Array(encryptedKey.length);
        reordered.set(ciphertext, 0);
        reordered.set(tag, ciphertext.length);

        let key = await decryptAesGcm(reordered, sharedSecret, iv);
        if (isBucketPadded(key)) key = unpadFromBucket(key);
        key = await decompress(key);
        return key;
    }

    /**
     * Decrypt a base64-encoded AES-GCM encrypted field with a given key.
     * Calendar event fields use WebCrypto format: iv(12) || ciphertext+tag (no HKDF).
     */
    private async decryptFieldWithKey(key: Uint8Array, encryptedBase64: string): Promise<string | null> {
        try {
            const encrypted = fromBase64(encryptedBase64);
            // Try browser format first (iv || ciphertext+tag), then PHP format as fallback
            let plaintext: Uint8Array;
            try {
                plaintext = await decryptClientAesGcm(encrypted, key);
            } catch {
                plaintext = await decryptPhpAesGcm(encrypted, key);
            }
            if (isBucketPadded(plaintext)) plaintext = unpadFromBucket(plaintext);
            plaintext = await decompress(plaintext);
            return new TextDecoder().decode(plaintext);
        } catch {
            return null;
        }
    }

    /**
     * Encrypt calendar event arguments (create_event / update_event).
     * Generates a new event key, encrypts plaintext fields, wraps key with Hybrid KEM.
     */
    private async encryptCalendarEventArgs(
        toolName: string,
        args: Record<string, unknown>
    ): Promise<Record<string, unknown>> {
        if (!this.masterKey) return args;

        // AI sends encrypted_title/encrypted_description/encrypted_location (per schema)
        // but with plaintext values — we encrypt them here
        const title = (args.title || args.encrypted_title) as string | undefined;
        const description = (args.description || args.encrypted_description) as string | undefined;
        const location = (args.location || args.encrypted_location) as string | undefined;
        const hasPlaintext = title || description || location;
        if (!hasPlaintext && toolName === 'update_event') return args;
        if (!title && toolName === 'create_event') return args;

        // Generate random 32-byte ephemeral event key
        const { randomBytes } = await import('node:crypto');
        const eventKey = new Uint8Array(randomBytes(32));

        // Wrap event key with Master Key (browser encryptData format)
        const wrappedKey = await encryptVaultData(eventKey, this.masterKey);

        // Encrypt fields with event key (simple AES-GCM: iv(12) || ciphertext+tag)
        const encryptField = async (text: string): Promise<string> => {
            const { webcrypto, randomBytes: rng } = await import('node:crypto');
            const iv = rng(12);
            const aesKey = await webcrypto.subtle.importKey('raw', eventKey, 'AES-GCM', false, ['encrypt']);
            const ct = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(text));
            const result = new Uint8Array(12 + ct.byteLength);
            result.set(new Uint8Array(iv), 0);
            result.set(new Uint8Array(ct), 12);
            return toBase64(result);
        };

        const result: Record<string, unknown> = { ...args };

        if (title) {
            result.encrypted_title = await encryptField(title);
            result.wrapped_key = toBase64(wrappedKey);
            delete result.title;
        }
        if (description) {
            result.encrypted_description = await encryptField(description);
            if (!result.wrapped_key) result.wrapped_key = toBase64(wrappedKey);
            delete result.description;
        }
        if (location) {
            result.encrypted_location = await encryptField(location);
            if (!result.wrapped_key) result.wrapped_key = toBase64(wrappedKey);
            delete result.location;
        }

        // Remove calendar_uuid from update args (not a DB field for update)
        if (toolName === 'update_event') {
            delete result.calendar_uuid;
        }

        return result;
    }

    // ─── Aufgaben (Tasks) - // #f1c8f3f1 ──────────────────────────────────

    /**
     * Decrypt a task entry (list_tasks response item).
     * Same crypto as the web frontend: per-task key, wrapped with the master key.
     */
    private async tryDecryptTask(task: Record<string, unknown>): Promise<Record<string, unknown>> {
        if (!this.masterKey || !task.wrapped_key) return task;
        try {
            const taskKey = await unwrapTaskKey(fromBase64(task.wrapped_key as string), this.masterKey);

            let title = '[encrypted]';
            let notes: string | null = null;
            let steps: unknown[] = [];
            let metadata: unknown = null;

            if (task.encrypted_title) {
                title = await decryptTaskField(task.encrypted_title as string, taskKey, 'title');
            }
            if (task.encrypted_notes) {
                notes = await decryptTaskField(task.encrypted_notes as string, taskKey, 'notes');
            }
            if (task.encrypted_steps) {
                try {
                    steps = parseSteps(await decryptTaskField(task.encrypted_steps as string, taskKey, 'steps'));
                } catch { /* kaputte Schritte duerfen die Aufgabe nicht kippen */ }
            }
            if (task.encrypted_metadata) {
                try {
                    metadata = JSON.parse(await decryptTaskField(task.encrypted_metadata as string, taskKey, 'metadata'));
                } catch { /* ignore */ }
            }

            return {
                uuid: task.uuid,
                list_uuid: task.list_uuid,
                title,
                notes,
                steps,
                metadata,
                due_date: task.due_date,
                reminder_time: task.reminder_time,
                is_important: task.is_important,
                is_completed: task.is_completed,
                completed_at: task.completed_at,
                my_day_date: task.my_day_date,
                linked_email_uuid: task.linked_email_uuid,
                position: task.position,
                created_at: task.created_at,
                updated_at: task.updated_at,
            };
        } catch (err) {
            process.stderr.write(`[proxy] Decrypt task failed: ${err}\n`);
            return task;
        }
    }

    /**
     * Decrypt a task list entry (list_task_lists response item)
     */
    private async tryDecryptTaskList(list: Record<string, unknown>): Promise<Record<string, unknown>> {
        if (!this.masterKey || !list.wrapped_key) return list;
        try {
            const listKey = await unwrapTaskKey(fromBase64(list.wrapped_key as string), this.masterKey);
            const name = list.encrypted_name
                ? await decryptTaskField(list.encrypted_name as string, listKey, 'list-name')
                : (list.uuid as string);

            return {
                uuid: list.uuid,
                name,
                position: list.position,
                is_default: list.is_default,
                task_count: list.task_count,
                created_at: list.created_at,
                updated_at: list.updated_at,
            };
        } catch (err) {
            process.stderr.write(`[proxy] Decrypt task list failed: ${err}\n`);
            return list;
        }
    }

    /**
     * Fetch the raw (still encrypted) task record for a UUID.
     * Needed by update_task: changed text fields must be encrypted with the
     * EXISTING task key, otherwise the untouched fields would become unreadable.
     */
    private async fetchRawTask(taskUuid: string): Promise<Record<string, unknown> | null> {
        const response = await this.forwardToServer({
            jsonrpc: '2.0', id: 0, method: 'tools/call',
            params: {
                name: 'list_tasks',
                arguments: { filter: 'all', include_completed: true, limit: 500 },
            },
        });

        const data = this.parseToolContent(response);
        const tasks = data?.tasks;
        if (!Array.isArray(tasks)) return null;

        return (tasks as Record<string, unknown>[]).find(t => t.uuid === taskUuid) ?? null;
    }

    /**
     * Encrypt task arguments (create_task / update_task).
     *
     * The AI provides plaintext title/notes/steps/metadata. create_task gets a
     * fresh per-task key, update_task reuses the existing one.
     */
    private async encryptTaskArgs(
        toolName: string,
        args: Record<string, unknown>
    ): Promise<Record<string, unknown>> {
        if (!this.masterKey) return args;

        const title = (args.title ?? args.encrypted_title) as string | undefined;
        const notes = (args.notes ?? args.encrypted_notes) as string | undefined;
        const hasSteps = args.steps !== undefined;
        const hasMetadata = args.metadata !== undefined;

        const result: Record<string, unknown> = { ...args };
        delete result.title;
        delete result.notes;
        delete result.steps;
        delete result.metadata;

        if (toolName === 'create_task') {
            if (!title) {
                throw new Error('create_task requires a title');
            }

            const taskKey = generateTaskKey();
            result.wrapped_key = toBase64(await wrapTaskKey(taskKey, this.masterKey));
            result.encrypted_title = await encryptTaskField(title, taskKey, 'title');

            if (notes) {
                result.encrypted_notes = await encryptTaskField(notes, taskKey, 'notes');
            }
            if (hasSteps) {
                result.encrypted_steps = await encryptTaskField(
                    JSON.stringify(normalizeSteps(args.steps)), taskKey, 'steps'
                );
            }
            if (hasMetadata) {
                result.encrypted_metadata = await encryptTaskField(JSON.stringify(args.metadata), taskKey, 'metadata');
            }

            return result;
        }

        // update_task: ohne Textfelder ist nichts zu verschluesseln
        if (!title && !notes && !hasSteps && !hasMetadata) {
            return result;
        }

        const taskUuid = args.task_uuid as string | undefined;
        if (!taskUuid) {
            throw new Error('update_task requires task_uuid');
        }

        const raw = await this.fetchRawTask(taskUuid);
        if (!raw?.wrapped_key) {
            // Ohne den bestehenden Key duerfen wir NICHT neu verschluesseln:
            // ein neuer wrapped_key wuerde alle unveraenderten Felder der
            // Aufgabe unlesbar machen. Lieber laut scheitern.
            throw new Error(`update_task: task ${taskUuid} not found - cannot re-encrypt fields`);
        }

        const taskKey = await unwrapTaskKey(fromBase64(raw.wrapped_key as string), this.masterKey);

        if (title) {
            result.encrypted_title = await encryptTaskField(title, taskKey, 'title');
        }
        if (notes !== undefined) {
            result.encrypted_notes = notes ? await encryptTaskField(notes, taskKey, 'notes') : null;
        }
        if (hasSteps) {
            const steps = normalizeSteps(args.steps);
            result.encrypted_steps = steps.length > 0
                ? await encryptTaskField(JSON.stringify(steps), taskKey, 'steps')
                : null;
        }
        if (hasMetadata) {
            result.encrypted_metadata = args.metadata
                ? await encryptTaskField(JSON.stringify(args.metadata), taskKey, 'metadata')
                : null;
        }

        return result;
    }

    /**
     * Encrypt task list arguments (create_task_list).
     * The list name is encrypted with its own key, exactly like the frontend.
     */
    private async encryptTaskListArgs(args: Record<string, unknown>): Promise<Record<string, unknown>> {
        if (!this.masterKey) return args;

        const name = (args.name ?? args.encrypted_name) as string | undefined;
        if (!name) {
            throw new Error('create_task_list requires a name');
        }

        const listKey = generateTaskKey();
        const result: Record<string, unknown> = { ...args };
        delete result.name;

        result.encrypted_name = await encryptTaskField(name, listKey, 'list-name');
        result.wrapped_key = toBase64(await wrapTaskKey(listKey, this.masterKey));

        return result;
    }

    /**
     * For shared folder emails: decrypt the ephemeral key via folder key.
     * Returns null for non-shared emails (normal decryption path).
     */
    private async getSharedFolderEphemeralKey(email: Record<string, unknown>): Promise<Uint8Array | null> {
        const rewrappedKey = email.rewrapped_key as string;
        const keyNonce = email.key_nonce as string;
        if (!rewrappedKey || !keyNonce || !this.privateKeys) return null;

        // Find the matching share for this email's folder
        const folderUuid = email.folder_uuid as string;
        if (!folderUuid) return null;

        // Ensure shares are cached
        if (this.cachedIncomingShares.length === 0) {
            const foldersResp = await this.forwardToServer({
                jsonrpc: '2.0', id: 0, method: 'tools/call',
                params: { name: 'list_folders', arguments: {} },
            });
            this.cacheSharedFolders(foldersResp);
        }

        const share = this.cachedIncomingShares.find(
            s => (s.folder_uuid as string) === folderUuid
        );
        if (!share) return null;

        try {
            // Decrypt folder key
            const folderKey = await decryptSharedFolderKey(
                share.encrypted_folder_key as string,
                share.x25519_ephemeral as string,
                share.mlkem_ciphertext as string,
                share.key_nonce as string,
                this.privateKeys
            );

            // Decrypt ephemeral key with folder key
            const folderAesKey = await webcrypto.subtle.importKey(
                'raw', folderKey, { name: 'AES-GCM' }, false, ['decrypt']
            );
            const ephemeralKey = new Uint8Array(await webcrypto.subtle.decrypt(
                { name: 'AES-GCM', iv: fromBase64(keyNonce) },
                folderAesKey,
                fromBase64(rewrappedKey)
            ));
            return ephemeralKey;
        } catch (e) {
            process.stderr.write(`[proxy] Shared folder key decryption failed: ${(e as Error).message}\n`);
            return null;
        }
    }

    /**
     * Mail-Schlüssel einer Mail aus einem geteilten Ordner holen (über deren
     * rewrapped_key und den Ordnerschlüssel). null, wenn es keine ist.
     */
    private async sharedFolderKeyForEmail(emailUuid: string): Promise<Uint8Array | null> {
        if (!emailUuid) return null;
        const resp = await this.forwardToServer({
            jsonrpc: '2.0', id: 0, method: 'tools/call',
            params: { name: 'read_email', arguments: { email_uuid: emailUuid } },
        });
        const raw = this.parseToolContent(resp);
        const email = ((raw?.data as Record<string, unknown> | undefined) ?? raw) as Record<string, unknown> | null;
        if (!email) return null;
        return this.getSharedFolderEphemeralKey(email);
    }

    /**
     * Decrypt attachment fields (filename, content, mimetype)
     */
    private async tryDecryptAttachment(att: Record<string, unknown>): Promise<Record<string, unknown>> {
        if (!this.masterKey || !this.privateKeys) return att;
        try {
            // #c2fb3967 - eine Stelle für alle Kapselarten, auch den
            // abgeleiteten Mail-Schlüssel. Anhänge benutzen den Schlüssel
            // IHRER Mail, deshalb `email_uuid`.
            let { key: decryptionKey, clientEncrypted } = await resolveContentKey(
                att.wrapped_ephemeral_key as string,
                att.email_uuid as string,
                this.masterKey,
                this.privateKeys
            );
            const decryptAttField = (hex: string): Promise<Uint8Array> =>
                decryptFieldBytes(fromHex(hex), decryptionKey, clientEncrypted);

            // Anhang aus einem geteilten Ordner: Er gehört zum Schlüssel der
            // Mail des EIGENTÜMERS, den nur der Ordnerschlüssel liefert. Der
            // Server legt dafür kein Material an den Anhang; es kommt über die
            // Mail. AES-GCM ist authentifiziert - der erste Versuch scheitert
            // laut, er kann nicht falsch „gelingen".
            if (att.encrypted_filename) {
                try {
                    await decryptAttField(att.encrypted_filename as string);
                } catch (ownKeyError) {
                    const sharedKey = await this.sharedFolderKeyForEmail(att.email_uuid as string);
                    if (!sharedKey) throw ownKeyError;
                    decryptionKey = sharedKey;
                    clientEncrypted = true;
                }
            }

            // Decrypt filename
            let filename = 'attachment';
            if (att.encrypted_filename) {
                filename = new TextDecoder().decode(await decryptAttField(att.encrypted_filename as string));
            }

            // Decrypt mimetype
            let mimetype = 'application/octet-stream';
            if (att.encrypted_mimetype) {
                mimetype = new TextDecoder().decode(await decryptAttField(att.encrypted_mimetype as string));
            }

            // Decrypt content and save to disk
            let filePath = '';
            let fileSize = 0;
            if (att.encrypted_content) {
                const content = await decryptAttField(att.encrypted_content as string);

                // Save to /tmp/aionda-mail-attachments/{uuid}/{filename}
                const attachDir = join(tmpdir(), 'aionda-mail-attachments', att.uuid as string);
                mkdirSync(attachDir, { recursive: true });
                // Sanitize filename (no path traversal)
                const safeFilename = filename.replace(/[/\\:*?"<>|]/g, '_');
                filePath = join(attachDir, safeFilename);
                writeFileSync(filePath, content);
                fileSize = content.length;
            }

            return {
                uuid: att.uuid,
                email_uuid: att.email_uuid,
                filename,
                mimetype,
                file_path: filePath,
                file_size_bytes: fileSize,
                note: `File saved to ${filePath}. Use the Read tool to view the file content.`,
            };
        } catch (e) {
            process.stderr.write(`[proxy] Attachment decryption failed: ${(e as Error).message}\n`);
            return att;
        }
    }

    /**
     * Cache incoming shared folder data from list_folders response
     */
    private cacheSharedFolders(response: JsonRpcResponse): void {
        try {
            const data = this.parseToolContent(response);
            const shares = (data?.shared_folders as Record<string, unknown>)?.incoming;
            if (Array.isArray(shares)) {
                this.cachedIncomingShares = shares as Record<string, unknown>[];
            }
        } catch { /* ignore */ }
    }

    /**
     * Intercept move_email when the email is in a shared folder.
     * Instead of moving (impossible cross-vault), copy to own vault with re-wrapped key.
     *
     * Returns null if this is a normal same-vault move (let it proceed normally).
     */
    private async maybeCrossVaultMove(request: JsonRpcRequest): Promise<JsonRpcResponse | null> {
        if (!this.masterKey || !this.privateKeys || !this.publicKeys) return null;

        const args = (request.params?.arguments as Record<string, unknown>) || {};
        const emailUuid = args.email_uuid as string;
        const targetFolder = args.target_folder as string;
        if (!emailUuid || !targetFolder) return null;

        // Try the normal move first — if it succeeds, the email was in own vault
        const moveResp = await this.forwardToServer(request);
        const moveResult = moveResp.result as McpToolResult | undefined;
        const moveData = this.parseToolContent(moveResp);

        // Check for errors in both MCP isError format and tool success format
        const isError = moveResult?.isError === true ||
                        moveData?.success === false ||
                        moveData?.error === true;

        if (!isError) {
            return moveResp;
        }

        // Extract error message from various formats
        const errorMsg = (moveData?.msg as string) ||
                         (moveData?.message as string) || '';
        if (!errorMsg.includes('not found') && !errorMsg.includes('move-out') && !errorMsg.includes('permission')) {
            return moveResp;
        }

        // Email is probably in a shared folder — attempt cross-vault copy
        process.stderr.write(`[proxy] move_email failed (${errorMsg}), attempting cross-vault copy...\n`);

        try {
            return await this.doCrossVaultCopy(emailUuid, targetFolder, request.id);
        } catch (e) {
            process.stderr.write(`[proxy] Cross-vault copy failed: ${(e as Error).message}\n`);
            // Return original error
            return moveResp;
        }
    }

    /**
     * Perform the cross-vault copy:
     * 1. Find share data for the email's folder
     * 2. Decrypt folder key → decrypt rewrapped_key → get ephemeral key
     * 3. Re-wrap ephemeral key with own public keys
     * 4. Call copy_from_shared_folder on server
     */
    private async doCrossVaultCopy(
        emailUuid: string,
        targetFolder: string,
        requestId?: number | string
    ): Promise<JsonRpcResponse> {
        // 1. Ensure we have shared folder data
        if (this.cachedIncomingShares.length === 0) {
            const foldersResp = await this.forwardToServer({
                jsonrpc: '2.0', id: 0, method: 'tools/call',
                params: { name: 'list_folders', arguments: {} },
            });
            this.cacheSharedFolders(foldersResp);
        }

        // 2. Get the email's rewrapped key via list_emails on each shared folder
        let emailData: Record<string, unknown> | null = null;
        let matchedShare: Record<string, unknown> | null = null;

        for (const share of this.cachedIncomingShares) {
            const folderUuid = share.folder_uuid as string;
            const listResp = await this.forwardToServer({
                jsonrpc: '2.0', id: 0, method: 'tools/call',
                params: { name: 'list_emails', arguments: { folder: `folder:${folderUuid}`, limit: 50 } },
            });
            const listData = this.parseToolContent(listResp);
            const emails = (listData?.emails as Record<string, unknown>[]) || [];
            const found = emails.find(e => (e.uuid as string) === emailUuid);
            if (found) {
                emailData = found;
                matchedShare = share;
                break;
            }
        }

        if (!emailData || !matchedShare) {
            throw new Error('Email not found in any shared folder');
        }

        const rewrappedKey = emailData.rewrapped_key as string;
        const keyNonce = emailData.key_nonce as string;
        if (!rewrappedKey || !keyNonce) {
            throw new Error('Email has no rewrapped_key (not a shared folder email)');
        }

        // 3. Decrypt folder key
        const folderKey = await decryptSharedFolderKey(
            matchedShare.encrypted_folder_key as string,
            matchedShare.x25519_ephemeral as string,
            matchedShare.mlkem_ciphertext as string,
            matchedShare.key_nonce as string,
            this.privateKeys!
        );

        // 4. Decrypt the rewrapped ephemeral key with the folder key
        const folderAesKey = await webcrypto.subtle.importKey(
            'raw', folderKey, { name: 'AES-GCM' }, false, ['decrypt']
        );
        const ephemeralKey = new Uint8Array(await webcrypto.subtle.decrypt(
            { name: 'AES-GCM', iv: fromBase64(keyNonce) },
            folderAesKey,
            fromBase64(rewrappedKey)
        ));

        // 5. Re-wrap with own vault public keys via Hybrid KEM.
        //
        // Das Pack-Format (mit der tag-vor-ciphertext-Falle) steht seit Ticket
        // 7cbc485d an genau EINER Stelle - sonst waere es hier und bei der
        // Zustellung in einen geteilten Ordner zweimal ausgeschrieben, und wer
        // die Reihenfolge einmal korrigiert, korrigiert sie dort nicht mit.
        // #53a45a9d: Bind the envelope to exactly the keys used here, even if
        // another operation refreshes the proxy's cached keys while awaiting.
        const targetKeys = {
            x25519: this.publicKeys!.x25519.slice(),
            mlkem: this.publicKeys!.mlkem.slice(),
        };
        const packedHex = await packWrappedKeyHex(
            ephemeralKey, targetKeys.x25519, targetKeys.mlkem
        );
        const packed = fromHex(packedHex);

        // 6. Call server to copy email into own vault
        const copyResp = await this.forwardToServer({
            jsonrpc: '2.0', id: requestId ?? 0, method: 'tools/call',
            params: {
                name: 'copy_from_shared_folder',
                arguments: {
                    email_uuid: emailUuid,
                    target_folder: targetFolder,
                    new_wrapped_ephemeral_key: toHex(packed),
                    target_x25519_public_key: toHex(targetKeys.x25519),
                    target_mlkem_public_key: toHex(targetKeys.mlkem),
                },
            },
        });

        const copyData = this.parseToolContent(copyResp);
        if (copyResp.error || (copyResp.result as McpToolResult)?.isError
            || copyData?.success === false || copyData?.error === true) {
            process.stderr.write('[proxy] Cross-vault copy rejected; no success reported\n');
        } else {
            process.stderr.write('[proxy] Cross-vault copy complete\n');
        }

        // Preserve the server result, including stable rejection codes.
        return copyResp;
    }

    /**
     * Handle deliver_to_shared_folder: AI provides email_uuid + share_uuid,
     * proxy does the crypto re-wrapping (ephemeral key → folder key).
     */
    /**
     * Export an email as PDF using Chrome headless.
     */
    private async handleExportEmailPdf(request: JsonRpcRequest): Promise<JsonRpcResponse> {
        const args = (request.params?.arguments as Record<string, unknown>) || {};
        const emailUuid = args.email_uuid as string;
        if (!emailUuid) {
            return this.makeToolResponse(request.id, { error: true, message: 'email_uuid is required' }, true);
        }

        try {
            // 1. Read and decrypt the email
            const readResp = await this.forwardToServer({
                jsonrpc: '2.0', id: 0, method: 'tools/call',
                params: { name: 'read_email', arguments: { email_uuid: emailUuid } },
            });
            const decryptedResult = await this.maybeDecryptResult(
                readResp.result as McpToolResult, 'read_email'
            );
            const email = this.parseToolContentFromResult(decryptedResult as McpToolResult);
            if (!email || email.decryption_error) {
                return this.makeToolResponse(request.id, {
                    error: true,
                    message: `Failed to read email: ${email?.decryption_error || 'not found'}`,
                }, true);
            }

            // 2. Extract email fields
            const subject = (email.subject as string) || '(No subject)';
            const from = (email.from as string) || '';
            const to = (email.to as string) || '';
            const date = (email.received_at as string) || '';
            const body = (email.body as string) || (email.body_text as string) || '';

            // 3. Replace CID images with inline data URLs
            let processedBody = body;
            const attachments = (email.attachments as Record<string, unknown>[]) || [];
            for (const att of attachments) {
                const contentId = (att.content_id as string) || (att.contentId as string) || '';
                const mimetype = (att.mimetype as string) || 'image/png';
                if (!contentId || !mimetype.startsWith('image/')) continue;

                try {
                    const attResp = await this.forwardToServer({
                        jsonrpc: '2.0', id: 0, method: 'tools/call',
                        params: { name: 'get_attachment', arguments: { attachment_uuid: att.uuid } },
                    });
                    const decAttResult = await this.maybeDecryptResult(
                        attResp.result as McpToolResult, 'get_attachment'
                    );
                    const attData = this.parseToolContentFromResult(decAttResult as McpToolResult);
                    if (attData?.file_path) {
                        const imgData = readFileSync(attData.file_path as string);
                        const dataUrl = `data:${mimetype};base64,${imgData.toString('base64')}`;
                        const cidClean = contentId.replace(/^<|>$/g, '');
                        processedBody = processedBody.replace(
                            new RegExp(`cid:${cidClean.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'gi'),
                            dataUrl
                        );
                    }
                } catch { /* skip failed attachment */ }
            }

            // 4. Generate HTML
            const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; color: #1a1a1a; }
  .header { border-bottom: 2px solid #e5e7eb; padding-bottom: 16px; margin-bottom: 24px; }
  .header h1 { font-size: 20px; margin: 0 0 12px 0; }
  .meta { font-size: 13px; color: #6b7280; line-height: 1.8; }
  .meta strong { color: #374151; min-width: 50px; display: inline-block; }
  .body { font-size: 14px; line-height: 1.6; }
  .body img { max-width: 100%; }
  @media print { body { margin: 20px; } }
</style></head><body>
<div class="header">
  <h1>${this.escapeHtml(subject)}</h1>
  <div class="meta">
    <div><strong>From:</strong> ${this.escapeHtml(from)}</div>
    <div><strong>To:</strong> ${this.escapeHtml(to)}</div>
    <div><strong>Date:</strong> ${this.escapeHtml(date)}</div>
  </div>
</div>
<div class="body">${processedBody}</div>
</body></html>`;

            // 5. Save HTML to temp
            const exportDir = join(tmpdir(), 'aionda-mail-exports', emailUuid);
            mkdirSync(exportDir, { recursive: true });
            const htmlPath = join(exportDir, 'email.html');
            const pdfPath = join(exportDir, `${this.sanitizeFilename(subject)}.pdf`);
            writeFileSync(htmlPath, html);

            // 4. Convert to PDF using Chrome headless
            const { execSync } = await import('node:child_process');
            const chromePaths = [
                '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                '/Applications/Chromium.app/Contents/MacOS/Chromium',
                '/usr/bin/google-chrome',
                '/usr/bin/chromium-browser',
                '/usr/bin/chromium',
            ];

            let chromePath = '';
            for (const p of chromePaths) {
                if (existsSync(p)) { chromePath = p; break; }
            }

            if (!chromePath) {
                // Fallback: try 'which' command
                try {
                    chromePath = execSync('which google-chrome || which chromium 2>/dev/null', { encoding: 'utf-8' }).trim();
                } catch { /* ignore */ }
            }

            if (!chromePath) {
                return this.makeToolResponse(request.id, {
                    error: true,
                    message: 'Chrome/Chromium not found. Install Google Chrome for PDF export.',
                    html_path: htmlPath,
                }, true);
            }

            execSync(`"${chromePath}" --headless --disable-gpu --no-sandbox --print-to-pdf="${pdfPath}" "file://${htmlPath}" 2>/dev/null`, {
                timeout: 15000,
            });

            const stats = statSync(pdfPath);

            return this.makeToolResponse(request.id, {
                file_path: pdfPath,
                file_size_bytes: stats.size,
                subject,
                from,
                to,
                date,
                note: `PDF exported to ${pdfPath}`,
            });
        } catch (e) {
            return this.makeToolResponse(request.id, {
                error: true,
                message: `PDF export failed: ${(e as Error).message}`,
            }, true);
        }
    }

    /**
     * Escape HTML characters
     */
    private escapeHtml(text: string): string {
        return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    /**
     * Sanitize filename
     */
    private sanitizeFilename(name: string): string {
        return name.replace(/[/\\:*?"<>|]/g, '_').substring(0, 100) || 'email';
    }

    /**
     * Search emails client-side (Zero Knowledge).
     * Fetches all emails from requested folders, decrypts, and filters.
     */
    private async handleSearchEmails(request: JsonRpcRequest): Promise<JsonRpcResponse> {
        const args = (request.params?.arguments as Record<string, unknown>) || {};
        const query = ((args.query as string) || '').toLowerCase().trim();
        const requestedFolders = args.folders as string[] | undefined;
        const limit = Math.min((args.limit as number) || 20, 100);

        if (!query) {
            return this.makeToolResponse(request.id, { error: true, message: 'query is required' }, true);
        }

        try {
            // 1. Determine which folders to search
            let foldersToSearch: string[];
            if (requestedFolders && requestedFolders.length > 0) {
                foldersToSearch = requestedFolders;
            } else {
                // Search all folders: system + custom + shared
                const foldersResp = await this.forwardToServer({
                    jsonrpc: '2.0', id: 0, method: 'tools/call',
                    params: { name: 'list_folders', arguments: {} },
                });
                throwOnServerError(foldersResp);
                this.cacheSharedFolders(foldersResp);
                const foldersData = this.parseToolContent(foldersResp);

                foldersToSearch = ['inbox', 'sent', 'drafts', 'spam', 'trash'];

                // Add custom folders
                const customFolders = (foldersData?.custom_folders as Record<string, unknown>[]) || [];
                for (const f of customFolders) {
                    foldersToSearch.push(`folder:${f.uuid as string}`);
                }

                // Add shared folders
                const sharedFolders = ((foldersData?.shared_folders as Record<string, unknown>)?.incoming as Record<string, unknown>[]) || [];
                for (const s of sharedFolders) {
                    foldersToSearch.push(`folder:${s.folder_uuid as string}`);
                }
            }

            // 2. Fetch and decrypt emails from each folder
            const results: Record<string, unknown>[] = [];
            let totalSearched = 0;
            // Jede Inhaltsprüfung kostet mindestens einen read_email-Aufruf
            // (plus get_attachment je PDF). Ohne Budget löste eine Suche über
            // alle Ordner über 1000 Serveraufrufe aus und riss die Grenze von
            // 500 Aufrufen je Minute (gemessen 04.11.2026) — #30209ea3
            let contentChecks = 0;
            let contentChecksSkipped = 0;

            for (const folder of foldersToSearch) {
                if (results.length >= limit) break;

                // Fetch up to 50 emails per folder
                const listResp = await this.forwardToServer({
                    jsonrpc: '2.0', id: 0, method: 'tools/call',
                    params: { name: 'list_emails', arguments: { folder, limit: 50 } },
                });
                throwOnServerError(listResp);

                // Decrypt the response
                const decryptedResult = await this.maybeDecryptResult(
                    listResp.result as McpToolResult, 'list_emails'
                );
                const listData = this.parseToolContentFromResult(decryptedResult as McpToolResult);
                const emails = (listData?.emails as Record<string, unknown>[]) || [];
                totalSearched += emails.length;

                // 3. Filter by search query (subject, from, to, body, PDF attachments)
                for (const email of emails) {
                    if (results.length >= limit) break;

                    const subject = ((email.subject as string) || '').toLowerCase();
                    const from = ((email.from as string) || '').toLowerCase();
                    const to = ((email.to as string) || '').toLowerCase();

                    let matchField = '';
                    if (subject.includes(query)) matchField = 'subject';
                    else if (from.includes(query)) matchField = 'from';
                    else if (to.includes(query)) matchField = 'to';

                    // If no header match, search email body and PDF attachments
                    if (!matchField && email.has_attachments) {
                        if (contentChecks < SEARCH_CONTENT_CHECK_BUDGET) {
                            contentChecks++;
                            const pdfMatch = await this.searchEmailContent(
                                email.uuid as string, query
                            );
                            if (pdfMatch) matchField = pdfMatch;
                        } else {
                            contentChecksSkipped++;
                        }
                    }

                    if (matchField) {
                        results.push({
                            uuid: email.uuid,
                            subject: email.subject,
                            from: email.from,
                            to: email.to,
                            folder,
                            has_attachments: email.has_attachments,
                            received_at: email.received_at,
                            match_field: matchField,
                        });
                    }
                }
            }

            return this.makeToolResponse(request.id, {
                results,
                total_searched: totalSearched,
                total_matched: results.length,
                query,
                ...(contentChecksSkipped > 0 ? {
                    content_search_skipped: contentChecksSkipped,
                    note: `Body/attachment search was limited to ${SEARCH_CONTENT_CHECK_BUDGET} emails; `
                        + `${contentChecksSkipped} emails with attachments were only matched by subject/from/to. `
                        + 'Narrow the search with "folders" to search their content.',
                } : {}),
            });
        } catch (e) {
            return this.makeToolResponse(request.id, {
                error: true,
                message: `Search failed: ${(e as Error).message}`,
            }, true);
        }
    }

    /**
     * Search inside an email's body and PDF attachments for a query string.
     * Returns the match field name or null.
     */
    private async searchEmailContent(emailUuid: string, query: string): Promise<string | null> {
        // 1. Read the full email (decrypted by proxy). Ein Serverfehler
        // (z. B. Ratenbegrenzung) bricht die Suche mit seiner Meldung ab,
        // statt als „kein Treffer“ durchzugehen — #30209ea3
        const readResp = await this.forwardToServer({
            jsonrpc: '2.0', id: 0, method: 'tools/call',
            params: { name: 'read_email', arguments: { email_uuid: emailUuid } },
        });
        throwOnServerError(readResp);
        try {
            const decryptedResult = await this.maybeDecryptResult(
                readResp.result as McpToolResult, 'read_email'
            );
            const emailData = this.parseToolContentFromResult(decryptedResult as McpToolResult);
            if (!emailData) return null;

            // 2. Search in body text
            const bodyText = ((emailData.body_text as string) || (emailData.body as string) || '').toLowerCase();
            if (bodyText.includes(query)) return 'body';

            // 3. Search in PDF attachment text
            const attachments = (emailData.attachments as Record<string, unknown>[]) || [];
            for (const att of attachments) {
                const mimetype = (att.mimetype as string) || '';
                if (mimetype !== 'application/pdf') continue;

                // Fetch and decrypt the attachment
                const attResp = await this.forwardToServer({
                    jsonrpc: '2.0', id: 0, method: 'tools/call',
                    params: { name: 'get_attachment', arguments: { attachment_uuid: att.uuid } },
                });
                const decAttResult = await this.maybeDecryptResult(
                    attResp.result as McpToolResult, 'get_attachment'
                );
                const attData = this.parseToolContentFromResult(decAttResult as McpToolResult);
                if (!attData?.file_path) continue;

                // Extract text from PDF: first pdfjs-dist (fast), then OCR fallback
                try {
                    const filePath = attData.file_path as string;
                    const attachmentName = (att.filename || att.uuid) as string;
                    const pdfMatch = await this.searchPdfText(filePath, query, attachmentName);
                    if (pdfMatch) return pdfMatch;
                } catch {
                    // PDF search failed — skip this attachment
                }

                // Also search image attachments via OCR
                if (mimetype.startsWith('image/')) {
                    try {
                        const ocrText = await this.ocrImage(attData.file_path as string);
                        if (ocrText.toLowerCase().includes(query)) {
                            return `attachment:${att.filename || att.uuid}`;
                        }
                    } catch {
                        // OCR failed — skip
                    }
                }
            }

            return null;
        } catch {
            return null;
        }
    }

    /**
     * Extract text from PDF: first try pdfjs-dist (text-based PDFs),
     * then fall back to tesseract.js OCR (scanned PDFs).
     */
    private async searchPdfText(filePath: string, query: string, attachmentName: string): Promise<string | null> {
        const { readFileSync } = await import('node:fs');
        const { getDocument } = await import('pdfjs-dist/legacy/build/pdf.mjs');

        const pdfBuffer = new Uint8Array(readFileSync(filePath));
        const doc = await getDocument({ data: pdfBuffer }).promise;

        // 1. Try text extraction (fast — works for text-based PDFs)
        let pdfText = '';
        for (let p = 1; p <= doc.numPages; p++) {
            const page = await doc.getPage(p);
            const content = await page.getTextContent();
            pdfText += (content.items as Array<{ str: string }>).map(item => item.str).join(' ');
        }

        if (pdfText.trim().length > 0) {
            // Text-based PDF — search in extracted text
            if (pdfText.toLowerCase().includes(query)) {
                return `attachment:${attachmentName}`;
            }
            return null;
        }

        // 2. No text found — scanned PDF, try OCR on each page
        process.stderr.write(`[proxy] PDF "${attachmentName}" has no text — trying OCR...\n`);
        try {
            const ocrText = await this.ocrImage(filePath);
            if (ocrText.toLowerCase().includes(query)) {
                return `attachment:${attachmentName} (OCR)`;
            }
        } catch {
            // OCR failed
        }

        return null;
    }

    /**
     * OCR an image or scanned PDF using tesseract.js.
     * Used as fallback when pdfjs-dist finds no text.
     */
    private async ocrImage(filePath: string): Promise<string> {
        const { createWorker } = await import('tesseract.js');
        const worker = await createWorker('deu+eng');
        try {
            const { data: { text } } = await worker.recognize(filePath);
            return text;
        } finally {
            await worker.terminate();
        }
    }

    /**
     * Helper: parse tool content from a McpToolResult (already decrypted)
     */
    private parseToolContentFromResult(result: McpToolResult): Record<string, unknown> | null {
        if (!result?.content) return null;
        const text = result.content.find(c => c.type === 'text');
        if (!text) return null;
        try {
            return JSON.parse(text.text);
        } catch {
            return null;
        }
    }

    /**
     * Helper: create a tool response
     */
    private makeToolResponse(
        id: number | string | undefined,
        data: Record<string, unknown>,
        isError = false
    ): JsonRpcResponse {
        return {
            jsonrpc: '2.0',
            id,
            result: {
                content: [{ type: 'text', text: JSON.stringify(data) }],
                ...(isError ? { isError: true } : {}),
            },
        };
    }

    private async handleDeliverToSharedFolder(request: JsonRpcRequest): Promise<JsonRpcResponse | null> {
        if (!this.masterKey || !this.privateKeys) return null;

        const args = (request.params?.arguments as Record<string, unknown>) || {};
        const emailUuid = args.email_uuid as string;
        const shareUuid = args.share_uuid as string;
        if (!emailUuid || !shareUuid) return null;

        try {
            // 1. Ensure we have shared folder data
            if (this.cachedIncomingShares.length === 0) {
                const foldersResp = await this.forwardToServer({
                    jsonrpc: '2.0', id: 0, method: 'tools/call',
                    params: { name: 'list_folders', arguments: {} },
                });
                this.cacheSharedFolders(foldersResp);
            }

            // 2. Find matching share
            const share = this.cachedIncomingShares.find(
                s => (s.share_uuid as string) === shareUuid
            );
            if (!share) throw new Error('Shared folder not found');
            if (!share.can_move_in) throw new Error('No move-in permission on this shared folder');

            // 3. Decrypt the shared folder key
            const folderKey = await decryptSharedFolderKey(
                share.encrypted_folder_key as string,
                share.x25519_ephemeral as string,
                share.mlkem_ciphertext as string,
                share.key_nonce as string,
                this.privateKeys
            );

            // 4. Get the email's wrapped ephemeral key
            const keyResp = await this.forwardToServer({
                jsonrpc: '2.0', id: 0, method: 'tools/call',
                params: { name: 'get_email_key', arguments: { email_uuid: emailUuid } },
            });
            const keyData = this.parseToolContent(keyResp);
            if (!keyData?.wrapped_ephemeral_key) throw new Error('Failed to get email key');

            // 5. Decrypt the ephemeral key
            // #c2fb3967 - auch der abgeleitete Mail-Schlüssel; vorher wurde
            // er als KEM-Kapsel gelesen und das Einliefern brach ab.
            const { key: ephemeralKey, source } = await resolveContentKey(
                keyData.wrapped_ephemeral_key as string,
                emailUuid,
                this.masterKey,
                this.privateKeys
            );
            // 🚩 Codex-Review 08.11.2026: Bei einer Altmail ist der „Mail-
            // Schlüssel" der Master-Key. Ihn für Ordnerempfänger zu verpacken,
            // gäbe ihnen das ganze Postfach. Lieber ablehnen.
            if (source === 'master') {
                throw new Error(
                    'This e-mail is still encrypted with the vault master key and cannot be shared safely. '
                    + 'Open it once in the Aionda Mail web app (it is migrated to its own key automatically), then try again.'
                );
            }

            // 6. Re-wrap ephemeral key with the folder key (AES-GCM)
            const folderAesKey = await webcrypto.subtle.importKey(
                'raw', folderKey, { name: 'AES-GCM' }, false, ['encrypt']
            );
            const nonce = webcrypto.getRandomValues(new Uint8Array(12));
            const rewrappedCiphertext = new Uint8Array(await webcrypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce }, folderAesKey, ephemeralKey
            ));

            // 7. Kapsel fuer den EIGENTUEMER des Ordners.
            //
            // 🚩 Ticket 7cbc485d: Ohne diese landete die Mail in seinem Postfach
            // mit der Kapsel des EINLIEFERNDEN - alle Empfaenger der Freigabe
            // konnten sie lesen, ausgerechnet er nicht. Der Server kann das
            // nicht nachholen: Er kennt den ephemeren Schluessel nicht und soll
            // ihn nie kennen (Zero Knowledge). Die Kapsel muss von dem Client
            // kommen, der den Schluessel gerade in der Hand hat.
            const ownerUsername = share.owner_username as string | undefined;
            if (!ownerUsername) throw new Error('Shared folder has no owner_username');

            const ownerKeysResp = await this.forwardToServer({
                jsonrpc: '2.0', id: 0, method: 'tools/call',
                params: { name: 'get_recipient_keys', arguments: { recipient_username: ownerUsername } },
            });
            const ownerKeys = this.parseToolContent(ownerKeysResp);
            if (!ownerKeys?.x25519_public_key || !ownerKeys?.mlkem_public_key) {
                throw new Error(`Failed to get public keys of folder owner "${ownerUsername}"`);
            }

            // ⚠️ get_recipient_keys liefert BASE64 - get_vault_keys liefert HEX.
            // Gleiche Feldnamen, verschiedene Kodierung; hier ist fromBase64
            // richtig und fromHex faellt nicht auf, es entstuende nur Unsinn.
            const ownerWrappedKey = await packWrappedKeyHex(
                ephemeralKey,
                fromBase64(ownerKeys.x25519_public_key as string),
                fromBase64(ownerKeys.mlkem_public_key as string)
            );

            // 8. Call server with re-wrapped key
            const deliverResp = await this.forwardToServer({
                jsonrpc: '2.0', id: request.id ?? 0, method: 'tools/call',
                params: {
                    name: 'deliver_to_shared_folder',
                    arguments: {
                        email_uuid: emailUuid,
                        share_uuid: shareUuid,
                        rewrapped_key: toBase64(rewrappedCiphertext),
                        key_nonce: toBase64(nonce),
                        owner_wrapped_key: ownerWrappedKey,
                    },
                },
            });

            process.stderr.write(`[proxy] deliver_to_shared_folder complete\n`);
            return deliverResp;
        } catch (e) {
            process.stderr.write(`[proxy] deliver_to_shared_folder failed: ${(e as Error).message}\n`);
            // Return error instead of null (don't let placeholder values through)
            return {
                jsonrpc: '2.0' as const,
                id: request.id,
                result: {
                    content: [{ type: 'text', text: JSON.stringify({
                        error: true,
                        message: `Proxy crypto failed: ${(e as Error).message}`,
                    }) }],
                    isError: true,
                },
            };
        }
    }

    /**
     * Load and decrypt the default signature from the server.
     * Caches the result — called once during bootstrap.
     */
    private async loadSignature(): Promise<void> {
        if (!this.masterKey) return;

        try {
            const sigResp = await this.forwardToServer({
                jsonrpc: '2.0', id: 0, method: 'tools/call',
                params: { name: 'get_default_signature', arguments: {} },
            });

            const sigRaw = this.parseToolContent(sigResp);
            // Server returns { success, data: { has_signature, ... } }
            const sigData = (sigRaw?.data as Record<string, unknown>) || sigRaw;
            if (!sigData?.has_signature || !sigData?.encrypted_content_html) {
                process.stderr.write('[proxy] No default signature configured\n');
                return;
            }

            this.signatureAutoInsertNew   = Boolean(sigData.auto_insert_new);
            this.signatureAutoInsertReply = Boolean(sigData.auto_insert_reply);

            // Decrypt: WebCrypto format = ciphertext || tag(16), IV separate
            const encryptedBuf = fromBase64(sigData.encrypted_content_html as string);
            const iv = fromBase64(sigData.iv as string);
            const ciphertext = encryptedBuf.slice(0, encryptedBuf.length - 16);
            const tag = encryptedBuf.slice(encryptedBuf.length - 16);

            // WebCrypto expects: ciphertext || tag
            const combined = new Uint8Array(ciphertext.length + tag.length);
            combined.set(ciphertext);
            combined.set(tag, ciphertext.length);

            const aesKey = await webcrypto.subtle.importKey(
                'raw', this.masterKey, { name: 'AES-GCM' }, false, ['decrypt']
            );
            const decrypted = await webcrypto.subtle.decrypt(
                { name: 'AES-GCM', iv }, aesKey, combined
            );

            this.signatureHtml = new TextDecoder().decode(decrypted);
            process.stderr.write(
                `[proxy] Signature loaded (${this.signatureHtml.length} chars, new=${this.signatureAutoInsertNew}, reply=${this.signatureAutoInsertReply})\n`
            );
        } catch (e) {
            process.stderr.write(`[proxy] Failed to load signature: ${(e as Error).message}\n`);
        }
    }

    /**
     * Append signature HTML to email body
     */
    private appendSignature(body: string): string {
        if (!this.signatureHtml) return body;
        return body + '<br><br>' + this.signatureHtml;
    }

    /**
     * Parse the text content from a tool result
     */
    private parseToolContent(response: JsonRpcResponse): Record<string, unknown> | null {
        const result = response.result as McpToolResult | undefined;
        if (!result?.content) return null;
        const text = result.content.find(c => c.type === 'text');
        if (!text) return null;
        try {
            return JSON.parse(text.text);
        } catch {
            return null;
        }
    }
}
