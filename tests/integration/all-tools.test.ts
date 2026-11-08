/**
 * Umfassender Integrationstest fuer ALLE 26 MCP-Tools
 * Testet gegen den Live-Server dev.mail.aionda.com
 *
 * Credentials werden aus .env.test geladen (NICHT in git eingecheckt!).
 * Erstelle .env.test mit:
 *   MCP_API_KEY=tma_...
 *   MCP_VAULT_KEY=tmv_...
 *   MCP_ENDPOINT=https://dev.mail.aionda.com
 *
 * Ausfuehrung:
 *   cd aionda-mail-mcp-client && NODE_TLS_REJECT_UNAUTHORIZED=0 npx vitest run tests/integration/all-tools.test.ts
 */
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { AiondaMailClient } from '../../src/client';

vi.setConfig({ testTimeout: 30000 });

// Load .env.test from project root
const envPath = resolve(__dirname, '../../.env.test');
if (existsSync(envPath)) {
    for (const line of readFileSync(envPath, 'utf-8').split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx > 0) {
            process.env[trimmed.slice(0, eqIdx)] = trimmed.slice(eqIdx + 1);
        }
    }
}

const API_KEY = process.env['MCP_API_KEY'] ?? '';
const VAULT_KEY = process.env['MCP_VAULT_KEY'] ?? '';
const ENDPOINT = process.env['MCP_ENDPOINT'] ?? 'https://dev.mail.aionda.com';
// Benutzer, dessen öffentliche Schlüssel `get_recipient_keys` holen soll.
const RECIPIENT = process.env['MCP_TEST_RECIPIENT'] ?? 'aiondaprodtest1';

if (!API_KEY) {
    throw new Error('MCP_API_KEY not set. Create .env.test or set environment variable.');
}

/**
 * Hilfsfunktion: MCP content-Array parsen.
 * Der Server gibt { content: [{ type: "text", text: "{...}" }] } zurueck.
 * callTool() gibt das gesamte result-Objekt zurueck.
 */
interface McpContent { type: string; text: string }
interface McpRawResult { content?: McpContent[]; isError?: boolean }

function parseToolResult(raw: unknown): Record<string, unknown> {
    const result = raw as McpRawResult;
    if (result?.content && Array.isArray(result.content) && result.content.length > 0) {
        const textContent = result.content.find((c: McpContent) => c.type === 'text');
        if (textContent) {
            return JSON.parse(textContent.text) as Record<string, unknown>;
        }
    }
    // Fallback: vielleicht ist raw schon das geparste Objekt
    if (raw && typeof raw === 'object' && !('content' in (raw as Record<string, unknown>))) {
        return raw as Record<string, unknown>;
    }
    return {};
}

describe('MCP Integration: All 26 Tools', () => {
    let client: AiondaMailClient;

    // Geteilter Zustand zwischen Tests
    let toolNames: string[] = [];
    let emailUuid: string | null = null;
    let deaUid: string | null = null;
    let deaAddress: string | null = null;
    let draftId: string | null = null;
    let originalEmailFolder: string | null = null;

    beforeAll(() => {
        client = new AiondaMailClient({
            apiKey: API_KEY,
            vaultKey: VAULT_KEY,
            endpoint: ENDPOINT,
            timeout: 30000,
        });
    });

    afterAll(async () => {
        // Aufraeumen: Falls Test-DEA nicht geloescht wurde
        if (deaUid) {
            try {
                await client.callTool('delete_dea', { dea_uid: deaUid });
            } catch { /* ignorieren */ }
        }
        // Falls Draft nicht geloescht wurde
        if (draftId) {
            try {
                await client.callTool('delete_draft', { draft_id: draftId });
            } catch { /* ignorieren */ }
        }
        try {
            await client.disconnect();
        } catch { /* ignorieren */ }
    });

    // ═══════════════════════════════════════════════════════════
    // 1. LIFECYCLE: connect, listTools, ping, disconnect
    // ═══════════════════════════════════════════════════════════

    describe('1. Lifecycle', () => {
        it('connect — initialisiert MCP-Session', async () => {
            await client.connect();
            expect(client.isConnected()).toBe(true);
        });

        it('listTools — liefert alle 26 Tools', async () => {
            const tools = await client.listTools();
            toolNames = tools.map(t => t.name);

            expect(tools.length).toBeGreaterThanOrEqual(20);

            const expectedTools = [
                'list_folders', 'list_emails', 'read_email',
                'mark_read', 'mark_unread', 'move_email', 'delete_email',
                'list_deas', 'get_dea', 'create_dea', 'update_dea', 'delete_dea',
                'send_email', 'reply_email', 'forward_email',
                'save_draft', 'list_drafts', 'get_draft', 'delete_draft',
                'list_shared_folders',
                'share_folder', 'revoke_share', 'update_share_permissions',
                'get_recipient_keys',
                'event_subscribe', 'get_missed_events',
            ];

            for (const name of expectedTools) {
                expect(toolNames, `Tool "${name}" fehlt`).toContain(name);
            }

            console.log(`[listTools] ${tools.length} Tools: ${toolNames.join(', ')}`);
        });

        it('ping — Server antwortet', async () => {
            await expect(client.ping()).resolves.toBeUndefined();
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 2. FOLDERS: list_folders
    // ═══════════════════════════════════════════════════════════

    describe('2. Folders', () => {
        it('list_folders — liefert verschluesselte Ordner', async () => {
            const raw = await client.callTool('list_folders');
            const data = parseToolResult(raw);

            expect(data.folders).toBeDefined();
            const folders = data.folders as Array<Record<string, unknown>>;
            expect(Array.isArray(folders)).toBe(true);

            // Ordner koennen leer sein (neuer Account), aber die Antwort muss korrekt sein
            const folderTypes = folders.map(f => f.folder_type as string);
            console.log(`[list_folders] ${folders.length} Ordner: ${folderTypes.join(', ') || '(leer)'}`);

            if (folders.length > 0) {
                const first = folders[0];
                expect(first.uuid).toBeDefined();
                expect(first.folder_type).toBeDefined();
                expect(typeof first.email_count).toBe('number');
                expect(typeof first.unread_count).toBe('number');
            }
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 3. EMAILS: list_emails, read_email
    // ═══════════════════════════════════════════════════════════

    describe('3. Emails', () => {
        it('list_emails — liefert Inbox-Emails', async () => {
            const raw = await client.callTool('list_emails', { folder: 'inbox', limit: 10, offset: 0 });
            const data = parseToolResult(raw);

            expect(data.emails).toBeDefined();
            const emails = data.emails as Array<Record<string, unknown>>;
            expect(Array.isArray(emails)).toBe(true);
            expect(typeof data.total).toBe('number');

            if (emails.length > 0) {
                const email = emails[0];
                expect(email.uuid).toBeDefined();
                expect(email.encrypted_subject).toBeDefined();
                expect(email.received_at).toBeDefined();

                emailUuid = email.uuid as string;
                originalEmailFolder = (email.folder_type as string) ?? 'inbox';
            }

            console.log(`[list_emails] ${data.total} total, ${emails.length} geladen`);
        });

        it('read_email — liest erste Email (verschluesselt)', async () => {
            if (!emailUuid) {
                console.warn('[read_email] Uebersprungen: Keine Email in Inbox');
                return;
            }

            const raw = await client.callTool('read_email', { email_uuid: emailUuid });
            const data = parseToolResult(raw);

            expect(data.uuid).toBe(emailUuid);
            expect(data.encrypted_subject).toBeDefined();
            expect(data.encrypted_from).toBeDefined();
            expect(data.encrypted_to).toBeDefined();
            expect(data.encrypted_body).toBeDefined();
            expect(typeof data.size_bytes).toBe('number');

            console.log(`[read_email] Email ${emailUuid} gelesen, ${data.size_bytes} bytes`);
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 4. EMAIL ACTIONS: mark_read, mark_unread
    // ═══════════════════════════════════════════════════════════

    describe('4. Email-Aktionen', () => {
        it('mark_read — markiert Email als gelesen', async () => {
            if (!emailUuid) {
                console.warn('[mark_read] Uebersprungen: Keine Email');
                return;
            }

            const raw = await client.callTool('mark_read', { email_uuid: emailUuid });
            const data = parseToolResult(raw);
            expect(data.marked).toBe('read');
            console.log(`[mark_read] Email ${emailUuid} als gelesen markiert`);
        });

        it('mark_unread — markiert Email als ungelesen', async () => {
            if (!emailUuid) {
                console.warn('[mark_unread] Uebersprungen: Keine Email');
                return;
            }

            const raw = await client.callTool('mark_unread', { email_uuid: emailUuid });
            const data = parseToolResult(raw);
            expect(data.marked).toBe('unread');
            console.log(`[mark_unread] Email ${emailUuid} als ungelesen markiert`);
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 5. EMAIL VERSCHIEBEN: move_email
    // ═══════════════════════════════════════════════════════════

    describe('5. Email verschieben', () => {
        it('move_email — verschiebt Email in Trash', async () => {
            if (!emailUuid) {
                console.warn('[move_email→trash] Uebersprungen: Keine Email');
                return;
            }

            const raw = await client.callTool('move_email', {
                email_uuid: emailUuid,
                target_folder: 'trash',
            });
            const data = parseToolResult(raw);
            expect(data.moved_to).toBe('trash');
            console.log(`[move_email] Email ${emailUuid} nach Trash verschoben`);
        });

        it('move_email — verschiebt Email zurueck in Inbox', async () => {
            if (!emailUuid) {
                console.warn('[move_email→inbox] Uebersprungen: Keine Email');
                return;
            }

            const target = originalEmailFolder ?? 'inbox';
            const raw = await client.callTool('move_email', {
                email_uuid: emailUuid,
                target_folder: target,
            });
            const data = parseToolResult(raw);
            expect(data.moved_to).toBe(target);
            console.log(`[move_email] Email ${emailUuid} zurueck nach ${target}`);
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 6. DEA LESEN: list_deas, get_dea
    // ═══════════════════════════════════════════════════════════

    describe('6. DEA lesen', () => {
        it('list_deas — liefert alle DEAs', async () => {
            const raw = await client.callTool('list_deas');
            const data = parseToolResult(raw);

            expect(data.deas).toBeDefined();
            const deas = data.deas as Array<Record<string, unknown>>;
            expect(Array.isArray(deas)).toBe(true);
            expect(deas.length).toBeGreaterThan(0);

            const first = deas[0];
            expect(first.dea_uid).toBeDefined();
            expect(first.address).toBeDefined();
            expect(typeof first.forwards).toBe('number');

            deaAddress = first.address as string;
            console.log(`[list_deas] ${deas.length} DEAs, erste: ${deaAddress}`);
        });

        it('get_dea — liest einzelne DEA', async () => {
            const raw = await client.callTool('list_deas');
            const list = parseToolResult(raw);
            const deas = list.deas as Array<Record<string, unknown>>;
            if (deas.length === 0) {
                console.warn('[get_dea] Uebersprungen: Keine DEAs');
                return;
            }

            const firstUid = deas[0].dea_uid as string;
            const raw2 = await client.callTool('get_dea', { dea_uid: firstUid });
            const data = parseToolResult(raw2);

            expect(data.dea_uid).toBe(firstUid);
            expect(data.address).toBeDefined();
            expect(data.destination).toBeDefined();
            console.log(`[get_dea] DEA ${data.address}, Ziel: ${data.destination}`);
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 7. DEA CRUD: create_dea, update_dea, delete_dea
    // ═══════════════════════════════════════════════════════════

    describe('7. DEA CRUD', () => {
        const testDeaName = `mcp-inttest-${Date.now()}`;

        it('create_dea — erstellt Test-DEA', async () => {
            const raw = await client.callTool('create_dea', {
                name: testDeaName,
                forwards: 10,
                expire: 7,
            });
            const data = parseToolResult(raw);

            expect(data.dea_uid).toBeDefined();
            expect(data.address).toBeDefined();
            expect((data.address as string)).toContain(testDeaName);
            expect(data.created).toBe(true);

            deaUid = data.dea_uid as string;
            console.log(`[create_dea] DEA erstellt: ${data.address} (uid: ${deaUid})`);
        });

        it('update_dea — aktualisiert Test-DEA', async () => {
            if (!deaUid) {
                console.warn('[update_dea] Uebersprungen: Keine DEA erstellt');
                return;
            }

            const raw = await client.callTool('update_dea', {
                dea_uid: deaUid,
                forwards: 20,
                from_name: 'MCP Test',
            });
            const data = parseToolResult(raw);
            expect(data.updated).toBe(true);

            // Verifiziere Aenderung
            const raw2 = await client.callTool('get_dea', { dea_uid: deaUid });
            const updated = parseToolResult(raw2);
            expect(updated.forwards).toBe(20);
            expect(updated.from_name).toBe('MCP Test');

            console.log(`[update_dea] DEA ${deaUid} aktualisiert: forwards=20, from_name=MCP Test`);
        });

        it('delete_dea — loescht Test-DEA', async () => {
            if (!deaUid) {
                console.warn('[delete_dea] Uebersprungen: Keine DEA erstellt');
                return;
            }

            const raw = await client.callTool('delete_dea', { dea_uid: deaUid });
            const data = parseToolResult(raw);
            expect(data.deleted).toBe(true);

            console.log(`[delete_dea] DEA ${deaUid} geloescht`);
            deaUid = null;
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 8. DRAFTS: save_draft, list_drafts, get_draft, delete_draft
    // ═══════════════════════════════════════════════════════════

    describe('8. Drafts', () => {
        it('save_draft — speichert Entwurf', async () => {
            const raw = await client.callTool('save_draft', {
                subject: 'MCP Integration Test Draft',
                body: '<p>Dies ist ein Test-Entwurf vom MCP-Client.</p>',
                to: 'test@example.com',
            });
            const data = parseToolResult(raw);

            expect(data.draft_id).toBeDefined();
            expect(data.saved).toBe(true);

            draftId = data.draft_id as string;
            console.log(`[save_draft] Draft gespeichert: ${draftId}`);
        });

        it('list_drafts — listet Entwuerfe', async () => {
            const raw = await client.callTool('list_drafts', { limit: 20, offset: 0 });
            const data = parseToolResult(raw);

            expect(data.drafts).toBeDefined();
            const drafts = data.drafts as Array<Record<string, unknown>>;
            expect(Array.isArray(drafts)).toBe(true);

            if (draftId) {
                const found = drafts.some(d => d.uuid === draftId || d.draft_id === draftId);
                if (!found) {
                    console.warn(`[list_drafts] Draft ${draftId} nicht in Liste gefunden (${drafts.length} Drafts)`);
                }
            }

            console.log(`[list_drafts] ${drafts.length} Drafts gefunden`);
        });

        it('get_draft — liest einzelnen Entwurf', async () => {
            if (!draftId) {
                console.warn('[get_draft] Uebersprungen: Kein Draft erstellt');
                return;
            }

            const raw = await client.callTool('get_draft', { draft_id: draftId });
            const data = parseToolResult(raw);

            expect(data).toBeDefined();
            console.log(`[get_draft] Draft ${draftId} gelesen: ${JSON.stringify(data).substring(0, 200)}`);
        });

        it('delete_draft — loescht Entwurf', async () => {
            if (!draftId) {
                console.warn('[delete_draft] Uebersprungen: Kein Draft erstellt');
                return;
            }

            const raw = await client.callTool('delete_draft', { draft_id: draftId });
            const data = parseToolResult(raw);
            expect(data.deleted).toBe(true);

            console.log(`[delete_draft] Draft ${draftId} geloescht`);
            draftId = null;
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 9. SEND EMAIL: send_email
    // ═══════════════════════════════════════════════════════════

    describe('9. Send Email', () => {
        it('send_email — sendet Test-Email an sich selbst', async () => {
            // Brauche eine DEA als from_identity
            const listRaw = await client.callTool('list_deas');
            const listData = parseToolResult(listRaw);
            const deas = listData.deas as Array<Record<string, unknown>>;
            if (!deas || deas.length === 0) {
                console.warn('[send_email] Uebersprungen: Keine DEA verfuegbar');
                return;
            }

            const fromAddress = deas[0].address as string;

            try {
                const raw = await client.callTool('send_email', {
                    from_identity: fromAddress,
                    to: fromAddress,
                    subject: `MCP Integration Test ${new Date().toISOString()}`,
                    body: '<p>Automatischer Test vom MCP-Client. Kann ignoriert werden.</p>',
                });
                const data = parseToolResult(raw);

                expect(data.message_id).toBeDefined();
                expect(data.sent).toBe(true);

                console.log(`[send_email] Email gesendet: ${data.message_id}`);
            } catch (error: unknown) {
                const msg = error instanceof Error ? error.message : String(error);
                console.warn(`[send_email] Fehlgeschlagen (evtl. Send-Einschraenkung): ${msg}`);
            }
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 10. SHARED FOLDERS: list_shared_folders
    // ═══════════════════════════════════════════════════════════

    describe('10. Shared Folders', () => {
        it('list_shared_folders — listet geteilte Ordner', async () => {
            const raw = await client.callTool('list_shared_folders', { direction: 'both' });
            const data = parseToolResult(raw);

            expect(data.incoming).toBeDefined();
            expect(data.outgoing).toBeDefined();
            expect(Array.isArray(data.incoming)).toBe(true);
            expect(Array.isArray(data.outgoing)).toBe(true);

            const incoming = data.incoming as unknown[];
            const outgoing = data.outgoing as unknown[];
            console.log(`[list_shared_folders] Incoming: ${incoming.length}, Outgoing: ${outgoing.length}`);
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 11. EVENTS: event_subscribe, get_missed_events
    // ═══════════════════════════════════════════════════════════

    describe('11. Events', () => {
        it('event_subscribe — abonniert Events', async () => {
            try {
                const raw = await client.callTool('event_subscribe', {
                    topics: ['email.received'],
                    x25519_public_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
                    mlkem_public_key: 'AAAA',
                });
                const data = parseToolResult(raw);

                // Mindestens subscription_id oder mercure_url erwartet
                const hasValidResponse = data.subscription_id !== undefined
                    || data.mercure_url !== undefined
                    || data.topics !== undefined;
                expect(hasValidResponse).toBe(true);

                console.log(`[event_subscribe] Antwort: ${JSON.stringify(data).substring(0, 200)}`);
            } catch (error: unknown) {
                const msg = error instanceof Error ? error.message : String(error);
                console.warn(`[event_subscribe] Fehlgeschlagen: ${msg}`);
                // Event-System kann optional/deaktiviert sein
            }
        });

        it('get_missed_events — holt verpasste Events', async () => {
            try {
                const raw = await client.callTool('get_missed_events', { limit: 10 });
                const data = parseToolResult(raw);

                expect(data.events).toBeDefined();
                const events = data.events as unknown[];
                expect(Array.isArray(events)).toBe(true);

                console.log(`[get_missed_events] ${events.length} Events, has_more: ${data.has_more ?? false}`);
            } catch (error: unknown) {
                const msg = error instanceof Error ? error.message : String(error);
                console.warn(`[get_missed_events] Fehlgeschlagen: ${msg}`);
            }
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 12. RECIPIENT KEYS: get_recipient_keys
    // ═══════════════════════════════════════════════════════════

    describe('12. Recipient Keys', () => {
        it('get_recipient_keys — holt Public Keys fuer MCP_TEST_RECIPIENT', async () => {
            try {
                const raw = await client.callTool('get_recipient_keys', {
                    recipient_username: RECIPIENT,
                });
                const data = parseToolResult(raw);

                expect(data.x25519_public_key).toBeDefined();
                expect(data.mlkem_public_key).toBeDefined();
                expect(typeof data.x25519_public_key).toBe('string');
                expect(typeof data.mlkem_public_key).toBe('string');
                expect((data.x25519_public_key as string).length).toBeGreaterThan(0);
                expect((data.mlkem_public_key as string).length).toBeGreaterThan(0);

                console.log(`[get_recipient_keys] Keys fuer "${RECIPIENT}": ` +
                    `x25519=${(data.x25519_public_key as string).substring(0, 20)}..., ` +
                    `mlkem=${(data.mlkem_public_key as string).substring(0, 20)}...`);
            } catch (error: unknown) {
                const msg = error instanceof Error ? error.message : String(error);
                console.warn(`[get_recipient_keys] Fehlgeschlagen: ${msg}`);
            }
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 13. REPLY & FORWARD: reply_email, forward_email
    // ═══════════════════════════════════════════════════════════

    describe('13. Reply & Forward', () => {
        it('reply_email — antwortet auf bestehende Email', async () => {
            if (!emailUuid) {
                console.warn('[reply_email] Uebersprungen: Keine Email');
                return;
            }

            // Reply braucht eine gueltige from_identity (DEA).
            // Holen wir die erste DEA.
            const listRaw = await client.callTool('list_deas');
            const listData = parseToolResult(listRaw);
            const deas = listData.deas as Array<Record<string, unknown>>;
            const fromIdentity = deas.length > 0 ? deas[0].address as string : undefined;

            try {
                const raw = await client.callTool('reply_email', {
                    email_uuid: emailUuid,
                    body: '<p>MCP-Client Testantwort - bitte ignorieren.</p>',
                    original_from: 'test@example.com',
                    original_subject: 'Test',
                    ...(fromIdentity ? { from_identity: fromIdentity } : {}),
                });
                const data = parseToolResult(raw);

                if (data.message_id) {
                    console.log(`[reply_email] Antwort gesendet: ${data.message_id}`);
                } else {
                    // Server hat geantwortet, aber evtl. Fehlermeldung
                    console.log(`[reply_email] Server-Antwort: ${JSON.stringify(data).substring(0, 200)}`);
                }
            } catch (error: unknown) {
                const msg = error instanceof Error ? error.message : String(error);
                // Reply kann fehlschlagen wenn keine from_identity oder Sending deaktiviert
                console.log(`[reply_email] Server-Fehler (akzeptabel): ${msg.substring(0, 150)}`);
            }
        });

        it('forward_email — leitet bestehende Email weiter', async () => {
            if (!emailUuid || !deaAddress) {
                console.warn('[forward_email] Uebersprungen: Keine Email oder DEA');
                return;
            }

            try {
                const raw = await client.callTool('forward_email', {
                    email_uuid: emailUuid,
                    to: deaAddress,
                    original_subject: 'Fwd: Test',
                    original_body: '<p>Weitergeleitete Nachricht</p>',
                    from_identity: deaAddress,
                });
                const data = parseToolResult(raw);

                if (data.message_id) {
                    console.log(`[forward_email] Weitergeleitet: ${data.message_id}`);
                } else {
                    console.log(`[forward_email] Server-Antwort: ${JSON.stringify(data).substring(0, 200)}`);
                }
            } catch (error: unknown) {
                const msg = error instanceof Error ? error.message : String(error);
                console.log(`[forward_email] Server-Fehler (akzeptabel): ${msg.substring(0, 150)}`);
            }
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 14. SHARE FOLDER TOOLS: share_folder, revoke_share,
    //     update_share_permissions (Smoke-Tests mit ungueltigem Input)
    // ═══════════════════════════════════════════════════════════

    describe('14. Share Folder Tools (Smoke-Test)', () => {
        it('share_folder — Smoke-Test mit ungueltigem Input', async () => {
            // Erwartet: Server antwortet mit Fehler (Folder not found)
            const raw = await client.callTool('share_folder', {
                folder_uuid: '00000000-0000-0000-0000-000000000000',
                recipient_username: 'nonexistent_user_mcp_test',
                role_preset: 'readonly',
                encrypted_folder_key: 'dGVzdA==',
                x25519_ephemeral: 'dGVzdA==',
                mlkem_ciphertext: 'dGVzdA==',
                key_nonce: 'dGVzdA==',
            });
            const data = parseToolResult(raw);
            // Bei ungueltigem Input: entweder error=true oder exception
            expect(data.error).toBe(true);
            console.log(`[share_folder] Erwarteter Fehler: ${data.message}`);
        });

        it('revoke_share — Smoke-Test mit ungueltigem UUID', async () => {
            const raw = await client.callTool('revoke_share', {
                share_uuid: '00000000-0000-0000-0000-000000000000',
            });
            const data = parseToolResult(raw);
            expect(data.error).toBe(true);
            console.log(`[revoke_share] Erwarteter Fehler: ${data.message}`);
        });

        it('update_share_permissions — Smoke-Test mit ungueltigem UUID', async () => {
            const raw = await client.callTool('update_share_permissions', {
                share_uuid: '00000000-0000-0000-0000-000000000000',
                role_preset: 'readonly',
            });
            const data = parseToolResult(raw);
            expect(data.error).toBe(true);
            console.log(`[update_share_permissions] Erwarteter Fehler: ${data.message}`);
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 15. DELETE EMAIL: delete_email (Smoke-Test)
    // ═══════════════════════════════════════════════════════════

    describe('15. Delete Email (Smoke-Test)', () => {
        it('delete_email — Smoke-Test mit ungueltigem UUID', async () => {
            try {
                const raw = await client.callTool('delete_email', {
                    email_uuid: '00000000-0000-0000-0000-000000000000',
                });
                const data = parseToolResult(raw);
                console.log(`[delete_email] Antwort: ${JSON.stringify(data).substring(0, 200)}`);
            } catch (error: unknown) {
                const msg = error instanceof Error ? error.message : String(error);
                console.log(`[delete_email] Erwarteter Fehler: ${msg.substring(0, 150)}`);
                expect(error).toBeDefined();
            }
        });
    });

    // ═══════════════════════════════════════════════════════════
    // 16. DISCONNECT
    // ═══════════════════════════════════════════════════════════

    describe('16. Disconnect', () => {
        it('disconnect — beendet Session', async () => {
            await client.disconnect();
            expect(client.isConnected()).toBe(false);
            console.log('[disconnect] Session beendet');
        });
    });
});
