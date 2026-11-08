import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AiondaMailClient } from '../src/client';

// Mock transport with proper class constructor
vi.mock('../src/transport', () => ({
    McpTransport: class MockMcpTransport {
        request = vi.fn();
        notify = vi.fn();
        setSessionId = vi.fn();
        getSessionId = vi.fn().mockReturnValue(null);
    },
}));

vi.mock('../src/session', () => {
    const toolResults: Record<string, unknown> = {
        list_shared_folders: {
            content: [{ type: 'text', text: '{}' }],
            data: {
                incoming: [{
                    share_uuid: 'share-1',
                    folder_uuid: 'folder-1',
                    owner_username: 'alice',
                    folder_encrypted_name: 'enc_name',
                    can_read: 1,
                    can_send: 0,
                    can_move_in: 1,
                    can_move_out: 0,
                    can_delete: 0,
                    can_manage: 0,
                    role_preset: 'einliefern',
                    encrypted_folder_key: 'enc_key',
                    x25519_ephemeral: 'eph',
                    mlkem_ciphertext: 'ct',
                    key_nonce: 'nonce',
                    email_count: 5,
                    unread_count: 2,
                    created_at: '2026-02-28',
                }],
                outgoing: [],
            },
        },
        share_folder: {
            content: [{ type: 'text', text: '{}' }],
            data: { uuid: 'share-new', created_at: '2026-02-28' },
        },
        revoke_share: {
            content: [{ type: 'text', text: '{}' }],
            data: { revoked: true },
        },
        update_share_permissions: {
            content: [{ type: 'text', text: '{}' }],
            data: { updated: true },
        },
        get_recipient_keys: {
            content: [{ type: 'text', text: '{}' }],
            data: {
                x25519_public_key: 'pub_x',
                mlkem_public_key: 'pub_ml',
            },
        },
    };

    return {
        McpSession: class MockMcpSession {
            initialize = vi.fn().mockResolvedValue({
                protocolVersion: '2025-03-26',
                capabilities: { tools: {} },
                serverInfo: { name: 'Test', version: '1.0.0' },
            });
            callTool = vi.fn().mockImplementation((name: string) => {
                return Promise.resolve(toolResults[name] || { data: {} });
            });
            isInitialized = vi.fn().mockReturnValue(true);
            isExpired = vi.fn().mockReturnValue(false);
            destroy = vi.fn();
            listTools = vi.fn().mockResolvedValue([]);
            ping = vi.fn().mockResolvedValue(undefined);
            getInitResult = vi.fn().mockReturnValue(null);
        },
    };
});

describe('AiondaMailClient - Shared Folders', () => {
    let client: AiondaMailClient;

    beforeEach(async () => {
        client = new AiondaMailClient({ apiKey: 'tma_test' });
        await client.connect();
    });

    it('should list shared folders', async () => {
        const result = await client.listSharedFolders();
        expect(result.incoming).toHaveLength(1);
        expect(result.incoming[0].share_uuid).toBe('share-1');
        expect(result.incoming[0].role_preset).toBe('einliefern');
        expect(result.outgoing).toHaveLength(0);
    });

    it('should share a folder', async () => {
        const result = await client.shareFolder({
            folder_uuid: 'folder-1',
            recipient_username: 'bob',
            permissions: {
                can_read: 1,
                can_send: 0,
                can_move_in: 1,
                can_move_out: 0,
                can_delete: 0,
                can_manage: 0,
            },
            encrypted_folder_key: 'enc_key',
            x25519_ephemeral: 'eph',
            mlkem_ciphertext: 'ct',
            key_nonce: 'nonce',
        });
        expect(result.uuid).toBe('share-new');
    });

    it('should revoke a share', async () => {
        const result = await client.revokeShare('share-1');
        expect(result.revoked).toBe(true);
    });

    it('should update share permissions', async () => {
        const result = await client.updateSharePermissions({
            share_uuid: 'share-1',
            permissions: {
                can_read: 1,
                can_send: 1,
                can_move_in: 1,
                can_move_out: 1,
                can_delete: 0,
                can_manage: 0,
            },
            role_preset: 'antworten',
        });
        expect(result.updated).toBe(true);
    });

    it('should get recipient keys', async () => {
        const result = await client.getRecipientKeys('bob');
        expect(result.x25519_public_key).toBe('pub_x');
        expect(result.mlkem_public_key).toBe('pub_ml');
    });
});
