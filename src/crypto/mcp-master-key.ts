/**
 * Umschlag des Master Keys für den MCP-Zugang echter Menschen
 *
 * Vertrag „MCP-Zugang für echte Menschen mit eigenem Tresor-Schlüssel"
 * (13.09.2026), Abschnitt 2. Identisch in Web, MCP-Client und Swift; der
 * gemeinsame Test-Vektor liegt in kat/mcp-menschenschluessel.json.
 *
 *   K   = SHA-256(utf8(tmv_-Text))            – dieselbe Ableitung wie beim
 *                                               KI-Mitarbeiter, deshalb bleibt
 *                                               AIONDA_VAULT_KEY dieselbe Variable
 *   AAD = utf8("aionda-mcp-master-key-v1:" + key_uuid in Kleinbuchstaben)
 *   Umschlag = iv(12) || AES-256-GCM(M, K, iv, AAD) || tag(16)   – 60 Byte
 *
 * 🚩 Geht das Entpacken nicht auf (falscher tmv_, falsche uuid, beschädigt),
 *    ist das ein harter Fehler. Es gibt KEINEN Rückfall auf SHA-256(tmv_) als
 *    Master Key – der wäre bei einem Menschen schlicht der falsche Schlüssel,
 *    und jede Mail käme als „[Decryption failed]" zurück, ohne dass jemand
 *    erfährt, warum.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */
import { webcrypto } from 'node:crypto';
import { McpDecryptionError } from '../errors';

export const MCP_MASTER_KEY_AAD_PREFIX = 'aionda-mcp-master-key-v1:';
export const MCP_VAULT_KEY_PREFIX = 'tmv_';

const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const MASTER_KEY_LENGTH = 32;
export const WRAPPED_MASTER_KEY_LENGTH = IV_LENGTH + MASTER_KEY_LENGTH + TAG_LENGTH;

/**
 * Umschlüssel K aus dem tmv_-Text ableiten.
 */
export async function deriveWrappingKey(vaultKeyText: string): Promise<Uint8Array> {
    if (!vaultKeyText.startsWith(MCP_VAULT_KEY_PREFIX)) {
        throw new McpDecryptionError(
            `AIONDA_VAULT_KEY must start with "${MCP_VAULT_KEY_PREFIX}"`
        );
    }
    const digest = await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(vaultKeyText));
    return new Uint8Array(digest);
}

/**
 * AAD für einen Schlüssel – die UUID immer in Kleinbuchstaben.
 */
export function masterKeyAad(keyUuid: string): Uint8Array {
    return new TextEncoder().encode(MCP_MASTER_KEY_AAD_PREFIX + keyUuid.toLowerCase());
}

/**
 * Umschlag öffnen → Master Key M (32 Byte).
 *
 * @throws McpDecryptionError bei jedem Fehlschlag – falsche Länge, falscher
 *         Schlüssel, falsche UUID, beschädigte Bytes.
 */
export async function unwrapMasterKey(
    wrapped: Uint8Array,
    vaultKeyText: string,
    keyUuid: string
): Promise<Uint8Array> {
    if (wrapped.length !== WRAPPED_MASTER_KEY_LENGTH) {
        throw new McpDecryptionError(
            `wrapped_master_key must be ${WRAPPED_MASTER_KEY_LENGTH} bytes, got ${wrapped.length}`
        );
    }
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(keyUuid)) {
        throw new McpDecryptionError('mcp_key_uuid is not a UUID');
    }

    const wrappingKey = await deriveWrappingKey(vaultKeyText);
    const iv = wrapped.slice(0, IV_LENGTH);
    const ciphertextWithTag = wrapped.slice(IV_LENGTH);

    let masterKey: Uint8Array;
    try {
        const aesKey = await webcrypto.subtle.importKey('raw', wrappingKey, 'AES-GCM', false, ['decrypt']);
        masterKey = new Uint8Array(await webcrypto.subtle.decrypt(
            { name: 'AES-GCM', iv, additionalData: masterKeyAad(keyUuid), tagLength: TAG_LENGTH * 8 },
            aesKey,
            ciphertextWithTag
        ));
    } catch {
        throw new McpDecryptionError(
            'wrapped_master_key could not be opened: AIONDA_VAULT_KEY does not match this MCP key '
            + '(wrong tmv_ key, wrong key uuid, or damaged envelope)'
        );
    }

    if (masterKey.length !== MASTER_KEY_LENGTH) {
        throw new McpDecryptionError(`unwrapped master key has ${masterKey.length} bytes, expected ${MASTER_KEY_LENGTH}`);
    }
    return masterKey;
}
