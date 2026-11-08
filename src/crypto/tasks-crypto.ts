/**
 * Tasks Crypto (Aufgaben-Modul)
 *
 * Clientseitige Ver- und Entschluesselung fuer Aufgaben und Aufgabenlisten.
 * Byte-identisch zum Web-Frontend (typescript/manager/tasks/tasks-crypto.ts):
 *
 *   Feldformat   : AES-256-GCM, iv(12) || ciphertext+tag  (WebCrypto-Layout)
 *   Aufgaben-Key : 32 Byte Zufall, pro Aufgabe bzw. pro Liste neu
 *   wrapped_key  : version(0x02) || salt(32) || iv(12) || ct+tag,
 *                  Key per HKDF-SHA-256 aus dem Master Key mit dem Label
 *                  'trashmail-tasks-v1' abgeleitet
 *
 * Dual-Read beim Entpacken: schlaegt das Aufgaben-Label fehl, wird das alte
 * Kontakte-Label 'trashmail-contacts-v2' probiert. Das ist KEIN unsicherer
 * Downgrade - beide Pfade sind authentifiziert, es scheitert schlicht der
 * falsche Schluessel. Noetig, damit bereits gespeicherte Aufgaben lesbar
 * bleiben.
 *
 * // #f1c8f3f1
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */
import { webcrypto } from 'node:crypto';
import type { webcrypto as WebCryptoNs } from 'node:crypto';

import { fromBase64, toBase64 } from './encoding';
import { decryptClientAesGcm, encryptClientAesGcm } from './aes-gcm';

/** HKDF-Label des Aufgaben-Moduls. */
export const TASKS_HKDF_INFO = 'trashmail-tasks-v1';
/** Versioned AEAD context.  Changing the context invalidates old ciphertext. */
export const TASKS_AAD_VERSION = 'trashmail-tasks-v1.1';

/** Altes Label - nur noch zum Lesen bereits gespeicherter Aufgaben. */
export const LEGACY_HKDF_INFO = 'trashmail-contacts-v2';

/** Versionsbyte des wrapped_key-Layouts. */
export const TASK_WRAP_VERSION = 0x02;

const SALT_LENGTH = 32;
const IV_LENGTH = 12;

/** Ein Teilschritt (Checklisten-Eintrag) einer Aufgabe. */
export interface TaskStep {
    id: string;
    title: string;
    completed: boolean;
}

/** Erzeugt einen frischen 32-Byte-Aufgaben-Key. */
export function generateTaskKey(): Uint8Array {
    return webcrypto.getRandomValues(new Uint8Array(32));
}

/** Leitet den Wrapping-Key per HKDF-SHA-256 ab. */
async function deriveWrapKey(
    masterKey: Uint8Array,
    salt: Uint8Array,
    info: string,
    usage: 'encrypt' | 'decrypt'
): Promise<WebCryptoNs.CryptoKey> {
    const keyMaterial = await webcrypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveKey']);
    return webcrypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt,
            info: new TextEncoder().encode(info),
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        [usage]
    );
}

/**
 * Wrappt einen Aufgaben-Key mit dem Master Key.
 * Layout: version(1) || salt(32) || iv(12) || ct+tag
 */
export async function wrapTaskKey(rawKey: Uint8Array, masterKey: Uint8Array): Promise<Uint8Array> {
    const salt = webcrypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = webcrypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const key = await deriveWrapKey(masterKey, salt, TASKS_HKDF_INFO, 'encrypt');

    const ciphertext = await webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(`${TASKS_AAD_VERSION}:wrapped-key`) },
        key,
        rawKey
    );

    const result = new Uint8Array(1 + SALT_LENGTH + IV_LENGTH + ciphertext.byteLength);
    result[0] = TASK_WRAP_VERSION;
    result.set(salt, 1);
    result.set(iv, 1 + SALT_LENGTH);
    result.set(new Uint8Array(ciphertext), 1 + SALT_LENGTH + IV_LENGTH);
    return result;
}

/**
 * Entpackt einen gewrappten Aufgaben-Key (Dual-Read tasks-v1 -> contacts-v2).
 */
export async function unwrapTaskKey(data: Uint8Array, masterKey: Uint8Array): Promise<Uint8Array> {
    if (data[0] !== TASK_WRAP_VERSION) {
        throw new Error(`Unsupported wrapped task key version: ${data[0]}`);
    }

    const salt = data.slice(1, 1 + SALT_LENGTH);
    const iv = data.slice(1 + SALT_LENGTH, 1 + SALT_LENGTH + IV_LENGTH);
    const ciphertext = data.slice(1 + SALT_LENGTH + IV_LENGTH);

    for (const info of [TASKS_HKDF_INFO, LEGACY_HKDF_INFO]) {
        try {
            const key = await deriveWrapKey(masterKey, salt, info, 'decrypt');
            for (const aad of [new TextEncoder().encode(`${TASKS_AAD_VERSION}:wrapped-key`), undefined]) {
                try {
                    const plaintext = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv, ...(aad ? { additionalData: aad } : {}) }, key, ciphertext);
                    return new Uint8Array(plaintext);
                } catch { /* old v1 wrapping had no AAD */ }
            }
        } catch {
            // Falsches Label - naechstes probieren.
        }
    }

    throw new Error('Task key could not be unwrapped');
}

/** Verschluesselt einen Text mit dem Aufgaben-Key (base64, iv(12) || ct+tag). */
export async function encryptTaskField(value: string, taskKey: Uint8Array, aad = 'field'): Promise<string> {
    const additionalData = new TextEncoder().encode(`${TASKS_AAD_VERSION}:${aad}`);
    return toBase64(await encryptClientAesGcm(new TextEncoder().encode(value), taskKey, undefined, additionalData));
}

/** Entschluesselt einen base64-Wert mit dem Aufgaben-Key. */
export async function decryptTaskField(base64Encrypted: string, taskKey: Uint8Array, aad = 'field'): Promise<string> {
    const data = fromBase64(base64Encrypted);
    let plaintext: Uint8Array;
    try {
        plaintext = await decryptClientAesGcm(
            data, taskKey, new TextEncoder().encode(`${TASKS_AAD_VERSION}:${aad}`)
        );
    } catch (modernError) {
        // Legacy task fields (including title/notes) were authenticated without AAD.
        try {
            plaintext = await decryptClientAesGcm(data, taskKey);
        } catch {
            throw modernError;
        }
    }
    return new TextDecoder().decode(plaintext);
}

/**
 * Bringt beliebige Schritt-Eingaben der KI in das Format des Web-Frontends.
 * Erlaubt sind Strings ("Einkaufen") und Objekte ({title, completed}).
 */
export function normalizeSteps(input: unknown): TaskStep[] {
    if (!Array.isArray(input)) return [];

    return input.map((entry, index) => {
        if (typeof entry === 'string') {
            return { id: `step-${index}`, title: entry, completed: false };
        }

        const step = (entry ?? {}) as Record<string, unknown>;
        return {
            id: typeof step['id'] === 'string' && step['id'] !== '' ? step['id'] : `step-${index}`,
            title: typeof step['title'] === 'string' ? step['title'] : String(step['title'] ?? ''),
            completed: Boolean(step['completed']),
        };
    });
}

/**
 * Liest ein verschluesseltes Schritte-JSON und erzwingt das Schema.
 * Kaputte Eintraege duerfen nicht als undefined in der KI-Antwort landen.
 */
export function parseSteps(raw: string): TaskStep[] {
    const parsed = JSON.parse(raw) as unknown;
    return normalizeSteps(parsed);
}
