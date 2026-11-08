/**
 * Tests fuer die Aufgaben-Krypto (Aufgaben-Modul)
 *
 * Prueft, dass der Proxy byte-kompatibel zum Web-Frontend arbeitet:
 * Feldformat iv(12) || ct+tag, wrapped_key version(1)||salt(32)||iv(12)||ct+tag,
 * HKDF-Label 'trashmail-tasks-v1' plus Dual-Read auf 'trashmail-contacts-v2'.
 *
 * // #f1c8f3f1
 */
import { webcrypto } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { fromBase64, toBase64 } from '../../src/crypto/encoding';
import {
    LEGACY_HKDF_INFO,
    TASK_WRAP_VERSION,
    decryptTaskField,
    encryptTaskField,
    generateTaskKey,
    normalizeSteps,
    parseSteps,
    unwrapTaskKey,
    wrapTaskKey,
} from '../../src/crypto/tasks-crypto';

const masterKey = new Uint8Array(32).fill(7);

/** Wrappt einen Key mit einem beliebigen HKDF-Label (fuer den Dual-Read-Test). */
async function wrapWithInfo(rawKey: Uint8Array, key: Uint8Array, info: string): Promise<Uint8Array> {
    const salt = webcrypto.getRandomValues(new Uint8Array(32));
    const iv = webcrypto.getRandomValues(new Uint8Array(12));

    const keyMaterial = await webcrypto.subtle.importKey('raw', key, 'HKDF', false, ['deriveKey']);
    const derived = await webcrypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(info) },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
    const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, derived, rawKey);

    const result = new Uint8Array(1 + 32 + 12 + ciphertext.byteLength);
    result[0] = TASK_WRAP_VERSION;
    result.set(salt, 1);
    result.set(iv, 33);
    result.set(new Uint8Array(ciphertext), 45);
    return result;
}

async function encryptLegacyField(value: string, keyBytes: Uint8Array): Promise<string> {
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const key = await webcrypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(value));
    return toBase64(new Uint8Array([...iv, ...new Uint8Array(ciphertext)]));
}

describe('tasks-crypto: Key-Wrapping', () => {
    it('wrappt und entpackt einen Aufgaben-Key (Roundtrip)', async () => {
        const taskKey = generateTaskKey();
        const wrapped = await wrapTaskKey(taskKey, masterKey);
        const unwrapped = await unwrapTaskKey(wrapped, masterKey);

        expect(Array.from(unwrapped)).toEqual(Array.from(taskKey));
    });

    it('haelt das Layout version(1) || salt(32) || iv(12) || ct+tag ein', async () => {
        const taskKey = generateTaskKey();
        const wrapped = await wrapTaskKey(taskKey, masterKey);

        expect(wrapped[0]).toBe(TASK_WRAP_VERSION);
        // 1 + 32 + 12 + (32 Key + 16 Tag) = 93 Bytes
        expect(wrapped.length).toBe(93);
        // Serverseitiges Minimum (TaskListService::MIN_WRAPPED_KEY_BYTES = 60)
        expect(wrapped.length).toBeGreaterThanOrEqual(60);
    });

    it('erzeugt bei jedem Wrappen neues Salt und neuen IV', async () => {
        const taskKey = generateTaskKey();
        const a = await wrapTaskKey(taskKey, masterKey);
        const b = await wrapTaskKey(taskKey, masterKey);

        expect(toBase64(a)).not.toBe(toBase64(b));
    });

    it('liest per Dual-Read auch Keys mit dem alten Kontakte-Label', async () => {
        const taskKey = generateTaskKey();
        const legacyWrapped = await wrapWithInfo(taskKey, masterKey, LEGACY_HKDF_INFO);

        const unwrapped = await unwrapTaskKey(legacyWrapped, masterKey);
        expect(Array.from(unwrapped)).toEqual(Array.from(taskKey));
    });

    it('scheitert bei falschem Master Key', async () => {
        const taskKey = generateTaskKey();
        const wrapped = await wrapTaskKey(taskKey, masterKey);
        const wrongKey = new Uint8Array(32).fill(9);

        await expect(unwrapTaskKey(wrapped, wrongKey)).rejects.toThrow(/could not be unwrapped/);
    });

    it('lehnt unbekannte Versionsbytes ab (kein stiller Downgrade)', async () => {
        const taskKey = generateTaskKey();
        const wrapped = await wrapTaskKey(taskKey, masterKey);
        wrapped[0] = 0x01;

        await expect(unwrapTaskKey(wrapped, masterKey)).rejects.toThrow(/Unsupported wrapped task key version/);
    });
});

describe('tasks-crypto: Feld-Verschluesselung', () => {
    it('verschluesselt und entschluesselt einen Titel (Roundtrip)', async () => {
        const taskKey = generateTaskKey();
        const encrypted = await encryptTaskField('Steuererklärung abgeben', taskKey);

        expect(await decryptTaskField(encrypted, taskKey)).toBe('Steuererklärung abgeben');
    });

    it('nutzt das WebCrypto-Layout iv(12) || ciphertext+tag', async () => {
        const taskKey = generateTaskKey();
        const encrypted = await encryptTaskField('abc', taskKey);
        const raw = fromBase64(encrypted);

        // 12 IV + 3 Klartext + 16 Tag
        expect(raw.length).toBe(31);
    });

    it('erhaelt Umlaute und Emojis', async () => {
        const taskKey = generateTaskKey();
        const text = 'Müll rausbringen 🗑️ - später';
        const encrypted = await encryptTaskField(text, taskKey);

        expect(await decryptTaskField(encrypted, taskKey)).toBe(text);
    });

    it('scheitert mit fremdem Key', async () => {
        const encrypted = await encryptTaskField('geheim', generateTaskKey());

        await expect(decryptTaskField(encrypted, generateTaskKey())).rejects.toThrow();
    });

    it('bindet AAD an das Feld (fremder Kontext wird abgelehnt)', async () => {
        const key = generateTaskKey();
        const encrypted = await encryptTaskField('geheim', key, 'title');

        await expect(decryptTaskField(encrypted, key, 'notes')).rejects.toThrow();
        await expect(decryptTaskField(encrypted, key, 'title')).resolves.toBe('geheim');
    });

    it('liest Legacy-Felder ohne AAD für Titel und Notizen', async () => {
        const key = generateTaskKey();
        const legacyTitle = await encryptLegacyField('alter Titel', key);
        const legacyNotes = await encryptLegacyField('alte Notizen', key);

        await expect(decryptTaskField(legacyTitle, key, 'title')).resolves.toBe('alter Titel');
        await expect(decryptTaskField(legacyNotes, key, 'notes')).resolves.toBe('alte Notizen');
    });

    it('macht einen vollstaendigen Aufgaben-Roundtrip (wrap + Felder)', async () => {
        const taskKey = generateTaskKey();
        const wrapped = toBase64(await wrapTaskKey(taskKey, masterKey));

        const encTitle = await encryptTaskField('Angebot schreiben', taskKey);
        const encNotes = await encryptTaskField('Für Kunde Müller', taskKey);
        const steps = normalizeSteps(['Preise prüfen', { title: 'Versenden', completed: true }]);
        const encSteps = await encryptTaskField(JSON.stringify(steps), taskKey);
        const encMeta = await encryptTaskField(JSON.stringify({ rrule: 'FREQ=WEEKLY' }), taskKey);

        // Server-Seite: Blobs kommen unveraendert als base64 zurueck
        const restoredKey = await unwrapTaskKey(fromBase64(wrapped), masterKey);

        expect(await decryptTaskField(encTitle, restoredKey)).toBe('Angebot schreiben');
        expect(await decryptTaskField(encNotes, restoredKey)).toBe('Für Kunde Müller');
        expect(parseSteps(await decryptTaskField(encSteps, restoredKey))).toEqual([
            { id: 'step-0', title: 'Preise prüfen', completed: false },
            { id: 'step-1', title: 'Versenden', completed: true },
        ]);
        expect(JSON.parse(await decryptTaskField(encMeta, restoredKey))).toEqual({ rrule: 'FREQ=WEEKLY' });
    });
});

describe('tasks-crypto: Schritte normalisieren', () => {
    it('macht aus Strings vollstaendige Schritte', () => {
        expect(normalizeSteps(['A', 'B'])).toEqual([
            { id: 'step-0', title: 'A', completed: false },
            { id: 'step-1', title: 'B', completed: false },
        ]);
    });

    it('erzwingt das Schema bei kaputten Eintraegen', () => {
        expect(normalizeSteps([{ completed: 1 }, null])).toEqual([
            { id: 'step-0', title: '', completed: true },
            { id: 'step-1', title: '', completed: false },
        ]);
    });

    it('behaelt vorhandene IDs', () => {
        expect(normalizeSteps([{ id: 'abc', title: 'X', completed: false }])).toEqual([
            { id: 'abc', title: 'X', completed: false },
        ]);
    });

    it('liefert bei Nicht-Arrays eine leere Liste', () => {
        expect(normalizeSteps('kein array')).toEqual([]);
        expect(normalizeSteps(undefined)).toEqual([]);
    });
});
