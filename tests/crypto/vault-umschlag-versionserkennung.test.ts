/**
 * Wächter über der Versionserkennung des Vault-Daten-Umschlags — Ticket #92e6ad10
 *
 * Diese Datei ist die "normative Referenz" für den Umschlag; der Fehler steckte
 * hier genauso wie im Manager und in der nativen App. `decryptVaultData`
 * entschied allein am ERSTEN BYTE, ob ein Blob Version 2 ist. Ein
 * Version-1-Blob hat aber kein Versionsbyte — sein erstes Byte ist ein IV-Byte,
 * also Zufall. In 1 von 256 Fällen ist es 0x02, der Blob läuft in den v2-Zweig
 * und ist danach DAUERHAFT unlesbar.
 *
 * FEHLTREFFERZAHL auf sauberem Baum: 0 von 7 (gemessen 27.08.2026).
 * ALARMPROBE in BEIDE Richtungen, gemessen 27.08.2026 (Rückfall in
 * `decryptVaultData` wieder entfernt):
 *   - Fix zurückgedreht           -> "5 failed | 2 passed (7)"
 *   - und er SCHWEIGT, wo er soll -> grün bleiben: echter v2-Blob geht auf,
 *     v1-Blob ohne 0x02 bleibt lesbar
 *   - Fix eingebaut               -> 7 von 7 grün, 0 Fehltreffer
 *
 * Die Zwillinge stehen in
 * `typescript/manager/vault/vault-umschlag-versionserkennung.spec.ts` und
 * `src/apps/apple/.../VaultUmschlagVersionserkennungTests.swift` — ein Wächter
 * über einer Quelle beweist nichts über die zweite.
 */

import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';

import {
    ENVELOPE_BEIDE_VERSIONEN_FEHLER,
    decryptVaultData,
    encryptVaultData,
} from '../../src/crypto/aes-gcm';

const VERSION_BYTE = 0x02;

function masterKey(): Uint8Array {
    return new Uint8Array(32).fill(0x5a);
}

/**
 * Baut einen ECHTEN Version-1-Blob (iv(12) || ciphertext || tag(16)), dessen IV
 * mit dem vorgegebenen Byte beginnt. Das Byte wird NICHT nachträglich verbogen —
 * es geht als IV in die Verschlüsselung ein.
 */
async function versionEinsBlob(erstesByte: number, klartext: Uint8Array): Promise<Uint8Array> {
    const iv = new Uint8Array(12);
    webcrypto.getRandomValues(iv);
    iv[0] = erstesByte;

    const key = await webcrypto.subtle.importKey('raw', masterKey(), 'AES-GCM', false, ['encrypt']);
    const sealed = new Uint8Array(
        await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, klartext)
    );

    const blob = new Uint8Array(iv.length + sealed.length);
    blob.set(iv, 0);
    blob.set(sealed, iv.length);
    return blob;
}

describe('Vault-Umschlag: Versionserkennung (#92e6ad10)', () => {
    it('liest einen Version-1-Blob, dessen IV zufällig mit 0x02 beginnt', async () => {
        const klartext = new TextEncoder().encode('{"firstName":"Alt","lastName":"Bestand"}');
        const blob = await versionEinsBlob(VERSION_BYTE, klartext);
        expect(blob[0]).toBe(VERSION_BYTE);
        expect(await decryptVaultData(blob, masterKey())).toEqual(klartext);
    });

    it('liest Version-1-Blobs mit JEDEM der 256 möglichen ersten Bytes', async () => {
        const klartext = new TextEncoder().encode('Kontakt');
        for (let byte = 0; byte < 256; byte++) {
            const blob = await versionEinsBlob(byte, klartext);
            expect(await decryptVaultData(blob, masterKey())).toEqual(klartext);
        }
    });

    it('liest auch den kurzen Fall: leerer Klartext, 28 Byte, führendes 0x02', async () => {
        const blob = await versionEinsBlob(VERSION_BYTE, new Uint8Array(0));
        expect(blob.length).toBe(28);
        expect((await decryptVaultData(blob, masterKey())).length).toBe(0);
    });

    it('liest einen echten Version-2-Blob unverändert', async () => {
        const klartext = new TextEncoder().encode('Kontaktliste');
        const blob = await encryptVaultData(klartext, masterKey());
        expect(blob[0]).toBe(VERSION_BYTE);
        expect(await decryptVaultData(blob, masterKey())).toEqual(klartext);
    });

    it('wirft bei einem wirklich kaputten Blob — und behauptet dabei nicht "v2"', async () => {
        const blob = new Uint8Array(100).fill(0xab);
        blob[0] = VERSION_BYTE;
        await expect(decryptVaultData(blob, masterKey())).rejects.toThrow(
            ENVELOPE_BEIDE_VERSIONEN_FEHLER
        );
        expect(ENVELOPE_BEIDE_VERSIONEN_FEHLER).toContain('weder');
    });

    it('haengt die Ursache an, statt sie wegzuwerfen', async () => {
        const blob = await encryptVaultData(new TextEncoder().encode('Kontaktliste'), masterKey());
        const gefangen = await decryptVaultData(blob, new Uint8Array(32).fill(0x66)).then(
            () => null,
            (e: unknown) => e
        );
        expect((gefangen as Error).message).toBe(ENVELOPE_BEIDE_VERSIONEN_FEHLER);
        const ursache = (gefangen as { cause?: unknown }).cause;
        expect(ursache).toBeDefined();
        expect((ursache as { name?: string }).name).toBe('OperationError');
    });

    it('schweigt dort, wo alles richtig ist: Version-1-Blob ohne 0x02 bleibt lesbar', async () => {
        const klartext = new TextEncoder().encode('Bestandskontakt');
        const blob = await versionEinsBlob(0x07, klartext);
        expect(await decryptVaultData(blob, masterKey())).toEqual(klartext);
    });
});
