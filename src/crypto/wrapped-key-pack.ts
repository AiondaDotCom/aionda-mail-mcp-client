/**
 * wrapped-key-pack.ts — das Pack-Format für gekapselte Mailschlüssel.
 *
 * Eine Bauform, ein Eigentümer. Vorher stand sie im Proxy ausgeschrieben da,
 * und mit `deliver_to_shared_folder` wäre sie ein zweites Mal danebengestanden.
 * Zwei Abschriften desselben Formats heisst: Wer die Reihenfolge einmal
 * korrigiert, korrigiert sie an der anderen Stelle nicht mit.
 *
 * ## Das Format
 *
 * ```
 * 0x01 || x25519Ct(32) || mlKemCt(1568) || nonce(12) || tag(16) || ciphertext
 * ```
 *
 * 🚩 **`tag` steht VOR `ciphertext`.** WebCrypto liefert es umgekehrt
 * (`ciphertext || tag`), PHP erwartet es so. Wer die Umordnung vergisst, baut
 * eine Kapsel, die *niemand* öffnet - und zwar erst beim Lesen sichtbar, nicht
 * beim Schreiben. Genau dieser Fehler war Ticket `7cbc485d`: Beim Einliefern in
 * einen geteilten Ordner bekam der Eigentümer eine Kapsel, die er nicht öffnen
 * konnte, während alle Empfänger der Freigabe die Mail lasen.
 *
 * ⚠️ Nicht zu verwechseln mit dem gleichnamigen Drive-Feld `owner_wrapped_key`:
 * Dort ist der Wert base64 mit **getrennter** Nonce-Spalte. Hier ist er hex und
 * selbsttragend (die Nonce steckt im Pack). Gleicher Feldname, anderes Format.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */

import { webcrypto } from 'node:crypto';

import { toHex } from './encoding';
import { hybridEncapsulate } from './hybrid-kem';

/** AES-GCM-Prüfsumme, in diesem Format am Anfang statt am Ende. */
const TAG_LENGTH = 16;

/** Länge des Packs bei einem rohen 32-Byte-Schlüssel. */
export const PACK_LENGTH_FOR_32_BYTE_KEY = 1 + 32 + 1568 + 12 + TAG_LENGTH + 32;

/**
 * Kapselt einen Mailschlüssel für einen Empfänger (Hybrid-KEM + AES-GCM).
 *
 * @param ephemeralKey    der rohe Mailschlüssel
 * @param x25519PublicKey öffentlicher X25519-Schlüssel des Empfängers
 * @param mlKemPublicKey  öffentlicher ML-KEM-1024-Schlüssel des Empfängers
 * @returns das fertige Pack als Bytes
 */
export async function packWrappedKeyForRecipient(
    ephemeralKey: Uint8Array,
    x25519PublicKey: Uint8Array,
    mlKemPublicKey: Uint8Array
): Promise<Uint8Array> {
    const kem = await hybridEncapsulate(x25519PublicKey, mlKemPublicKey);

    const aesKey = await webcrypto.subtle.importKey(
        'raw', kem.sharedSecret, { name: 'AES-GCM' }, false, ['encrypt']
    );
    const nonce = webcrypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(await webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce }, aesKey, ephemeralKey
    ));

    // WebCrypto: ciphertext || tag  ->  hier gilt: tag || ciphertext
    const ciphertext = sealed.slice(0, sealed.length - TAG_LENGTH);
    const tag = sealed.slice(sealed.length - TAG_LENGTH);

    const pack = new Uint8Array(
        1 + 32 + kem.mlKemCiphertext.length + 12 + TAG_LENGTH + ciphertext.length
    );
    let offset = 0;
    pack[offset++] = 0x01;
    pack.set(kem.x25519Ciphertext, offset); offset += 32;
    pack.set(kem.mlKemCiphertext, offset);  offset += kem.mlKemCiphertext.length;
    pack.set(nonce, offset);                offset += 12;
    pack.set(tag, offset);                  offset += TAG_LENGTH;
    pack.set(ciphertext, offset);

    return pack;
}

/**
 * Dasselbe, hex-kodiert - so, wie `vault_emails.wrapped_ephemeral_key` und das
 * Feld `owner_wrapped_key` der Zustellung es erwarten.
 */
export async function packWrappedKeyHex(
    ephemeralKey: Uint8Array,
    x25519PublicKey: Uint8Array,
    mlKemPublicKey: Uint8Array
): Promise<string> {
    return toHex(await packWrappedKeyForRecipient(ephemeralKey, x25519PublicKey, mlKemPublicKey));
}
