/**
 * wrapped-key-pack.test.ts — die Reihenfolge von tag und ciphertext.
 *
 * 🔴 Ticket `7cbc485d`: Genau diese Verwechslung liess den Eigentümer eines
 * geteilten Ordners auf einer Mail sitzen, die alle anderen lesen konnten.
 *
 * Der Aufbau hier ist bewusst so gewählt, dass er etwas beweist: Geprüft wird
 * gegen den **echten Entpackweg** (`hybridDecapsulate` + AES-GCM in der
 * Reihenfolge, die der Bestandscode benutzt), nicht gegen eine Nachbildung des
 * Packs. Und die Gegenprobe kommt zuerst - ein Pack in der falschen Reihenfolge
 * **muss** scheitern. Gingen beide Reihenfolgen durch, wäre nichts gemessen.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */

import { webcrypto } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { ml_kem1024 } from '@noble/post-quantum/ml-kem';

import { hybridDecapsulate } from '../../src/crypto/hybrid-kem';
import {
    PACK_LENGTH_FOR_32_BYTE_KEY,
    packWrappedKeyForRecipient,
    packWrappedKeyHex,
} from '../../src/crypto/wrapped-key-pack';

const TAG_LENGTH = 16;

/** Ein Empfaenger mit beiden Schluesselpaaren - Muster aus shared-folder-key.test.ts. */
async function empfaengerAnlegen(): Promise<{
    x25519PublicKey: Uint8Array; x25519PrivateKey: Uint8Array;
    mlKemPublicKey: Uint8Array;  mlKemPrivateKey: Uint8Array;
}> {
    const x = await webcrypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pub = new Uint8Array(await webcrypto.subtle.exportKey('raw', x.publicKey));
    const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', x.privateKey));
    const mlKem = ml_kem1024.keygen();
    return {
        x25519PublicKey:  pub,
        x25519PrivateKey: pkcs8.slice(pkcs8.length - 32),   // rohe 32 Byte am Ende
        mlKemPublicKey:   mlKem.publicKey,
        mlKemPrivateKey:  mlKem.secretKey,
    };
}

/**
 * Der Entpackweg, den der Bestand benutzt (proxy.ts, Schritt 5 der
 * Zustellung): tag steht vorn und wird für WebCrypto nach hinten sortiert.
 */
async function auspacken(
    pack: Uint8Array,
    x25519PrivateKey: Uint8Array,
    mlKemPrivateKey: Uint8Array
): Promise<Uint8Array> {
    expect(pack[0]).toBe(0x01);
    const x25519Ct = pack.slice(1, 33);
    const mlKemCt  = pack.slice(33, 33 + 1568);
    const nonce    = pack.slice(33 + 1568, 33 + 1568 + 12);
    const encKey   = pack.slice(33 + 1568 + 12);

    const sharedSecret = await hybridDecapsulate(x25519Ct, mlKemCt, x25519PrivateKey, mlKemPrivateKey);

    const tag        = encKey.slice(0, TAG_LENGTH);
    const ciphertext = encKey.slice(TAG_LENGTH);
    const fuerWebCrypto = new Uint8Array(encKey.length);
    fuerWebCrypto.set(ciphertext, 0);
    fuerWebCrypto.set(tag, ciphertext.length);

    const aesKey = await webcrypto.subtle.importKey(
        'raw', sharedSecret, { name: 'AES-GCM' }, false, ['decrypt']
    );
    return new Uint8Array(await webcrypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce }, aesKey, fuerWebCrypto
    ));
}

describe('wrapped-key-pack (7cbc485d)', () => {
    it('⚠️ ein Pack mit vertauschter Reihenfolge laesst sich NICHT oeffnen', async () => {
        // Die Gegenprobe zuerst: Wenn das hier durchginge, wuerde der Test
        // darunter nichts beweisen - dann waere die Reihenfolge egal.
        const empfaenger = await empfaengerAnlegen();
        const schluessel = webcrypto.getRandomValues(new Uint8Array(32));

        const richtig = await packWrappedKeyForRecipient(
            schluessel, empfaenger.x25519PublicKey, empfaenger.mlKemPublicKey
        );

        // Dieselben Bytes, nur tag und ciphertext getauscht - also genau die
        // Bauform, die WebCrypto von sich aus liefert.
        const kopf = richtig.slice(0, 33 + 1568 + 12);
        const encKey = richtig.slice(33 + 1568 + 12);
        const tag = encKey.slice(0, TAG_LENGTH);
        const ciphertext = encKey.slice(TAG_LENGTH);
        const vertauscht = new Uint8Array(richtig.length);
        vertauscht.set(kopf, 0);
        vertauscht.set(ciphertext, kopf.length);
        vertauscht.set(tag, kopf.length + ciphertext.length);

        await expect(
            auspacken(vertauscht, empfaenger.x25519PrivateKey, empfaenger.mlKemPrivateKey)
        ).rejects.toThrow();
    });

    it('ein richtig gebautes Pack oeffnet der Empfaenger wieder', async () => {
        const empfaenger = await empfaengerAnlegen();
        const schluessel = webcrypto.getRandomValues(new Uint8Array(32));

        const pack = await packWrappedKeyForRecipient(
            schluessel, empfaenger.x25519PublicKey, empfaenger.mlKemPublicKey
        );
        const zurueck = await auspacken(
            pack, empfaenger.x25519PrivateKey, empfaenger.mlKemPrivateKey
        );

        expect(Array.from(zurueck)).toEqual(Array.from(schluessel));
    });

    it('haelt die Laenge ein, die die Gegenstellen erwarten', async () => {
        const empfaenger = await empfaengerAnlegen();

        const pack = await packWrappedKeyForRecipient(
            new Uint8Array(32), empfaenger.x25519PublicKey, empfaenger.mlKemPublicKey
        );

        // Derselbe Wert, den der Swift-Kern als `expectedLengthFor32ByteKey`
        // fuehrt und den die Server-Strukturpruefung als Untergrenze nimmt.
        expect(pack.length).toBe(1661);
        expect(pack.length).toBe(PACK_LENGTH_FOR_32_BYTE_KEY);
    });

    it('liefert hex in Kleinbuchstaben fuer owner_wrapped_key', async () => {
        const empfaenger = await empfaengerAnlegen();

        const hex = await packWrappedKeyHex(
            new Uint8Array(32), empfaenger.x25519PublicKey, empfaenger.mlKemPublicKey
        );

        expect(hex).toMatch(/^[0-9a-f]+$/);
        expect(hex.length).toBe(1661 * 2);
        expect(hex.slice(0, 2)).toBe('01');
    });

    it('kapselt fuer den genannten Empfaenger, nicht fuer irgendwen', async () => {
        const eigentuemer = await empfaengerAnlegen();
        const jemandAnders = await empfaengerAnlegen();
        const schluessel = webcrypto.getRandomValues(new Uint8Array(32));

        const pack = await packWrappedKeyForRecipient(
            schluessel, eigentuemer.x25519PublicKey, eigentuemer.mlKemPublicKey
        );

        await expect(
            auspacken(pack, jemandAnders.x25519PrivateKey, jemandAnders.mlKemPrivateKey)
        ).rejects.toThrow();
    });
});
