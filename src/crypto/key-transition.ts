/**
 * Postfach-Schlüsselwechsel: Fingerabdruck v2, Wechselakte, Einrichtungsakte,
 * Seed-AAD.
 *
 * Vertrag: docs/VAULT_SCHLUESSELWECHSEL_SIGNATUR.md (#658912ef, v2), Abschnitt 3.
 * Diese Datei ist die Quelle der KAT-Fixture `kat/fixtures/key_transition.json`,
 * gegen die Web (schluesselwechsel-signatur.ts), PHP
 * (VaultSchluesselwechselService) und Apple byte-genau geprüft werden.
 *
 * Reine Byte-Arbeit. Signiert wird mit ML-DSA-65 ausserhalb dieser Datei.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */

import { webcrypto } from 'node:crypto';

/** Vertrag 3.1 - v2: KEM UND Signierschlüssel. v1 (nur KEM) ist ausser Kraft. */
export const FINGERPRINT_DOMAIN = 'aionda-postfachschluessel-fingerabdruck-v2';

/** Vertrag 3.2 - Kopf der Wechselakte, ASCII ohne Längenfeld. */
export const TRANSITION_TAG = 'aionda-vault-schluesselwechsel-v1';
export const TRANSITION_VERSION = 1;
/** Vertrag 3.2 - FIPS-204-Kontext der Signatur über die Wechselakte. */
export const TRANSITION_CONTEXT = 'aionda-vault-schluesselwechsel-sig-v1';

/** Vertrag 3.3 - Einrichtungsakte (Nachweis des Master Keys). */
export const INSTALL_TAG = 'aionda-vault-signierschluessel-einrichtung-v1';
export const INSTALL_VERSION = 1;
export const INSTALL_CONTEXT = 'aionda-vault-signierschluessel-einrichtung-sig-v1';

/** Vertrag 3.4 - AAD-Kopf des Seed-Chiffrats. */
export const SEED_AAD_TAG = 'aionda-vault-signierschluessel-seed-v1';

export const X25519_PUBLIC_BYTES = 32;
export const MLKEM_PUBLIC_BYTES = 1568;
export const MLDSA65_PUBLIC_BYTES = 1952;
export const MLDSA65_SIGNATURE_BYTES = 3309;
export const FINGERPRINT_BYTES = 32;
export const CHALLENGE_NONCE_BYTES = 32;
export const CHALLENGE_SECRET_BYTES = 32;

/** Vertrag 3.2 - `anlass`-Byte. */
export const TRANSITION_REASON = {
    rotation: 1,
    signierschluessel: 2,
    setup: 3,
} as const;

export type TransitionReason = (typeof TRANSITION_REASON)[keyof typeof TRANSITION_REASON];

export const TRANSITION_REASON_NAMES: Record<TransitionReason, keyof typeof TRANSITION_REASON> = {
    1: 'rotation',
    2: 'signierschluessel',
    3: 'setup',
};

export interface TransitionRecordInput {
    reason: TransitionReason;
    /** Anmeldename in Aktenform (`normalizeLogin`). */
    login: string;
    /** Fingerabdruck v2 des Satzes VOR dem Wechsel (32 B). */
    oldFingerprint: Uint8Array;
    newX25519PublicKey: Uint8Array;
    newMlkemPublicKey: Uint8Array;
    newSigningPublicKey: Uint8Array;
    /** Unix-Sekunden. */
    signedAt: number;
}

export interface InstallRecordInput {
    login: string;
    /** Nonce der Challenge (32 B). */
    nonce: Uint8Array;
    /** Shared Secret aus der Hybrid-KEM-Decapsulation (32 B). */
    sharedSecret: Uint8Array;
    /** Fingerabdruck v2 des AKTUELLEN Satzes (32 B). */
    currentFingerprint: Uint8Array;
    newSigningPublicKey: Uint8Array;
}

function expectLength(name: string, value: Uint8Array, length: number): void {
    if (!(value instanceof Uint8Array) || value.length !== length) {
        throw new Error(`key-transition: ${name} muss ${length} Byte haben, hat ${value?.length ?? 'kein Uint8Array'}`);
    }
}

function u16(value: number): Uint8Array {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
        throw new Error(`key-transition: u16 ausserhalb des Bereichs: ${value}`);
    }
    return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function u32(value: number): Uint8Array {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
        throw new Error(`key-transition: u32 ausserhalb des Bereichs: ${value}`);
    }
    return new Uint8Array([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

function u64(value: number): Uint8Array {
    if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
        throw new Error(`key-transition: u64 ausserhalb des Bereichs: ${value}`);
    }
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
    return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

const ascii = (text: string): Uint8Array => new TextEncoder().encode(text);

/**
 * Anmeldename in Aktenform: ASCII-Leerraum an den Enden weg, A-Z → a-z,
 * sonst nichts (keine Unicode-Faltung).
 */
export function normalizeLogin(login: string): string {
    return login.trim().replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

/**
 * Vertrag 3.1 (v2): `domain || u32 len || x25519 || u32 len || mlkem || u32 len || sig_pk`.
 * `signingPublicKey === null` → `u32 0` ohne Bytes: „kein Signierschlüssel" ist
 * eine eigene Aussage, keine Auslassung.
 */
export function fingerprintPreimage(
    x25519PublicKey: Uint8Array,
    mlkemPublicKey: Uint8Array,
    signingPublicKey: Uint8Array | null,
): Uint8Array {
    expectLength('x25519PublicKey', x25519PublicKey, X25519_PUBLIC_BYTES);
    expectLength('mlkemPublicKey', mlkemPublicKey, MLKEM_PUBLIC_BYTES);
    const sig = signingPublicKey ?? new Uint8Array(0);
    if (sig.length !== 0) {
        expectLength('signingPublicKey', sig, MLDSA65_PUBLIC_BYTES);
    }
    return concatBytes(
        ascii(FINGERPRINT_DOMAIN),
        u32(x25519PublicKey.length), x25519PublicKey,
        u32(mlkemPublicKey.length), mlkemPublicKey,
        u32(sig.length), sig,
    );
}

/** Vertrag 3.1: SHA-256 des Preimage, 32 Byte - so steht er in den Akten. */
export async function fingerprintFull(
    x25519PublicKey: Uint8Array,
    mlkemPublicKey: Uint8Array,
    signingPublicKey: Uint8Array | null,
): Promise<Uint8Array> {
    const digest = await webcrypto.subtle.digest(
        'SHA-256',
        fingerprintPreimage(x25519PublicKey, mlkemPublicKey, signingPublicKey),
    );
    return new Uint8Array(digest);
}

/**
 * Die Form, die zwei Menschen am Telefon vergleichen: erste 16 Byte,
 * Großbuchstaben-Hex, Vierergruppen mit Bindestrich.
 */
export function formatFingerprint(full: Uint8Array): string {
    expectLength('fingerprint', full, FINGERPRINT_BYTES);
    const hex = Array.from(full.subarray(0, 16), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return hex.match(/.{1,4}/g)?.join('-') ?? hex;
}

/** Vertrag 3.2: die kanonische Bytefolge, über die signiert wird (3635 + len(login) Byte). */
export function transitionRecord(input: TransitionRecordInput): Uint8Array {
    if (!(input.reason in TRANSITION_REASON_NAMES)) {
        throw new Error(`key-transition: unbekannter Anlass ${input.reason}`);
    }
    const login = ascii(input.login);
    if (login.length === 0) {
        throw new Error('key-transition: login ist leer');
    }
    expectLength('oldFingerprint', input.oldFingerprint, FINGERPRINT_BYTES);
    expectLength('newX25519PublicKey', input.newX25519PublicKey, X25519_PUBLIC_BYTES);
    expectLength('newMlkemPublicKey', input.newMlkemPublicKey, MLKEM_PUBLIC_BYTES);
    expectLength('newSigningPublicKey', input.newSigningPublicKey, MLDSA65_PUBLIC_BYTES);

    return concatBytes(
        ascii(TRANSITION_TAG),
        new Uint8Array([TRANSITION_VERSION]),
        new Uint8Array([input.reason]),
        u16(login.length), login,
        input.oldFingerprint,
        u16(input.newX25519PublicKey.length), input.newX25519PublicKey,
        u16(input.newMlkemPublicKey.length), input.newMlkemPublicKey,
        u16(input.newSigningPublicKey.length), input.newSigningPublicKey,
        u64(input.signedAt),
    );
}

/** Vertrag 3.3: die Einrichtungsakte (2098 + len(login) Byte), signiert vom NEUEN Signierschlüssel. */
export function installRecord(input: InstallRecordInput): Uint8Array {
    const login = ascii(input.login);
    if (login.length === 0) {
        throw new Error('key-transition: login ist leer');
    }
    expectLength('nonce', input.nonce, CHALLENGE_NONCE_BYTES);
    expectLength('sharedSecret', input.sharedSecret, CHALLENGE_SECRET_BYTES);
    expectLength('currentFingerprint', input.currentFingerprint, FINGERPRINT_BYTES);
    expectLength('newSigningPublicKey', input.newSigningPublicKey, MLDSA65_PUBLIC_BYTES);

    return concatBytes(
        ascii(INSTALL_TAG),
        new Uint8Array([INSTALL_VERSION]),
        u16(login.length), login,
        input.nonce,
        input.sharedSecret,
        input.currentFingerprint,
        u16(input.newSigningPublicKey.length), input.newSigningPublicKey,
    );
}

/** Vertrag 3.4: AAD des Seed-Chiffrats = Kopf || u16 len || login. */
export function seedAad(login: string): Uint8Array {
    const bytes = ascii(login);
    return concatBytes(ascii(SEED_AAD_TAG), u16(bytes.length), bytes);
}
