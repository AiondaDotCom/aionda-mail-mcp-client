/**
 * Postfach-Schlüsselwechsel: Fingerabdruck, Wechselakte, Einrichtungsakte
 * und Seed-AAD byte-genau gegen die KAT-Fixture `kat/fixtures/key_transition.json`,
 * gegen die auch Web, PHP und Apple geprüft werden. Dazu die Grenzen der
 * Eingabeprüfung.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import {
    FINGERPRINT_DOMAIN, TRANSITION_REASON, TRANSITION_REASON_NAMES, fingerprintFull, fingerprintPreimage,
    formatFingerprint, installRecord, normalizeLogin, seedAad, transitionRecord, type TransitionReason,
} from '../../src/crypto/key-transition';
import { fromHex, toHex } from '../../src/crypto/encoding';

interface Fixture {
    material: { seed_aad: string; seed_aad_utf8: string };
    fingerprints: { name: string; x25519_public: string; mlkem_public: string; signing_public: string | null; preimage: string; full: string; display: string }[];
    cases: {
        name: string; anlass: number; login: string; old_x25519_public: string; old_mlkem_public: string; old_signing_public: string | null;
        old_fingerprint_preimage: string; old_fingerprint_full: string; old_fingerprint_display: string;
        new_x25519_public: string; new_mlkem_public: string; new_signing_public: string; signed_at: number; record: string;
    }[];
    install_cases: {
        name: string; login: string; nonce: string; shared_secret: string; current_x25519_public: string; current_mlkem_public: string;
        current_signing_public: string | null; current_fingerprint_full: string; new_signing_public: string; record: string;
    }[];
}

const fixture = JSON.parse(readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '../../kat/fixtures/key_transition.json'), 'utf8'
)) as Fixture;
const opt = (h: string | null): Uint8Array | null => (h === null ? null : fromHex(h));

describe('Fingerabdruck v2 (KAT)', () => {
    it.each(fixture.fingerprints.map(f => [f.name, f] as const))('%s', async (_n, f) => {
        const x = fromHex(f.x25519_public);
        const m = fromHex(f.mlkem_public);
        const s = opt(f.signing_public);
        expect(toHex(fingerprintPreimage(x, m, s))).toBe(f.preimage);
        const full = await fingerprintFull(x, m, s);
        expect(toHex(full)).toBe(f.full);
        expect(formatFingerprint(full)).toBe(f.display);
    });

    it('beginnt mit der Domäne; „kein Signierschlüssel“ ist eine eigene Aussage (u32 0)', () => {
        const f = fixture.fingerprints.find(x => x.signing_public === null)!;
        const pre = fingerprintPreimage(fromHex(f.x25519_public), fromHex(f.mlkem_public), null);
        expect(new TextDecoder().decode(pre.slice(0, FINGERPRINT_DOMAIN.length))).toBe(FINGERPRINT_DOMAIN);
        expect(toHex(pre.slice(-4))).toBe('00000000');
    });
});

describe('Wechselakte (KAT)', () => {
    it.each(fixture.cases.map(c => [c.name, c] as const))('%s', async (_n, c) => {
        const oldFp = await fingerprintFull(fromHex(c.old_x25519_public), fromHex(c.old_mlkem_public), opt(c.old_signing_public));
        expect(toHex(fingerprintPreimage(fromHex(c.old_x25519_public), fromHex(c.old_mlkem_public), opt(c.old_signing_public)))).toBe(c.old_fingerprint_preimage);
        expect(toHex(oldFp)).toBe(c.old_fingerprint_full);
        expect(formatFingerprint(oldFp)).toBe(c.old_fingerprint_display);

        const record = transitionRecord({
            reason: c.anlass as TransitionReason, login: c.login, oldFingerprint: oldFp,
            newX25519PublicKey: fromHex(c.new_x25519_public), newMlkemPublicKey: fromHex(c.new_mlkem_public),
            newSigningPublicKey: fromHex(c.new_signing_public), signedAt: c.signed_at,
        });
        expect(toHex(record)).toBe(c.record);
        expect(record.length).toBe(3635 + c.login.length);
    });
});

describe('Einrichtungsakte und Seed-AAD (KAT)', () => {
    it.each(fixture.install_cases.map(c => [c.name, c] as const))('%s', async (_n, c) => {
        const fp = await fingerprintFull(fromHex(c.current_x25519_public), fromHex(c.current_mlkem_public), opt(c.current_signing_public));
        expect(toHex(fp)).toBe(c.current_fingerprint_full);
        const record = installRecord({
            login: c.login, nonce: fromHex(c.nonce), sharedSecret: fromHex(c.shared_secret),
            currentFingerprint: fp, newSigningPublicKey: fromHex(c.new_signing_public),
        });
        expect(toHex(record)).toBe(c.record);
        expect(record.length).toBe(2098 + c.login.length);
    });

    it('seedAad', () => {
        const login = fixture.cases[0].login;
        expect(toHex(seedAad(login))).toBe(fixture.material.seed_aad);
    });
});

describe('Eingabeprüfung', () => {
    const base = fixture.cases[0];
    const input = () => ({
        reason: 1 as TransitionReason, login: base.login, oldFingerprint: new Uint8Array(32),
        newX25519PublicKey: fromHex(base.new_x25519_public), newMlkemPublicKey: fromHex(base.new_mlkem_public),
        newSigningPublicKey: fromHex(base.new_signing_public), signedAt: base.signed_at,
    });

    it('normalizeLogin: nur ASCII-Großbuchstaben und Randleerraum', () => {
        expect(normalizeLogin('  Max.MUSTER \t')).toBe('max.muster');
        expect(normalizeLogin('ÄÖÜ')).toBe('ÄÖÜ');
    });

    it('Anlass-Namen passen zu den Werten', () => {
        for (const [name, value] of Object.entries(TRANSITION_REASON)) {
            expect(TRANSITION_REASON_NAMES[value as TransitionReason]).toBe(name);
        }
    });

    it('falsche Längen, leerer Login, unbekannter Anlass, Zahlenbereich: laute Fehler', () => {
        expect(() => fingerprintPreimage(new Uint8Array(31), new Uint8Array(1568), null)).toThrow('x25519PublicKey muss 32 Byte haben, hat 31');
        expect(() => fingerprintPreimage(new Uint8Array(32), new Uint8Array(10), null)).toThrow('mlkemPublicKey muss 1568 Byte haben');
        expect(() => fingerprintPreimage(new Uint8Array(32), new Uint8Array(1568), new Uint8Array(5))).toThrow('signingPublicKey muss 1952 Byte haben');
        expect(() => fingerprintPreimage('x' as never, new Uint8Array(1568), null)).toThrow('hat 1');
        expect(() => formatFingerprint(new Uint8Array(16))).toThrow('fingerprint muss 32 Byte haben');

        expect(() => transitionRecord({ ...input(), reason: 9 as TransitionReason })).toThrow('unbekannter Anlass 9');
        expect(() => transitionRecord({ ...input(), login: '' })).toThrow('login ist leer');
        expect(() => transitionRecord({ ...input(), oldFingerprint: new Uint8Array(1) })).toThrow('oldFingerprint muss 32 Byte haben');
        expect(() => transitionRecord({ ...input(), signedAt: -1 })).toThrow('u64 ausserhalb des Bereichs: -1');
        expect(() => transitionRecord({ ...input(), signedAt: 1.5 })).toThrow('u64 ausserhalb des Bereichs');
        expect(() => transitionRecord({ ...input(), login: 'a'.repeat(0x10000) })).toThrow('u16 ausserhalb des Bereichs: 65536');

        const inst = { login: 'a', nonce: new Uint8Array(32), sharedSecret: new Uint8Array(32), currentFingerprint: new Uint8Array(32), newSigningPublicKey: new Uint8Array(1952) };
        expect(installRecord(inst).length).toBe(2099);
        expect(() => installRecord({ ...inst, login: '' })).toThrow('login ist leer');
        expect(() => installRecord({ ...inst, nonce: new Uint8Array(31) })).toThrow('nonce muss 32 Byte haben');
        expect(() => installRecord({ ...inst, sharedSecret: new Uint8Array(0) })).toThrow('sharedSecret muss 32 Byte haben');
        expect(() => seedAad('a'.repeat(0x10000))).toThrow('u16 ausserhalb des Bereichs');
    });
});
