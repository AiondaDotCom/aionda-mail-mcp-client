/**
 * AiondaEventClient: echte, für das eigene Postfach gekapselte Ereignisse
 * (Hybrid-KEM + AES-GCM im PHP-Layout, wahlweise gzip) kommen entschlüsselt
 * bei den Handlern an – live über den Ereignisstrom und nachgeholt über
 * get_missed_events. Dazu Wiederverbinden mit Rückfallzeit.
 */
import { gzipSync } from 'node:zlib';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { AiondaEventClient } from '../src/events';
import { toBase64 } from '../src/crypto/encoding';
import { hybridEncapsulate } from '../src/crypto/hybrid-kem';
import type { AiondaMailClient } from '../src/client';
import { aesGcmRaw, makeVault, rnd, utf8, type Vault } from './helpers/vault';

class FakeEventSource {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSED = 2;
    static instances: FakeEventSource[] = [];
    readyState = 0;
    onmessage: ((e: { data: string; lastEventId: string }) => Promise<void>) | null = null;
    onerror: (() => void) | null = null;
    onopen: (() => void) | null = null;
    closed = false;
    constructor(public url: string) { FakeEventSource.instances.push(this); }
    close(): void { this.closed = true; this.readyState = 2; }
}

let vault: Vault;
beforeAll(async () => { vault = await makeVault(); });

/** Ereignis so verschlüsseln, wie der Server es an Mercure gibt. */
async function encryptEvent(target: Vault, body: unknown, opts: { gzip?: boolean } = {}) {
    const kem = await hybridEncapsulate(target.publicKeys.x25519, target.publicKeys.mlkem);
    const nonce = rnd(12);
    const plain = utf8(JSON.stringify(body));
    const ctTag = await aesGcmRaw(kem.sharedSecret, nonce, opts.gzip ? new Uint8Array(gzipSync(plain)) : plain);
    return {
        x25519_ephemeral: toBase64(kem.x25519Ciphertext),
        mlkem_ciphertext: toBase64(new Uint8Array(kem.mlKemCiphertext)),
        encrypted: toBase64(new Uint8Array([...nonce, ...ctTag.slice(-16), ...ctTag.slice(0, -16)])),
        timestamp: 1700000000,
    };
}

function mailClient(missed: unknown[] = []) {
    const callTool = vi.fn(async (name: string) => {
        if (name === 'event_subscribe') {
            return { data: {
                subscription_id: 'sub', mercure_url: 'https://hub.example/.well-known/mercure',
                subscriber_jwt: 'jwt.token', topics: ['email.received.15849', 'notification.new.15849'],
            } };
        }
        return { data: { events: missed } };
    });
    return { client: { callTool } as unknown as AiondaMailClient, callTool };
}

beforeEach(() => {
    FakeEventSource.instances = [];
    vi.stubGlobal('EventSource', FakeEventSource);
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

describe('Live-Ereignisse', () => {
    it('öffnet den Strom mit Themen und JWT und reicht entschlüsselte Ereignisse an die Handler', async () => {
        const { client, callTool } = mailClient();
        const events = new AiondaEventClient(client, vault.privateKeys);
        const received: unknown[] = [];
        const kaputt = vi.fn(() => { throw new Error('Handlerfehler'); });
        events.on('email.received', kaputt);
        events.on('email.received', e => received.push(e));

        await events.connect(['email.received', 'notification.new']);

        expect(callTool).toHaveBeenCalledWith('event_subscribe', { topics: ['email.received', 'notification.new'] });
        const es = FakeEventSource.instances[0];
        const url = new URL(es.url);
        expect(url.origin + url.pathname).toBe('https://hub.example/.well-known/mercure');
        expect(url.searchParams.getAll('topic')).toEqual(['email.received.15849', 'notification.new.15849']);
        expect(url.searchParams.get('authorization')).toBe('jwt.token');
        expect(url.searchParams.has('Last-Event-ID')).toBe(false);

        const payload = await encryptEvent(vault, { type: 'email.received', data: { email_uuid: 'm1' }, event_id: 'ev-1' }, { gzip: true });
        await es.onmessage!({ data: JSON.stringify(payload), lastEventId: 'ev-1' });

        expect(kaputt).toHaveBeenCalledTimes(1);
        expect(received).toEqual([{ type: 'email.received', data: { email_uuid: 'm1' }, timestamp: 1700000000, eventId: 'ev-1' }]);

        es.readyState = FakeEventSource.OPEN;
        expect(events.connected).toBe(true);
        events.disconnect();
        expect(es.closed).toBe(true);
        expect(events.connected).toBe(false);
    });

    it('Ereignis ohne data-Hülle, fremder Schlüssel, kein JSON, unbekannter Typ: nichts kommt beim Handler an außer dem gültigen', async () => {
        const { client } = mailClient();
        const events = new AiondaEventClient(client, vault.privateKeys);
        const handler = vi.fn();
        events.on('notification.new', handler);
        await events.connect(['notification.new']);
        const es = FakeEventSource.instances[0];

        await es.onmessage!({ data: JSON.stringify(await encryptEvent(await makeVault(), { type: 'notification.new' })), lastEventId: '' });
        await es.onmessage!({ data: 'kein json', lastEventId: '' });
        await es.onmessage!({ data: JSON.stringify(await encryptEvent(vault, { type: 'calendar.changed' })), lastEventId: '' });
        await es.onmessage!({ data: JSON.stringify(await encryptEvent(vault, { type: 'notification.new', title: 'Hallo' })), lastEventId: '' });

        expect(handler).toHaveBeenCalledTimes(1);
        expect(handler.mock.calls[0][0]).toMatchObject({ type: 'notification.new', data: { type: 'notification.new', title: 'Hallo' } });

        events.off('notification.new', handler);
        await es.onmessage!({ data: JSON.stringify(await encryptEvent(vault, { type: 'notification.new' })), lastEventId: '' });
        expect(handler).toHaveBeenCalledTimes(1);
    });
});

describe('Nachholen und Wiederverbinden', () => {
    it('fetchMissedEvents: entschlüsselt, was geht, überspringt den Rest, reicht an die Handler', async () => {
        const ok = await encryptEvent(vault, { type: 'email.received', data: { email_uuid: 'm2' }, event_id: 'ev-2' });
        const fremd = await encryptEvent(await makeVault(), { type: 'email.received' });
        const { client, callTool } = mailClient([ok, fremd]);
        const events = new AiondaEventClient(client, vault.privateKeys, { missedEventsLimit: 7 });
        const handler = vi.fn();
        events.on('email.received', handler);

        const out = await events.fetchMissedEvents();

        expect(callTool).toHaveBeenCalledWith('get_missed_events', { last_event_id: '', limit: 7 });
        expect(out).toEqual([{ type: 'email.received', data: { email_uuid: 'm2' }, timestamp: 1700000000, eventId: 'ev-2' }]);
        expect(handler).toHaveBeenCalledTimes(1);
    });

    it('Abbruch des Stroms: verbindet nach der Wartezeit neu, mit Last-Event-ID, und holt Verpasstes nach', async () => {
        vi.useFakeTimers();
        const { client, callTool } = mailClient();
        const events = new AiondaEventClient(client, vault.privateKeys, { reconnectDelay: 1000 });
        await events.connect(['email.received']);
        const first = FakeEventSource.instances[0];
        await first.onmessage!({ data: 'kein json', lastEventId: 'ev-9' });
        first.onopen!();

        first.onerror!();
        expect(first.closed).toBe(true);
        expect(FakeEventSource.instances).toHaveLength(1);

        await vi.advanceTimersByTimeAsync(999);
        expect(FakeEventSource.instances).toHaveLength(1);
        await vi.advanceTimersByTimeAsync(1);

        expect(FakeEventSource.instances).toHaveLength(2);
        // Themen ohne Kontonummer-Suffix, wie sie der Aufrufer angegeben hat.
        expect(callTool.mock.calls[1]).toEqual(['event_subscribe', { topics: ['email.received', 'notification.new'] }]);
        expect(new URL(FakeEventSource.instances[1].url).searchParams.get('Last-Event-ID')).toBe('ev-9');
        expect(callTool.mock.calls[2]).toEqual(['get_missed_events', { last_event_id: 'ev-9', limit: 100 }]);
        events.disconnect();
    });

    it('scheitert das Wiederverbinden, verdoppelt sich die Wartezeit bis zur Obergrenze', async () => {
        vi.useFakeTimers();
        const { client, callTool } = mailClient();
        const events = new AiondaEventClient(client, vault.privateKeys, { reconnectDelay: 100, maxReconnectDelay: 300 });
        await events.connect(['email.received']);
        callTool.mockRejectedValue(new Error('offline'));

        FakeEventSource.instances[0].onerror!();
        await vi.advanceTimersByTimeAsync(100);   // Versuch 1 scheitert → 200
        expect(callTool).toHaveBeenCalledTimes(2);
        await vi.advanceTimersByTimeAsync(199);
        expect(callTool).toHaveBeenCalledTimes(2);
        await vi.advanceTimersByTimeAsync(1);     // Versuch 2 scheitert → 300 (Obergrenze)
        expect(callTool).toHaveBeenCalledTimes(3);
        await vi.advanceTimersByTimeAsync(300);   // Versuch 3
        expect(callTool).toHaveBeenCalledTimes(4);

        events.disconnect();
        await vi.advanceTimersByTimeAsync(10_000);
        expect(callTool).toHaveBeenCalledTimes(4);
    });

    it('nach disconnect löst ein später Fehler kein Wiederverbinden aus; zweites connect während des ersten ist wirkungslos', async () => {
        vi.useFakeTimers();
        const { client, callTool } = mailClient();
        const events = new AiondaEventClient(client, vault.privateKeys, { reconnectDelay: 10 });
        const a = events.connect(['email.received']);
        const b = events.connect(['email.received']);
        await Promise.all([a, b]);
        expect(callTool).toHaveBeenCalledTimes(1);

        const es = FakeEventSource.instances[0];
        events.disconnect();
        es.onerror!();
        await vi.advanceTimersByTimeAsync(1000);
        expect(callTool).toHaveBeenCalledTimes(1);
    });
});
