/**
 * Deterministische Zufallsinjektion für den KAT-Generator.
 *
 * Der Generator ruft die ECHTEN Krypto-Funktionen aus src/crypto/ auf. Wo diese
 * intern Zufall ziehen (crypto.getRandomValues, subtle.generateKey), wird der
 * Zufall hier von außen vorgegeben, damit die erzeugten Vektoren reproduzierbar
 * sind. Es wird KEINE Krypto-Logik nachgebaut.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */
import { createHash, createPrivateKey, createPublicKey, webcrypto } from 'node:crypto';

/** PKCS#8-Präambel für rohe X25519-Private-Keys (RFC 8410). */
const X25519_PKCS8_HEADER = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x6e,
    0x04, 0x22,
    0x04, 0x20,
]);

/**
 * Reproduzierbarer Byte-Strom: SHA-256(label || counter) aneinandergehängt.
 * Bewusst simpel gehalten - das ist reines Testmaterial, keine Produktivkrypto.
 */
export class SeededStream {
    private counter = 0;

    constructor(private readonly label: string) {}

    bytes(length: number): Uint8Array {
        const out = new Uint8Array(length);
        let offset = 0;
        while (offset < length) {
            const block = createHash('sha256')
                .update(this.label)
                .update(Buffer.from([
                    (this.counter >>> 24) & 0xff,
                    (this.counter >>> 16) & 0xff,
                    (this.counter >>> 8) & 0xff,
                    this.counter & 0xff,
                ]))
                .digest();
            this.counter += 1;
            const take = Math.min(block.length, length - offset);
            out.set(block.subarray(0, take), offset);
            offset += take;
        }
        return out;
    }
}

type RandomFn = <T extends ArrayBufferView | null>(array: T) => T;

const realGetRandomValues = webcrypto.getRandomValues.bind(webcrypto) as RandomFn;
const realGenerateKey = webcrypto.subtle.generateKey.bind(webcrypto.subtle);

/** Exakte Werte, die die nächsten getRandomValues-Aufrufe liefern sollen. */
let scriptedRandom: Uint8Array[] = [];
/** Fallback-Strom, wenn kein Skript mehr vorliegt. */
let fallbackStream: SeededStream | null = null;
/** Nächster X25519-Private-Key, den subtle.generateKey liefern soll. */
let scriptedX25519Private: Uint8Array | null = null;
let installed = false;

/**
 * Hängt die deterministischen Quellen in das globale WebCrypto-Objekt.
 * webcrypto === globalThis.crypto in Node, deshalb deckt ein Patch beide ab
 * (auch @noble/post-quantum zieht seinen Zufall darüber).
 */
export function installDeterministicRandom(seedLabel: string): void {
    if (installed) { return; }
    installed = true;
    fallbackStream = new SeededStream(seedLabel);

    Object.defineProperty(webcrypto, 'getRandomValues', {
        configurable: true,
        writable: true,
        value: <T extends ArrayBufferView | null>(array: T): T => {
            if (array === null) { return array; }
            const view = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);

            const scripted = scriptedRandom.shift();
            if (scripted) {
                if (scripted.length !== view.length) {
                    throw new Error(
                        `Skriptierter Zufall passt nicht: erwartet ${view.length} Byte, vorgegeben ${scripted.length}`
                    );
                }
                view.set(scripted);
                return array;
            }

            if (fallbackStream) {
                view.set(fallbackStream.bytes(view.length));
                return array;
            }
            return realGetRandomValues(array);
        },
    });

    Object.defineProperty(webcrypto.subtle, 'generateKey', {
        configurable: true,
        writable: true,
        value: async (
            algorithm: Parameters<typeof realGenerateKey>[0],
            extractable: boolean,
            usages: Parameters<typeof realGenerateKey>[2]
        ) => {
            const name = typeof algorithm === 'string' ? algorithm : algorithm.name;
            if (name === 'X25519' && scriptedX25519Private) {
                const priv = scriptedX25519Private;
                scriptedX25519Private = null;
                return importX25519KeyPair(priv);
            }
            return realGenerateKey(algorithm, extractable, usages);
        },
    });
}

/** Entfernt die Patches wieder (für die vitest-Spec, die echte Krypto testet). */
export function uninstallDeterministicRandom(): void {
    if (!installed) { return; }
    installed = false;
    scriptedRandom = [];
    fallbackStream = null;
    scriptedX25519Private = null;
    Object.defineProperty(webcrypto, 'getRandomValues', {
        configurable: true, writable: true, value: realGetRandomValues,
    });
    Object.defineProperty(webcrypto.subtle, 'generateKey', {
        configurable: true, writable: true, value: realGenerateKey,
    });
}

/**
 * Führt fn aus, wobei die getRandomValues-Aufrufe der Reihe nach genau die
 * übergebenen Werte liefern.
 */
export async function withScriptedRandom<T>(values: Uint8Array[], fn: () => Promise<T>): Promise<T> {
    scriptedRandom = [...values];
    try {
        return await fn();
    } finally {
        scriptedRandom = [];
    }
}

/** Gibt den ephemeren X25519-Private-Key vor, den der nächste generateKey liefert. */
export function scriptNextX25519Ephemeral(privateKey: Uint8Array): void {
    scriptedX25519Private = privateKey;
}

/** Baut die PKCS#8-DER-Kodierung eines rohen X25519-Private-Keys. */
export function x25519Pkcs8(privateKey: Uint8Array): Uint8Array {
    const pkcs8 = new Uint8Array(X25519_PKCS8_HEADER.length + privateKey.length);
    pkcs8.set(X25519_PKCS8_HEADER, 0);
    pkcs8.set(privateKey, X25519_PKCS8_HEADER.length);
    return pkcs8;
}

/** Leitet den öffentlichen X25519-Key aus dem privaten ab (nur Node-Bordmittel). */
export function x25519PublicFromPrivate(privateKey: Uint8Array): Uint8Array {
    const keyObject = createPrivateKey({
        key: Buffer.from(x25519Pkcs8(privateKey)),
        format: 'der',
        type: 'pkcs8',
    });
    const spki = createPublicKey(keyObject).export({ format: 'der', type: 'spki' });
    return new Uint8Array(spki.subarray(spki.length - 32));
}

/** Importiert ein X25519-Schlüsselpaar aus dem rohen Private-Key. */
async function importX25519KeyPair(privateKey: Uint8Array): Promise<webcrypto.CryptoKeyPair> {
    const priv = await webcrypto.subtle.importKey(
        'pkcs8', x25519Pkcs8(privateKey), { name: 'X25519' }, true, ['deriveBits']
    );
    const pub = await webcrypto.subtle.importKey(
        'raw', x25519PublicFromPrivate(privateKey), { name: 'X25519' }, true, []
    );
    return { privateKey: priv, publicKey: pub } as webcrypto.CryptoKeyPair;
}
