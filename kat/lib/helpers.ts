/**
 * Kleine Bausteine für den KAT-Generator.
 *
 * Hier steht bewusst NUR Testmaterial-Konstruktion (Padding aufbauen, gzip
 * packen, Bytes zusammenschieben). Die eigentliche Krypto kommt immer aus
 * src/crypto/ bzw. direkt aus WebCrypto.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */
import { webcrypto } from 'node:crypto';

/** Buckets aus src/crypto/bucket-padding.ts - hier nur zum Aufbauen. */
const PADDING_BUCKETS = [
    256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216,
];

/** Hängt Uint8Arrays aneinander. */
export function concat(...parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

/** UTF-8-Bytes eines Strings. */
export function utf8(value: string): Uint8Array {
    return new TextEncoder().encode(value);
}

/** CRC-32 nach ISO 3309, wie im gzip-Trailer vorgeschrieben. */
function crc32(data: Uint8Array): number {
    let crc = 0xffffffff;
    for (const byte of data) {
        crc ^= byte;
        for (let bit = 0; bit < 8; bit++) {
            crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
        }
    }
    return (crc ^ 0xffffffff) >>> 0;
}

function littleEndian32(value: number): Uint8Array {
    return new Uint8Array([
        value & 0xff,
        (value >>> 8) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 24) & 0xff,
    ]);
}

/**
 * Kanonisches gzip mit ungepackten DEFLATE-Blöcken.
 *
 * Die Kompressionsheuristik von zlib ist nicht Teil des gzip-Formats und hat
 * zwischen den auf macOS unterstützten Node-Versionen unterschiedliche, aber
 * gültige Bytes erzeugt. Für eine KAT muss die Darstellung selbst feststehen.
 * Ungepackte Blöcke sind vollständig spezifiziert, plattformunabhängig und
 * prüfen denselben produktiven gzip-Lesepfad.
 */
export function gzip(data: Uint8Array): Uint8Array {
    const blocks: Uint8Array[] = [];
    if (data.length === 0) {
        blocks.push(new Uint8Array([0x01, 0x00, 0x00, 0xff, 0xff]));
    } else {
        for (let offset = 0; offset < data.length; offset += 0xffff) {
            const length = Math.min(0xffff, data.length - offset);
            const complement = (~length) & 0xffff;
            const final = offset + length === data.length ? 0x01 : 0x00;
            blocks.push(new Uint8Array([
                final,
                length & 0xff,
                (length >>> 8) & 0xff,
                complement & 0xff,
                (complement >>> 8) & 0xff,
            ]));
            blocks.push(data.slice(offset, offset + length));
        }
    }

    return concat(
        // ID1, ID2, CM=DEFLATE, FLG=0, MTIME=0, XFL=0, OS=unbekannt.
        new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]),
        ...blocks,
        littleEndian32(crc32(data)),
        littleEndian32(data.length >>> 0)
    );
}

/**
 * Baut Bucket-Padding auf: 0xDE 0xAD || len(4, big endian) || data || Füllbytes.
 * Gegenstück zu unpadFromBucket() aus src/crypto/bucket-padding.ts.
 */
export function padToBucket(data: Uint8Array, filler: Uint8Array): Uint8Array {
    const needed = data.length + 6;
    const bucket = PADDING_BUCKETS.find(size => size >= needed);
    if (bucket === undefined) {
        throw new Error(`Kein Bucket für ${needed} Byte`);
    }

    const out = new Uint8Array(bucket);
    out[0] = 0xde;
    out[1] = 0xad;
    out[2] = (data.length >>> 24) & 0xff;
    out[3] = (data.length >>> 16) & 0xff;
    out[4] = (data.length >>> 8) & 0xff;
    out[5] = data.length & 0xff;
    out.set(data, 6);
    for (let i = 6 + data.length; i < bucket; i++) {
        out[i] = filler[i % filler.length];
    }
    return out;
}

/**
 * AES-256-GCM-Primitive direkt aus WebCrypto: Ergebnis ist ciphertext || tag.
 * Wird nur genutzt, um Fixture-Eingaben zu ERZEUGEN; geprüft wird jede davon
 * anschließend mit den echten Entschlüsselungsfunktionen aus src/crypto/.
 */
export async function aesGcmEncryptRaw(
    plaintext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array
): Promise<Uint8Array> {
    const aesKey = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
    return new Uint8Array(ciphertext);
}

/** HKDF-SHA-256 -> rohe Bytes (identische Parameter wie die deriveKey-Aufrufe im Produktivcode). */
export async function hkdfBits(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    lengthBits = 256
): Promise<Uint8Array> {
    const keyMaterial = await webcrypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await webcrypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt, info },
        keyMaterial,
        lengthBits
    );
    return new Uint8Array(bits);
}

/** SHA-256 über beliebige Bytes. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await webcrypto.subtle.digest('SHA-256', data));
}

/**
 * Baut einen gewrappten Key im Layout version(1) || salt(32) || iv(12) || ct+tag
 * mit frei wählbarem HKDF-Label. Wird für die Dual-Read- und Negativ-Fälle
 * gebraucht, die der Produktivcode selbst nicht schreiben kann.
 */
export async function wrapWithLabel(
    payload: Uint8Array,
    masterKey: Uint8Array,
    salt: Uint8Array,
    iv: Uint8Array,
    label: string,
    version = 0x02
): Promise<Uint8Array> {
    const wrapKey = await hkdfBits(masterKey, salt, utf8(label));
    const ciphertext = await aesGcmEncryptRaw(payload, wrapKey, iv);
    return concat(new Uint8Array([version]), salt, iv, ciphertext);
}
