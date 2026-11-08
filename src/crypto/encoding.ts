/**
 * Hex/Base64 ↔ Uint8Array encoding utilities
 */

export function fromHex(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

export function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

export function fromBase64(base64: string): Uint8Array {
    let normalized = base64
        .replace(/\s/g, '')
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    while (normalized.length % 4 !== 0) {
        normalized += '=';
    }
    return Uint8Array.from(Buffer.from(normalized, 'base64'));
}

export function toBase64(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64');
}
