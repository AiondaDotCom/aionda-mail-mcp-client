/**
 * RFC 2047 MIME Encoded-Word Decoder
 */

function decodeCharset(binaryStr: string, charset: string): string {
    const normalizedCharset = charset.toLowerCase().replace(/[_-]/g, '');

    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
    }

    if (normalizedCharset === 'utf8') {
        return new TextDecoder('utf-8').decode(bytes);
    } else if (normalizedCharset === 'iso88591' || normalizedCharset === 'latin1') {
        return binaryStr;
    } else {
        try {
            return new TextDecoder(charset).decode(bytes);
        } catch {
            return binaryStr;
        }
    }
}

/**
 * Decode MIME encoded-word format (RFC 2047)
 *
 * Handles:
 * - =?charset?B?base64data?=  (Base64 encoding)
 * - =?charset?Q?quotedprintable?=  (Quoted-Printable encoding)
 */
export function decodeMimeEncodedWords(str: string): string {
    if (!str) return str;

    const encodedWordPattern = /=\?([^?]+)\?([BQ])\?([^?]*)\?=/gi;

    return str.replace(encodedWordPattern, (match, charset: string, encoding: string, data: string) => {
        try {
            const enc = encoding.toUpperCase();

            if (enc === 'B') {
                const decoded = Buffer.from(data, 'base64').toString('binary');
                return decodeCharset(decoded, charset);
            } else if (enc === 'Q') {
                const normalized = data.replace(/_/g, ' ');
                const decoded = normalized.replace(
                    /=([0-9A-Fa-f]{2})/g,
                    (_: string, hex: string) => String.fromCharCode(parseInt(hex, 16))
                );
                return decodeCharset(decoded, charset);
            }

            return match;
        } catch {
            return match;
        }
    });
}

/**
 * Extract Message-ID from raw email headers
 */
export function extractMessageId(headers: string | null | undefined): string | null {
    if (!headers) return null;
    const unfolded = headers.replace(/\r?\n[ \t]+/g, ' ');
    const match = unfolded.match(/^Message-ID:\s*<?([^>\r\n]+)>?\s*$/im);
    return match?.[1]?.trim() ?? null;
}

/**
 * Extract Reply-To from raw email headers
 */
export function extractReplyTo(headers: string | null | undefined): string | null {
    if (!headers) return null;
    const unfolded = headers.replace(/\r?\n[ \t]+/g, ' ');
    const match = unfolded.match(/^Reply-To:\s*(.+?)\s*$/im);
    return match?.[1]?.trim() ?? null;
}
