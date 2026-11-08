import { describe, it, expect } from 'vitest';
import { decodeMimeEncodedWords, extractMessageId, extractReplyTo } from '../../src/crypto/mime-decoder';

describe('MIME Decoder', () => {
    it('decodes Base64 encoded word', () => {
        const input = '=?utf-8?B?SGVsbG8gV29ybGQ=?=';
        expect(decodeMimeEncodedWords(input)).toBe('Hello World');
    });

    it('decodes Quoted-Printable encoded word', () => {
        const input = '=?utf-8?Q?Hello_World?=';
        expect(decodeMimeEncodedWords(input)).toBe('Hello World');
    });

    it('decodes QP with hex escapes', () => {
        const input = '=?utf-8?Q?=C3=BC=C3=A4=C3=B6?=';
        expect(decodeMimeEncodedWords(input)).toBe('\u00fc\u00e4\u00f6');
    });

    it('preserves non-encoded strings', () => {
        expect(decodeMimeEncodedWords('Plain text')).toBe('Plain text');
    });

    it('handles empty/null input', () => {
        expect(decodeMimeEncodedWords('')).toBe('');
        expect(decodeMimeEncodedWords(null as unknown as string)).toBe(null);
    });

    it('decodes multiple encoded words', () => {
        const input = '=?utf-8?B?SGVsbG8=?= =?utf-8?B?V29ybGQ=?=';
        expect(decodeMimeEncodedWords(input)).toBe('Hello World');
    });
});

describe('extractMessageId', () => {
    it('extracts Message-ID from headers', () => {
        const headers = 'From: test@example.com\r\nMessage-ID: <abc123@mail.example.com>\r\nSubject: Test';
        expect(extractMessageId(headers)).toBe('abc123@mail.example.com');
    });

    it('returns null for missing Message-ID', () => {
        expect(extractMessageId('From: test@example.com\r\nSubject: Test')).toBeNull();
    });

    it('handles null/undefined', () => {
        expect(extractMessageId(null)).toBeNull();
        expect(extractMessageId(undefined)).toBeNull();
    });
});

describe('extractReplyTo', () => {
    it('extracts Reply-To address', () => {
        const headers = 'From: a@b.com\r\nReply-To: reply@example.com\r\nSubject: Test';
        expect(extractReplyTo(headers)).toBe('reply@example.com');
    });

    it('returns null when no Reply-To', () => {
        expect(extractReplyTo('From: a@b.com\r\nSubject: Test')).toBeNull();
    });
});
