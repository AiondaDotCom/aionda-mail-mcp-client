/**
 * Wächter: jeder relative Import in src/ trägt die Endung `.js`.
 *
 * Ohne Endung lädt Node die gebaute Bibliothek nicht: Bis 0.17.2 endete
 * `import('@aiondadotcom/mail-mcp-client')` in reinem Node-ESM mit
 * ERR_MODULE_NOT_FOUND (…/dist/esm/client), gemessen 14.11.2026 an der
 * veröffentlichten 0.17.2. Vitest und esbuild lösen Endungslose auf und
 * merken davon nichts – deshalb dieser Wächter und der Importschritt in CI.
 *
 * Fehltrefferzahl auf dem sauberen Baum: 0 (14.11.2026).
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/** Relative Import-/Export-/import()-Angaben ohne .js/.json – beide Anführungszeichen. */
export function endungsloseImporte(quelltext: string): string[] {
    const treffer: string[] = [];
    const muster = /(?:\bfrom\s*|\bimport\s*\(\s*|^\s*import\s+)(['"])(\.{1,2}\/[^'"]*)\1/gm;
    for (const m of quelltext.matchAll(muster)) {
        if (!/\.(js|json)$/.test(m[2])) treffer.push(m[2]);
    }
    return treffer;
}

function tsDateien(dir: string): string[] {
    return readdirSync(dir).flatMap((n) => {
        const p = join(dir, n);
        return statSync(p).isDirectory() ? tsDateien(p) : p.endsWith('.ts') ? [p] : [];
    });
}

describe('ESM-Importendungen', () => {
    it('Alarmprobe: das Muster findet eigene und fremde Schreibweisen und schweigt bei .js', () => {
        expect(endungsloseImporte(`import { a } from './client';`)).toEqual(['./client']);
        expect(endungsloseImporte(`export * from "../types";`)).toEqual(['../types']);
        expect(endungsloseImporte(`const x = await import('./crypto/aes-gcm');`)).toEqual(['./crypto/aes-gcm']);
        expect(endungsloseImporte(`import './seiteneffekt';`)).toEqual(['./seiteneffekt']);
        expect(endungsloseImporte(`import type {\n  A,\n} from './types/email';`)).toEqual(['./types/email']);
        expect(endungsloseImporte(`import { a } from './client.js';\nimport b from '@noble/hashes/hkdf';`)).toEqual([]);
    });

    it('src/ hat keinen relativen Import ohne Endung', () => {
        const dateien = tsDateien(join(__dirname, '..', 'src'));
        expect(dateien.length).toBeGreaterThan(20);
        const funde = dateien.flatMap((d) => endungsloseImporte(readFileSync(d, 'utf8')).map((i) => `${d}: ${i}`));
        expect(funde).toEqual([]);
    });
});
