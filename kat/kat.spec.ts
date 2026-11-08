/**
 * CI-Wächter für die KAT-Fixtures.
 *
 * Fällt dieser Test um, ist entweder die TS-Krypto geändert worden oder die
 * Fixtures sind veraltet. Beides muss auffallen, BEVOR der Swift-Core gegen
 * falsche Vektoren gebaut wird.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { verifyAll } from './verify-kat';
import { findFixtureDrift } from './lib/fixture-drift';

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const PACKAGE_DIR = dirname(dirname(FIXTURE_DIR));

/**
 * 🚩 #478cc256 - `vault_unlock.json` FEHLTE in dieser Liste, obwohl die Datei
 * seit langem im Verzeichnis liegt und von `verifyAll()` geprueft wird. Der
 * erste Test dieser Reihe war deshalb auf dem sauberen Baum ROT (gemessen am
 * 25.08.2026 vor jeder Aenderung: 1 von 3 Tests rot). Eine hart verdrahtete
 * Namensliste ist ein Waechter, der bei jedem legitimen Zuwachs falsch
 * anschlaegt - und dann gewoehnt man sich das Wegsehen an.
 */
const EXPECTED_FILES = [
    'aes_gcm.json',
    'email_field.json',
    'hybrid_kem.json',
    'key_derivation.json',
    'key_transition.json',
    'pack_format.json',
    'vault_unlock.json',
    'wrapped_key_tasks.json',
];

describe('KAT-Fixtures', () => {
    it(`enthält alle ${EXPECTED_FILES.length} Fixture-Dateien`, () => {
        const found = readdirSync(FIXTURE_DIR).filter(f => f.endsWith('.json')).sort();
        expect(found).toEqual(EXPECTED_FILES);
    });

    it('trägt überall die Generator-Herkunft', () => {
        for (const file of EXPECTED_FILES) {
            const data = JSON.parse(readFileSync(join(FIXTURE_DIR, file), 'utf8')) as {
                generator?: { source?: string; date?: string };
            };
            expect(data.generator?.source, `${file}: generator.source fehlt`).toBeTruthy();
            expect(data.generator?.date, `${file}: generator.date fehlt`).toBeTruthy();
        }
    });

    it('stimmt byte-genau mit der echten TypeScript-Krypto überein', async () => {
        const results = await verifyAll();
        const failures = results.flatMap(r => r.failures.map(f => `${r.fixture}: ${f}`));
        expect(failures).toEqual([]);

        const total = results.reduce((sum, r) => sum + r.checks, 0);
        // 180 bis 07.10.2026; +106 durch key_transition.json (#658912ef, v2):
        // 3 Fingerabdrücke × 3 + 10 Wechselakten × 6 + 2 Nenner + 6 Einrichtungsakten × 4
        // + 2 Nenner + 1 Seed-AAD + 13 Kettenglieder.
        expect(total).toBe(286);
    }, 60_000);

    it('erzeugt alle eingecheckten Fixtures byte-genau neu', () => {
        const generatedDirectory = mkdtempSync(join(tmpdir(), 'aionda-kat-generated-'));
        try {
            const generated = spawnSync('npm', ['run', 'generate-kat'], {
                cwd: PACKAGE_DIR,
                encoding: 'utf8',
                env: { ...process.env, AIONDA_KAT_OUTPUT_DIR: generatedDirectory },
                timeout: 60_000,
            });
            expect(
                generated.status,
                `Generator fehlgeschlagen:\n${generated.stdout}\n${generated.stderr}`
            ).toBe(0);
            expect(findFixtureDrift(FIXTURE_DIR, generatedDirectory)).toEqual([]);
        } finally {
            rmSync(generatedDirectory, { recursive: true, force: true });
        }
    }, 70_000);

    it('meldet eine byteweise Fixture-Abweichung und schweigt bei Gleichheit', () => {
        const expectedDirectory = mkdtempSync(join(tmpdir(), 'aionda-kat-expected-'));
        const actualDirectory = mkdtempSync(join(tmpdir(), 'aionda-kat-actual-'));
        try {
            mkdirSync(expectedDirectory, { recursive: true });
            mkdirSync(actualDirectory, { recursive: true });
            writeFileSync(join(expectedDirectory, 'email_field.json'), '{"wert":1}\n');
            writeFileSync(join(actualDirectory, 'email_field.json'), '{"wert":1}\n');
            expect(findFixtureDrift(expectedDirectory, actualDirectory)).toEqual([]);

            writeFileSync(join(actualDirectory, 'email_field.json'), '{"wert":2}\n');
            expect(findFixtureDrift(expectedDirectory, actualDirectory)).toEqual(['email_field.json']);
        } finally {
            rmSync(expectedDirectory, { recursive: true, force: true });
            rmSync(actualDirectory, { recursive: true, force: true });
        }
    });
});
