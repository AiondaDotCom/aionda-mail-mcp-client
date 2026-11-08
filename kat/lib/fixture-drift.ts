import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// #0f545b9b - Regeneration muss Bytes prüfen, nicht nur Entschlüsselbarkeit.

function fixtureNames(directory: string): string[] {
    return readdirSync(directory).filter(name => name.endsWith('.json')).sort();
}

/**
 * Nennt jede JSON-Fixture, die fehlt, zusätzlich vorliegt oder byteweise
 * abweicht. Semantisch gültiger Ersatzinhalt gilt ausdrücklich als Drift.
 */
export function findFixtureDrift(expectedDirectory: string, actualDirectory: string): string[] {
    const names = new Set([
        ...fixtureNames(expectedDirectory),
        ...fixtureNames(actualDirectory),
    ]);

    return [...names].sort().filter(name => {
        try {
            return !readFileSync(join(expectedDirectory, name))
                .equals(readFileSync(join(actualDirectory, name)));
        } catch {
            return true;
        }
    });
}
