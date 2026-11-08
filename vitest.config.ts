import { defineConfig } from 'vitest/config';

export default defineConfig({
    resolve: {
        alias: {
            '@noble/post-quantum/ml-kem': '@noble/post-quantum/ml-kem.js',
        },
    },
    test: {
        include: ['tests/**/*.test.ts', 'kat/**/*.spec.ts'],
        testTimeout: 10000,
        coverage: {
            provider: 'v8',
            include: ['src/**/*.ts'],
            // Untergrenzen für `npm run test:coverage`. Zeilen und Anweisungen
            // sind fest auf 90 %; Zweige und Funktionen liegen 2 Punkte unter
            // dem erreichten Stand, damit ein Rückgang auffällt.
            thresholds: {
                lines: 90,
                statements: 90,
                branches: 88,
                functions: 97,
            },
        },
    },
});
