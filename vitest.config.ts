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
    },
});
