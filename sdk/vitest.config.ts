import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    // `happy-dom` for the element tests; the client and controller tests are
    // environment-agnostic and run fine under it too.
    environment: 'happy-dom',
    include: ['test/**/*.test.ts'],
    // The live-API suite talks to a real stack booted with `make e2e-up`.
    // Opt in with OVERSLASH_E2E=1.
    exclude: process.env.OVERSLASH_E2E ? [] : ['test/integration/**'],
  },
});
