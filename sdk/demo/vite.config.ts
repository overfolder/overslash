import { defineConfig } from 'vite';

/**
 * The playground. Not published — it exists to exercise the elements against a
 * real stack and to produce the screenshots a UI PR needs.
 */
export default defineConfig({
  root: __dirname,
  server: {
    port: 5183,
    // Same-origin proxy to the API, so the demo can use cookie auth from
    // `/auth/dev/token` exactly as the dashboard does.
    proxy: {
      '/v1': { target: process.env.API_URL ?? 'http://localhost:3000', changeOrigin: true },
      '/auth': { target: process.env.API_URL ?? 'http://localhost:3000', changeOrigin: true },
      '/public': { target: process.env.API_URL ?? 'http://localhost:3000', changeOrigin: true },
    },
  },
});
