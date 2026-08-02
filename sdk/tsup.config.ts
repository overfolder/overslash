import { defineConfig } from 'tsup';

/**
 * One entry per subpath export (see package.json). Entries are added as the
 * layers land, so every commit builds what it declares and nothing more.
 *
 * `elements` is ESM-only: custom elements are browser-only, and a CJS consumer
 * of one does not exist.
 */
export default defineConfig([
  {
    entry: {
      index: 'src/index.ts',
      'controllers/index': 'src/controllers/index.ts',
      'node/index': 'src/node/index.ts',
      'format/index': 'src/format/index.ts',
    },
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    target: 'es2022',
  },
  {
    entry: { 'elements/index': 'src/elements/index.ts' },
    format: ['esm'],
    dts: true,
    sourcemap: true,
    target: 'es2022',
  },
]);
