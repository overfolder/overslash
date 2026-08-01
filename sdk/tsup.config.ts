import { defineConfig } from 'tsup';

/**
 * One entry per subpath export (see package.json). Entries are added as the
 * layers land, so every commit builds what it declares and nothing more.
 */
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'controllers/index': 'src/controllers/index.ts',
    'format/index': 'src/format/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2022',
});
