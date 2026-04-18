#!/usr/bin/env node
// Fails if any emitted client chunk exceeds the threshold Vite warns at.
// This catches the Vite "Some chunks are larger than N kB" reporter output,
// which is plain stderr (not a Rollup warning) and otherwise slips past
// rollupOptions.onwarn.

import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const LIMIT_BYTES = 500 * 1024;
const ROOT = new URL('../.svelte-kit/output/client/_app/immutable', import.meta.url).pathname;

function walk(dir) {
	const out = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const p = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...walk(p));
		else if (entry.isFile() && entry.name.endsWith('.js')) out.push(p);
	}
	return out;
}

let offenders;
try {
	offenders = walk(ROOT).filter((p) => statSync(p).size > LIMIT_BYTES);
} catch (e) {
	console.error(`check-chunk-sizes: could not scan ${ROOT}: ${e.message}`);
	process.exit(1);
}

if (offenders.length > 0) {
	console.error(`\ncheck-chunk-sizes: ${offenders.length} chunk(s) exceed ${LIMIT_BYTES / 1024} kB:`);
	for (const p of offenders) {
		const kb = (statSync(p).size / 1024).toFixed(2);
		console.error(`  ${p.replace(ROOT + '/', '')}  ${kb} kB`);
	}
	console.error('\nSplit the chunk via dynamic import or adjust the threshold deliberately.');
	process.exit(1);
}
