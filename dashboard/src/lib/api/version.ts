/**
 * Build identity of the API.
 *
 * Deliberately fetched rather than baked into the bundle at build time: the
 * dashboard ships both to Vercel and embedded in the Rust binary
 * (`ADAPTER=static`), so a Vite-time constant would drift from whichever API
 * the browser is actually pointed at. `/health` carries the same version and
 * commit for uptime monitors; this route is the one that skips `/health`'s
 * per-request database probe and pre-abbreviates the SHA.
 */
import { session } from '$lib/session';
import type { BuildInfo } from '$lib/types';

export const getVersion = (signal?: AbortSignal) =>
	session.get<BuildInfo>('/v1/version', signal);

/** A build with no discoverable commit reports `"unknown"` (see
 *  overslash-core's build.rs) — treat that as "no SHA to show" rather than
 *  printing a line that reads like a real one. */
export const hasCommit = (info: BuildInfo | null): boolean =>
	!!info && info.commit !== 'unknown';

/**
 * Primary build label. Pass `short` (the collapsed sidebar rail) to drop the
 * SHA — the version is what people recognise at a glance, and the full commit
 * is always one hover away via `buildTitle`.
 */
export function buildLabel(info: BuildInfo | null, short = false): string {
	if (!info) return '';
	if (short || !hasCommit(info)) return `v${info.version}`;
	return `v${info.version} · ${info.commit_short}`;
}

/** Hover tooltip — carries the full SHA whenever there is one. */
export function buildTitle(info: BuildInfo | null, copyable = false): string {
	if (!info) return '';
	if (!hasCommit(info)) return `Overslash v${info.version}`;
	const base = `Overslash v${info.version}\ncommit ${info.commit}`;
	return copyable ? `${base}\n(click to copy)` : base;
}
