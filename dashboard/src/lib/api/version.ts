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
