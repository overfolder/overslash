// Pure presentation helpers shared across the approval surfaces (the queue at
// /approvals, the full-page ApprovalDetail, and the ApprovalRow embedded in the
// agents tree). Kept framework-free so all three stay in lockstep — see
// resolution.svelte.ts for the async/lifecycle half of the split.

import { highlightJson } from '$lib/api';
import { ApiError, type ApprovalResponse, type DerivedKey, type DisclosedField } from '$lib/session';

/**
 * Extract a human-readable message from a failed request. Prefers the gateway's
 * typed `{ error }` envelope, then a raw text body, then the platform Error
 * message, and finally `fallback` — never the opaque "API error 422".
 */
export function pickApiError(e: unknown, fallback = 'Something went wrong.'): string {
	if (e instanceof ApiError) {
		const body = e.body as { error?: string } | string;
		if (typeof body === 'object' && body && 'error' in body) {
			return body.error ?? `Error ${e.status}`;
		}
		return typeof body === 'string' && body ? body : `Error ${e.status}`;
	}
	return e instanceof Error ? e.message : fallback;
}

export const TTL_OPTIONS = [
	{ value: 'forever', label: 'Never' },
	{ value: '1h', label: '1 hour' },
	{ value: '24h', label: '24 hours' },
	{ value: '7d', label: '7 days' },
	{ value: '30d', label: '30 days' }
] as const;

const HUMANIZED: Record<string, string> = {
	github: 'GitHub',
	gitlab: 'GitLab',
	google_calendar: 'Google Calendar',
	gmail: 'Gmail',
	outlook: 'Outlook'
};

/** Turn a service/action slug into a display label ("google_calendar" → "Google Calendar"). */
export function humanize(slug: string): string {
	if (HUMANIZED[slug]) return HUMANIZED[slug];
	return slug
		.split(/[_-]/)
		.map((s) => s.charAt(0).toUpperCase() + s.slice(1))
		.join(' ');
}

/**
 * What the approval is *about*, from the first derived key: the scoped value,
 * prefixed with its label when the key carries one. `email:send:recipient=jane@x.com`
 * reads as "recipient: jane@x.com" rather than leaking the raw `=` syntax, and
 * an unlabelled key (or none at all) falls back to the arg verbatim.
 */
export function scopeArgDisplay(key: DerivedKey | null): string {
	if (!key) return '*';
	return key.label ? `${key.label}: ${key.value}` : key.arg;
}

/**
 * One-line scope summary across *every* derived key, for the compact contexts
 * (queue row, detail header). A send to two recipients reads
 * "recipient: ada@x.com, bob@y.com" rather than naming only the first — the
 * omitted one is usually the reason the approval exists. Past `max` values it
 * collapses to "recipient: ada@x.com +2 more"; the full list lives in the
 * detail panel.
 */
export function scopeArgSummary(keys: DerivedKey[], max = 2): string {
	if (!keys.length) return '*';
	const label = keys[0].label;
	// Mixed labels can't share one prefix — fall back to whole-key displays.
	const uniform = label && keys.every((k) => k.label === label);
	const parts = [...new Set(keys.map((k) => (uniform ? k.value : scopeArgDisplay(k))))];
	const shown = parts.slice(0, max).join(', ');
	const hidden = parts.length - Math.min(parts.length, max);
	const tail = hidden > 0 ? `${shown} +${hidden} more` : shown;
	return uniform ? `${label}: ${tail}` : tail;
}

/**
 * How many permission keys a surface renders before offering a "show more"
 * toggle. Generous on purpose: the keys are short, few (one per recipient),
 * and are exactly what the approver is being asked to grant — a bare "+1"
 * hides the decision.
 */
export const KEY_DISPLAY_CAP = 6;

/** Split a key list into the ones to render and the count held back. */
export function splitKeys(
	keys: string[],
	cap = KEY_DISPLAY_CAP
): { shown: string[]; hidden: number } {
	return { shown: keys.slice(0, cap), hidden: Math.max(0, keys.length - cap) };
}

/** Last unit segment of a SPIFFE-ish identity path, or a short id fallback. */
export function extractAgentName(path: string | null, fallbackId: string): string {
	if (path) {
		const parts = path.replace(/^spiffe:\/\//, '').split('/');
		const last = parts[parts.length - 1];
		if (last) return last;
	}
	return fallbackId.slice(0, 8);
}

export function escapeHtml(s: string): string {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Syntax-highlight a raw JSON payload string; fall back to escaped text. */
export function renderPayload(raw: string): string {
	try {
		return highlightJson(JSON.parse(raw));
	} catch {
		return escapeHtml(raw);
	}
}

export function formatBytes(n: number): string {
	if (n < 1024) return `${n} B`;
	if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
	return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

const utf8Encoder = new TextEncoder();
export function utf8ByteLength(s: string): number {
	return utf8Encoder.encode(s).byteLength;
}

/**
 * Split disclosed fields into the template-designated "hero" fields and the
 * rest. A field is a hero only when the template explicitly marked its
 * `disclose[]` entry `primary` (and it resolved to a value). Multiple fields
 * may be primary — they are returned in declaration order. When no field is
 * marked primary, `primaries` is empty and every field falls into `remaining`,
 * so the UI renders a uniform table with nothing highlighted.
 */
export function splitDisclosed(fields: DisclosedField[] | null): {
	primaries: DisclosedField[];
	remaining: DisclosedField[];
} {
	const all = fields ?? [];
	const primaries = all.filter((f) => f.primary && f.value !== null && !f.error);
	const remaining = primaries.length ? all.filter((f) => !primaries.includes(f)) : all;
	return { primaries, remaining };
}

/**
 * One-line confirmation for a resolution that has already succeeded. The row
 * that was resolved is gone by the time this is read, so the message has to
 * name both what happened and which request it happened to.
 *
 * `updated` is the server's response — it carries the cascade list, i.e. the
 * sibling approvals a freshly-written rule just covered.
 */
export function resolutionToast(
	resolution: 'allow' | 'deny' | 'allow_remember' | 'bubble_up',
	approval: ApprovalResponse,
	updated?: ApprovalResponse | null,
	rememberedKeys?: string[]
): string {
	const agent = extractAgentName(approval.identity_path, approval.requesting_identity_id);
	const service = approval.derived_keys[0] ? humanize(approval.derived_keys[0].service) : 'the service';
	const cascaded = updated?.cascaded_approval_ids?.length ?? 0;
	const alsoResolved =
		cascaded > 0 ? ` · also resolved ${cascaded} related ${cascaded === 1 ? 'request' : 'requests'}` : '';

	switch (resolution) {
		case 'allow':
			return `Allowed once — ${agent} → ${service}`;
		case 'allow_remember': {
			// A toast is one line, so this is the one place keys *are* elided —
			// two named, the rest counted. The written rules are on the agent's
			// Permission Rules table in full.
			const { shown, hidden } = splitKeys(rememberedKeys ?? approval.permission_keys, 2);
			const keys = shown.join(', ') + (hidden > 0 ? ` and ${hidden} more` : '');
			return `Allowed & remembered — ${keys || service}${alsoResolved}`;
		}
		case 'deny':
			return `Denied — ${agent}'s ${service} action`;
		case 'bubble_up':
			return `Bubbled up — ${agent} → ${service} now waits on an ancestor`;
	}
}

/**
 * Resolve the `remember_keys` for an "Allow & Remember", from either a
 * hand-typed custom key or the selected suggested tier. Returns an error string
 * instead of throwing so callers can surface it inline.
 */
export function rememberKeys(opts: {
	useCustomKey: boolean;
	customKey: string;
	tiers: { keys: string[] }[];
	selectedTier: number;
}): string[] | { error: string } {
	if (opts.useCustomKey) {
		const k = opts.customKey.trim();
		if (!k) return { error: 'Enter a permission key to remember.' };
		return [k];
	}
	const tier = opts.tiers[opts.selectedTier];
	if (!tier) return { error: 'Select a permission scope to remember.' };
	return tier.keys;
}
