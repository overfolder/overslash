// The audit log's time window. Owned by the range picker, not the search bar:
// time is the one filter every query carries, so it gets a control of its own
// and a default instead of a `time =` bubble nobody remembered to add.
//
// A relative range lives in the URL as `?range=24h` and means "the last 24h
// from whenever this is opened" — a shared link keeps meaning what it said.
// A custom range lives as `?since=…&until=…` (ISO, UTC) and is fixed.

export const RANGE_PRESETS = ['5m', '1h', '24h', '7d'] as const;
export type RangePreset = (typeof RANGE_PRESETS)[number];

/** Preselected when the URL names no window. A day covers "what just
 *  happened" without making every load walk the org's whole history. */
export const DEFAULT_PRESET: RangePreset = '24h';

const PRESET_MS: Record<RangePreset, number> = {
	'5m': 5 * 60 * 1000,
	'1h': 60 * 60 * 1000,
	'24h': 24 * 60 * 60 * 1000,
	'7d': 7 * 24 * 60 * 60 * 1000
};

const PRESET_LABEL: Record<RangePreset, string> = {
	'5m': 'last 5 minutes',
	'1h': 'last hour',
	'24h': 'last 24 hours',
	'7d': 'last 7 days'
};

export type TimeRange =
	| { kind: 'relative'; preset: RangePreset }
	/** `until` absent means "up to now" — an old `?since=` link without one. */
	| { kind: 'absolute'; since: string; until?: string };

/** Concrete bounds for one fetch session. */
export interface ResolvedRange {
	since: string;
	until: string;
}

export const DEFAULT_RANGE: TimeRange = { kind: 'relative', preset: DEFAULT_PRESET };

function isPreset(v: string | null): v is RangePreset {
	return v !== null && (RANGE_PRESETS as readonly string[]).includes(v);
}

function isInstant(v: string | null): v is string {
	return !!v && !Number.isNaN(Date.parse(v));
}

export function rangeFromSearchParams(params: URLSearchParams): TimeRange {
	const preset = params.get('range');
	if (isPreset(preset)) return { kind: 'relative', preset };
	const since = params.get('since');
	const until = params.get('until');
	if (isInstant(since)) {
		return isInstant(until) ? { kind: 'absolute', since, until } : { kind: 'absolute', since };
	}
	return DEFAULT_RANGE;
}

/** URL params for a range. The default is written out too, so a copied link
 *  says which window it was looking at. */
export function rangeToParams(range: TimeRange): Record<string, string> {
	if (range.kind === 'relative') return { range: range.preset };
	return range.until ? { since: range.since, until: range.until } : { since: range.since };
}

/** Bounds as of `now`. Called once per reset fetch (load, filter change,
 *  refresh) and then held: infinite scroll keeps paging the same window
 *  instead of one that slides a little further with every page. */
export function resolveRange(range: TimeRange, now: Date = new Date()): ResolvedRange {
	if (range.kind === 'absolute') {
		return { since: range.since, until: range.until ?? now.toISOString() };
	}
	return {
		since: new Date(now.getTime() - PRESET_MS[range.preset]).toISOString(),
		until: now.toISOString()
	};
}

export function sameRange(a: TimeRange, b: TimeRange): boolean {
	if (a.kind === 'relative' && b.kind === 'relative') return a.preset === b.preset;
	if (a.kind === 'absolute' && b.kind === 'absolute')
		return a.since === b.since && a.until === b.until;
	return false;
}

/** The next preset up, for the empty state's "try a wider range". */
export function widerPreset(preset: RangePreset): RangePreset | null {
	const i = RANGE_PRESETS.indexOf(preset);
	return i >= 0 && i < RANGE_PRESETS.length - 1 ? RANGE_PRESETS[i + 1] : null;
}

const SHORT = new Intl.DateTimeFormat(undefined, {
	month: 'short',
	day: 'numeric',
	hour: '2-digit',
	minute: '2-digit'
});

/** Human label: "last 24 hours", or "Oct 20, 14:00 → Oct 21, 09:30" in local
 *  time for a custom window. */
export function rangeLabel(range: TimeRange): string {
	if (range.kind === 'relative') return PRESET_LABEL[range.preset];
	const since = SHORT.format(new Date(range.since));
	return range.until ? `${since} → ${SHORT.format(new Date(range.until))}` : `${since} → now`;
}

/** `<input type="datetime-local">` speaks local wall-clock time with no zone
 *  (`2026-10-23T14:05`). These convert to and from the UTC ISO the API takes. */
export function toLocalInput(iso: string): string {
	const d = new Date(iso);
	const pad = (n: number) => String(n).padStart(2, '0');
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function fromLocalInput(value: string): string | null {
	// No zone in the string, so `Date` reads it as local time — which is what
	// the input showed.
	const t = Date.parse(value);
	return Number.isNaN(t) ? null : new Date(t).toISOString();
}
