/**
 * The search bar's data model.
 *
 * A search is an ordered list of **terms**, and every term renders as a bubble
 * with a ✕. A term is either a `key op value` column filter or a plain-text
 * phrase; both kinds AND together, whatever order they were added in.
 *
 * This lives in a plain `.ts` (rather than `SearchBar.svelte`'s module block)
 * so it can be unit-tested — the Playwright unit runner under
 * `tests/e2e/units/` can only transform `.ts`.
 */

export type Operator = '=' | '~' | '!=' | '>=';

export interface SearchKey {
	/** Key name shown to the user (e.g. `event`, `identity`). */
	name: string;
	/** Allowed operators. Defaults to `['=']`. */
	operators?: Operator[];
	/** Static value list, or an async loader for value autocomplete. */
	values?: string[] | (() => Promise<string[]>);
	/** Help text shown next to the key suggestion. */
	hint?: string;
}

/**
 * A `key op value` column filter. `label` overrides the rendered value for
 * filters whose canonical value is an id (`connection = <uuid>`), so the bubble
 * reads as the account name while the filter still carries the id.
 */
export interface FilterTerm {
	kind: 'filter';
	key: string;
	op: Operator;
	value: string;
	label?: string;
}

/** A plain-text phrase. */
export interface TextTerm {
	kind: 'text';
	value: string;
}

export type Term = FilterTerm | TextTerm;

export interface SearchValue {
	terms: Term[];
}

/**
 * A fresh empty search. A *function*, not a shared constant: every consumer
 * hands the result to `$state()`, which deep-proxies it — one shared literal
 * would alias five pages' search state together.
 */
export function emptySearch(): SearchValue {
	return { terms: [] };
}

export function filterTerms(v: SearchValue): FilterTerm[] {
	return v.terms.filter((t): t is FilterTerm => t.kind === 'filter');
}

export function textTerms(v: SearchValue): string[] {
	return v.terms.flatMap((t) => (t.kind === 'text' ? [t.value] : []));
}

/**
 * The AND rule, defined once: a row survives only if **every** text bubble is
 * found in **at least one** of its searchable fields.
 *
 * Takes the fields separately rather than one joined string on purpose — joining
 * would let a term straddle a boundary, so searching `github slack` would match
 * a row whose provider ends in `github` and whose account starts with `slack`.
 */
export function matchesAllText(fields: string[], v: SearchValue): boolean {
	const terms = textTerms(v);
	if (!terms.length) return true;
	const hay = fields.map((f) => f.toLowerCase());
	return terms.every((t) => {
		const needle = t.toLowerCase();
		return hay.some((f) => f.includes(needle));
	});
}

/** Stable identity for `{#each}` keying. Dedup keeps these unique. */
export function termId(t: Term): string {
	return t.kind === 'text' ? `text:${t.value.toLowerCase()}` : `${t.key}${t.op}${t.value}`;
}

/**
 * Two terms are the same bubble. Text compares case-insensitively (`GitHub` and
 * `github` are one search); filter values compare exactly, because tag values
 * and identity names are case-carrying.
 */
export function sameTerm(a: Term, b: Term): boolean {
	if (a.kind === 'text' && b.kind === 'text') {
		return a.value.toLowerCase() === b.value.toLowerCase();
	}
	if (a.kind === 'filter' && b.kind === 'filter') {
		return a.key === b.key && a.op === b.op && a.value === b.value;
	}
	return false;
}

export function hasTerm(v: SearchValue, t: Term): boolean {
	return v.terms.some((x) => sameTerm(x, t));
}

/**
 * Append a term unless an identical one is already there. Returns the *same
 * object* on a duplicate, so callers can skip a pointless emit (which on the
 * audit page would cost a refetch).
 */
export function addTerm(v: SearchValue, t: Term): SearchValue {
	if (t.kind === 'text' && !t.value.trim()) return v;
	if (hasTerm(v, t)) return v;
	return { terms: [...v.terms, t] };
}

export function addTerms(v: SearchValue, ts: Term[]): SearchValue {
	let next = v;
	for (const t of ts) next = addTerm(next, t);
	return next;
}

export function removeTermAt(v: SearchValue, index: number): SearchValue {
	if (index < 0 || index >= v.terms.length) return v;
	return { terms: v.terms.filter((_, i) => i !== index) };
}

// Longest-first alternation: `=` would otherwise win the race against the
// two-character operators and leave their first char stranded in the key.
const TOKEN_RE = /(\w+)\s*(!=|>=|=|~)\s*("[^"]*"|\S+)/g;

/** Byte ranges covered by a `"…"` span, which the tokenizer treats as opaque. */
function quotedSpans(input: string): Array<[number, number]> {
	const spans: Array<[number, number]> = [];
	const re = /"[^"]*"/g;
	let m: RegExpExecArray | null;
	while ((m = re.exec(input)) !== null) spans.push([m.index, m.index + m[0].length]);
	return spans;
}

/** Strip one layer of surrounding quotes, if they wrap the whole string. */
function unquote(raw: string): string {
	const s = raw.trim();
	if (s.length >= 2 && s.startsWith('"') && s.endsWith('"') && !s.slice(1, -1).includes('"')) {
		return s.slice(1, -1).trim();
	}
	return s;
}

/**
 * Drop the quotes from every balanced `"…"` span in a run of free text.
 *
 * Quotes are grouping syntax, not something to search for: they exist so a
 * phrase can be held together and shielded from the `key op value` tokenizer.
 * Stripping them only when they wrapped the *whole* run left the marks inside
 * the bubble anywhere else — `hello "foo=bar" world` searched for text that
 * included the quote characters. An unbalanced quote is left alone, since it
 * is far likelier to be part of what the user meant to search for.
 */
function stripQuoteSpans(raw: string): string {
	return raw.replace(/"([^"]*)"/g, '$1');
}

/**
 * Parse raw input into terms.
 *
 * Recognised `key op value` tokens become filter terms; each remaining *gap*
 * becomes one text term, so `foo bar` stays a single phrase bubble while
 * `hello event=x world` yields `[hello] [event = x] [world]` in typed order.
 *
 * An unknown key is not a filter, and `lastIndex` deliberately does not advance
 * past it — the span stays part of the surrounding text gap, so `foo=bar` comes
 * back as the text term `foo=bar`.
 */
export function parseSearch(input: string, knownKeys: string[]): Term[] {
	const terms: Term[] = [];
	let lastIndex = 0;
	const re = new RegExp(TOKEN_RE);
	const spans = quotedSpans(input);
	let m: RegExpExecArray | null;

	const pushText = (raw: string) => {
		const value = stripQuoteSpans(raw).replace(/\s+/g, ' ').trim();
		if (value) terms.push({ kind: 'text', value });
	};

	while ((m = re.exec(input)) !== null) {
		const [full, key, op, rawValue] = m;
		if (!knownKeys.includes(key)) continue;
		// A quoted phrase is opaque: `"foo=bar"` is the text the user asked for,
		// not a filter, even once the surface grows a `foo` key.
		if (spans.some(([from, to]) => m!.index > from && m!.index < to)) continue;
		pushText(input.slice(lastIndex, m.index));
		lastIndex = m.index + full.length;
		const value = unquote(rawValue);
		// `key=""` carries no filter — drop it rather than filtering on empty.
		if (value) terms.push({ kind: 'filter', key, op: op as Operator, value });
	}
	pushText(input.slice(lastIndex));
	return terms;
}

/** True when a string would parse back as a `key op value` token. */
const LOOKS_STRUCTURED = /\w+\s*(!=|=|~)\s*\S/;

/**
 * Render a term back into input text for click-to-edit. Text that looks
 * structured is quoted, so a text bubble like `foo=bar` cannot silently turn
 * into a filter when the surface's key list later grows a `foo` key.
 */
export function termToDraft(t: Term): string {
	if (t.kind === 'text') {
		return LOOKS_STRUCTURED.test(t.value) ? `"${t.value}"` : t.value;
	}
	const value = /\s/.test(t.value) ? `"${t.value}"` : t.value;
	return `${t.key}${t.op}${value}`;
}
