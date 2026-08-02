/**
 * Pure presentation helpers.
 *
 * Ported from `dashboard/src/lib/approvals/format.ts` (and `highlightJson` from
 * `dashboard/src/lib/api.ts`), which are already framework-free and were only
 * unreachable because they live inside a SvelteKit app. Nothing here touches
 * the network, the DOM, or a framework — the elements use them, and so can a
 * host rendering its own markup.
 */

import type {
  ApprovalResponse,
  DerivedKey,
  DisclosedField,
  Resolution,
} from '../types/approvals.js';

export const TTL_OPTIONS = [
  { value: 'forever', label: 'Never' },
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
] as const;

const HUMANIZED: Record<string, string> = {
  github: 'GitHub',
  gitlab: 'GitLab',
  google_calendar: 'Google Calendar',
  gmail: 'Gmail',
  outlook: 'Outlook',
};

/** Turn a slug into a display label: `google_calendar` → `Google Calendar`. */
export function humanize(slug: string): string {
  const known = HUMANIZED[slug];
  if (known) return known;
  return slug
    .split(/[_-]/)
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join(' ');
}

/**
 * What the approval is *about*, from one derived key: the scoped value with its
 * label when the key carries one. `email:send:recipient=jane@x.com` reads as
 * "recipient: jane@x.com" rather than leaking the raw `=` syntax.
 */
export function scopeArgDisplay(key: DerivedKey | null | undefined): string {
  if (!key) return '*';
  return key.label ? `${key.label}: ${key.value}` : key.arg;
}

/**
 * One-line scope summary across *every* derived key, for compact surfaces.
 *
 * A send to two recipients reads "recipient: ada@x.com, bob@y.com" rather than
 * naming only the first — the omitted one is usually the reason the approval
 * exists. Past `max`, it collapses to "+2 more".
 */
export function scopeArgSummary(keys: DerivedKey[], max = 2): string {
  if (!keys.length) return '*';
  const label = keys[0]?.label;
  // Mixed labels cannot share one prefix — fall back to whole-key displays.
  const uniform = !!label && keys.every((k) => k.label === label);
  const parts = [...new Set(keys.map((k) => (uniform ? k.value : scopeArgDisplay(k))))];
  const shown = parts.slice(0, max).join(', ');
  const hidden = parts.length - Math.min(parts.length, max);
  const tail = hidden > 0 ? `${shown} +${hidden} more` : shown;
  return uniform ? `${label}: ${tail}` : tail;
}

/**
 * How many permission keys to render before offering "show more". Generous on
 * purpose: the keys are short, few, and are exactly what the approver is being
 * asked to grant — a bare "+1" hides the decision.
 */
export const KEY_DISPLAY_CAP = 6;

export function splitKeys(
  keys: string[],
  cap = KEY_DISPLAY_CAP,
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
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Syntax-highlight a JSON value into an HTML string with `json-*` classes.
 *
 * Everything interpolated is escaped, which matters more here than in the
 * dashboard: this renders an agent-supplied payload inside a host's page.
 */
export function highlightJson(value: unknown, indent = 0): string {
  const pad = '  '.repeat(indent);
  if (value === null) return `<span class="json-null">null</span>`;
  if (typeof value === 'boolean') return `<span class="json-bool">${value}</span>`;
  if (typeof value === 'number') return `<span class="json-number">${value}</span>`;
  if (typeof value === 'string') return `<span class="json-string">"${escapeHtml(value)}"</span>`;
  if (Array.isArray(value)) {
    if (value.length === 0) return `<span class="json-bracket">[]</span>`;
    const items = value.map((v) => `${pad}  ${highlightJson(v, indent + 1)}`).join(',\n');
    return `<span class="json-bracket">[</span>\n${items}\n${pad}<span class="json-bracket">]</span>`;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return `<span class="json-bracket">{}</span>`;
    const lines = entries
      .map(
        ([k, v]) =>
          `${pad}  <span class="json-key">"${escapeHtml(k)}"</span>: ${highlightJson(v, indent + 1)}`,
      )
      .join(',\n');
    return `<span class="json-bracket">{</span>\n${lines}\n${pad}<span class="json-bracket">}</span>`;
  }
  return escapeHtml(String(value));
}

/** Highlight a raw JSON payload string; fall back to escaped text. */
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
 * Split disclosed fields into the template-designated "hero" fields and the rest.
 *
 * A field is a hero only when the template explicitly marked its `disclose[]`
 * entry `primary` *and* it resolved to a value. When none is marked, every
 * field falls into `remaining` so the UI renders a uniform table with nothing
 * spuriously highlighted.
 */
export function splitDisclosed(fields: DisclosedField[] | null | undefined): {
  primaries: DisclosedField[];
  remaining: DisclosedField[];
} {
  const all = fields ?? [];
  const primaries = all.filter((f) => f.primary && f.value !== null && !f.error);
  const remaining = primaries.length ? all.filter((f) => !primaries.includes(f)) : all;
  return { primaries, remaining };
}

/**
 * One-line confirmation for a resolution that already succeeded.
 *
 * The row is gone by the time this is read, so the message names both what
 * happened and which request it happened to. `updated` is the server's
 * response — it carries the cascade list, i.e. the sibling approvals a
 * freshly-written rule just covered.
 */
export function resolutionToast(
  resolution: Resolution,
  approval: ApprovalResponse,
  updated?: ApprovalResponse | null,
  rememberedKeys?: string[],
): string {
  const agent = extractAgentName(approval.identity_path, approval.requesting_identity_id);
  const first = approval.derived_keys[0];
  const service = first ? humanize(first.service) : 'the service';
  const cascaded = updated?.cascaded_approval_ids?.length ?? 0;
  const alsoResolved =
    cascaded > 0
      ? ` · also resolved ${cascaded} related ${cascaded === 1 ? 'request' : 'requests'}`
      : '';

  switch (resolution) {
    case 'allow':
      return `Allowed once — ${agent} → ${service}`;
    case 'allow_remember': {
      // A toast is one line, so this is the one place keys *are* elided — two
      // named, the rest counted. The written rules appear in full on the
      // agent's permission-rules table.
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
 * Resolve `remember_keys` from either a hand-typed key or a selected tier.
 * Returns an error string rather than throwing, so callers surface it inline.
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

export { pickApiError } from '../errors.js';
