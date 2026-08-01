import { describe, expect, it } from 'vitest';
import {
  extractAgentName,
  formatBytes,
  highlightJson,
  humanize,
  rememberKeys,
  renderPayload,
  resolutionToast,
  scopeArgSummary,
  splitDisclosed,
  splitKeys,
} from '../src/format/index.js';
import { approvalFixture } from './helpers.js';
import type { DerivedKey } from '../src/types/approvals.js';

const key = (over: Partial<DerivedKey> = {}): DerivedKey => ({
  service: 'email',
  action: 'send',
  arg: 'recipient=ada@x.com',
  label: 'recipient',
  value: 'ada@x.com',
  ...over,
});

describe('humanize', () => {
  it('uses the override table before title-casing', () => {
    expect(humanize('google_calendar')).toBe('Google Calendar');
    expect(humanize('github')).toBe('GitHub');
    expect(humanize('acme_crm')).toBe('Acme Crm');
  });
});

describe('scopeArgSummary', () => {
  it('shares one label across uniform keys', () => {
    expect(scopeArgSummary([key(), key({ value: 'bob@y.com', arg: 'recipient=bob@y.com' })])).toBe(
      'recipient: ada@x.com, bob@y.com',
    );
  });

  it('counts the overflow rather than silently naming only the first', () => {
    const keys = ['a', 'b', 'c', 'd'].map((n) =>
      key({ value: `${n}@x.com`, arg: `recipient=${n}@x.com` }),
    );
    expect(scopeArgSummary(keys)).toBe('recipient: a@x.com, b@x.com +2 more');
  });

  it('falls back to whole-key display when labels differ', () => {
    const mixed = [key(), key({ label: 'folder', value: 'inbox', arg: 'folder=inbox' })];
    expect(scopeArgSummary(mixed)).toBe('recipient: ada@x.com, folder: inbox');
  });

  it('renders a wildcard for no keys', () => {
    expect(scopeArgSummary([])).toBe('*');
  });
});

describe('splitKeys', () => {
  it('holds back the overflow count', () => {
    expect(splitKeys(['a', 'b', 'c'], 2)).toEqual({ shown: ['a', 'b'], hidden: 1 });
    expect(splitKeys(['a'], 2)).toEqual({ shown: ['a'], hidden: 0 });
  });
});

describe('extractAgentName', () => {
  it('takes the last SPIFFE segment', () => {
    expect(extractAgentName('spiffe://acme/user/alice/agent/henry', 'x')).toBe('henry');
  });

  it('falls back to a short id when the path could not be resolved', () => {
    expect(extractAgentName(null, 'abcdefgh-1111')).toBe('abcdefgh');
  });
});

describe('splitDisclosed', () => {
  it('promotes only fields the template marked primary that actually resolved', () => {
    const fields = [
      { label: 'To', value: 'jane@x.com', error: null, truncated: false, primary: true },
      { label: 'Body', value: 'hi', error: null, truncated: false },
      { label: 'Broken', value: null, error: 'filter failed', truncated: false, primary: true },
    ];
    const { primaries, remaining } = splitDisclosed(fields);
    expect(primaries.map((f) => f.label)).toEqual(['To']);
    expect(remaining.map((f) => f.label)).toEqual(['Body', 'Broken']);
  });

  it('renders a uniform table when nothing is primary', () => {
    const fields = [{ label: 'Body', value: 'hi', error: null, truncated: false }];
    const { primaries, remaining } = splitDisclosed(fields);
    expect(primaries).toEqual([]);
    expect(remaining).toHaveLength(1);
  });

  it('tolerates both absent shapes', () => {
    // The server omits the key entirely when the template declared no disclose
    // entries (serde `skip_serializing_if`), so `undefined` is the common case
    // on the wire and `null` only appears in hand-built fixtures.
    expect(splitDisclosed(null)).toEqual({ primaries: [], remaining: [] });
    expect(splitDisclosed(undefined)).toEqual({ primaries: [], remaining: [] });
  });
});

describe('highlightJson', () => {
  it('escapes interpolated strings — this renders agent-supplied payloads', () => {
    const html = highlightJson({ '<k>': '<script>alert(1)</script>' });
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('&lt;k&gt;');
  });

  it('falls back to escaped text for a payload that is not JSON', () => {
    expect(renderPayload('<not json>')).toBe('&lt;not json&gt;');
  });
});

describe('formatBytes', () => {
  it('scales units', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.00 MB');
  });
});

describe('resolutionToast', () => {
  const approval = approvalFixture();

  it('names the agent and service for a one-off allow', () => {
    expect(resolutionToast('allow', approval)).toBe('Allowed once — henry → Email');
  });

  it('reports the cascade so a vanished sibling row is accounted for', () => {
    const updated = approvalFixture({ cascaded_approval_ids: ['x', 'y'] });
    const msg = resolutionToast('allow_remember', approval, updated, ['email:send:*']);
    expect(msg).toContain('email:send:*');
    expect(msg).toContain('also resolved 2 related requests');
  });

  it('singularises a lone cascade', () => {
    const updated = approvalFixture({ cascaded_approval_ids: ['x'] });
    expect(resolutionToast('allow_remember', approval, updated)).toContain('1 related request');
  });
});

describe('rememberKeys', () => {
  const tiers = [{ keys: ['email:send:recipient=jane@x.com'] }, { keys: ['email:send:*'] }];

  it('returns the selected tier', () => {
    expect(rememberKeys({ useCustomKey: false, customKey: '', tiers, selectedTier: 1 })).toEqual([
      'email:send:*',
    ]);
  });

  it('reports rather than throws when nothing is selected', () => {
    expect(rememberKeys({ useCustomKey: false, customKey: '', tiers, selectedTier: 9 })).toEqual({
      error: 'Select a permission scope to remember.',
    });
  });

  it('trims a custom key and rejects an empty one', () => {
    expect(rememberKeys({ useCustomKey: true, customKey: '  a:b:c ', tiers, selectedTier: 0 })).toEqual(
      ['a:b:c'],
    );
    expect(rememberKeys({ useCustomKey: true, customKey: '   ', tiers, selectedTier: 0 })).toEqual({
      error: 'Enter a permission key to remember.',
    });
  });
});
