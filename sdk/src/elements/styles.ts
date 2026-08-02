/**
 * The theming contract.
 *
 * Every value a host might want to change is a `--overslash-*` custom property,
 * and custom properties inherit *through* the shadow boundary — so branding
 * needs no piercing at all. Anything the tokens do not reach is still reachable
 * with `::part()`, because every structural node carries one.
 *
 * Defaults are derived from the dashboard's design tokens but deliberately
 * neutral: a widget should look like the product it is embedded in, not like
 * Overslash wearing someone else's colours.
 */

export const TOKENS = `
:host {
  --overslash-font: var(--overslash-font-family, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif);
  --overslash-font-mono-resolved: var(--overslash-font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);

  --_bg: var(--overslash-bg, #ffffff);
  --_bg-subtle: var(--overslash-bg-subtle, #f5f5f7);
  --_fg: var(--overslash-fg, #383a42);
  --_fg-heading: var(--overslash-fg-heading, #17191c);
  --_muted: var(--overslash-muted, #737580);
  --_border: var(--overslash-border, #e8e8ee);
  --_radius: var(--overslash-radius, 8px);
  --_space: var(--overslash-spacing, 8px);

  --_accent: var(--overslash-accent, #6359d9);
  --_accent-fg: var(--overslash-accent-fg, #ffffff);
  --_danger: var(--overslash-danger, #e63836);
  --_warn: var(--overslash-warn, #ebb01e);
  --_ok: var(--overslash-ok, #21b86b);

  --_risk-low: var(--overslash-risk-low, var(--_ok));
  --_risk-med: var(--overslash-risk-med, var(--_warn));
  --_risk-high: var(--overslash-risk-high, var(--_danger));

  --_shadow: var(--overslash-shadow, 0 1px 2px rgba(0, 0, 0, 0.06));

  display: block;
  font: 400 14px/20px var(--overslash-font);
  color: var(--_fg);
  box-sizing: border-box;
}

:host([hidden]) { display: none; }
*, *::before, *::after { box-sizing: inherit; }
`;

/** Shared chrome: buttons, fields, the JSON viewer's colour classes. */
export const BASE = `
.card {
  background: var(--_bg);
  border: 1px solid var(--_border);
  border-radius: var(--_radius);
  box-shadow: var(--_shadow);
  overflow: hidden;
}

.risk-bar { height: 3px; background: var(--_risk-med); }
.risk-bar[data-risk='low'] { background: var(--_risk-low); }
.risk-bar[data-risk='med'] { background: var(--_risk-med); }
.risk-bar[data-risk='high'] { background: var(--_risk-high); }

.body { padding: calc(var(--_space) * 2); display: grid; gap: var(--_space); }
.title { font-weight: 600; color: var(--_fg-heading); margin: 0; }
.meta { color: var(--_muted); font-size: 12px; }

.row { display: flex; gap: var(--_space); align-items: center; flex-wrap: wrap; }
.actions {
  display: flex;
  gap: var(--_space);
  flex-wrap: wrap;
  padding: var(--_space) calc(var(--_space) * 2) calc(var(--_space) * 2);
}

button {
  font: inherit;
  font-weight: 500;
  padding: 6px 12px;
  border-radius: calc(var(--_radius) - 2px);
  border: 1px solid var(--_border);
  background: var(--_bg);
  color: var(--_fg);
  cursor: pointer;
}
button:hover:not(:disabled) { background: var(--_bg-subtle); }
button:disabled { opacity: 0.55; cursor: default; }
/* Never remove the ring: this control authorises an action. */
button:focus-visible, input:focus-visible, select:focus-visible {
  outline: 2px solid var(--_accent);
  outline-offset: 2px;
}
button.primary { background: var(--_accent); border-color: var(--_accent); color: var(--_accent-fg); }
button.primary:hover:not(:disabled) { filter: brightness(0.94); }
button.danger { color: var(--_danger); border-color: var(--_danger); }
button.danger:hover:not(:disabled) { background: var(--_danger); color: #fff; }

input, select {
  font: inherit;
  padding: 6px 8px;
  border: 1px solid var(--_border);
  border-radius: calc(var(--_radius) - 2px);
  background: var(--_bg);
  color: var(--_fg);
}
/* Text fields fill their row; a radio or checkbox stretched to 100% pushes its
   own label off to the far side. */
input:not([type='radio']):not([type='checkbox']) { width: 100%; }
select { width: auto; }
input[type='radio'], input[type='checkbox'] { flex: none; padding: 0; margin: 0; }

.chip {
  display: inline-block;
  font: 400 12px/16px var(--overslash-font-mono-resolved);
  background: var(--_bg-subtle);
  border: 1px solid var(--_border);
  border-radius: 999px;
  padding: 2px 8px;
}

.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}
.badge::before {
  content: '';
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: currentColor;
}
.badge[data-risk='low'] { color: var(--_risk-low); }
.badge[data-risk='med'] { color: var(--_risk-med); }
.badge[data-risk='high'] { color: var(--_risk-high); }

.error { color: var(--_danger); font-size: 13px; }
.empty { color: var(--_muted); padding: calc(var(--_space) * 2); text-align: center; }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 4px 0; vertical-align: top; }
th { color: var(--_muted); font-weight: 500; width: 30%; }

pre {
  margin: 0;
  padding: var(--_space);
  background: var(--_bg-subtle);
  border-radius: calc(var(--_radius) - 2px);
  overflow: auto;
  max-height: 320px;
  font: 400 12px/18px var(--overslash-font-mono-resolved);
  white-space: pre-wrap;
  word-break: break-word;
}
.json-key { color: var(--_accent); }
.json-string { color: var(--_ok); }
.json-number, .json-bool { color: var(--_warn); }
.json-null, .json-bracket { color: var(--_muted); }

/* Announced to screen readers, invisible to everyone else. */
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
  border: 0;
}

@media (prefers-reduced-motion: no-preference) {
  .spin { animation: overslash-spin 1s linear infinite; }
}
@keyframes overslash-spin { to { transform: rotate(360deg); } }
`;

/** One parsed sheet per distinct CSS string, shared by every instance. */
const sheetCache = new Map<string, CSSStyleSheet>();

/**
 * Attach the shared stylesheet to a shadow root.
 *
 * Constructable stylesheets are parsed once no matter how many cards are on the
 * page. The `<style>` clone covers browsers without `adoptedStyleSheets`
 * (Safari before 16.4), which costs a little memory per element and nothing
 * else — worth it silently rather than as a documented caveat.
 */
export function adoptStyles(root: ShadowRoot, css: string): void {
  const supportsConstructable =
    typeof CSSStyleSheet !== 'undefined' &&
    typeof Document !== 'undefined' &&
    'adoptedStyleSheets' in Document.prototype &&
    'replaceSync' in CSSStyleSheet.prototype;

  if (!supportsConstructable) {
    const style = document.createElement('style');
    style.textContent = css;
    root.appendChild(style);
    return;
  }

  let sheet = sheetCache.get(css);
  if (!sheet) {
    sheet = new CSSStyleSheet();
    sheet.replaceSync(css);
    sheetCache.set(css, sheet);
  }
  root.adoptedStyleSheets = [...root.adoptedStyleSheets, sheet];
}
