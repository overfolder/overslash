/**
 * Custom elements.
 *
 * Importing this module registers nothing — call `defineOverslashElements()`.
 * That keeps the import side-effect free, so it survives SSR bundling, and lets
 * two SDK versions coexist on one page under different tag names.
 */

import { OverslashProvider } from './provider.js';
import { OverslashApprovalCard } from './approval-card.js';
import { OverslashApprovalList } from './approval-list.js';
import { OverslashSecretPrompt } from './secret-prompt.js';
import { OverslashConnectButton } from './connect-button.js';

export { OverslashElement } from './base.js';
export { OverslashProvider } from './provider.js';
export { OverslashApprovalCard } from './approval-card.js';
export { OverslashApprovalList } from './approval-list.js';
export { OverslashSecretPrompt } from './secret-prompt.js';
export { OverslashConnectButton } from './connect-button.js';
export { configureOverslash, resetOverslash } from './context.js';
export type { OverslashContext } from './context.js';
export { BASE as OVERSLASH_BASE_CSS, TOKENS as OVERSLASH_TOKEN_CSS } from './styles.js';

export interface DefineOptions {
  /** Tag prefix. Defaults to `overslash`. */
  prefix?: string;
}

/**
 * Register the elements.
 *
 * Safe to call more than once: an already-registered tag is skipped rather than
 * throwing, which matters under hot reload and in a page that loads the SDK
 * from two bundles.
 */
export function defineOverslashElements(options: DefineOptions = {}): void {
  if (typeof window === 'undefined' || !window.customElements) return;

  const prefix = options.prefix ?? 'overslash';

  define(`${prefix}-provider`, OverslashProvider);
  define(`${prefix}-approval-card`, OverslashApprovalCard);
  define(`${prefix}-approval-list`, OverslashApprovalList);
  define(`${prefix}-secret-prompt`, OverslashSecretPrompt);
  define(`${prefix}-connect-button`, OverslashConnectButton);
}

/**
 * Register a tag, tolerating both forms of "already done".
 *
 * A constructor can only be registered **once** per registry, so a second call
 * under a different prefix has to hand over a distinct class — hence the empty
 * subclass. Without it, `defineOverslashElements({ prefix })` throws for any
 * page that also registered the defaults.
 */
function define(tag: string, ctor: CustomElementConstructor): void {
  if (customElements.get(tag)) return;
  const alreadyUsed = customElements.getName?.(ctor) != null;
  customElements.define(tag, alreadyUsed ? class extends ctor {} : ctor);
}
