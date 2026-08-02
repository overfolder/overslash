/**
 * Shared plumbing for every element: a shadow root, the stylesheet, context
 * resolution, controller lifecycle, and a render pass batched to a microtask.
 */

import type { Store } from '../controllers/store.js';
import { adoptStyles, BASE, TOKENS } from './styles.js';
import {
  onContextChanged,
  resolveContext,
  type OverslashContext,
} from './context.js';

export abstract class OverslashElement extends HTMLElement {
  protected readonly root: ShadowRoot;
  private ownContext: OverslashContext | null = null;
  private resolved: OverslashContext | null = null;
  private controllers: Array<Store<unknown>> = [];
  private unsubscribes: Array<() => void> = [];
  private renderQueued = false;
  private connected = false;

  /** Copy overrides, merged over the element's English defaults. */
  strings: Record<string, string> = {};

  constructor() {
    super();
    this.root = this.attachShadow({ mode: 'open' });
    adoptStyles(this.root, TOKENS + BASE + this.styles());
  }

  /** Per-element CSS, appended to the shared base. */
  protected styles(): string {
    return '';
  }

  /**
   * Set the client explicitly. Highest precedence — this is what a React `ref`
   * or a Svelte `bind:this` assigns.
   */
  set context(value: OverslashContext | null) {
    this.ownContext = value;
    if (this.connected) this.restart();
  }

  get context(): OverslashContext | null {
    return this.ownContext;
  }

  /**
   * The context actually in use — the assigned one, a provider's, or the global
   * default. Null until `connectedCallback`, and whenever nothing is configured.
   */
  protected get activeContext(): OverslashContext | null {
    return this.resolved;
  }

  private offContextChanged: (() => void) | null = null;

  connectedCallback(): void {
    this.connected = true;
    // A host usually assigns the context *after* mount, so an element that
    // resolved nothing here has to be told when one turns up.
    this.offContextChanged = onContextChanged(() => {
      if (!this.connected) return;
      if (resolveContext(this, this.ownContext) === this.resolved) return;
      this.restart();
    });
    this.restart();
  }

  disconnectedCallback(): void {
    this.connected = false;
    this.offContextChanged?.();
    this.offContextChanged = null;
    this.teardown();
  }

  /** Rebuild controllers against the currently-resolved context. */
  protected restart(): void {
    this.teardown();
    this.resolved = resolveContext(this, this.ownContext);
    this.setup(this.resolved);
    this.queueRender();
  }

  /** Build controllers. Called with `null` when nothing is configured yet. */
  protected abstract setup(context: OverslashContext | null): void;

  protected abstract render(): void;

  /** Register a controller so it is disposed with the element. */
  protected own<T>(controller: Store<T>): Store<T> {
    this.controllers.push(controller as Store<unknown>);
    this.unsubscribes.push(controller.subscribe(() => this.queueRender()));
    return controller;
  }

  protected track(unsubscribe: () => void): void {
    this.unsubscribes.push(unsubscribe);
  }

  private teardown(): void {
    for (const off of this.unsubscribes) off();
    for (const c of this.controllers) c.dispose();
    this.unsubscribes = [];
    this.controllers = [];
  }

  /**
   * Batch renders onto a microtask: a controller can set several fields in one
   * turn, and each would otherwise repaint.
   */
  protected queueRender(): void {
    if (this.renderQueued) return;
    this.renderQueued = true;
    queueMicrotask(() => {
      this.renderQueued = false;
      if (!this.connected) return;
      this.render();
    });
  }

  protected emit<T>(name: string, detail: T): void {
    this.dispatchEvent(new CustomEvent<T>(name, { detail, bubbles: true, composed: true }));
  }

  protected text(key: string, fallback: string): string {
    return this.strings[key] ?? fallback;
  }

  /** Attribute value, or undefined when absent or empty. */
  protected attr(name: string): string | undefined {
    const v = this.getAttribute(name);
    return v === null || v === '' ? undefined : v;
  }

  /**
   * Bind click handlers by `data-action`.
   *
   * Re-bound on every render, which is fine because the render replaces the
   * nodes, and is what keeps the templates plain strings.
   */
  protected bind(handlers: Record<string, (el: HTMLElement) => void>): void {
    for (const [action, handler] of Object.entries(handlers)) {
      for (const el of this.root.querySelectorAll<HTMLElement>(`[data-action="${action}"]`)) {
        el.addEventListener('click', () => handler(el));
      }
    }
  }
}
