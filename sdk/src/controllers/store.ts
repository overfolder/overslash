/**
 * The store contract every controller implements.
 *
 * This is `useSyncExternalStore`'s signature verbatim, so React consumes a
 * controller in one line and a Svelte `readable` wraps it in three. Shipping
 * framework bindings would buy nothing and cost two more packages to version
 * (D46).
 *
 * ```ts
 * // React
 * const state = useSyncExternalStore(ctrl.subscribe, ctrl.getState);
 *
 * // Svelte
 * const state = readable(ctrl.getState(), (set) => ctrl.subscribe(() => set(ctrl.getState())));
 * ```
 */
export interface Store<T> {
  /** Stable reference until the state actually changes. */
  getState(): T;
  subscribe(listener: () => void): () => void;
  /** Stop timers, abort in-flight requests, drop subscriptions. */
  dispose(): void;
}

/**
 * Minimal observable state cell.
 *
 * State objects are replaced rather than mutated, so referential equality is a
 * valid change check — which is what `useSyncExternalStore` requires to avoid
 * an infinite render loop.
 */
export function createStore<T extends object>(initial: T) {
  let state = initial;
  const listeners = new Set<() => void>();
  let disposed = false;

  return {
    getState: (): T => state,

    subscribe(listener: () => void): () => void {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    /** Merge a patch and notify. A no-op patch does not notify. */
    set(patch: Partial<T>): void {
      if (disposed) return;
      let changed = false;
      for (const k of Object.keys(patch) as Array<keyof T>) {
        if (!Object.is(state[k], patch[k])) {
          changed = true;
          break;
        }
      }
      if (!changed) return;
      state = { ...state, ...patch };
      emit(listeners);
    },

    get disposed(): boolean {
      return disposed;
    },

    markDisposed(): void {
      disposed = true;
      listeners.clear();
    },
  };
}

function emit(listeners: Set<() => void>): void {
  for (const listener of [...listeners]) {
    try {
      listener();
    } catch (e) {
      // One bad subscriber must not stop delivery to the others.
      reportError(e);
    }
  }
}

/** Log without assuming a console-shaped global exists. */
export function reportError(e: unknown): void {
  if (typeof console !== 'undefined' && console.error) {
    console.error('[overslash-sdk]', e);
  }
}
