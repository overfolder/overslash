/**
 * The one place polling cadence lives.
 *
 * Today this logic is inlined in three dashboard files with three slightly
 * different shapes. Centralising it means the wall-clock cap, the
 * skip-while-in-flight guard and the stream-aware tick skip cannot drift apart.
 */

export interface PollSchedulerOptions {
  intervalMs?: number;
  /**
   * Stop after this long, measured from when polling *started* — not from the
   * last response. A cap anchored to the last response never expires under a
   * slow server, which is the opposite of what a cap is for.
   */
  deadlineMs?: number;
  /**
   * Consulted before every tick. Returning true skips it. The event stream sets
   * this while it is live: polling on top of a working stream is duplicate
   * requests, and dropping the timer entirely would leave nothing to fall back
   * to when the stream dies.
   */
  shouldSkip?: () => boolean;
  /** Pause while the document is hidden. Defaults to true in a browser. */
  pauseWhenHidden?: boolean;
  onError?: (e: unknown) => void;
}

export class PollScheduler {
  private timer: ReturnType<typeof setInterval> | null = null;
  private startedAt = 0;
  private inFlight = false;
  private visibilityHandler: (() => void) | null = null;

  constructor(
    private readonly tick: () => Promise<void>,
    private readonly opts: PollSchedulerOptions = {},
  ) {}

  get running(): boolean {
    return this.timer !== null;
  }

  /** Idempotent: calling `start` on a running scheduler does not reset the deadline. */
  start(): void {
    if (this.timer !== null) return;
    this.startedAt = Date.now();
    const interval = this.opts.intervalMs ?? 1500;
    this.timer = setInterval(() => void this.run(), interval);
    this.watchVisibility();
  }

  /** Restart the deadline window — e.g. when the watched resource changes. */
  restart(): void {
    this.stop();
    this.start();
  }

  stop(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.unwatchVisibility();
  }

  private async run(): Promise<void> {
    const { deadlineMs, shouldSkip } = this.opts;

    if (deadlineMs !== undefined && Date.now() - this.startedAt > deadlineMs) {
      this.stop();
      return;
    }
    if (shouldSkip?.()) return;
    if (this.inFlight) return;
    if (this.hidden()) return;

    this.inFlight = true;
    try {
      await this.tick();
    } catch (e) {
      // Transient by assumption. A poll failure must not stomp the error a
      // user action produced, which is the one the UI is showing.
      this.opts.onError?.(e);
    } finally {
      this.inFlight = false;
    }
  }

  private hidden(): boolean {
    if (this.opts.pauseWhenHidden === false) return false;
    return typeof document !== 'undefined' && document.visibilityState === 'hidden';
  }

  /** Fire immediately on becoming visible, rather than waiting out the interval. */
  private watchVisibility(): void {
    if (this.opts.pauseWhenHidden === false) return;
    if (typeof document === 'undefined' || !document.addEventListener) return;
    this.visibilityHandler = () => {
      if (document.visibilityState === 'visible') void this.run();
    };
    document.addEventListener('visibilitychange', this.visibilityHandler);
  }

  private unwatchVisibility(): void {
    if (!this.visibilityHandler) return;
    if (typeof document !== 'undefined' && document.removeEventListener) {
      document.removeEventListener('visibilitychange', this.visibilityHandler);
    }
    this.visibilityHandler = null;
  }
}
