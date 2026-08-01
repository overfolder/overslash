/**
 * `<overslash-connect-button>` — link a provider account.
 *
 * The popup must be opened from the click itself, not from a promise
 * continuation, or the browser blocks it. So the controller's `openWindow` is
 * handed a window this element opened synchronously and later navigates.
 */

import { createConnectController, type ConnectController } from '../controllers/connect.js';
import { escapeHtml, humanize } from '../format/index.js';
import { OverslashElement } from './base.js';
import type { OverslashContext } from './context.js';

export class OverslashConnectButton extends OverslashElement {
  private controller: ConnectController | null = null;
  private pendingWindow: Window | null = null;

  static get observedAttributes(): string[] {
    return ['provider', 'scopes', 'byoc-credential-id', 'on-behalf-of'];
  }

  attributeChangedCallback(): void {
    if (this.isConnected) this.restart();
  }

  protected setup(context: OverslashContext | null): void {
    this.controller = null;
    if (!context) return;

    const provider = this.attr('provider');
    if (!provider) return;

    const scopes = this.attr('scopes')?.split(/[,\s]+/).filter(Boolean);

    this.controller = this.own(
      createConnectController(context.client, {
        provider,
        ...(scopes?.length ? { scopes } : {}),
        ...(this.attr('byoc-credential-id')
          ? { byoc_credential_id: this.attr('byoc-credential-id') as string }
          : {}),
        ...(this.attr('on-behalf-of') ? { on_behalf_of: this.attr('on-behalf-of') as string } : {}),
        events: context.events,
        // The window was opened by the click, before any await. Handing it over
        // here is what keeps the popup blocker satisfied.
        openWindow: (url) => {
          const win = this.pendingWindow;
          this.pendingWindow = null;
          if (!win) return null;
          win.location.href = url;
          return win;
        },
        onNeedsExternalAuth: (info) => this.emit('needs-external-auth', info),
      }),
    ) as ConnectController;
  }

  protected override styles(): string {
    return `
      :host { display: inline-block; }
      .wrap { display: inline-flex; align-items: center; gap: var(--_space); }
      a { color: var(--_accent); font-size: 13px; }
    `;
  }

  protected render(): void {
    const state = this.controller?.getState();
    const provider = this.attr('provider') ?? '';
    const busy = state?.status === 'starting' || state?.status === 'awaiting_user';
    const connected = state?.status === 'connected';

    this.root.innerHTML = `
      <div class="wrap" part="wrap">
        <button class="primary" part="button" data-action="connect" ${
          busy || connected || !this.controller ? 'disabled' : ''
        }>
          ${
            busy
              ? `<span class="spin" aria-hidden="true">◌</span> ${escapeHtml(
                  this.text('connecting', 'Waiting for authorization…'),
                )}`
              : connected
                ? escapeHtml(this.text('connected', 'Connected'))
                : `<slot>${escapeHtml(
                    `${this.text('connect', 'Connect')} ${humanize(provider)}`.trim(),
                  )}</slot>`
          }
        </button>
        ${
          state?.status === 'popup_blocked' && state.authUrl
            ? `<a part="fallback-link" href="${escapeHtml(state.authUrl)}"
                  target="_blank" rel="noopener noreferrer">${escapeHtml(
                    this.text('openManually', 'Open authorization page'),
                  )}</a>`
            : ''
        }
        ${
          state?.status === 'needs_external_auth'
            ? `<span class="meta" part="external-note">${escapeHtml(
                this.text('externalAuth', 'Continue in your own sign-in flow.'),
              )}</span>`
            : ''
        }
        ${
          state?.status === 'timed_out'
            ? `<span class="meta" part="timeout-note">${escapeHtml(
                this.text('timedOut', 'Not completed. Try again.'),
              )}</span>`
            : ''
        }
        ${state?.error ? `<span class="error" part="error" role="alert">${escapeHtml(state.error)}</span>` : ''}
      </div>
      <div class="sr-only" role="status" aria-live="polite">${escapeHtml(state?.status ?? '')}</div>
    `;

    this.bind({ connect: () => void this.connect() });
  }

  private async connect(): Promise<void> {
    if (!this.controller) return;

    // Synchronously, inside the click: anything after an await is no longer a
    // user gesture as far as the popup blocker is concerned.
    this.pendingWindow =
      typeof window !== 'undefined'
        ? window.open('', 'oss_oauth', 'width=520,height=680')
        : null;

    const connection = await this.controller.start();
    if (connection) {
      this.emit('connected', { connection });
    } else if (this.controller.getState().status === 'error') {
      this.emit('error', { message: this.controller.getState().error });
    }
    // A window we opened and never navigated would sit there blank.
    this.pendingWindow?.close();
    this.pendingWindow = null;
  }
}
