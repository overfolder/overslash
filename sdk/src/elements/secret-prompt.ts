/**
 * `<overslash-secret-prompt>` — the inline "paste your credential" form.
 *
 * Uses the public provide endpoints, which authenticate with the request's own
 * single-use token rather than the page's credential. That is what lets the
 * form live in the host's UI instead of bouncing the user to the Overslash
 * dashboard, which for a white-label product is a domain their user has never
 * heard of.
 */

import { createProvideController, type ProvideController } from '../controllers/provide.js';
import { escapeHtml } from '../format/index.js';
import { OverslashElement } from './base.js';
import type { OverslashContext } from './context.js';

export class OverslashSecretPrompt extends OverslashElement {
  private controller: ProvideController | null = null;

  static get observedAttributes(): string[] {
    return ['req-id', 'token'];
  }

  attributeChangedCallback(): void {
    if (this.isConnected) this.restart();
  }

  protected setup(context: OverslashContext | null): void {
    this.controller = null;
    if (!context) return;

    const reqId = this.attr('req-id');
    if (!reqId) return;

    this.controller = this.own(
      createProvideController(context.client, {
        reqId,
        ...(this.attr('token') ? { token: this.attr('token') as string } : {}),
      }),
    ) as ProvideController;
  }

  protected override styles(): string {
    return `
      .form { display: grid; gap: var(--_space); }
      .name { font: 400 13px/18px var(--overslash-font-mono-resolved); }
      .reason { color: var(--_muted); font-size: 13px; }
      .done { color: var(--_ok); font-weight: 500; }
    `;
  }

  protected render(): void {
    if (!this.controller) {
      this.root.innerHTML = `<div class="card" part="card"><div class="empty" part="empty">${escapeHtml(
        this.text('unconfigured', 'No secret request specified.'),
      )}</div></div>`;
      return;
    }

    const state = this.controller.getState();
    const terminal = this.terminalMessage(state.status);

    if (terminal) {
      this.root.innerHTML = `<div class="card" part="card"><div class="body" part="body">
        <p class="title" part="title">${escapeHtml(this.text('title', 'Credential request'))}</p>
        <p class="${state.status === 'submitted' ? 'done' : 'meta'}" part="message" role="status">${escapeHtml(
          terminal,
        )}</p>
      </div></div>`;
      return;
    }

    const meta = state.metadata;
    const busy = state.status === 'submitting';

    this.root.innerHTML = `
      <div class="card" part="card">
        <div class="body" part="body">
          <p class="title" part="title">${escapeHtml(this.text('title', 'Credential request'))}</p>
          ${
            meta
              ? `<div class="meta" part="meta">
                   ${escapeHtml(meta.requested_by_label)} ${escapeHtml(
                     this.text('needs', 'needs'),
                   )} <span class="name" part="secret-name">${escapeHtml(meta.secret_name)}</span>
                 </div>
                 ${
                   meta.reason
                     ? `<p class="reason" part="reason">${escapeHtml(meta.reason)}</p>`
                     : ''
                 }`
              : ''
          }

          ${
            state.needsSignIn
              ? `<div part="signin"><slot name="signin">${escapeHtml(
                  this.text(
                    'signInRequired',
                    'This request must be completed while signed in.',
                  ),
                )}</slot></div>`
              : `<form class="form" part="form">
                   <label class="sr-only" for="v">${escapeHtml(
                     meta?.secret_name ?? this.text('value', 'Value'),
                   )}</label>
                   <input id="v" type="password" part="input" autocomplete="off"
                          spellcheck="false" ${busy ? 'disabled' : ''}
                          placeholder="${escapeHtml(this.text('placeholder', 'Paste the value'))}">
                 </form>`
          }

          ${state.error ? `<div class="error" part="error" role="alert">${escapeHtml(state.error)}</div>` : ''}
        </div>
        ${
          state.needsSignIn
            ? ''
            : `<div class="actions" part="actions">
                 <button class="primary" part="button button-submit" data-action="submit" ${
                   busy ? 'disabled' : ''
                 }>${escapeHtml(busy ? this.text('saving', 'Saving…') : this.text('submit', 'Save'))}</button>
               </div>`
        }
      </div>
    `;

    const input = this.root.querySelector<HTMLInputElement>('#v');
    this.root.querySelector('form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      void this.submit(input?.value ?? '');
    });
    this.bind({ submit: () => void this.submit(input?.value ?? '') });
  }

  private terminalMessage(status: string): string | null {
    switch (status) {
      case 'submitted':
        return this.text('submitted', 'Saved. You can close this.');
      case 'expired':
        return this.text('expired', 'This request has expired. Ask for a new link.');
      case 'already_fulfilled':
        return this.text('alreadyFulfilled', 'This request has already been completed.');
      case 'invalid':
        return this.text('invalid', 'This link is not valid.');
      case 'missing_token':
        return this.text('missingToken', 'This link is missing its token.');
      case 'server_error':
        return this.text('serverError', 'Something went wrong. Try again shortly.');
      default:
        return null;
    }
  }

  private async submit(value: string): Promise<void> {
    if (!this.controller) return;
    const ok = await this.controller.submit(value);
    const state = this.controller.getState();
    if (ok) {
      // Deliberately does not carry the value: it went to the vault, and an
      // event bubbles through the host's whole DOM.
      this.emit('submitted', {
        reqId: this.attr('req-id'),
        secretName: state.metadata?.secret_name,
      });
    } else {
      this.emit('error', { message: state.error, status: state.status });
    }
  }
}
