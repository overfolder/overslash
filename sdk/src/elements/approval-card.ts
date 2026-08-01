/**
 * `<overslash-approval-card>` — one approval, and the controls to decide it.
 *
 * This is the element the whole SDK exists for. What it shows is what a person
 * is agreeing to, so the rendering rules are not cosmetic: disclosed fields the
 * template marked `primary` lead, permission keys are shown rather than counted,
 * and risk is carried by a label as well as a colour.
 */

import { createApprovalController, type ApprovalController } from '../controllers/approval.js';
import type { ApprovalResponse, Resolution, SuggestedTier } from '../types/approvals.js';
import {
  escapeHtml,
  extractAgentName,
  formatBytes,
  humanize,
  renderPayload,
  resolutionToast,
  scopeArgSummary,
  splitDisclosed,
  splitKeys,
  TTL_OPTIONS,
} from '../format/index.js';
import { OverslashElement } from './base.js';
import type { OverslashContext } from './context.js';

const RISK_LABEL: Record<string, string> = { low: 'Low risk', med: 'Write', high: 'Destructive' };

export class OverslashApprovalCard extends OverslashElement {
  private controller: ApprovalController | null = null;
  private seed: ApprovalResponse | null = null;
  private showPayload = false;
  private rememberTier: number | null = null;
  private ttl = 'forever';

  static get observedAttributes(): string[] {
    return ['approval-id', 'readonly', 'hide-payload'];
  }

  /** Render an approval you already hold — no round trip. */
  set approval(value: ApprovalResponse | null) {
    this.seed = value;
    if (this.isConnected) this.restart();
  }

  get approval(): ApprovalResponse | null {
    return this.controller?.getState().approval ?? this.seed;
  }

  attributeChangedCallback(name: string): void {
    if (!this.isConnected) return;
    if (name === 'approval-id') this.restart();
    else this.queueRender();
  }

  protected setup(context: OverslashContext | null): void {
    this.controller = null;
    if (!context) return;

    const id = this.attr('approval-id') ?? this.seed?.id;
    if (!id) return;

    this.controller = this.own(
      createApprovalController(context.client, {
        ...(this.seed ? { approval: this.seed } : { id }),
        events: context.events,
        onResolved: (approval) => {
          this.emit('resolved', {
            approval,
            resolution: this.lastResolution,
            message: this.lastResolution
              ? resolutionToast(this.lastResolution, approval, approval, this.rememberKeys())
              : '',
          });
        },
      }),
    ) as ApprovalController;
  }

  private lastResolution: Resolution | null = null;

  private rememberKeys(): string[] | undefined {
    const tiers = this.approval?.suggested_tiers ?? [];
    if (this.rememberTier === null) return undefined;
    return tiers[this.rememberTier]?.keys;
  }

  protected override styles(): string {
    return `
      .head { display: flex; justify-content: space-between; gap: var(--_space); align-items: start; }
      .hero { font-size: 16px; font-weight: 600; color: var(--_fg-heading); }
      .hero-label { color: var(--_muted); font-size: 12px; font-weight: 400; }
      .keys { display: flex; flex-wrap: wrap; gap: 4px; }
      .exec { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--_muted); }
      .exec[data-state='failed'] { color: var(--_danger); }
      .exec[data-state='executed'] { color: var(--_ok); }
      .disclosed-error { color: var(--_danger); font-style: italic; }
      details > summary { cursor: pointer; color: var(--_muted); font-size: 13px; }
      .remember { display: grid; gap: 6px; padding-top: var(--_space); border-top: 1px solid var(--_border); }
      .remember label {
        display: flex;
        gap: 8px;
        align-items: center;
        justify-content: flex-start;
        font-size: 13px;
        cursor: pointer;
      }
    `;
  }

  protected render(): void {
    const state = this.controller?.getState();
    const approval = state?.approval ?? this.seed;

    if (!approval) {
      this.root.innerHTML = `<div class="card" part="card"><div class="empty" part="empty">${escapeHtml(
        this.controller
          ? this.text('loading', 'Loading approval…')
          : this.text('unconfigured', 'No Overslash client configured.'),
      )}</div></div>`;
      return;
    }

    const readonly = this.hasAttribute('readonly') || !this.controller;
    const submitting = state?.submitting ?? false;
    const pending = state?.isPending ?? approval.status === 'pending';
    const { primaries, remaining } = splitDisclosed(approval.disclosed_fields);
    const { shown, hidden } = splitKeys(approval.permission_keys);
    const agent = extractAgentName(approval.identity_path, approval.requesting_identity_id);
    const service = approval.derived_keys[0] ? humanize(approval.derived_keys[0].service) : '';
    const riskLabel = RISK_LABEL[approval.risk] ?? approval.risk;

    this.root.innerHTML = `
      <div class="card" part="card" role="group" aria-labelledby="t">
        <div class="risk-bar" part="risk-bar" data-risk="${approval.risk}"></div>
        <div class="body" part="body">
          <div class="head" part="header">
            <div>
              <p class="title" id="t" part="title">${escapeHtml(approval.action_summary)}</p>
              <div class="meta" part="meta">${escapeHtml(agent)}${
                service ? ` → ${escapeHtml(service)}` : ''
              }</div>
            </div>
            <span class="badge" part="risk-badge" data-risk="${approval.risk}">${escapeHtml(riskLabel)}</span>
          </div>

          ${primaries
            .map(
              (f) => `<div part="disclosed-primary">
                <div class="hero-label">${escapeHtml(f.label)}</div>
                <div class="hero">${escapeHtml(f.value ?? '')}</div>
              </div>`,
            )
            .join('')}

          ${
            remaining.length
              ? `<table part="disclosed"><tbody>${remaining
                  .map(
                    (f) => `<tr>
                      <th>${escapeHtml(f.label)}</th>
                      <td>${
                        f.error
                          ? `<span class="disclosed-error">${escapeHtml(f.error)}</span>`
                          : escapeHtml(f.value ?? '—')
                      }${f.truncated ? ' <span class="meta">(truncated)</span>' : ''}</td>
                    </tr>`,
                  )
                  .join('')}</tbody></table>`
              : ''
          }

          <div part="scope" class="meta">${escapeHtml(scopeArgSummary(approval.derived_keys))}</div>

          <div class="keys" part="keys">
            ${shown.map((k) => `<span class="chip" part="key">${escapeHtml(k)}</span>`).join('')}
            ${hidden > 0 ? `<span class="chip" part="key-more">+${hidden}</span>` : ''}
          </div>

          ${this.payloadBlock(approval)}
          ${pending && !readonly ? this.rememberBlock(approval.suggested_tiers) : ''}
          ${this.executionBlock(state)}
          ${state?.error ? `<div class="error" part="error" role="alert">${escapeHtml(state.error)}</div>` : ''}
        </div>

        ${
          pending && !readonly
            ? `<div class="actions" part="actions">
                 <button class="primary" part="button button-allow" data-action="allow" ${
                   submitting ? 'disabled' : ''
                 }>${escapeHtml(
                   this.rememberTier === null
                     ? this.text('allow', 'Allow once')
                     : this.text('allowRemember', 'Allow & remember'),
                 )}</button>
                 <button class="danger" part="button button-deny" data-action="deny" ${
                   submitting ? 'disabled' : ''
                 }>${escapeHtml(this.text('deny', 'Deny'))}</button>
                 <button part="button button-bubble" data-action="bubble" ${
                   submitting ? 'disabled' : ''
                 }>${escapeHtml(this.text('bubble', 'Ask someone else'))}</button>
               </div>`
            : ''
        }
        <div class="sr-only" role="status" aria-live="polite" part="status">${escapeHtml(
          this.statusText(state, approval),
        )}</div>
      </div>
    `;

    this.wire();
  }

  private payloadBlock(approval: ApprovalResponse): string {
    if (this.hasAttribute('hide-payload') || !approval.action_detail) return '';
    const size = approval.action_detail_size_bytes
      ? ` (${formatBytes(approval.action_detail_size_bytes)}${
          approval.action_detail_truncated ? ', truncated' : ''
        })`
      : '';
    return `<details part="payload" ${this.showPayload ? 'open' : ''}>
      <summary data-action="toggle-payload">${escapeHtml(
        this.text('payload', 'Request payload'),
      )}${escapeHtml(size)}</summary>
      <pre part="payload-body">${renderPayload(approval.action_detail)}</pre>
    </details>`;
  }

  private rememberBlock(tiers: SuggestedTier[]): string {
    if (!tiers.length) return '';
    return `<div class="remember" part="remember">
      <label part="remember-option">
        <input type="radio" name="tier" data-action="tier--1" ${
          this.rememberTier === null ? 'checked' : ''
        }>
        ${escapeHtml(this.text('justOnce', 'Just this once'))}
      </label>
      ${tiers
        .map(
          (tier, i) => `<label part="remember-option">
            <input type="radio" name="tier" data-action="tier-${i}" ${
              this.rememberTier === i ? 'checked' : ''
            }>
            ${escapeHtml(tier.description)}
          </label>`,
        )
        .join('')}
      ${
        this.rememberTier !== null
          ? `<label part="remember-ttl">${escapeHtml(this.text('ttl', 'For'))}
              <select data-action="ttl">
                ${TTL_OPTIONS.map(
                  (o) =>
                    `<option value="${o.value}" ${o.value === this.ttl ? 'selected' : ''}>${escapeHtml(
                      o.label,
                    )}</option>`,
                ).join('')}
              </select>
            </label>`
          : ''
      }
    </div>`;
  }

  private executionBlock(state: ReturnType<ApprovalController['getState']> | undefined): string {
    const execution = state?.execution;
    if (!execution) return '';
    const running = state?.executionPending || state?.executionRunning;
    return `<div class="exec" part="execution" data-state="${escapeHtml(execution.status)}">
      ${running ? '<span class="spin" aria-hidden="true">◌</span>' : ''}
      <span>${escapeHtml(this.executionText(execution.status))}</span>
      ${
        running
          ? `<button part="button button-cancel" data-action="cancel">${escapeHtml(
              this.text('cancel', 'Cancel'),
            )}</button>`
          : ''
      }
    </div>`;
  }

  private executionText(status: string): string {
    switch (status) {
      case 'pending':
        return this.text('execPending', 'Queued to run…');
      case 'executing':
        return this.text('execRunning', 'Running…');
      case 'executed':
        return this.text('execDone', 'Completed');
      case 'failed':
        return this.text('execFailed', 'Failed');
      case 'cancelled':
        return this.text('execCancelled', 'Cancelled');
      case 'expired':
        return this.text('execExpired', 'Expired before it ran');
      default:
        return status;
    }
  }

  private statusText(
    state: ReturnType<ApprovalController['getState']> | undefined,
    approval: ApprovalResponse,
  ): string {
    if (state?.error) return state.error;
    if (state?.execution) return this.executionText(state.execution.status);
    return approval.status === 'pending' ? 'Awaiting your decision' : `Approval ${approval.status}`;
  }

  private wire(): void {
    const tiers = this.approval?.suggested_tiers ?? [];

    this.bind({
      allow: () => void this.decide(this.rememberTier === null ? 'allow' : 'allow_remember'),
      deny: () => void this.decide('deny'),
      bubble: () => void this.decide('bubble_up'),
      cancel: () => {
        void this.controller?.cancelExecution();
      },
      'toggle-payload': () => {
        this.showPayload = !this.showPayload;
      },
      'tier--1': () => {
        this.rememberTier = null;
        this.queueRender();
      },
      ...Object.fromEntries(
        tiers.map((_, i) => [
          `tier-${i}`,
          () => {
            this.rememberTier = i;
            this.queueRender();
          },
        ]),
      ),
    });

    const ttl = this.root.querySelector<HTMLSelectElement>('[data-action="ttl"]');
    ttl?.addEventListener('change', () => {
      this.ttl = ttl.value;
    });
  }

  private async decide(resolution: Resolution): Promise<void> {
    if (!this.controller) return;
    this.lastResolution = resolution;

    const keys = resolution === 'allow_remember' ? this.rememberKeys() : undefined;
    const updated = await this.controller.resolve({
      resolution,
      ...(keys ? { remember_keys: keys } : {}),
      // `forever` is the absence of a TTL, not a value the API knows.
      ...(keys && this.ttl !== 'forever' ? { ttl: this.ttl } : {}),
    });

    if (!updated) {
      this.emit('error', { message: this.controller.getState().error });
    }
  }
}
