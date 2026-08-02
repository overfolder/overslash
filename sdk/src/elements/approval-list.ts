/**
 * `<overslash-approval-list>` — the queue.
 *
 * Composes one `<overslash-approval-card>` per row rather than reimplementing
 * the card, so a fix to how an approval reads lands in both places.
 */

import {
  createApprovalListController,
  type ApprovalListController,
} from '../controllers/approval-list.js';
import type { ApprovalResponse, ApprovalScope, ApprovalStatus } from '../types/approvals.js';
import { escapeHtml } from '../format/index.js';
import { OverslashElement } from './base.js';
import type { OverslashContext } from './context.js';
import type { OverslashApprovalCard } from './approval-card.js';

export class OverslashApprovalList extends OverslashElement {
  private controller: ApprovalListController | null = null;
  /**
   * Row tag. Defaults to this element's own prefix — an `<acme-approval-list>`
   * builds `<acme-approval-card>` rows — so a page registering the SDK twice
   * under two prefixes keeps each list on its own version, with no global state
   * for the second registration to overwrite.
   */
  cardTag: string | null = null;

  static get observedAttributes(): string[] {
    return ['scope', 'status', 'readonly'];
  }

  attributeChangedCallback(name: string): void {
    if (!this.isConnected) return;
    if (name === 'readonly') {
      this.queueRender();
      return;
    }
    this.controller?.setFilters({
      scope: (this.attr('scope') as ApprovalScope | undefined) ?? 'assigned',
      ...(this.attr('status') ? { status: this.attr('status') as ApprovalStatus } : {}),
    });
  }

  protected setup(context: OverslashContext | null): void {
    this.controller = null;
    if (!context) return;

    this.controller = this.own(
      createApprovalListController(context.client, {
        scope: (this.attr('scope') as ApprovalScope | undefined) ?? 'assigned',
        ...(this.attr('status') ? { status: this.attr('status') as ApprovalStatus } : {}),
        events: context.events,
      }),
    ) as ApprovalListController;
  }

  protected override styles(): string {
    return `
      .list { display: grid; gap: var(--_space); }
      .head { display: flex; justify-content: space-between; align-items: center; gap: var(--_space); }
      .live { font-size: 12px; color: var(--_muted); display: inline-flex; align-items: center; gap: 5px; }
      .live::before { content: ''; width: 7px; height: 7px; border-radius: 50%; background: var(--_muted); }
      .live[data-state='live']::before { background: var(--_ok); }
    `;
  }

  protected render(): void {
    const state = this.controller?.getState();

    if (!this.controller) {
      this.root.innerHTML = `<div class="empty" part="empty">${escapeHtml(
        this.text('unconfigured', 'No Overslash client configured.'),
      )}</div>`;
      return;
    }

    if (state?.loading && !state.approvals.length) {
      this.root.innerHTML = `<div class="empty" part="empty">${escapeHtml(
        this.text('loading', 'Loading…'),
      )}</div>`;
      return;
    }

    if (state?.error && !state.approvals.length) {
      this.root.innerHTML = `<div class="error" part="error" role="alert">${escapeHtml(
        state.error,
      )}</div>`;
      return;
    }

    const streamState = this.activeContext?.events.status ?? 'idle';
    const approvals = state?.approvals ?? [];

    this.root.innerHTML = `
      <div class="head" part="header">
        <slot name="header"></slot>
        <span class="live" part="live" data-state="${streamState}">${escapeHtml(
          streamState === 'live'
            ? this.text('live', 'Live')
            : this.text('polling', 'Auto-refresh'),
        )}</span>
      </div>
      ${
        approvals.length
          ? `<div class="list" part="list"></div>`
          : `<div class="empty" part="empty"><slot name="empty">${escapeHtml(
              this.text('empty', 'Nothing waiting on you.'),
            )}</slot></div>`
      }
      <div class="sr-only" role="status" aria-live="polite">${escapeHtml(
        `${approvals.length} approval${approvals.length === 1 ? '' : 's'} awaiting a decision`,
      )}</div>
    `;

    const list = this.root.querySelector('.list');
    if (!list) return;

    for (const approval of approvals) {
      list.appendChild(this.card(approval));
    }
  }

  private card(approval: ApprovalResponse): HTMLElement {
    const card = document.createElement(
      this.cardTag ?? this.localName.replace(/-approval-list$/, '-approval-card'),
    ) as OverslashApprovalCard;
    card.setAttribute('part', 'row');
    if (this.hasAttribute('readonly')) card.setAttribute('readonly', '');
    // The card would resolve its own context through the provider chain, but
    // pass it explicitly so a list handed a client directly still works.
    if (this.activeContext) card.context = this.activeContext;
    card.approval = approval;
    card.strings = this.strings;

    card.addEventListener('resolved', (event) => {
      const detail = (event as CustomEvent<{ approval: ApprovalResponse }>).detail;
      // Drop it now, with its cascade. The refetch is coming, but a row that
      // lingers invites a second click on something already gone.
      this.controller?.dropResolved(detail.approval);
    });

    return card;
  }
}
