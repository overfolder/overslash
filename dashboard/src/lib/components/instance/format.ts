// Display helpers for the Instance Admin panel. Pure, so they can be tested
// without a browser.

export type Tone = 'neutral' | 'primary' | 'success' | 'warning' | 'error';

export const PLAN_LABEL: Record<string, string> = {
	standard: 'Standard',
	trial: 'Trial',
	free_unlimited: 'Free unlimited'
};

export const PLAN_TONE: Record<string, Tone> = {
	standard: 'neutral',
	trial: 'primary',
	free_unlimited: 'success'
};

const DAY = 86_400;

/** `3m ago`, `1h ago`, `4d ago`, `2w ago`; `now` under a minute. */
export function relativeAgo(unixSecs: number, nowSecs = Date.now() / 1000): string {
	const d = Math.max(0, nowSecs - unixSecs);
	if (d < 60) return 'now';
	if (d < 3600) return `${Math.floor(d / 60)}m ago`;
	if (d < DAY) return `${Math.floor(d / 3600)}h ago`;
	if (d < 14 * DAY) return `${Math.floor(d / DAY)}d ago`;
	if (d < 60 * DAY) return `${Math.floor(d / (7 * DAY))}w ago`;
	return isoDate(unixSecs);
}

/** `2026-11-09`, in UTC so every admin reads the same date. */
export function isoDate(unixSecs: number): string {
	return new Date(unixSecs * 1000).toISOString().slice(0, 10);
}

/**
 * The Trial-ends cell: `in 12d` (neutral), `in 3d` (warning at three days or
 * fewer), `ends today`, `ended 2d ago` (error).
 */
export function trialBadge(
	endsAt: number,
	nowSecs = Date.now() / 1000
): { label: string; tone: Tone } {
	const left = endsAt - nowSecs;
	if (left <= 0) {
		const ago = Math.floor(-left / DAY);
		return { label: ago === 0 ? 'ended today' : `ended ${ago}d ago`, tone: 'error' };
	}
	const days = Math.ceil(left / DAY);
	if (days <= 1) return { label: 'ends today', tone: 'warning' };
	return { label: `in ${days}d`, tone: days <= 3 ? 'warning' : 'neutral' };
}

/** Root IdP key as shown in the Sign-in column. */
export function providerLabel(provider: string | null): string {
	switch (provider) {
		case 'google':
			return 'Google';
		case 'github':
			return 'GitHub';
		case 'email':
			return 'Magic link';
		case null:
			return 'Org IdP only';
		default:
			return provider.charAt(0).toUpperCase() + provider.slice(1);
	}
}

/** One-line summary of an audit row's `detail`, for the Detail column. */
export function auditDetail(action: string, detail: Record<string, unknown>): string {
	const ends =
		typeof detail.trial_ends_at === 'number' ? ` · ends ${isoDate(detail.trial_ends_at)}` : '';
	switch (action) {
		case 'org.trial_started':
			return `${detail.duration_days ?? '?'} days${ends}`;
		case 'org.trial_extended':
			return `+${detail.extend_days ?? '?'} days${ends}`;
		case 'org.plan.updated':
			return detail.previous_plan
				? `${detail.previous_plan} → ${detail.plan}`
				: `plan ${detail.plan ?? '?'}`;
		case 'org.created':
			return `plan ${detail.plan ?? '?'}${ends}`;
		case 'instance_admin.granted':
		case 'instance_admin.revoked':
			return typeof detail.email === 'string' ? detail.email : String(detail.user_id ?? '');
		default:
			return JSON.stringify(detail);
	}
}
