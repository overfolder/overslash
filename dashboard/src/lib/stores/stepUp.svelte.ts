// The pending admin step-up, if any.
//
// An admin-class mutation in a shared org needs a recent sign-in through one
// of the org's IdPs; otherwise the API answers 403 `step_up_required`. The
// session client hands that body here, and `StepUpModal` (mounted once in the
// root layout) offers the sign-ins that would satisfy it. The failed request
// still throws, so the page that made it shows its usual error too.

export type StepUpReason = 'idp_required' | 'provider_not_allowed' | 'stale';

export interface StepUpProvider {
	key: string;
	display_name: string;
	/** `/auth/login/{key}?step_up=true[&org=…]`; the modal appends `next`. */
	login_path: string;
}

export interface StepUpChallenge {
	reason: StepUpReason;
	providers: StepUpProvider[];
	max_age_secs: number;
}

let pending = $state<StepUpChallenge | null>(null);

export const stepUp = {
	get pending() {
		return pending;
	}
};

/** True when `body` is a `step_up_required` answer; records it if so. */
export function requestStepUp(body: unknown): boolean {
	if (!body || typeof body !== 'object') return false;
	const b = body as { error?: unknown } & Partial<StepUpChallenge>;
	if (b.error !== 'step_up_required') return false;
	pending = {
		reason: (b.reason ?? 'idp_required') as StepUpReason,
		providers: Array.isArray(b.providers) ? b.providers : [],
		max_age_secs: typeof b.max_age_secs === 'number' ? b.max_age_secs : 3600
	};
	return true;
}

export function dismissStepUp(): void {
	pending = null;
}
