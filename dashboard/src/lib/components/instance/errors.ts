import { apiErrorReason } from '#lib/session.ts';
import { isStepUpError } from '#lib/stores/stepUp.svelte.ts';

const MESSAGES: Record<string, string> = {
	slug_taken: 'That slug is already taken.',
	org_creation_disabled: 'Org creation is turned off on this instance (ALLOW_ORG_CREATION).',
	not_eligible: 'That user has no Overslash sign-in, so they can’t hold this role.',
	last_instance_admin: 'The last instance admin can’t be revoked.',
	instance_admin_required: 'Your account is no longer an instance admin.'
};

/**
 * The message a panel dialog shows for a failed mutation, or null when the
 * failure was a step-up: the global sign-in prompt (`StepUpModal`) is already
 * open then, and the dialog stays as it was so the admin can retry once back.
 */
export function mutationError(e: unknown): string | null {
	if (isStepUpError(e)) return null;
	const reason = apiErrorReason(e);
	return (reason && MESSAGES[reason]) ?? reason ?? 'Something went wrong. Please try again.';
}
