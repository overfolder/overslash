<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import PendingInvites from './PendingInvites.svelte';
	import type { PendingInvitation } from '$lib/api/account';

	// Accept/Decline hit the real API, so these stories are for layout only —
	// the buttons will error against a Storybook origin with no session.
	const invite = (over: Partial<PendingInvitation> = {}): PendingInvitation => ({
		id: 'ac1de1fa-0000-4000-8000-000000000001',
		org_id: '0b9d1a2c-0000-4000-8000-000000000001',
		org_name: 'Acme Corp',
		org_slug: 'acme',
		role: 'member',
		created_at: '2026-08-01T09:30:00Z',
		can_accept_in_place: true,
		sign_in_url: 'https://acme.app.overslash.com/',
		...over
	});

	const { Story } = defineMeta({
		title: 'Shell/PendingInvites',
		component: PendingInvites,
		tags: ['autodocs'],
		parameters: { layout: 'padded' },
		argTypes: { collapsed: { control: 'boolean' } },
		args: { invitations: [invite()], collapsed: false }
	});
</script>

<Story name="One invitation" args={{ invitations: [invite()] }} />

<Story
	name="Admin invitation"
	args={{ invitations: [invite({ role: 'admin', org_name: 'Reveni' })] }}
/>

<Story
	name="Several"
	args={{
		invitations: [
			invite(),
			invite({
				id: 'ac1de1fa-0000-4000-8000-000000000002',
				org_name: 'Globex International Holdings',
				org_slug: 'globex',
				role: 'admin'
			})
		]
	}}
/>

<Story
	name="Org runs its own IdP"
	args={{ invitations: [invite({ can_accept_in_place: false, org_name: 'Initech' })] }}
/>

<Story name="Collapsed rail" args={{ invitations: [invite(), invite({ id: 'b' })], collapsed: true }} />

<Story name="None (renders nothing)" args={{ invitations: [] }} />
