<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import type { Identity } from '$lib/types';
	import OwnerCell from './OwnerCell.svelte';

	function ident(partial: Partial<Identity> & Pick<Identity, 'id' | 'name' | 'kind'>): Identity {
		return {
			org_id: 'org1',
			external_id: null,
			parent_id: null,
			depth: 0,
			owner_id: null,
			inherit_permissions: false,
			...partial
		};
	}

	const alice = ident({ id: 'u1', name: 'alice', kind: 'user' });
	const henry = ident({ id: 'a1', name: 'henry', kind: 'agent', owner_id: 'u1', parent_id: 'u1', depth: 1 });
	const researcher = ident({
		id: 's1',
		name: 'researcher',
		kind: 'sub_agent',
		owner_id: 'a1',
		parent_id: 'a1',
		depth: 2
	});

	const identityById = new Map<string, Identity>([
		[alice.id, alice],
		[henry.id, henry],
		[researcher.id, researcher]
	]);

	const { Story } = defineMeta({
		title: 'Secrets/OwnerCell',
		component: OwnerCell,
		tags: ['autodocs'],
		parameters: { layout: 'padded' },
		args: { identityById, currentUserId: 'u1', ownerId: 'u1' }
	});
</script>

<Story name="Self (you)" args={{ ownerId: 'u1' }} />
<Story name="Agent owner" args={{ ownerId: 'a1' }} />
<Story name="Sub-agent (deep path)" args={{ ownerId: 's1' }} />
<Story name="Unknown" args={{ ownerId: 'missing' }} />
<Story name="System" args={{ ownerId: null }} />
