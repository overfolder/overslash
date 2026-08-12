// Real-stack screenshots for gated async (D66): a call that hit the permission
// chain, asked to run in the background, and is handed to the async worker when
// its replay is triggered.
//
// Four states, all driven through the real gateway — no route fakes:
//   1. the reviewer's view *before* approving, which now says the call will run
//      in the background rather than producing a result on the page;
//   2. the approval right after the replay was triggered (queued / running in
//      the background, with no "Call now" to press);
//   3. the executions list, where the queued row appears alongside direct
//      async calls;
//   4. the execution detail, which links back to the approval that authorised it.
//
// Prereq: `make e2e-up` (which sets ASYNC_EXECUTION_ENABLED=1 — without it the
// gateway answers 400 and none of this exists). Output:
// dashboard/screenshots/async-gated-{review,triggered,list,detail}.png.

import {
	login,
	makeSnapper,
	resolveEnv,
	seedApproval,
	seedApprovalCall,
	seedApprovalResolution,
	api
} from '../tests/scenarios/index.mjs';

const session = await login('admin');
const env = resolveEnv();

// A slow export is the motivating shape: gated because it injects a secret,
// async because nobody wants to hold a connection open for it. Pointed at the
// openapi fake's `/slow` route rather than a made-up host, for two reasons: the
// worker's run actually succeeds (a screenshot of a DNS failure would show the
// plumbing, not the feature), and the deliberate delay keeps the page on the
// "running in the background" state long enough to capture it. Without it the
// job finishes inside one worker tick and the shot races the result.
const SLOW_MS = 12_000;
const approval = await seedApproval(session, {
	method: 'POST',
	url: `${env.openapiUrl}/slow?ms=${SLOW_MS}`,
	body: '{"format":"csv"}',
	execution: 'async'
});

const snap = await makeSnapper(session);
try {
	// 1. Pending — the reviewer is told what approving actually starts.
	await snap.navigateAndSnap('async-gated-review', `/approvals/${approval.id}`, {
		waitFor: (page) => page.getByText(/runs? in the background/i).first().waitFor({ timeout: 10_000 })
	});

	// 2. Approve, then trigger. `allow` leaves the row for an explicit trigger
	//    unless the agent has auto-call on; either way the enqueue is what
	//    happens next, so poll for the queued row rather than assuming which
	//    path got there first.
	await seedApprovalResolution(session, approval.id, 'allow');
	let queued = await pollExecution(approval.id, (e) => e?.queued === true);
	if (!queued) {
		const called = await seedApprovalCall(session, approval.id);
		queued = called.execution;
	}
	if (!queued?.queued) {
		throw new Error(
			`expected a queued execution for approval ${approval.id}, got ${JSON.stringify(queued)}`
		);
	}
	// The worker claims within one 2s tick, so this lands on "Queued" or
	// "Running in the background" — both are the state this change introduces,
	// and the slow upstream keeps whichever one it is on screen.
	await snap.navigateAndSnap('async-gated-triggered', `/approvals/${approval.id}`, {
		waitFor: (page) => page.getByText(/background/i).first().waitFor({ timeout: 15_000 })
	});

	// 3 + 4. Let the worker finish, then the executions surfaces.
	await pollExecution(
		approval.id,
		(e) => e && e.status !== 'pending' && e.status !== 'executing',
		SLOW_MS + 20_000
	);
	// Scope "Subtree": the execution belongs to the *agent* that made the call,
	// so the default "Mine" view of the signed-in user is legitimately empty.
	await snap.navigateAndSnap('async-gated-list', '/executions', {
		waitFor: async (page) => {
			await page.getByLabel(/scope/i).selectOption('subtree');
			await page.getByText(/Approved call|approval/i).first().waitFor({ timeout: 10_000 });
		}
	});
	await snap.navigateAndSnap('async-gated-detail', `/executions/${queued.id}`, {
		waitFor: (page) => page.getByText(/Approved call/i).first().waitFor({ timeout: 10_000 })
	});
} finally {
	await snap.close();
}

/**
 * Poll `GET /v1/approvals/{id}/execution` until `done` accepts it, or give up.
 * Returns the last execution seen (possibly undefined) rather than throwing —
 * the callers above decide what an unmet condition means.
 */
async function pollExecution(approvalId, done, timeoutMs = 30_000) {
	const deadline = Date.now() + timeoutMs;
	let last;
	while (Date.now() < deadline) {
		last = await api(session, `/v1/approvals/${approvalId}/execution`, {
			expect: [200, 404]
		}).catch(() => undefined);
		if (done(last)) return last;
		await new Promise((r) => setTimeout(r, 500));
	}
	return last;
}
