// Pure-logic checks for the Instance Admin panel's display helpers — no
// browser, no stack. The trial badge's tone thresholds and the audit Detail
// summaries are what an instance admin scans the tables by, so they are
// pinned here rather than left to a screenshot.
import { test, expect } from '@playwright/test';
import {
	auditDetail,
	isoDate,
	providerLabel,
	relativeAgo,
	trialBadge
} from '../../../src/lib/components/instance/format';
import { INSTANCE_SECTION_IDS, instanceHref } from '../../../src/lib/components/instance/sections';

const NOW = Date.UTC(2026, 10, 9, 12, 0, 0) / 1000;
const DAY = 86_400;

test('trial badge: neutral, warning at three days, error once ended', () => {
	expect(trialBadge(NOW + 12 * DAY, NOW)).toEqual({ label: 'in 12d', tone: 'neutral' });
	expect(trialBadge(NOW + 3 * DAY, NOW)).toEqual({ label: 'in 3d', tone: 'warning' });
	expect(trialBadge(NOW + 3600, NOW)).toEqual({ label: 'ends today', tone: 'warning' });
	expect(trialBadge(NOW - 2 * DAY, NOW)).toEqual({ label: 'ended 2d ago', tone: 'error' });
	expect(trialBadge(NOW - 60, NOW)).toEqual({ label: 'ended today', tone: 'error' });
});

test('relative time buckets', () => {
	expect(relativeAgo(NOW - 10, NOW)).toBe('now');
	expect(relativeAgo(NOW - 180, NOW)).toBe('3m ago');
	expect(relativeAgo(NOW - 2 * 3600, NOW)).toBe('2h ago');
	expect(relativeAgo(NOW - 4 * DAY, NOW)).toBe('4d ago');
	expect(relativeAgo(NOW - 15 * DAY, NOW)).toBe('2w ago');
	expect(relativeAgo(NOW - 90 * DAY, NOW)).toBe(isoDate(NOW - 90 * DAY));
});

test('audit detail summaries', () => {
	const ends = NOW + 30 * DAY;
	expect(auditDetail('org.trial_extended', { extend_days: 30, trial_ends_at: ends })).toBe(
		`+30 days · ends ${isoDate(ends)}`
	);
	expect(auditDetail('org.plan.updated', { plan: 'standard', previous_plan: 'trial' })).toBe(
		'trial → standard'
	);
	expect(auditDetail('instance_admin.granted', { email: 'maria@example.com' })).toBe(
		'maria@example.com'
	);
});

test('provider labels', () => {
	expect(providerLabel('github')).toBe('GitHub');
	expect(providerLabel('email')).toBe('Magic link');
	expect(providerLabel(null)).toBe('Org IdP only');
});

test('routable sections exclude the Later placeholder', () => {
	expect([...INSTANCE_SECTION_IDS].sort()).toEqual(['admins', 'audit', 'config', 'orgs']);
	expect(instanceHref('orgs')).toBe('/instance');
	expect(instanceHref('audit')).toBe('/instance/audit');
});
