# Changelog

## [0.5.0](https://github.com/overfolder/overslash/compare/v0.4.0...v0.5.0) (2026-07-08)


### Features

* **actions:** make resolved display params a first-class map for disclosure ([#426](https://github.com/overfolder/overslash/issues/426)) ([cf4db8a](https://github.com/overfolder/overslash/commit/cf4db8ae3aa6c8319216c80f4b3cb4b533336713))
* **auth:** decouple managed-IdP sign-in from invite-only admission ([#434](https://github.com/overfolder/overslash/issues/434)) ([d557486](https://github.com/overfolder/overslash/commit/d557486dda9bfa7b76e91f9534d9ef52c970ef14))
* **connections:** admin "show all users' connections" view + full management ([#407](https://github.com/overfolder/overslash/issues/407)) ([e52590f](https://github.com/overfolder/overslash/commit/e52590fdb96159ee1ee7b8a8df67311966e66094))
* **executor:** expand array-valued query params to repeated key=value pairs ([#420](https://github.com/overfolder/overslash/issues/420)) ([462ceed](https://github.com/overfolder/overslash/commit/462ceed12536f0ef29d967f06353d66b7f245776))
* **gmail:** threads, label modify/CRUD, and untrash operations ([#415](https://github.com/overfolder/overslash/issues/415)) ([98ebf4c](https://github.com/overfolder/overslash/commit/98ebf4c0c18c2abe5bf559a2f35dca12c03d930c))
* **mcp:** OAuth-authenticated MCP servers + HubSpot via remote MCP ([#418](https://github.com/overfolder/overslash/issues/418)) ([788df5e](https://github.com/overfolder/overslash/commit/788df5ea8537219de746cb5d920f14fe30577eb8))
* **members:** promote/demote org admins + fix invite-as-admin grant ([#433](https://github.com/overfolder/overslash/issues/433)) ([fcf8d24](https://github.com/overfolder/overslash/commit/fcf8d248c65999baf655be8b917aa7e737efa097))
* **oauth:** bind connections to the owner identity on import/connect (D23) ([#410](https://github.com/overfolder/overslash/issues/410)) ([5244ca0](https://github.com/overfolder/overslash/commit/5244ca02cc603f8a2e637ebcbaed9205a76a3dbe))
* **oauth:** expose provider OAuth metadata + template scopes for white-label partners ([#401](https://github.com/overfolder/overslash/issues/401)) ([b50e4f9](https://github.com/overfolder/overslash/commit/b50e4f9b37ffecb151adb0b14f1e26d2b8e98e8e))
* **oauth:** per-org oauth_redirect_url + opt-in white-label switch ([#398](https://github.com/overfolder/overslash/issues/398)) ([210a2fc](https://github.com/overfolder/overslash/commit/210a2fce8aa4fe95695e71438044df1cb025da93))
* **oauth:** resolve connections at the owner identity (D22) ([#406](https://github.com/overfolder/overslash/issues/406)) ([7a5bd8b](https://github.com/overfolder/overslash/commit/7a5bd8ba0a885fdc8f4426f06db79c523defda85))
* **oauth:** surface partial OAuth grants at discovery + self-heal NULL scopes ([#411](https://github.com/overfolder/overslash/issues/411)) ([937130b](https://github.com/overfolder/overslash/commit/937130b707c646b7213d2b08d35c3d72a298afd7))
* **oauth:** white-label connections as a token vault (POST /v1/connections/import) ([#400](https://github.com/overfolder/overslash/issues/400)) ([c93289a](https://github.com/overfolder/overslash/commit/c93289a561f3bcd84e02d89ba8553b69e58f2e13))
* **oauth:** white-label headless OAuth — URL-less auth-recovery ([#402](https://github.com/overfolder/overslash/issues/402)) ([301b02d](https://github.com/overfolder/overslash/commit/301b02da0cbeee254e2bc6241a41fe96fd79c1b5))
* **orgs:** trial mode — instance-admin managed trials + self-serve Stripe trial ([#436](https://github.com/overfolder/overslash/issues/436)) ([630be78](https://github.com/overfolder/overslash/commit/630be784acecdb0feda0f7243a89b40d11a161bf))
* save feedback ([03da0ff](https://github.com/overfolder/overslash/commit/03da0ff7fb9f3fac8a07beeab19033575638dd77))
* **services:** add built-in Google Keep (Notes) service ([#409](https://github.com/overfolder/overslash/issues/409)) ([69fb7b4](https://github.com/overfolder/overslash/commit/69fb7b46e81787ca9424f5a9f15f542014bb6e7d))
* **services:** add built-in Google Tasks service definition ([#408](https://github.com/overfolder/overslash/issues/408)) ([220a1f9](https://github.com/overfolder/overslash/commit/220a1f9aa67573cc52cbffa13348d13beade6d22))
* **services:** add LinkedIn service + OAuth provider ([#414](https://github.com/overfolder/overslash/issues/414)) ([7d3f8b5](https://github.com/overfolder/overslash/commit/7d3f8b522995a2b27a0a272bc7d1b514c6b4852a))
* **services:** add Notion service template + OAuth provider ([#417](https://github.com/overfolder/overslash/issues/417)) ([26aba42](https://github.com/overfolder/overslash/commit/26aba421ca23e31626f749e79c8f2c09f73f17b3))
* **services:** explicit disclose declarations for all shipped write actions ([#425](https://github.com/overfolder/overslash/issues/425)) ([a18bbd6](https://github.com/overfolder/overslash/commit/a18bbd6461c58b32feec818af3aa18f3d12c0258))
* **services:** org-admin curated service catalogs + hard instantiation gate ([#435](https://github.com/overfolder/overslash/issues/435)) ([95bcc3e](https://github.com/overfolder/overslash/commit/95bcc3e3f7afa6449ad9e4f50f60561969987273))
* **services:** resolve IDs to names on destructive actions and chain them into disclose ([#427](https://github.com/overfolder/overslash/issues/427)) ([2b5f97e](https://github.com/overfolder/overslash/commit/2b5f97e755dd0571b2c8a5c40698f01b1a1c7e0b))
* **services:** use_default_connection opt-out + atomic pin_service_ids ([#431](https://github.com/overfolder/overslash/issues/431)) ([493cbb8](https://github.com/overfolder/overslash/commit/493cbb88c4be9b911b1a3bb84377d3d138135150))
* **slack:** wrap Slack's MCP server with OAuth-connection auth ([#416](https://github.com/overfolder/overslash/issues/416)) ([30a830b](https://github.com/overfolder/overslash/commit/30a830be17a5f63e32774e45d506180078131b06))


### Bug Fixes

* **connections:** scope credentials page listing to the service owner ([#430](https://github.com/overfolder/overslash/issues/430)) ([0a09e88](https://github.com/overfolder/overslash/commit/0a09e88c5d1f97af3d6cd01abacf74ec9139dd00))
* **dashboard:** move use_default_connection toggle to service Connection tab ([#432](https://github.com/overfolder/overslash/issues/432)) ([814198f](https://github.com/overfolder/overslash/commit/814198f890461294a464812c7ced3af7c0916a18))
* **db:** size the connection pool and isolate background jobs to stop pool exhaustion ([#424](https://github.com/overfolder/overslash/issues/424)) ([a3df33d](https://github.com/overfolder/overslash/commit/a3df33d7b1fea459508ae34057643ad936215b32))
* **deps:** patch Dependabot security advisories ([#412](https://github.com/overfolder/overslash/issues/412)) ([107d689](https://github.com/overfolder/overslash/commit/107d68916ba19be20164be1a531677d0cd365da2))
* **hubspot:** re-sync to HubSpot's replaced MCP tool catalog + record requested scopes when /token omits scope ([#428](https://github.com/overfolder/overslash/issues/428)) ([6660857](https://github.com/overfolder/overslash/commit/6660857ae7b9b5cf61e63576754642c89ad834d8))
* **oauth:** never narrow recorded scopes on refresh; break the metadata-scope reconnect loop ([#423](https://github.com/overfolder/overslash/issues/423)) ([1b70d5a](https://github.com/overfolder/overslash/commit/1b70d5a43de10956772266b0e090bed57807510d))
* **services:** allow Write members to manage their own services ([#437](https://github.com/overfolder/overslash/issues/437)) ([3943c99](https://github.com/overfolder/overslash/commit/3943c99bfe06561362135ae4a0ffc2f5822ef28a))

## [0.4.0](https://github.com/overfolder/overslash/compare/v0.3.0...v0.4.0) (2026-06-13)


### Features

* **auth:** passwordless email magic-link login ([#385](https://github.com/overfolder/overslash/issues/385)) ([414a0b8](https://github.com/overfolder/overslash/commit/414a0b8bd66e1a411b41045522ab1d7ac631d08b))
* **identities:** add on-demand cascade-archive endpoint ([#383](https://github.com/overfolder/overslash/issues/383)) ([d3c2888](https://github.com/overfolder/overslash/commit/d3c28881bffd09f93b8b7a88afc7c83838c96b3e))
* **identities:** admin can remove user members from an org ([#393](https://github.com/overfolder/overslash/issues/393)) ([6957c8e](https://github.com/overfolder/overslash/commit/6957c8eee9719bea795e73e6c6bc0549b1a70d55))
* **infra:** provision GitHub login OAuth secrets, gate login providers ([#396](https://github.com/overfolder/overslash/issues/396)) ([3cda726](https://github.com/overfolder/overslash/commit/3cda72602ef45e932d68c2462f92c27ed1799b35))
* **login:** use landing wordmark's skewed slash on login page ([#395](https://github.com/overfolder/overslash/issues/395)) ([87c9ace](https://github.com/overfolder/overslash/commit/87c9ace13c4910c69e69fa97f91596cda08175b5))
* **oauth:** allow dashboard override of env-configured OAuth providers ([#382](https://github.com/overfolder/overslash/issues/382)) ([da661af](https://github.com/overfolder/overslash/commit/da661afac213a5cb21b78fe75860e499b2a7d697))
* **oauth:** expose raw authorize URL on upgrade_scopes reauth ([#392](https://github.com/overfolder/overslash/issues/392)) ([604e3e3](https://github.com/overfolder/overslash/commit/604e3e39b1746bf370f1bb59ed734982e9348f06))
* **oauth:** white-label custom redirect URIs for connect flows ([#388](https://github.com/overfolder/overslash/issues/388)) ([4382bba](https://github.com/overfolder/overslash/commit/4382bbac87648a48d8f254e49548f8df435c0e15))
* **services:** add hidden api-key test_email fake for eval fixtures ([#384](https://github.com/overfolder/overslash/issues/384)) ([daf1d60](https://github.com/overfolder/overslash/commit/daf1d6010c47ff1511f4a43c5a025848afb1dbe7))


### Bug Fixes

* **agents:** only badge the logged-in identity as "(you)" ([#386](https://github.com/overfolder/overslash/issues/386)) ([27d0f78](https://github.com/overfolder/overslash/commit/27d0f78fbfe36af5568a434cdfccd5d9aaff0377))
* **connections:** "Wrong account" on /connect-authorize for multi-org + admin/actor override ([#381](https://github.com/overfolder/overslash/issues/381)) ([2578103](https://github.com/overfolder/overslash/commit/25781038f1620216ebd44199b14522748a77e5d6))
* **dashboard:** don't logout on a service-auth 401 in "try it" ([#379](https://github.com/overfolder/overslash/issues/379)) ([d1fcabb](https://github.com/overfolder/overslash/commit/d1fcabb29ec616c135bf89b9254cef97bad6a5f9))
* disable local MCP to avoid errs ([82fc93e](https://github.com/overfolder/overslash/commit/82fc93e406f6fadbf71559a7b0280ba19380a12a))
* **services:** reflect provider auto-resolve in credentials_status ([#378](https://github.com/overfolder/overslash/issues/378)) ([f8ff3af](https://github.com/overfolder/overslash/commit/f8ff3affc1b0468e0321124c0410f1f2e602480d))

## [0.3.0](https://github.com/overfolder/overslash/compare/v0.2.0...v0.3.0) (2026-06-08)


### Features

* **approvals:** auto-call cascade-resolved approvals when the requester opts in ([#361](https://github.com/overfolder/overslash/issues/361)) ([498f6f9](https://github.com/overfolder/overslash/commit/498f6f9d9268875c8191ad03717a79b7165613a8))
* **audit:** optional response-body capture + transport-error audit rows ([#372](https://github.com/overfolder/overslash/issues/372)) ([3cf0e13](https://github.com/overfolder/overslash/commit/3cf0e13675d89bf4b5b88a5f154ee2d7491d2ef7))
* **audit:** surface upstream errors in audit logs, the call envelope, and the dashboard ([3e5e88a](https://github.com/overfolder/overslash/commit/3e5e88adf45395a473319b0a1f4368c3d6a8788f))
* **metrics:** distinguish upstream errors from gateway errors ([#368](https://github.com/overfolder/overslash/issues/368)) ([6828a61](https://github.com/overfolder/overslash/commit/6828a61104a43d9a8c14f4feec2254927d8a670b))
* **release:** automate tagging + changelog with release-please ([#374](https://github.com/overfolder/overslash/issues/374)) ([0714428](https://github.com/overfolder/overslash/commit/0714428115682cc31c14572bcdbf79097edc6936))
* **services:** add reminders/recurrence/colorId/sendUpdates to Google Calendar; route query params on writes ([#362](https://github.com/overfolder/overslash/issues/362)) ([90b7522](https://github.com/overfolder/overslash/commit/90b752235387312a07cc296aba3500ca530269c4))
* **services:** migrate builtin GitHub template to GitHub App user-to-server OAuth ([#358](https://github.com/overfolder/overslash/issues/358)) ([4d02ac0](https://github.com/overfolder/overslash/commit/4d02ac072789a49e5a5836f57130f4759c8ef3ac))
* **templates:** enforce x-overslash-hidden on catalog surfaces ([#366](https://github.com/overfolder/overslash/issues/366)) ([7763606](https://github.com/overfolder/overslash/commit/7763606eea942751dfec1fb4b096a2a11bde7ca9))


### Bug Fixes

* **api:** plug slow memory leak in rate-limit caches; bump prod memory to 1Gi ([#357](https://github.com/overfolder/overslash/issues/357)) ([0149cea](https://github.com/overfolder/overslash/commit/0149cea6a933753c1b6102ea0fb9b6e1cae7f0a9))
* **dashboard:** "Try It" link on service detail page should use UUID ([#367](https://github.com/overfolder/overslash/issues/367)) ([500c4ef](https://github.com/overfolder/overslash/commit/500c4ef6753ab1df8cfe0bfde831fd1131ecff4a))
* **dev:** repair `make dev` — workspace manifests + missing runtime assets ([#353](https://github.com/overfolder/overslash/issues/353)) ([1f05f30](https://github.com/overfolder/overslash/commit/1f05f307a45c5c041b2cc19b95f05d28457fc75a))
* **dev:** repair dev-stack redirects, logging, session expiry, and build caching ([#354](https://github.com/overfolder/overslash/issues/354)) ([5e8e934](https://github.com/overfolder/overslash/commit/5e8e9348c7432d5f2c9817dd71f3a4416445a06b))
* **monitoring:** gate upstream_error_rate alert behind a feature flag ([55adb8a](https://github.com/overfolder/overslash/commit/55adb8ad9294eb721edb0dd9defcfe4be7c02665))
* **release:** pin release-please target-branch to master ([ab5a5cc](https://github.com/overfolder/overslash/commit/ab5a5cc7a89eacaa4967b7e7d1599c9d0b82f15c))
* **security:** stop leaking OAuth tokens through approval envelopes and replay payloads ([#365](https://github.com/overfolder/overslash/issues/365)) ([a494ad2](https://github.com/overfolder/overslash/commit/a494ad276c9526effd3c3f1b396b5d41be8ca331))
* **services:** apply OpenAPI param defaults at runtime ([#356](https://github.com/overfolder/overslash/issues/356)) ([5e2eb85](https://github.com/overfolder/overslash/commit/5e2eb85f3f444fbbabb5e35e64f36190b9dc71ab))
* **services:** correct required_scopes for Google templates via root-level security ([#355](https://github.com/overfolder/overslash/issues/355)) ([904223b](https://github.com/overfolder/overslash/commit/904223b39e93c0a208e0d8d11f7672630e6f0ca9))
* **tests:** keep shared-router server alive across test runtimes and close finished tests' pools ([#369](https://github.com/overfolder/overslash/issues/369)) ([d2453b9](https://github.com/overfolder/overslash/commit/d2453b9d2a44b5072f93a51206d49d9dbdbd73d2))
