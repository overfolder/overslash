# Changelog

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
