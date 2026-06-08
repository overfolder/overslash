# Changelog

## [0.3.0](https://github.com/overfolder/overslash/compare/v0.2.0...v0.3.0) (2026-06-08)


### Features

* **approvals:** auto-call cascade-resolved approvals when the requester opts in ([#361](https://github.com/overfolder/overslash/issues/361)) ([498f6f9](https://github.com/overfolder/overslash/commit/498f6f9d9268875c8191ad03717a79b7165613a8))
* **audit:** optional response-body capture + transport-error audit rows ([#372](https://github.com/overfolder/overslash/issues/372)) ([3cf0e13](https://github.com/overfolder/overslash/commit/3cf0e13675d89bf4b5b88a5f154ee2d7491d2ef7))
* **audit:** surface upstream errors in audit logs, the call envelope, and the dashboard ([2ebafc6](https://github.com/overfolder/overslash/commit/2ebafc680bde8b3d3096ca3f6a2dd472f21fef74))
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
* **release:** pin release-please target-branch to master ([1ee1bc6](https://github.com/overfolder/overslash/commit/1ee1bc6ef7b953ea27d74e3f4bfed12d1c85e720))
* **release:** pin release-please target-branch to master ([ab5a5cc](https://github.com/overfolder/overslash/commit/ab5a5cc7a89eacaa4967b7e7d1599c9d0b82f15c))
* **security:** stop leaking OAuth tokens through approval envelopes and replay payloads ([#365](https://github.com/overfolder/overslash/issues/365)) ([a494ad2](https://github.com/overfolder/overslash/commit/a494ad276c9526effd3c3f1b396b5d41be8ca331))
* **services:** apply OpenAPI param defaults at runtime ([#356](https://github.com/overfolder/overslash/issues/356)) ([5e2eb85](https://github.com/overfolder/overslash/commit/5e2eb85f3f444fbbabb5e35e64f36190b9dc71ab))
* **services:** correct required_scopes for Google templates via root-level security ([#355](https://github.com/overfolder/overslash/issues/355)) ([904223b](https://github.com/overfolder/overslash/commit/904223b39e93c0a208e0d8d11f7672630e6f0ca9))
* **tests:** keep shared-router server alive across test runtimes and close finished tests' pools ([#369](https://github.com/overfolder/overslash/issues/369)) ([d2453b9](https://github.com/overfolder/overslash/commit/d2453b9d2a44b5072f93a51206d49d9dbdbd73d2))
