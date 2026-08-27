# Changelog

## [0.9.0](https://github.com/overfolder/overslash/compare/v0.8.0...v0.9.0) (2026-08-27)


### Features

* **whatsapp:** sync template to whatsapp-mcp-docker 0.7.0 ([e85c1e2](https://github.com/overfolder/overslash/commit/e85c1e27bc7655bb5d59a7b13ce168ad76728698))
* **whatsapp:** sync template to whatsapp-mcp-docker 0.7.0 ([9e632dd](https://github.com/overfolder/overslash/commit/9e632dd3dbfbb4b811edaa1ca8ec3c12a1d2e8f4))


### Bug Fixes

* **compact:** keep pagination headers and rank cursor keys above the alphabet ([#572](https://github.com/overfolder/overslash/issues/572)) ([e01ced9](https://github.com/overfolder/overslash/commit/e01ced96461ffba7a341ae77a4de095766d5a8de)), closes [#537](https://github.com/overfolder/overslash/issues/537)

## [0.8.0](https://github.com/overfolder/overslash/compare/v0.7.0...v0.8.0) (2026-08-14)


### ⚠ BREAKING CHANGES

* **actions:** execution result bodies are no longer readable org-wide. A caller who is not the requester, not above them in the chain with write access, and not an org admin now gets 403 from `/v1/approvals/{id}/execution` and `result_redacted: true` (with no body) from the approval detail and list.

### Features

* **actions:** a truncated result is stored and re-fetchable behind a URL ([#547](https://github.com/overfolder/overslash/issues/547)) ([1a25374](https://github.com/overfolder/overslash/commit/1a25374d7b6df6a3d7b5625e8ada63528dc6e6e5))
* **actions:** an action can declare the mode a call defaults to, and the caller still outranks it ([#563](https://github.com/overfolder/overslash/issues/563)) ([0b3ae9f](https://github.com/overfolder/overslash/commit/0b3ae9f8230fed1adf12d00985c498f506d81aa0))
* **actions:** async (non-blocking) action calls (D60) ([#546](https://github.com/overfolder/overslash/issues/546)) ([4a4cbf6](https://github.com/overfolder/overslash/commit/4a4cbf608dca2c3978e8dc542aa56664eefa9eb9))
* **actions:** cache display-param resolvers on a bounded-staleness window (D64) ([#548](https://github.com/overfolder/overslash/issues/548)) ([76a68a1](https://github.com/overfolder/overslash/commit/76a68a16a9e1a2d6f5bb55808da7cdffd3b0c9cd))
* **actions:** deferred downloads via capability URLs (deliver: "url") ([#512](https://github.com/overfolder/overslash/issues/512)) ([4955529](https://github.com/overfolder/overslash/commit/495552975575aadd50113ff2ac339813841c46b4))
* **actions:** execution: "hybrid" — the connection waits on the call, it does not own it (D68) ([#557](https://github.com/overfolder/overslash/issues/557)) ([bec6cc4](https://github.com/overfolder/overslash/commit/bec6cc4b8680cc6002005f819748b3ac9a397e92))
* **actions:** gated async — an approved call runs on the worker, not the connection (D66) ([#553](https://github.com/overfolder/overslash/issues/553)) ([dd03842](https://github.com/overfolder/overslash/commit/dd038427459430f4dfa20558b9716c428e807ba9))
* **actions:** give list-heavy actions a middle gear, and mint the retry into the 502 (D57) ([#543](https://github.com/overfolder/overslash/issues/543)) ([5fdd844](https://github.com/overfolder/overslash/commit/5fdd844bf1e22833f0b32293d6a657a26e00d6aa))
* **actions:** layered call timeouts, and bound the unbounded call path (D56) ([#535](https://github.com/overfolder/overslash/issues/535)) ([b87d0d6](https://github.com/overfolder/overslash/commit/b87d0d62e7c45c08194809c7f338c91b94e9450c))
* **agents:** an agent wears its MCP client's mark, and a stripe of its own ([#560](https://github.com/overfolder/overslash/issues/560)) ([589311a](https://github.com/overfolder/overslash/commit/589311a4f1272fc0138099182738934484415873))
* **dashboard:** label audit-log actors by email ([#517](https://github.com/overfolder/overslash/issues/517)) ([1cd48bb](https://github.com/overfolder/overslash/commit/1cd48bb6dc172be3535759b774097b230c2dfb20))
* **dashboard:** label user identities by email, not IdP display name ([#513](https://github.com/overfolder/overslash/issues/513)) ([9bf6bd0](https://github.com/overfolder/overslash/commit/9bf6bd085e403e2351b7b3550622238309614f96))
* **dashboard:** show the OAuth profile pictures we already fetch ([#549](https://github.com/overfolder/overslash/issues/549)) ([4d927c4](https://github.com/overfolder/overslash/commit/4d927c4b0df817678b760e1c0b9dc0bb76d0b850))
* **events:** approval expiry stops being invisible, and the sweep stays bounded ([#544](https://github.com/overfolder/overslash/issues/544)) ([9fc835d](https://github.com/overfolder/overslash/commit/9fc835d0632b4c017391de08d2faf890888369c7))
* **groups:** auto-approval is a level, not a boolean (D53) ([#522](https://github.com/overfolder/overslash/issues/522)) ([b4893dd](https://github.com/overfolder/overslash/commit/b4893ddd542ab0b9a50590cff2c4cca07e22df7d))
* **identity:** an identifier says who, a name says what to call them ([#562](https://github.com/overfolder/overslash/issues/562)) ([b87fef9](https://github.com/overfolder/overslash/commit/b87fef99094df18d47c903a286672d93c80bd83e))
* **invitations:** pending-invitations section in the dashboard sidebar ([#514](https://github.com/overfolder/overslash/issues/514)) ([24dd988](https://github.com/overfolder/overslash/commit/24dd9887e91e63d435012af8de2b9e8fc660054d))
* **map:** Live Map, on a gated per-call event topic (D57) ([#542](https://github.com/overfolder/overslash/issues/542)) ([23f90b1](https://github.com/overfolder/overslash/commit/23f90b1d887cac3caa3050252e4ca5a57f2d20ae))
* **map:** service nodes draw their catalog mark, and a ball image no longer steals the drag ([#558](https://github.com/overfolder/overslash/issues/558)) ([9ac09d3](https://github.com/overfolder/overslash/commit/9ac09d37a67db6daa2d8bdcee9d9c89217181c04))
* **metabase:** resolve database ids to names in disclosures ([#532](https://github.com/overfolder/overslash/issues/532)) ([0b301d0](https://github.com/overfolder/overslash/commit/0b301d0c04d88abc3474faefe2dfc43709beef0b))
* **resolvers:** resolve MCP params to readable names, canonicalize scope keys (D55) ([#534](https://github.com/overfolder/overslash/issues/534)) ([507ce0e](https://github.com/overfolder/overslash/commit/507ce0ea8e0882d2380f0db309bd0dcfee9ce695))
* **search:** every search term is a composable bubble ([#533](https://github.com/overfolder/overslash/issues/533)) ([419f2cb](https://github.com/overfolder/overslash/commit/419f2cb8cc3de9a5647acb937c61a246d03de007))
* **services:** org-level instances must name a group the creator is in ([#521](https://github.com/overfolder/overslash/issues/521)) ([90bd275](https://github.com/overfolder/overslash/commit/90bd275fabbab55e32005b43259a3c27c20eb674))
* **services:** service templates carry an icon, and we self-host the built-in set ([#550](https://github.com/overfolder/overslash/issues/550)) ([8ba19bf](https://github.com/overfolder/overslash/commit/8ba19bfd926dd86f90e3b71e7cf5d0f8f7955b5a))
* **sql-policy:** a SELECT is a read only while every function it calls is one (D69) ([#559](https://github.com/overfolder/overslash/issues/559)) ([470e261](https://github.com/overfolder/overslash/commit/470e261b17d30eddf4ef220a04cffdf5c5e6e3cb))
* **templates:** lint keys the compiler ignores, at template compile (D67) ([#554](https://github.com/overfolder/overslash/issues/554)) ([753364d](https://github.com/overfolder/overslash/commit/753364dd91f6f2743d6d775163a7f13ca63e061d))


### Bug Fixes

* **actions:** an unconfigured instance says which field, not 401-from-upstream (D60) ([#545](https://github.com/overfolder/overslash/issues/545)) ([c99c5c6](https://github.com/overfolder/overslash/commit/c99c5c6f288c2829d608413c577d3ecefe842d2e))
* **agents:** one name per concept in metabase, and a size hint that fits the caller ([#540](https://github.com/overfolder/overslash/issues/540)) ([bb07c76](https://github.com/overfolder/overslash/commit/bb07c76cfe5bd4e5ac111dc519fe46652524cd15))
* **audit:** record auto_approve_level on service-create group grants ([#531](https://github.com/overfolder/overslash/issues/531)) ([2a402ad](https://github.com/overfolder/overslash/commit/2a402ad97c92a1e605d09559cd928c781483a6c7))
* **auth:** honor Overslash-managed sign-in in the MCP authorize bounce ([#516](https://github.com/overfolder/overslash/issues/516)) ([a2af377](https://github.com/overfolder/overslash/commit/a2af377fc014a7458118fc3759457c30912aee26))
* **build:** compile the SQL policy parser into the container image ([#519](https://github.com/overfolder/overslash/issues/519)) ([47e0505](https://github.com/overfolder/overslash/commit/47e0505032d3b74d182abb6e2bf81dfcb3781a14))
* **build:** keep the API build on E2_HIGHCPU_8 ([#527](https://github.com/overfolder/overslash/issues/527)) ([945570a](https://github.com/overfolder/overslash/commit/945570a83d4858d8d6c2c97e4a1a0cadd52b200f))
* **build:** stop Kaniko OOM-killing the API image build ([#526](https://github.com/overfolder/overslash/issues/526)) ([c3fa6e0](https://github.com/overfolder/overslash/commit/c3fa6e0d1f5c51c6ccf499e55445910f5804d5b4))
* **dashboard:** keep the audit User cell on one line ([#520](https://github.com/overfolder/overslash/issues/520)) ([086a34b](https://github.com/overfolder/overslash/commit/086a34bd33b0ad3a44984caa7848e53f80c1906e))
* **disclosure:** jq error text stops quoting the values redaction hides (D65) ([#552](https://github.com/overfolder/overslash/issues/552)) ([4ae9fb6](https://github.com/overfolder/overslash/commit/4ae9fb626e1e8919c1efce2f86b97c678585d587)), closes [#538](https://github.com/overfolder/overslash/issues/538)
* **infra:** drop timeout_sec from the serverless-NEG backend service ([#528](https://github.com/overfolder/overslash/issues/528)) ([46995b3](https://github.com/overfolder/overslash/commit/46995b3b13948b84a95a97218d5d6b2744946b62))
* **services:** proxy /icons from the app origin, so cloud icons resolve ([#555](https://github.com/overfolder/overslash/issues/555)) ([2c0c2da](https://github.com/overfolder/overslash/commit/2c0c2dac27339d8a25701ea0119bde09d34c0cd2))

## [0.7.0](https://github.com/overfolder/overslash/compare/v0.6.0...v0.7.0) (2026-08-02)


### Features

* **dashboard:** per-env dev favicon + "{env} environment" top ribbon ([#495](https://github.com/overfolder/overslash/issues/495)) ([c3e9ad0](https://github.com/overfolder/overslash/commit/c3e9ad0a77a13061b4375f72e8ba8d565a04b6e3))
* **events:** real-time SSE event stream (GET /v1/events/stream) ([#504](https://github.com/overfolder/overslash/issues/504)) ([a175ce6](https://github.com/overfolder/overslash/commit/a175ce636cdd3473163000e2bd25a063c77d7e54))
* **oauth:** pre-select the account on reconnect via login_hint ([#509](https://github.com/overfolder/overslash/issues/509)) ([8e0b52b](https://github.com/overfolder/overslash/commit/8e0b52b95b1a8156ff535eba3805b0458e5c298f))
* **perms:** editable rule expiry dropdown + show Human rules in Agents view ([#493](https://github.com/overfolder/overslash/issues/493)) ([743b418](https://github.com/overfolder/overslash/commit/743b4184751194d14afa98087cd601532a8d48ed))
* **perms:** lead rule descriptions with the service (and principal) ([#494](https://github.com/overfolder/overslash/issues/494)) ([f9d2396](https://github.com/overfolder/overslash/commit/f9d239638661e4d338c4b4e99a784b146314a17a))
* **sdk:** @overslash/sdk — embed approvals, secret requests and connects in your own product ([#508](https://github.com/overfolder/overslash/issues/508)) ([93ab687](https://github.com/overfolder/overslash/commit/93ab68749670cb48bc02c97e5f41b046a60f2bf4))
* **sql-policy:** Metabase template + D42 SQL content policy (classifier, dynamic risk, per-table keys, column deny-screen) ([#496](https://github.com/overfolder/overslash/issues/496)) ([774340e](https://github.com/overfolder/overslash/commit/774340e50c4cbe09f23874f97deee4dbad05dfbc))
* **tags:** system-derived metadata tags on approvals, executions and audit logs ([#501](https://github.com/overfolder/overslash/issues/501)) ([f75d3c1](https://github.com/overfolder/overslash/commit/f75d3c1d079600da03d8f3b6ec75c877d45f01bf))
* **templates:** resolve deployment-specific values from ${VAR} (D44) ([#503](https://github.com/overfolder/overslash/issues/503)) ([ccf3ec2](https://github.com/overfolder/overslash/commit/ccf3ec24e632d7fb994226f232adc3d8dd169143))


### Bug Fixes

* **version:** report clean version in prod instead of &lt;version&gt;-dev ([#491](https://github.com/overfolder/overslash/issues/491)) ([c33a229](https://github.com/overfolder/overslash/commit/c33a2298cad678e9706c6a2e8057be94216a9769))

## [0.6.0](https://github.com/overfolder/overslash/compare/v0.5.0...v0.6.0) (2026-07-24)


### Features

* **actions:** accept declared parameter aliases before validation ([#460](https://github.com/overfolder/overslash/issues/460)) ([49dbd0e](https://github.com/overfolder/overslash/commit/49dbd0e10948e2390aa45eaccee3de92bd756692))
* **actions:** validate types + enums and coerce args before approvals ([#459](https://github.com/overfolder/overslash/issues/459)) ([7b9991c](https://github.com/overfolder/overslash/commit/7b9991c9371a84797144066b98a00279f2ab704a))
* **api:** report database connectivity from /health and /ready ([#478](https://github.com/overfolder/overslash/issues/478)) ([f186c7b](https://github.com/overfolder/overslash/commit/f186c7b1fc007b04b3f57c9a191a650194bb81fb))
* **approvals:** explicit `primary` disclose flag for hero fields ([#449](https://github.com/overfolder/overslash/issues/449)) ([a15de51](https://github.com/overfolder/overslash/commit/a15de51338863bd2fb6369e36c090d387365ce23))
* **approvals:** one row component, three one-click resolutions, merged action bar ([#488](https://github.com/overfolder/overslash/issues/488)) ([62e8530](https://github.com/overfolder/overslash/commit/62e85308993df9b346f71edcb6460bb8f6418559))
* **byoc:** metadata tags + in-place replace for BYOC OAuth creds ([#455](https://github.com/overfolder/overslash/issues/455)) ([66c44b7](https://github.com/overfolder/overslash/commit/66c44b7642265c5ec89a9384511f8c3a0d7891e9))
* **dashboard:** full-screen Approval Queue + detail page (retire modal) ([#442](https://github.com/overfolder/overslash/issues/442)) ([5329ba8](https://github.com/overfolder/overslash/commit/5329ba886cf732fe6f1974166c5ff0189b14fda9))
* **dashboard:** show the API's release version and commit ([#480](https://github.com/overfolder/overslash/issues/480)) ([3086b4c](https://github.com/overfolder/overslash/commit/3086b4cb0000e94a95af2318a2cf249191ed4f3a))
* **dashboard:** stamp the build on the login page, version on the rail ([#483](https://github.com/overfolder/overslash/issues/483)) ([0c8c566](https://github.com/overfolder/overslash/commit/0c8c5669de8fa3c18f0bf173ace772e8418cc389))
* **e2e:** per-run org isolation + per-instance config, proven by a real email user story ([#467](https://github.com/overfolder/overslash/issues/467)) ([7a99073](https://github.com/overfolder/overslash/commit/7a99073c9b7e721cfea305cde137767a5b3fd3bd))
* **email:** integrate overfwd Mailbox Gateway as an HTTP service ([#458](https://github.com/overfolder/overslash/issues/458)) ([1d7d339](https://github.com/overfolder/overslash/commit/1d7d3394aceae870b94cbadb7cdc63f2a3392ed6))
* **email:** name the IMAP criteria, scope sends per recipient ([#479](https://github.com/overfolder/overslash/issues/479)) ([28fb032](https://github.com/overfolder/overslash/commit/28fb03209607187c76016f123d5243b5a55be795))
* **identity:** name-based impersonation + fold invites into identities ([#487](https://github.com/overfolder/overslash/issues/487)) ([d3e0b37](https://github.com/overfolder/overslash/commit/d3e0b3720a278f08950575107653f40f046b232c))
* **infra:** deploy overfwd as the shared Mailbox Gateway ([#477](https://github.com/overfolder/overslash/issues/477)) ([ca4071b](https://github.com/overfolder/overslash/commit/ca4071b833bf8b6c8a4450d89b7a25b658e66b83))
* **mcp:** an agent can collect the result of an approved action ([#482](https://github.com/overfolder/overslash/issues/482)) ([d721058](https://github.com/overfolder/overslash/commit/d7210580a9294db625713de23feb2e740492f179))
* **mcp:** instance-scoped tool resync — fix 400 on templates that defer url/secret ([#466](https://github.com/overfolder/overslash/issues/466)) ([066d881](https://github.com/overfolder/overslash/commit/066d8812cc897c9c0354e96ed2fa21e9c54238bf))
* **mcp:** org-scope MCP enrollment to the subdomain ([#443](https://github.com/overfolder/overslash/issues/443)) ([932f64c](https://github.com/overfolder/overslash/commit/932f64c03df142ba1609308b32af4b8b82adc494))
* **perms:** human-readable descriptions for agent permission rules ([#486](https://github.com/overfolder/overslash/issues/486)) ([c8aeb6a](https://github.com/overfolder/overslash/commit/c8aeb6a6646767c142febefcaf8508686b05d3d5))
* **perms:** scope_param takes a list, keys carry a scope label ([#481](https://github.com/overfolder/overslash/issues/481)) ([831cd7e](https://github.com/overfolder/overslash/commit/831cd7ee63765a32b9c88f963209799250b97ebd))
* **services:** a credential template may read declared non-secret inputs ([#476](https://github.com/overfolder/overslash/issues/476)) ([710a671](https://github.com/overfolder/overslash/commit/710a6711531c475c90a5153cdcda6af7ec0e1d91))
* **services:** credential slots + jq composition templates ([#470](https://github.com/overfolder/overslash/issues/470)) ([3f0d04a](https://github.com/overfolder/overslash/commit/3f0d04a5c915132d5e20366aa6a4b4811e84270c))
* **services:** delete orphaned OAuth connection on service deletion ([#447](https://github.com/overfolder/overslash/issues/447)) ([a837b91](https://github.com/overfolder/overslash/commit/a837b9164d18db74bd4d9c63eadd6a433288cb07))
* **services:** let a user manage services/templates owned by its agents ([#454](https://github.com/overfolder/overslash/issues/454)) ([d6d068e](https://github.com/overfolder/overslash/commit/d6d068ee5bbf7df13e328a2176aad31e3bce44f1))
* **services:** Microsoft Graph (Outlook) mail service, Gmail-equivalent ([#445](https://github.com/overfolder/overslash/issues/445)) ([a902fc3](https://github.com/overfolder/overslash/commit/a902fc3952fdd770c2ad6677ca70e39680afd79b))
* **services:** per-scheme credential bindings — one labelled credential per securityScheme ([#464](https://github.com/overfolder/overslash/issues/464)) ([881fc3a](https://github.com/overfolder/overslash/commit/881fc3a4cacf92f89382d38fc0091b3ebe091f95))
* **templates:** layered service templates — extends/delta layers + the fold ([#444](https://github.com/overfolder/overslash/issues/444)) ([16fcb3c](https://github.com/overfolder/overslash/commit/16fcb3c80d78128a91f173eb98f9412c4defea66))
* **templates:** org layers can preset the per-instance surface (`delta.instance_defaults`) ([#471](https://github.com/overfolder/overslash/issues/471)) ([ba60835](https://github.com/overfolder/overslash/commit/ba6083594c21d720d26033d71342ae52bdc7365b))


### Bug Fixes

* **actions:** send a request body when the template declares one ([#465](https://github.com/overfolder/overslash/issues/465)) ([b48f94e](https://github.com/overfolder/overslash/commit/b48f94e86600710195a993311e1b8831a0ccc227))
* **approvals:** show every derived key, dedupe collapsed tiers ([#485](https://github.com/overfolder/overslash/issues/485)) ([35f197f](https://github.com/overfolder/overslash/commit/35f197f4cfe072d262f0d58494289180b5609292))
* **dashboard:** reflect real catalog allow-list so toggling a global off can't 404 ([#450](https://github.com/overfolder/overslash/issues/450)) ([5bebb5c](https://github.com/overfolder/overslash/commit/5bebb5cf88f9a845ab2fa40af29b7d9cbe890ebd))


### Performance Improvements

* **ci:** one api test binary, one coverage job (was 5 shards) ([#475](https://github.com/overfolder/overslash/issues/475)) ([d2d52e0](https://github.com/overfolder/overslash/commit/d2d52e00771f0a7f1eb1cf0078b2457e47695857))

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
