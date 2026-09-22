//! Gates over the shipped `services/` corpus.
//!
//! These are not tests of [`super::ServiceRegistry`] — they are assertions
//! about the YAML the product ships, and each one exists to stop the *next*
//! template from quietly skipping something the rest of the corpus does.
//! None of them proves the corpus is complete; they stop it from getting
//! worse, which is the achievable version.
//!
//! Every allow-list here takes an entry only with a comment saying why the
//! *upstream* makes the thing impossible. "It was tedious" is not a reason.

use super::*;
use std::path::Path;

use crate::template_vars::Vars;

fn shipped_services_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("services")
}

/// Every shipped list action either declares how it pages, or says why it
/// cannot.
///
/// The sibling of `shipped_mutating_actions_declare_disclose`, for the
/// other thing a template can silently fail to say. An action that returns
/// a collection and declares no `x-overslash-pagination` reads every row
/// the upstream has into one response, which is how an agent asking which
/// Metabase cards were popular found all 2,033 of them and blew the
/// transport cap (D57, and D75 under it).
///
/// "Returns a collection" is not a fact this test can read, so it uses the
/// two signals that are:
///
///  1. the **key**, for the actions that announce themselves — `list_*`,
///     `search*`, `query_*`, and the two Metabase feeds that are lists
///     without saying so; and
///  2. a declared numeric **page-size parameter**, under any of the seven
///     spellings the corpus uses. A parameter whose whole job is to bound
///     a page is an admission that there is a page to bound, whatever the
///     key is called — which is what catches `read_channel_history`,
///     `get_conversation` and `get_user_tweets`.
///
/// Neither signal is complete, and that is fine: the gate exists to stop
/// the *next* unbounded list from landing unnoticed, not to prove the
/// corpus has none. Widening it is cheap — add a spelling below.
#[test]
fn shipped_list_actions_declare_pagination() {
    /// The page-size spellings the corpus actually uses. `topics_limit` is
    /// deliberately absent: it bounds a sub-list inside one chat's
    /// metadata, not a page of the thing the action returns.
    const PAGE_SIZE_SPELLINGS: &[&str] = &[
        "limit",
        "per_page",
        "page_size",
        "pageSize",
        "maxResults",
        "max_results",
        "$top",
        "count",
    ];

    // Format: "service_key:action_key". Add entries only with a comment
    // saying why the *upstream* cannot page — not why annotating it was
    // inconvenient. An entry here is a claim that the collection is
    // bounded by something other than a page.
    const ALLOW_MISSING: &[&str] = &[
        // Stripe's continuation is `starting_after=<id of the last object
        // on the page>` — an array-indexed body position, and the dotted
        // path grammar takes no indices on purpose. Both actions declare
        // `limit` (default 10) and `starting_after`, so they are bounded
        // and a caller can walk them; only the gateway cannot compute the
        // next call.
        "stripe:list_charges",
        "stripe:list_customers",
        // The mailbox gateway answers `{results, total, truncated}` and
        // mints no continuation. `limit` now defaults to 50, and `total`
        // is what tells a caller what it has not seen. A page size with no
        // way to reach page two is a limit, not pagination.
        "email:search",
        // Gmail's labels endpoint takes no page size and mints no page
        // token; the label set is tens of entries by construction.
        "gmail:list_labels",
        // Resend's /domains takes no page size and mints no cursor; the
        // collection is an account's own sending domains.
        "resend:list_domains",
        // Metabase offers no page size, offset or sort on any of these.
        // `list_cards` says so in its own description and points at
        // `search`, which pages; the other three are small by
        // construction (a handful of databases, a capped activity feed).
        "metabase:list_cards",
        "metabase:list_databases",
        "metabase:popular_items",
        "metabase:recents",
        // HubSpot's MCP server exposes no page size for these. The first
        // two are batch reads bounded by the ids passed (1-100, max 20);
        // the rest are schema and keyword lookups over a bounded set.
        // `query_crm_data` pages with LIMIT/OFFSET inside the SQL.
        "hubspot:get_crm_objects",
        "hubspot:get_campaign_analytics",
        "hubspot:get_properties",
        "hubspot:search_properties",
        "hubspot:query_crm_data",
        "hubspot:get_campaign_asset_metrics",
        // Telegram's MCP server bounds every one of these with a `limit`
        // that declares its own default, and exposes no continuation
        // parameter at all — there is nowhere to send a cursor back.
        "telegram:search_messages_globally",
        "telegram:get_messages",
        "telegram:find_chats",
        // Shortcut pages three actions — both searches and the `/epics/
        // paginated` endpoint — and offers nothing to page on the rest.
        // Every one of these takes no page size and mints no continuation: the
        // workspace-wide sets (workflows, members, teams, labels,
        // iterations) are tens of rows by construction, and the rest are
        // bounded by the parent entity named in the path — one epic's
        // stories, one iteration's stories, one story's comments.
        // `query_stories` is the structured-filter twin of `search_stories`
        // and is bounded by how narrow the filters are; a caller who needs
        // to page reaches for `search_stories`, which says so.
        "shortcut:query_stories",
        "shortcut:list_story_comments",
        "shortcut:list_epic_stories",
        "shortcut:list_iterations",
        "shortcut:list_iteration_stories",
        "shortcut:list_workflows",
        "shortcut:list_members",
        "shortcut:list_groups",
        "shortcut:list_labels",
        // `/api/v3/projects` declares no parameters at all — no page size, no
        // cursor, not even a filter — and that is the point: it is the only
        // thing in the service that surfaces a project with no stories in it.
        // One project's stories are bounded by the project in the path, like
        // an epic's and an iteration's above.
        "shortcut:list_projects",
        "shortcut:list_project_stories",
        // The httpbin echo fixture used by the dev/e2e stack. It returns
        // whatever was sent, not a collection.
        "test_email:list_messages",
        // Holded exposes no cursor and no page size on any of these three.
        // They are settings, not collections: an account's tax rates, its
        // expense accounts and its chart of accounts each come back whole in
        // one response. The chart of accounts is narrowed with `text` instead,
        // which is what its description tells a caller to reach for.
        "holded:list_taxes",
        "holded:list_expenses_accounts",
        "holded:list_accounting_accounts",
        // Figma paginates exactly two things — the team-library endpoints and
        // version history — and those declare it. Everything below returns the
        // whole collection in one response, with neither a page size nor a
        // cursor to offer: each is already bounded by the entity named in its
        // path. One file's comments, one file's published components, one
        // file's published styles, one file's dev resources, one project's
        // files, one team's projects. `list_dev_resources` narrows with
        // `node_ids` and `list_comments` with nothing at all, which is Figma's
        // design, not an omission in the template.
        "figma:list_comments",
        "figma:list_dev_resources",
        "figma:list_file_components",
        "figma:list_file_styles",
        "figma:list_project_files",
        "figma:list_team_projects",
        // A Langfuse key pair is scoped to one project, so this endpoint
        // returns exactly that one — it declares no page size, no cursor and
        // no filter because there is nothing to page through. The
        // single-element `data` array is the shape of the answer, not a first
        // page. Same situation as `shortcut:list_projects` above.
        "langfuse:list_projects",
    ];

    fn looks_like_a_list(key: &str) -> bool {
        key.starts_with("list_")
            || key.starts_with("search")
            || key.starts_with("query_")
            || matches!(key, "recents" | "popular_items")
    }

    let reg = ServiceRegistry::load_from_dir(
        &shipped_services_dir(),
        crate::template_vars::Vars::for_tests(),
    )
    .unwrap();

    let mut checked = 0usize;
    let mut missing: Vec<String> = Vec::new();
    for def in reg.all() {
        // A platform action answers from this process, so there is no
        // upstream page to be on — `ext::READS` does not admit the key at
        // `Pos::PlatformAction`, and a declaration there would be dropped.
        if matches!(def.runtime, Runtime::Platform) {
            continue;
        }
        for (key, action) in &def.actions {
            let bounded_param = action.params.iter().any(|(name, p)| {
                PAGE_SIZE_SPELLINGS.contains(&name.as_str())
                    && (p.param_type == "integer" || p.param_type == "number")
            });
            if !looks_like_a_list(key) && !bounded_param {
                continue;
            }
            checked += 1;
            let id = format!("{}:{}", def.key, key);
            if action.pagination.is_none() && !ALLOW_MISSING.contains(&id.as_str()) {
                missing.push(id);
            }
        }
    }

    // Without this the test passes by enumerating nothing — a renamed
    // directory or a loader that quietly skipped every template would read
    // as a clean sweep. `shipped_services_lint_clean` carries the same
    // guard for the same reason.
    assert!(
        checked > 20,
        "only {checked} list-shaped actions found — the corpus did not load"
    );
    missing.sort();
    assert!(
        missing.is_empty(),
        "every shipped list action must declare `x-overslash-pagination`, \
             so a caller gets one page and the call for the next one instead of \
             the whole collection; missing: {missing:#?}"
    );
}

#[test]
fn shipped_mutating_actions_declare_disclose() {
    // Escape hatch for actions where disclosure is intentionally
    // omitted. Format: "service_key:action_key". Keep empty; add
    // entries only with a comment explaining why review disclosure
    // is impossible for that action.
    const ALLOW_MISSING: &[&str] = &[];

    let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("services");
    let reg =
        ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
            .unwrap();

    let mut missing: Vec<String> = Vec::new();
    for def in reg.all() {
        // Platform-runtime actions cannot carry disclose blocks:
        // extract_platform_action drops them at parse time and
        // compute_approval_detail never runs disclose filters for the
        // platform projection ({runtime, action, params, service}
        // already is the full reviewable payload).
        if matches!(def.runtime, Runtime::Platform) {
            continue;
        }
        for (key, action) in &def.actions {
            let id = format!("{}:{}", def.key, key);
            // `dynamic` counts as mutating here: a per-call-classified
            // action can write, so its approvals need disclose too.
            if action.risk.display_risk().is_mutating()
                && action.disclose.is_empty()
                && !ALLOW_MISSING.contains(&id.as_str())
            {
                missing.push(id);
            }
        }
    }
    missing.sort();
    assert!(
        missing.is_empty(),
        "every shipped write/delete action must declare `disclose:` so \
             approval reviewers see what the action will do; missing: {missing:#?}"
    );
}

#[test]
fn shipped_github_templates_auth() {
    use crate::types::ServiceAuth;

    let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("services");
    let reg =
        ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
            .unwrap();

    // `github` targets GitHub App user-to-server tokens: no OAuth scopes
    // (the app's permissions + installations govern access) plus an
    // installation diagnostic action.
    let gh = reg.get("github").expect("github template missing");
    match gh
        .auth
        .iter()
        .find(|a| matches!(a, ServiceAuth::OAuth { .. }))
    {
        Some(ServiceAuth::OAuth {
            provider, scopes, ..
        }) => {
            assert_eq!(provider, "github");
            assert!(
                scopes.is_empty(),
                "GitHub App template must not declare OAuth scopes, got {scopes:?}"
            );
        }
        _ => panic!("github template must declare OAuth auth"),
    }
    assert!(gh.actions.contains_key("list_installations"));
    assert!(!gh.hidden, "github template must not be hidden");

    // …and it offers a personal access token as the alternative, on the same
    // host and the same paths. The two are modes of one template rather than
    // two templates, which is what `github_legacy_oauth` used to be.
    let modes = gh.auth_modes();
    assert_eq!(
        modes.iter().map(|m| m.key.as_str()).collect::<Vec<_>>(),
        ["oauth", "token"],
        "github must declare both auth modes"
    );
    assert_eq!(gh.default_auth_mode(), "oauth");

    // The narrowing the whole feature rests on: each mode resolves to exactly
    // its own credential, never both, and never the other one's.
    assert!(
        gh.oauth_provider_for_mode(Some("oauth")).is_some(),
        "the oauth mode must resolve a provider"
    );
    assert!(
        gh.oauth_provider_for_mode(Some("token")).is_none(),
        "the token mode must resolve no OAuth provider — otherwise create_service \
         mints an auth_url nobody asked for and the credentials badge demands a \
         connection that will never come"
    );
    assert_eq!(
        gh.all_slots_for_mode(Some("token"))
            .iter()
            .map(|s| s.key.as_str())
            .collect::<Vec<_>>(),
        ["token"],
    );
    assert!(
        gh.all_slots_for_mode(Some("oauth")).is_empty(),
        "the oauth mode owes no vault secret"
    );
}

/// Every template that offers alternative auth modes must offer them
/// *completely*: a mode nobody can finish setting up is worse than not
/// offering it, because `create_service` will have already committed the
/// instance by the time anyone finds out.
#[test]
fn shipped_dual_mode_templates_are_resolvable_in_every_mode() {
    let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("services");
    let reg =
        ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
            .unwrap();

    let mut seen = Vec::new();
    for key in ["figma", "github", "notion"] {
        let def = reg
            .get(key)
            .unwrap_or_else(|| panic!("{key} template missing"));
        let modes = def.auth_modes();
        assert!(
            modes.len() > 1,
            "{key} is expected to offer alternative auth modes"
        );
        assert_eq!(
            modes.iter().filter(|m| m.default).count(),
            1,
            "{key} must mark exactly one default mode"
        );
        for mode in &modes {
            let entries = def.auth_for_mode(Some(&mode.key));
            assert!(
                !entries.is_empty(),
                "{key}/{} resolves no credential at all",
                mode.key
            );
            assert!(
                !mode.label.is_empty(),
                "{key}/{} needs a label; the dashboard picker renders it",
                mode.key
            );
            // A secret mode with no vault name has nowhere to store the value,
            // so no setup link can be minted and the operator is stuck.
            for slot in def.all_slots_for_mode(Some(&mode.key)) {
                assert!(
                    !slot.default_secret_name.is_empty(),
                    "{key}/{}: slot `{}` declares no default_secret_name, so no \
                     setup link can ever be minted for it",
                    mode.key,
                    slot.key
                );
            }
        }
        // The probe has to work in *both* modes — it is what gates go-live.
        assert!(
            def.test_action().is_some(),
            "{key} offers alternative modes but declares no credential probe"
        );
        seen.push(key);
    }
    assert_eq!(seen.len(), 3);
}

/// Every shipped template's declared credential probe must resolve to a real,
/// read-risk action whose params exist — and the catalogue must keep most
/// templates carrying one at all.
///
/// Nothing asserts `!disabled` here because `test_action()` already filters
/// disabled actions out: such a template would read as having no probe and
/// fall to the count assertion below instead.
///
/// The first half duplicates `check_test` on purpose: that rule runs over a
/// *parsed* definition, while this one runs over the registry the gateway
/// actually serves, so it also catches a probe lost to a layer fold or an
/// action renamed out from under its marker.
///
/// The second half is the one a reviewer should weigh. A count assertion
/// noticing a *drop* is what keeps "declare a probe" from quietly becoming
/// optional as templates are added; the floor is deliberately well under the
/// current number so adding an unprobeable template (deepwiki — every tool
/// needs a repo name, and it authenticates with nothing) is not a failure.
#[test]
fn shipped_test_actions_resolve_to_read_actions() {
    let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("services");
    let reg =
        ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
            .unwrap();

    let mut with_probe = 0;
    for def in reg.all() {
        let Some((key, action)) = def.test_action() else {
            continue;
        };
        with_probe += 1;
        assert!(
            action.risk == crate::types::Risk::Read,
            "{}: test action {key} is risk {:?}, not read",
            def.key,
            action.risk
        );
        for name in action.test.as_ref().unwrap().params.keys() {
            assert!(
                action.params.contains_key(name),
                "{}: test param {name:?} is not a param of {key}",
                def.key
            );
        }
    }
    assert!(
        with_probe >= 15,
        "only {with_probe} shipped templates declare a test action; \
         a new template should declare one unless it genuinely cannot be probed"
    );
}

/// Every shipped `object`/`array` parameter declares its inner shape.
///
/// A parameter whose contract lives only in its prose `description` is one a
/// model has to guess at, and the guess costs a round trip or an upstream 400
/// after an approval was burned. The loader now carries `properties`/`items`
/// (`openapi::extract::shape`), so the only thing standing between the corpus
/// and a complete contract is someone writing it down — this keeps the next
/// template from quietly skipping it.
///
/// Add an entry to `ALLOW_MISSING` only with a comment saying why the
/// *upstream* shape is genuinely free-form. "It was tedious" is not a reason.
#[test]
fn shipped_structured_params_declare_their_shape() {
    // Format: "service_key:action_key:param_name".
    const ALLOW_MISSING: &[&str] = &[
        // Notion blocks are a recursive, open union of ~30 block types whose
        // members each carry their own rich-text tree. Transcribing it would
        // be transcribing the Notion API, and getting it subtly wrong would
        // reject pages the upstream accepts.
        "notion:create_page:children",
        "notion:append_block_children:children",
        // Notion's filter grammar is recursive (`and`/`or` nest arbitrarily)
        // and its leaf conditions are keyed by the property's own type, so
        // the valid key set depends on the database being queried.
        "notion:query_database:filter",
        "notion:search:filter",
        "notion:search:sort",
        // A Notion page's `properties` map is keyed by the database's own
        // column names, and each value's shape depends on that column's type.
        // There is no fixed key set to declare.
        "notion:create_page:properties",
        // `parent`, `icon` and `cover` are discriminated unions keyed by a
        // `type` field; a flat `properties` block would advertise mutually
        // exclusive keys as though they combined.
        "notion:create_page:parent",
        "notion:create_page:icon",
        "notion:create_page:cover",
        // Metabase's MCP `query` is a whole dataset-query document, and the
        // SQL inside it is already addressed structurally by
        // `x-overslash-sql-field`.
        "metabase:export_query:query",
        // Card parameter bindings are keyed by the card's own template tags,
        // which differ per card.
        "metabase:run_card:parameters",
        // LinkedIn's UGC post body is a union over `shareMediaCategory`, and
        // `visibility` is a single-key map whose key is a namespaced URN.
        "linkedin:create_post:specificContent",
        "linkedin:create_post:visibility",
        // Keep's note body is a union of `text` and `list`, exactly one of
        // which may be present.
        "google_keep:create_note:body",
        // Figma's comment anchor is a union discriminated by *shape*, not by a
        // `type` field: a canvas point `{x, y}`, a frame offset `{node_id,
        // node_offset}`, or either of those with a region. A flat `properties`
        // block would advertise all of them as though they combined.
        "figma:post_comment:client_meta",
        // Outlook's `flag` is a union over `flagStatus` whose date members
        // only apply in one of the three states.
        "outlook:update_message:flag",
        // A platform action declares its params as a flat `{name: type}` map
        // (`x-overslash-platform_actions`), which has nowhere to put a
        // sub-schema — the shape is structurally unreachable rather than
        // merely unwritten. Closing these means giving that block a schema
        // form of its own, which is its own change.
        "overslash:create_connection:scopes",
        "overslash:create_service:config",
        "overslash:create_service:credentials",
        "overslash:create_service:groups",
        "overslash:import_template:include_operations",
        // A score's metadata is caller-owned free-form JSON: Langfuse declares
        // it `additionalProperties: true` with no key set, and the keys are
        // whoever wrote the score's own. There is no shape to transcribe.
        // Every other free-form field on this service is untyped upstream and
        // is declared untyped here, which needs no entry; this one is the
        // single place Langfuse says `object` and means "anything".
        "langfuse:create_score:metadata",
    ];

    let reg = ServiceRegistry::load_from_dir(&shipped_services_dir(), Vars::for_tests()).unwrap();
    let mut missing: Vec<String> = Vec::new();
    for def in reg.all() {
        for (action_key, action) in &def.actions {
            for (name, param) in &action.params {
                if !matches!(param.param_type.as_str(), "object" | "array") {
                    continue;
                }
                if param.shape.is_some() {
                    continue;
                }
                let key = format!("{}:{action_key}:{name}", def.key);
                if !ALLOW_MISSING.contains(&key.as_str()) {
                    missing.push(key);
                }
            }
        }
    }
    missing.sort();
    assert!(
        missing.is_empty(),
        "these object/array params declare no `properties`/`items`, so a caller \
         can only guess at them:\n  {}",
        missing.join("\n  ")
    );

    // The allow-list must not outlive what it excuses: an entry for a param
    // that has since been given a shape (or deleted) would quietly stop
    // guarding anything.
    let live: std::collections::HashSet<String> = reg
        .all()
        .iter()
        .flat_map(|def| {
            def.actions.iter().flat_map(move |(action_key, action)| {
                action
                    .params
                    .iter()
                    .filter(|(_, param)| param.shape.is_none())
                    .map(move |(name, _)| format!("{}:{action_key}:{name}", def.key))
            })
        })
        .collect();
    let stale: Vec<&&str> = ALLOW_MISSING
        .iter()
        .filter(|k| !live.contains(**k))
        .collect();
    assert!(
        stale.is_empty(),
        "these ALLOW_MISSING entries no longer exclude anything: {stale:?}"
    );
}
