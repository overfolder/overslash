use super::*;

#[test]
fn user_instance_reads_only_owner_and_org() {
    let owner = Uuid::new_v4();
    let other = Uuid::new_v4();
    let own = format!("{owner}/tok");
    let foreign = format!("{other}/tok");
    assert_eq!(
        readable_instance_binding(Some(owner), &own),
        Some(SecretNamespace::User(owner).path("tok"))
    );
    assert_eq!(
        readable_instance_binding(Some(owner), "org/k"),
        Some(SecretNamespace::Org.path("k"))
    );
    assert_eq!(readable_instance_binding(Some(owner), &foreign), None);
    assert_eq!(
        readable_instance_binding(Some(owner), "tok"),
        Some(SecretNamespace::User(owner).path("tok"))
    );
    assert_eq!(readable_instance_binding(Some(owner), "angel/tok"), None);
}

#[test]
fn org_instance_reads_stored_path() {
    let admin = Uuid::new_v4();
    assert_eq!(
        readable_instance_binding(None, &format!("{admin}/tok")),
        Some(SecretNamespace::User(admin).path("tok"))
    );
    assert_eq!(
        readable_instance_binding(None, "tok"),
        Some(SecretNamespace::Org.path("tok"))
    );
}

#[test]
fn default_cascade() {
    let owner = Uuid::new_v4();
    let slots = OrgVaultGate::Slots([("k".to_string(), "org_k".to_string())].into());
    assert_eq!(
        org_default_candidates(Some(owner), "k", "k", &slots),
        vec![
            SecretNamespace::User(owner).path("k"),
            // The org/global tier's name, not the owner's template's.
            SecretNamespace::Org.path("org_k")
        ]
    );
    assert_eq!(
        org_default_candidates(None, "k", "k", &OrgVaultGate::Open),
        vec![SecretNamespace::Org.path("k")]
    );
    // An overridden destination keeps the owner's own copy and drops the org's.
    assert_eq!(
        org_default_candidates(Some(owner), "k", "k", &OrgVaultGate::Closed),
        vec![SecretNamespace::User(owner).path("k")]
    );
    // A slot the org tier doesn't source from the org gets no org fallback.
    assert_eq!(
        org_default_candidates(Some(owner), "other", "k", &slots),
        vec![SecretNamespace::User(owner).path("k")]
    );
}

#[test]
fn the_org_vault_gate_applies_to_explicit_bindings() {
    let owner = Uuid::new_v4();
    let own = format!("{owner}/tok");
    let slots = OrgVaultGate::Slots([("gateway".to_string(), "gk".to_string())].into());
    // Own vault: the gate is irrelevant.
    for gate in [&OrgVaultGate::Open, &slots, &OrgVaultGate::Closed] {
        assert!(readable_slot_binding(Some(owner), &own, gate, Some("x")).is_some());
    }
    // Org vault: only through an admitted org-source slot.
    assert!(readable_slot_binding(Some(owner), "org/gk", &slots, Some("gateway")).is_some());
    assert!(readable_slot_binding(Some(owner), "org/gk", &slots, Some("token")).is_none());
    assert!(readable_slot_binding(Some(owner), "org/gk", &slots, None).is_none());
    assert!(
        readable_slot_binding(
            Some(owner),
            "org/gk",
            &OrgVaultGate::Closed,
            Some("gateway")
        )
        .is_none()
    );
    assert!(readable_slot_binding(None, "org/gk", &OrgVaultGate::Open, None).is_some());
}

// ── Exhaustive invariants ──────────────────────────────────────────────
//
// The rule inputs are small finite domains — which vault a path names, who
// writes, what kind of instance, what is stored — so every combination is
// enumerated and checked against independently-stated invariants, rather
// than sampled. A failure prints the exact combination.

/// Secret names that stress the grammar: plain, legacy names holding `/` and
/// `:`, prefixes that look like other forms, non-ASCII.
const NAMES: &[&str] = &[
    "tok",
    "shortcut_api_token",
    "a/b",
    "org",
    "org/x",
    "user:x",
    "x:y/z",
    "ünï/çødé",
    "OAUTH_GOOGLE_CLIENT_ID",
];

struct World {
    owner: Uuid,
    other: Uuid,
    admin: Uuid,
}

impl World {
    fn new() -> Self {
        Self {
            owner: Uuid::new_v4(),
            other: Uuid::new_v4(),
            admin: Uuid::new_v4(),
        }
    }
    fn namespaces(&self) -> [SecretNamespace; 4] {
        [
            SecretNamespace::User(self.owner),
            SecretNamespace::User(self.other),
            SecretNamespace::User(self.admin),
            SecretNamespace::Org,
        ]
    }
    fn paths(&self) -> Vec<SecretPath> {
        self.namespaces()
            .into_iter()
            .flat_map(|ns| NAMES.iter().map(move |n| ns.path(*n)))
            .collect()
    }
}

#[test]
fn every_path_round_trips_through_its_canonical_form() {
    let w = World::new();
    for p in w.paths() {
        let c = p.to_canonical();
        assert_eq!(
            SecretPath::parse(&c),
            ParsedBinding::Qualified(p.clone()),
            "{c}"
        );
        // `user:` explicit form of a user path resolves to the same path.
        if let SecretNamespace::User(u) = p.ns {
            assert_eq!(
                SecretPath::parse(&format!("user:{u}/{}", p.name)),
                ParsedBinding::Qualified(p.clone())
            );
        }
    }
}

#[test]
fn pseudo_random_names_round_trip() {
    // A tiny LCG instead of a property-testing crate: deterministic, no new
    // dependency, and enough to shake out grammar edge cases.
    const ALPHABET: &[char] = &[
        'a', 'Z', '0', '_', '-', '/', ':', '.', ' ', '@', 'é', '字', '🔑', 'o', 'r', 'g', 'u', 's',
        'e',
    ];
    let mut seed: u64 = 0x5eed_1234_abcd_ef01;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    let w = World::new();
    for _ in 0..5_000 {
        let len = 1 + next() % 12;
        let name: String = (0..len)
            .map(|_| ALPHABET[next() % ALPHABET.len()])
            .collect();
        for ns in w.namespaces() {
            let p = ns.path(name.clone());
            assert_eq!(
                SecretPath::parse(&p.to_canonical()),
                ParsedBinding::Qualified(p.clone()),
                "{:?}",
                p
            );
        }
        // A name that passes the write-boundary check can never be read as
        // a path — it is always bare.
        if !is_reserved_name(&name) {
            assert_eq!(SecretPath::parse(&name), ParsedBinding::Bare(name.clone()));
        }
    }
}

#[test]
fn read_rule_is_exactly_owner_and_org_vaults() {
    let w = World::new();
    for p in w.paths() {
        let c = p.to_canonical();
        let user_level = readable_instance_binding(Some(w.owner), &c);
        let expect = matches!(p.ns, SecretNamespace::Org) || p.ns == SecretNamespace::User(w.owner);
        assert_eq!(
            user_level.is_some(),
            expect,
            "user-level instance reading {c}"
        );
        if let Some(r) = user_level {
            assert_eq!(r, p);
        }
        // An org-level instance resolves whatever the write rule stored.
        assert_eq!(readable_instance_binding(None, &c), Some(p.clone()), "{c}");
    }
    // Handles never resolve at read time; they are resolved on write only.
    assert_eq!(readable_instance_binding(Some(w.owner), "angel/tok"), None);
    assert_eq!(readable_instance_binding(None, "user:angel/tok"), None);
}

#[test]
fn write_rule_matches_its_specification_everywhere() {
    let w = World::new();
    let paths = w.paths();
    let mut stored_options: Vec<Option<String>> = vec![None];
    stored_options.extend(paths.iter().map(|p| Some(p.to_canonical())));

    for instance_owner in [Some(w.owner), None] {
        for (caller, caller_is_admin) in [(w.owner, false), (w.admin, true), (w.other, false)] {
            let writer = BindingWriter {
                caller_user: caller,
                caller_is_admin,
                instance_owner,
            };
            let home = instance_owner.unwrap_or(caller);
            for org_source in [false, true] {
                for stored in &stored_options {
                    for path in &paths {
                        let canonical = path.to_canonical();
                        let got = writer.authorize(path.clone(), stored.as_deref(), org_source);
                        let unchanged = stored.as_deref() == Some(canonical.as_str());
                        // The specification, stated independently of the code.
                        let allowed = unchanged
                            || match path.ns {
                                SecretNamespace::User(u) => u == home,
                                SecretNamespace::Org => {
                                    caller_is_admin && (instance_owner.is_none() || org_source)
                                }
                            };
                        let ctx = format!(
                            "owner={instance_owner:?} caller={caller} admin={caller_is_admin} \
                             org_source={org_source} stored={stored:?} path={canonical}"
                        );
                        assert_eq!(got.is_ok(), allowed, "{ctx}");
                        let Ok(out) = got else { continue };
                        // Whatever is stored is the canonical path asked for.
                        assert_eq!(out, canonical, "{ctx}");
                        if unchanged {
                            continue;
                        }
                        // A newly written binding is always one the read rule
                        // will resolve — the write rule can't create a binding
                        // that silently never works…
                        assert!(
                            readable_instance_binding(instance_owner, &out).is_some(),
                            "{ctx}"
                        );
                        // …and it never names a third party's vault.
                        if let SecretNamespace::User(u) = path.ns {
                            assert_eq!(u, home, "{ctx}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn a_user_level_instance_can_never_be_made_to_resolve_a_foreign_vault() {
    // Whatever sequence of writes any caller makes, a user-level instance
    // ends up only with bindings into its owner's vault or the org vault, so
    // the read rule's refusal is a second line, not the only one.
    let w = World::new();
    for (caller, admin) in [(w.owner, false), (w.admin, true), (w.other, false)] {
        let writer = BindingWriter {
            caller_user: caller,
            caller_is_admin: admin,
            instance_owner: Some(w.owner),
        };
        for path in w.paths() {
            if let Ok(out) = writer.authorize(path.clone(), None, true) {
                let resolved = readable_instance_binding(Some(w.owner), &out).unwrap();
                assert!(
                    resolved.ns == SecretNamespace::User(w.owner)
                        || resolved.ns == SecretNamespace::Org,
                    "caller {caller} bound {out}"
                );
            }
        }
    }
}

#[test]
fn echoing_a_response_back_is_always_a_no_op() {
    // `relative_to_instance` is what the API shows; a client that sends it
    // straight back must change nothing, for every reader of every instance.
    let w = World::new();
    for instance_owner in [Some(w.owner), None] {
        for (viewer, admin) in [(w.owner, false), (w.admin, true), (w.other, false)] {
            let writer = BindingWriter {
                caller_user: viewer,
                caller_is_admin: admin,
                instance_owner,
            };
            for stored in w.paths() {
                let stored_c = stored.to_canonical();
                let shown = relative_to_instance(instance_owner, Some(viewer), &stored_c);
                // What the server would resolve `shown` to (handles never
                // appear in responses, so no DB lookup is needed).
                let resolved = match SecretPath::parse(&shown) {
                    ParsedBinding::Qualified(p) => p,
                    ParsedBinding::Bare(n) => writer.home().path(n),
                    ParsedBinding::Handle { .. } => panic!("response showed a handle: {shown}"),
                };
                assert_eq!(
                    resolved, stored,
                    "owner={instance_owner:?} viewer={viewer} shown={shown}"
                );
                let out = writer.authorize(resolved, Some(&stored_c), false);
                assert_eq!(
                    out.ok().as_deref(),
                    Some(stored_c.as_str()),
                    "shown={shown}"
                );
            }
        }
    }
}

#[test]
fn inline_secrets_reach_exactly_the_callers_own_vault() {
    let w = World::new();
    let own = SecretNamespace::User(w.owner);
    for p in w.paths() {
        let c = p.to_canonical();
        let got = authorize_inline(own, p.clone(), &c);
        assert_eq!(got.is_ok(), p.ns == own, "{c}");
    }
}
