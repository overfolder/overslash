use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::action::{ActionParam, DisclosureField};
use super::risk::Risk;
use super::scope::ScopeParams;

/// `x-overslash-subactions`: the declared variants of one overloaded action,
/// classified per call from the request's own params.
///
/// HubSpot's `manage_crm_objects` creates or updates *any* CRM object, a batch
/// at a time, so one action key and one static label cover "create a contact"
/// and "update a deal" alike. A subaction gives each of those its own
/// description, risk, permission key and disclosure without changing what is
/// sent upstream: the call still goes to the parent, and the variants only
/// decide how it is *described and gated*.
///
/// Classification is per **item**. [`each`](Self::each) splits the params
/// into units of work (one per object in a batch); every item is matched
/// against [`variants`](Self::variants) in order, and the call needs the keys
/// of every variant any item fell into. An item no variant claims stays with
/// the parent — its key and its description — which is exactly the
/// pre-subaction behaviour, so a gap in the variant list can only fail coarse.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubactionSpec {
    /// jq over the parent's params emitting one item per unit of work. `None`
    /// is the same as `.`: the whole params object is the single item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub each: Option<String>,
    /// Call-level description override. May `enumerate` over every item, and
    /// each item exposes `verb`, `phrase` and `subaction` beside its fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Verb for items no variant claims, in the default composition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    /// Per-item phrase for items no variant claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phrase: Option<String>,
    pub variants: Vec<Subaction>,
}

/// One variant of an overloaded action. See [`SubactionSpec`].
///
/// Carries the same controls a top-level action does — risk, `scope_param`,
/// disclose, redact, timeout, OAuth scopes — because a variant *is* an action
/// as far as a reviewer or an admin writing rules is concerned. Its permission
/// key is `{service}:{parent}/{key}:{arg}`, which a rule on the parent also
/// covers (see `permissions::matching`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subaction {
    pub key: String,
    /// jq predicate over one item. Truthy if any output is truthy.
    #[serde(rename = "match")]
    pub matches: String,
    /// Agent-facing description: listings, search, and a callable variant's
    /// own action entry.
    pub description: String,
    /// Clause verb in the default composition (`create`). Items sharing a verb
    /// are enumerated in one clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    /// Per-item noun phrase (`contact {item.label}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phrase: Option<String>,
    /// Description used when every item of the call fell into this variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Named jq expressions evaluated against the item, exposed as
    /// `{item.<name>}`. Where nested or array-shaped content is lifted into
    /// something a description can name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
    /// Defaults to the parent's risk at extraction.
    pub risk: Risk,
    /// Resolved against the item (its fields plus `vars`), not the call.
    #[serde(default, skip_serializing_if = "ScopeParams::is_empty")]
    pub scope_param: ScopeParams,
    /// Appended to the parent's. The jq input gains `.items`: this variant's
    /// items, vars merged in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclose: Vec<DisclosureField>,
    /// Unioned with the parent's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
    /// When set, the variant is also an action of its own under [`key`](Self::key),
    /// taking a narrow `input_schema` that this jq rewrites into the parent's
    /// params.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<String>,
    /// A callable variant's own params, lowered from its `input_schema`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub params: HashMap<String, ActionParam>,
}

impl Subaction {
    pub fn is_callable(&self) -> bool {
        self.transform.is_some()
    }
}

/// On a callable variant's compiled action: which parent it rewrites into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubactionRef {
    pub parent: String,
    pub variant: String,
}

impl SubactionSpec {
    pub fn variant(&self, key: &str) -> Option<&Subaction> {
        self.variants.iter().find(|v| v.key == key)
    }

    /// The single jq program that classifies a call: `each`, every `match` and
    /// every `vars` expression folded together, so a call costs one evaluation.
    ///
    /// Output is one array of `{item, sub, vars}`, `sub` being the matched
    /// variant's index or `null`. Every user expression is parenthesised and
    /// wrapped so it cannot change the shape around it:
    ///
    /// - a predicate counts as matched if *any* of its outputs is truthy, so
    ///   one that emits nothing is a non-match rather than an item that
    ///   silently vanishes from the array (and from the gate);
    /// - a var takes its first output, `null` when it has none.
    ///
    /// An error anywhere fails the whole program, and the caller treats that
    /// as "unclassified": every item stays with the parent.
    pub fn classifier_program(&self) -> String {
        let each = self.each.as_deref().unwrap_or(".");
        let mut sub = String::from("(");
        for (i, v) in self.variants.iter().enumerate() {
            let kw = if i == 0 { "if" } else { "elif" };
            sub.push_str(&format!(" {kw} __ovs_m({}) then {i}", v.matches));
        }
        if self.variants.is_empty() {
            sub.push_str("null)");
        } else {
            sub.push_str(" else null end)");
        }
        let mut vars = String::from("(");
        let with_vars: Vec<(usize, &Subaction)> = self
            .variants
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.vars.is_empty())
            .collect();
        for (n, (i, v)) in with_vars.iter().enumerate() {
            let kw = if n == 0 { "if" } else { "elif" };
            let fields: Vec<String> = v
                .vars
                .iter()
                .map(|(name, expr)| {
                    let name = serde_json::to_string(name).expect("string serializes");
                    format!("{name}: ([{expr}] | first)")
                })
                .collect();
            vars.push_str(&format!(" {kw} $s == {i} then {{{}}}", fields.join(", ")));
        }
        if with_vars.is_empty() {
            vars.push_str("{})");
        } else {
            vars.push_str(" else {} end)");
        }
        format!(
            "def __ovs_m(f): [f] | any;\n\
             [{each}] | map(. as $it | {sub} as $s | {{item: $it, sub: $s, vars: {vars}}})"
        )
    }
}
