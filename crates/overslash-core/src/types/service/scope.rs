use serde::{Deserialize, Serialize};

/// One scoped param: which argument supplies the value, and the **label** that
/// value is filed under in the derived permission key
/// (`{service}:{action}:{label}={value}`).
///
/// The label defaults to the param name and only differs when several params
/// mean the same thing to a human granting access: `to`, `cc`, and `bcc` are
/// all *recipients*, so all three are authored as `<param>:recipient` and one
/// `email:send:recipient=jane@example.com` grant covers an address wherever it
/// appears — and the same address on two headers collapses to one key, hence
/// one approval.
///
/// Serializes as `{param, label}` — API responses hand clients the resolved
/// pair so no consumer has to re-implement the `param:label` grammar. Only
/// the template document carries the compact authored form (see
/// [`ScopeParams`]'s `Serialize`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeParamRef {
    /// The action param whose value is scoped.
    pub param: String,
    /// The permission-key namespace the value is filed under.
    pub label: String,
}

impl ScopeParamRef {
    /// Parse the wire form: `"to"` (label = param) or `"to:recipient"`.
    /// Both sides must be bare identifiers — the key grammar is `:`-delimited,
    /// so a label containing `:` or `=` would produce a key no one can parse
    /// back.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (param, label) = match s.split_once(':') {
            Some((p, l)) => (p, l),
            None => (s, s),
        };
        for (side, v) in [("param", param), ("label", label)] {
            if !is_scope_ident(v) {
                return Err(format!(
                    "scope_param entry {s:?}: {side} {v:?} must be an identifier \
                     ([A-Za-z_][A-Za-z0-9_]*)"
                ));
            }
        }
        Ok(Self {
            param: param.to_string(),
            label: label.to_string(),
        })
    }

    /// The wire form — `param` when the label is implicit, else `param:label`.
    pub fn to_wire(&self) -> String {
        if self.param == self.label {
            self.param.clone()
        } else {
            format!("{}:{}", self.param, self.label)
        }
    }
}

/// Is `s` a bare identifier? Used for both sides of a `param:label` entry and,
/// in `permissions`, to recognize a `label=` prefix on a derived key.
pub fn is_scope_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Which params provide the `{arg}` segment of an action's permission keys.
///
/// Empty means the action is unscoped and its arg is `*`. One entry is the
/// common case (`scope_param: repo`); several entries fan the keys out over
/// the union of their values, which is what lets a send be gated on every
/// recipient rather than just the ones in `to`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeParams(Vec<ScopeParamRef>);

impl ScopeParams {
    pub fn refs(&self) -> &[ScopeParamRef] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parse from the authored form: one string, or a list of them.
    pub fn parse_list<'a>(entries: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        entries
            .into_iter()
            .map(ScopeParamRef::parse)
            .collect::<Result<Vec<_>, _>>()
            .map(ScopeParams)
    }
}

impl FromIterator<ScopeParamRef> for ScopeParams {
    fn from_iter<I: IntoIterator<Item = ScopeParamRef>>(iter: I) -> Self {
        ScopeParams(iter.into_iter().collect())
    }
}

impl From<&str> for ScopeParams {
    /// One param under its own name — the `scope_param: repo` shape, for call
    /// sites holding a param name rather than authored text (tests, in-code
    /// service definitions).
    ///
    /// Deliberately **not** a second parser: the `param:label` grammar lives
    /// only in [`ScopeParamRef::parse`], so text that might carry a label must
    /// go through [`ScopeParams::parse_list`], which rejects the shapes this
    /// would otherwise accept silently.
    fn from(param: &str) -> Self {
        ScopeParams(vec![ScopeParamRef {
            param: param.to_string(),
            label: param.to_string(),
        }])
    }
}

impl Serialize for ScopeParams {
    /// Round-trips the authored shape: a lone entry serializes as a bare
    /// string (so every template that predates lists stays byte-identical),
    /// several as a sequence.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.as_slice() {
            [one] => serializer.serialize_str(&one.to_wire()),
            many => serializer.collect_seq(many.iter().map(ScopeParamRef::to_wire)),
        }
    }
}

impl<'de> Deserialize<'de> for ScopeParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            One(String),
            Many(Vec<String>),
        }
        let raw = Raw::deserialize(deserializer)?;
        let entries = match &raw {
            Raw::One(s) => std::slice::from_ref(s),
            Raw::Many(v) => v.as_slice(),
        };
        ScopeParams::parse_list(entries.iter().map(String::as_str))
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ScopeParams ──────────────────────────────────────────────────────

    /// A template that scopes on one param must round-trip as the bare string
    /// it was authored as — otherwise adopting the list syntax would rewrite
    /// every shipped YAML on the next normalize-and-persist.
    #[test]
    fn scope_params_round_trip_a_single_bare_param() {
        let sp: ScopeParams = serde_json::from_value(serde_json::json!("repo")).unwrap();
        assert_eq!(
            sp.refs(),
            [ScopeParamRef {
                param: "repo".into(),
                label: "repo".into()
            }]
        );
        assert_eq!(
            serde_json::to_value(&sp).unwrap(),
            serde_json::json!("repo")
        );
    }

    #[test]
    fn scope_params_round_trip_a_labelled_list() {
        let authored = serde_json::json!(["to:recipient", "cc:recipient", "bcc:recipient"]);
        let sp: ScopeParams = serde_json::from_value(authored.clone()).unwrap();
        assert_eq!(
            sp.refs()
                .iter()
                .map(|r| (r.param.as_str(), r.label.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("to", "recipient"),
                ("cc", "recipient"),
                ("bcc", "recipient")
            ]
        );
        assert_eq!(serde_json::to_value(&sp).unwrap(), authored);
    }

    /// An implicit label is not written back out: `to` in, `to` out, never
    /// `to:to`.
    #[test]
    fn scope_params_omit_an_implicit_label() {
        let sp: ScopeParams = serde_json::from_value(serde_json::json!(["to", "cc"])).unwrap();
        assert_eq!(
            serde_json::to_value(&sp).unwrap(),
            serde_json::json!(["to", "cc"])
        );
    }

    #[test]
    fn scope_params_reject_malformed_entries() {
        for bad in [
            serde_json::json!("a:b:c"),
            serde_json::json!(":x"),
            serde_json::json!("to:"),
            serde_json::json!("to recipient"),
            serde_json::json!(["ok", 3]),
            serde_json::json!({ "to": "recipient" }),
        ] {
            assert!(
                serde_json::from_value::<ScopeParams>(bad.clone()).is_err(),
                "{bad} should not parse as a scope_param"
            );
        }
    }
}
