//! Static analysis of credential templates: which inputs does this expression
//! read?
//!
//! Answered once, at template-compile time, so the request path never parses
//! jq to decide what to decrypt. The result is stored on the compiled
//! `ServiceAuth::Secret` and narrowed into each `SecretRef`'s bindings, so a
//! template declaring five slots whose header names two decrypts two.
//!
//! An expression reads two kinds of input, and the *only* thing that tells
//! them apart is the declarations: a key listed under
//! `components.x-overslash-config` is a plain per-instance value, anything else
//! is a vault secret slot. [`referenced_inputs`] finds the reads;
//! [`partition_reads`] splits them. The walk is identical either way — a
//! non-secret input does not relax a single one of the refusals below, because
//! an expression that can reach *any* unnamed key can reach a secret.
//!
//! Evaluation lives in `overslash-api` (it needs `jaq-std`/`jaq-json`); this
//! module only lexes, parses and walks.

use jaq_core::load::{
    Lexer,
    lex::StrPart,
    parse::{Parser, Term},
};
use jaq_core::path::Part;

use crate::types::CredentialTemplate;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TemplateError {
    /// The expression does not lex/parse. Carries jq's own message, which
    /// quotes program text only — never a value.
    #[error("invalid jq expression: {0}")]
    Syntax(String),
    /// A path access whose key is not a literal. Static slot analysis is what
    /// lets us decrypt exactly the named secrets and hand the evaluator
    /// nothing else, so a computed key is refused rather than over-approximated.
    #[error(
        "`{0}` reads a secret slot by a computed key; slots must be named \
         literally (e.g. `.mailbox_user`) so the gateway knows which secrets \
         to decrypt"
    )]
    DynamicAccess(String),
}

/// The reads an expression's inputs must satisfy, split by kind.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TemplateReads {
    /// Vault secret slots — every read not declared as config.
    pub slots: Vec<String>,
    /// Non-secret per-instance values, in declaration-agnostic source order.
    pub config: Vec<String>,
}

/// Split an expression's reads against the template's declared config keys.
///
/// Anything not declared as config is a secret slot: the default is the safe
/// one, so a config declaration that is later removed turns its reads back into
/// slots (which then fail extraction as undeclared) rather than silently
/// leaving a credential half-built from a value nobody supplies.
pub fn partition_reads(
    template: &CredentialTemplate,
    declared_config: &[String],
) -> Result<TemplateReads, TemplateError> {
    let (config, slots): (Vec<String>, Vec<String>) = referenced_inputs(template)?
        .into_iter()
        .partition(|key| declared_config.iter().any(|d| d == key));
    Ok(TemplateReads { slots, config })
}

/// Every input key the expression reads, in source order, deduped — secrets and
/// config alike. Callers that need the split use [`partition_reads`]; callers
/// that only need "is every input present?" (send-time rendering) use this.
pub fn referenced_inputs(template: &CredentialTemplate) -> Result<Vec<String>, TemplateError> {
    let CredentialTemplate::Jq { expr } = template;

    let tokens = Lexer::new(expr.as_str())
        .lex()
        .map_err(|errs| TemplateError::Syntax(format_lex_errors(&errs)))?;
    let term = Parser::new(&tokens)
        .parse(|p| p.term())
        .map_err(|_| TemplateError::Syntax("could not parse expression".into()))?;

    let mut slots = Vec::new();
    walk(&term, &mut slots)?;
    slots.dedup();
    Ok(slots)
}

/// Collect literal `.slot` reads, rejecting anything that could reach a slot
/// we cannot see. `push_slot` keeps source order while deduping neighbours;
/// the caller's `dedup` is not enough for repeats far apart, so check first.
fn push_slot(slots: &mut Vec<String>, key: &str) {
    if !slots.iter().any(|s| s == key) {
        slots.push(key.to_string());
    }
}

fn walk(term: &Term<&str>, slots: &mut Vec<String>) -> Result<(), TemplateError> {
    match term {
        // `.a`, `."a"`, and longer paths. Only a path rooted at `.` with a
        // single literal string index names a slot; `.a.b` would index into a
        // secret's value, which is a string, so it is a template bug — but it
        // is not a *safety* problem, and jq will fail it at runtime. What we
        // must refuse is a key we cannot read statically.
        Term::Path(inner, path) => {
            walk(inner, slots)?;
            for (part, _opt) in &path.0 {
                match part {
                    Part::Index(idx) => match literal_str(idx) {
                        Some(key) => push_slot(slots, key),
                        None => return Err(TemplateError::DynamicAccess(describe(idx))),
                    },
                    // `.[]`, `.[1:2]` — iterating or slicing the slot object
                    // reaches every slot without naming one.
                    Part::Range(..) => {
                        return Err(TemplateError::DynamicAccess(".[]".into()));
                    }
                }
            }
            Ok(())
        }
        // Any call that can reach the whole input by name rather than by
        // literal path. Allowing these would silently break the guarantee
        // that we decrypt only what the expression names.
        Term::Call(name, args) => {
            if matches!(
                *name,
                "getpath"
                    | "keys"
                    | "keys_unsorted"
                    | "to_entries"
                    | "with_entries"
                    | "paths"
                    | "leaf_paths"
                    | "any"
                    | "all"
                    | "env"
                    | "input"
                    | "inputs"
                    | "$ENV"
            ) {
                return Err(TemplateError::DynamicAccess((*name).to_string()));
            }
            args.iter().try_for_each(|a| walk(a, slots))
        }
        Term::Recurse => Err(TemplateError::DynamicAccess("..".into())),

        Term::Str(_fmt, parts) => parts.iter().try_for_each(|p| match p {
            StrPart::Term(t) => walk(t, slots),
            StrPart::Str(_) | StrPart::Char(_) => Ok(()),
        }),
        Term::Arr(inner) => inner.iter().try_for_each(|t| walk(t, slots)),
        Term::Obj(pairs) => pairs.iter().try_for_each(|(k, v)| {
            walk(k, slots)?;
            v.iter().try_for_each(|v| walk(v, slots))
        }),
        Term::Neg(t) => walk(t, slots),
        Term::BinOp(l, _, r) => {
            walk(l, slots)?;
            walk(r, slots)
        }
        Term::Label(_, t) => walk(t, slots),
        Term::Fold(_, source, _, body) => {
            walk(source, slots)?;
            body.iter().try_for_each(|t| walk(t, slots))
        }
        Term::TryCatch(t, c) => {
            walk(t, slots)?;
            c.iter().try_for_each(|t| walk(t, slots))
        }
        Term::IfThenElse(branches, otherwise) => {
            branches.iter().try_for_each(|(c, t)| {
                walk(c, slots)?;
                walk(t, slots)
            })?;
            otherwise.iter().try_for_each(|t| walk(t, slots))
        }
        Term::Def(defs, t) => {
            defs.iter().try_for_each(|d| walk(&d.body, slots))?;
            walk(t, slots)
        }
        Term::Id | Term::Num(_) | Term::Break(_) | Term::Var(_) => Ok(()),
    }
}

/// The string a path index names, when it is a plain literal.
fn literal_str<'s>(term: &Term<&'s str>) -> Option<&'s str> {
    match term {
        // `.a` — the parser stores the bare key as a format-less string with
        // one unescaped part, same as `."a"`.
        Term::Str(None, parts) => match parts.as_slice() {
            [StrPart::Str(s)] => Some(s),
            _ => None,
        },
        _ => None,
    }
}

/// A short, value-free description of a term, for error messages.
fn describe(term: &Term<&str>) -> String {
    match term {
        Term::Var(v) => format!(".[{v}]"),
        Term::Str(..) => ".[<interpolated string>]".into(),
        Term::BinOp(..) => ".[<computed expression>]".into(),
        _ => ".[<computed key>]".into(),
    }
}

fn format_lex_errors(errs: &[jaq_core::load::lex::Error<&str>]) -> String {
    let mut out = String::new();
    for (expect, src) in errs {
        out.push_str(&format!(
            "expected {} near `{}`; ",
            expect.as_str(),
            src.chars().take(30).collect::<String>()
        ));
    }
    if out.is_empty() {
        out.push_str("could not lex expression");
    }
    out.trim_end_matches([';', ' ']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slots(expr: &str) -> Result<Vec<String>, TemplateError> {
        referenced_inputs(&CredentialTemplate::Jq {
            expr: expr.to_string(),
        })
    }

    fn ok(expr: &str) -> Vec<String> {
        slots(expr).expect("expression should analyse")
    }

    fn split(expr: &str, declared_config: &[&str]) -> TemplateReads {
        partition_reads(
            &CredentialTemplate::Jq {
                expr: expr.to_string(),
            },
            &declared_config
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )
        .expect("expression should analyse")
    }

    #[test]
    fn partitions_the_email_template() {
        // The shape `services/email.yaml` ships: a declared-config username
        // joined with a vaulted password.
        let reads = split(
            r#""Basic " + (.mailbox_user + ":" + .mailbox_pass | @base64)"#,
            &["mailbox_user"],
        );
        assert_eq!(reads.slots, ["mailbox_pass"]);
        assert_eq!(reads.config, ["mailbox_user"]);
    }

    #[test]
    fn undeclared_reads_default_to_secret_slots() {
        // Nothing declared → every read is a slot, which is exactly the
        // pre-config behaviour and the safe default.
        let reads = split(".mailbox_user + .mailbox_pass", &[]);
        assert_eq!(reads.slots, ["mailbox_user", "mailbox_pass"]);
        assert!(reads.config.is_empty());
    }

    #[test]
    fn declared_config_the_expression_never_reads_is_not_reported() {
        let reads = split(".token", &["region", "tenant"]);
        assert_eq!(reads.slots, ["token"]);
        assert!(reads.config.is_empty());
    }

    /// A config declaration must not buy an expression any freedom: `.[$k]`
    /// can reach a secret whatever else the template declares.
    #[test]
    fn partition_still_refuses_dynamic_access() {
        let err = partition_reads(
            &CredentialTemplate::Jq {
                expr: ".[$k]".to_string(),
            },
            &["k".to_string()],
        )
        .unwrap_err();
        assert!(matches!(err, TemplateError::DynamicAccess(_)));
    }

    #[test]
    fn bare_key() {
        assert_eq!(ok(".mailbox_user"), ["mailbox_user"]);
    }

    #[test]
    fn quoted_key() {
        assert_eq!(ok(r#"."mailbox user""#), ["mailbox user"]);
    }

    #[test]
    fn the_email_template() {
        assert_eq!(
            ok(r#""Basic " + (.mailbox_user + ":" + .mailbox_pass | @base64)"#),
            ["mailbox_user", "mailbox_pass"]
        );
    }

    #[test]
    fn string_interpolation() {
        assert_eq!(ok(r#""\(.user):\(.pass)""#), ["user", "pass"]);
    }

    #[test]
    fn repeated_slot_deduped_in_source_order() {
        assert_eq!(ok(".b + .a + .b"), ["b", "a"]);
    }

    #[test]
    fn alternative_default() {
        assert_eq!(ok(r#".tenant // "default""#), ["tenant"]);
    }

    #[test]
    fn conditional() {
        assert_eq!(
            ok(r#"if .tenant then .tenant + "\\" + .user else .user end"#),
            ["tenant", "user"]
        );
    }

    #[test]
    fn no_slots_is_allowed_here() {
        // A constant expression analyses fine; extract.rs is what rejects a
        // scheme whose template names no slot.
        assert_eq!(ok(r#""static""#), Vec::<String>::new());
    }

    // --- rejections: anything that could reach an unnamed slot ---

    #[test]
    fn variable_index_rejected() {
        assert!(matches!(
            slots(".[$k]"),
            Err(TemplateError::DynamicAccess(_))
        ));
    }

    #[test]
    fn computed_index_rejected() {
        assert!(matches!(
            slots(r#".["a" + "b"]"#),
            Err(TemplateError::DynamicAccess(_))
        ));
    }

    #[test]
    fn iteration_rejected() {
        assert!(matches!(slots(".[]"), Err(TemplateError::DynamicAccess(_))));
    }

    #[test]
    fn getpath_rejected() {
        assert!(matches!(
            slots(r#"getpath(["mailbox_user"])"#),
            Err(TemplateError::DynamicAccess(_))
        ));
    }

    #[test]
    fn keys_and_entries_rejected() {
        for expr in ["keys", "to_entries", "with_entries(.value)", "paths"] {
            assert!(
                matches!(slots(expr), Err(TemplateError::DynamicAccess(_))),
                "{expr} should be rejected"
            );
        }
    }

    #[test]
    fn recurse_rejected() {
        assert!(matches!(slots(".."), Err(TemplateError::DynamicAccess(_))));
    }

    #[test]
    fn syntax_error_reported() {
        assert!(matches!(
            slots(r#""unterminated"#),
            Err(TemplateError::Syntax(_))
        ));
    }

    #[test]
    fn errors_never_quote_values() {
        // The analyser only ever sees program text, but pin the property:
        // no error may echo something that looks like a credential.
        let err = slots(".[$secret]").unwrap_err().to_string();
        assert!(!err.contains("password"));
        assert!(err.contains("literally"));
    }
}
