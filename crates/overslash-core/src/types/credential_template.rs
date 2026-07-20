use serde::{Deserialize, Serialize};

/// How a credential's value is built from the service's secret slots.
///
/// Tagged by `lang` so a second language is a new variant rather than a
/// breaking change — the same wire shape as the response filter
/// (`overslash-api`'s `ResponseFilter`), and deliberately so: jq is the one
/// expression language in this product.
///
/// The expression's input is a JSON object of slot key → plaintext secret,
/// containing only the slots the expression names. It must produce exactly one
/// string, which becomes the header or query-parameter value verbatim.
///
/// ```yaml
/// x-overslash-template:
///   lang: jq
///   expr: '"Basic " + (.mailbox_user + ":" + .mailbox_pass | @base64)'
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "lang", rename_all = "lowercase")]
pub enum CredentialTemplate {
    Jq { expr: String },
}

impl CredentialTemplate {
    pub fn lang(&self) -> &'static str {
        match self {
            Self::Jq { .. } => "jq",
        }
    }

    pub fn expr(&self) -> &str {
        match self {
            Self::Jq { expr } => expr,
        }
    }
}
