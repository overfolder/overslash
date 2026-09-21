mod ceiling;
mod describe;
mod evaluate;
mod key;
mod matching;

pub use ceiling::{AccessLevel, CeilingGrant, GroupCeilingResult, check_group_ceiling};
pub use describe::{describe_pattern, describe_pattern_named, suggest_tiers};
pub use evaluate::{PermissionResult, check_permissions, check_permissions_screened};
/// Shared with `crate::tags` so `table:` tags name a database exactly the way
/// the `table=` permission keys minted from the same analysis do — one
/// sanitized, lowercased, length-capped string, built once.
pub use key::DbLabel;
pub use key::{DerivedKey, PermissionKey, SuggestedTier};
pub use matching::{derive_keys, key_covers, parse_derived_key};
