mod ceiling;
mod describe;
mod evaluate;
mod key;
mod matching;

pub use ceiling::{AccessLevel, CeilingGrant, GroupCeilingResult, check_group_ceiling};
pub use describe::{describe_pattern, describe_pattern_named, suggest_tiers};
pub use evaluate::{PermissionResult, check_permissions, check_permissions_screened};
pub use key::{DerivedKey, PermissionKey, SuggestedTier};
pub use matching::{derive_keys, key_covers, parse_derived_key};
