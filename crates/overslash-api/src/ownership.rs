use overslash_db::repos::OrgOwned;
use uuid::Uuid;

use crate::error::AppError;

/// Unwraps an `Option<T>` from a DB lookup and verifies the resource belongs
/// to the given org. Returns `AppError::NotFound` if the resource is missing
/// or belongs to a different org (preventing enumeration attacks).
pub fn require_org_owned<T: OrgOwned>(
    resource: Option<T>,
    org_id: Uuid,
    label: &str,
) -> Result<T, AppError> {
    let resource = resource.ok_or_else(|| AppError::NotFound(format!("{label} not found")))?;
    if resource.org_id() != org_id {
        return Err(AppError::NotFound(format!("{label} not found")));
    }
    Ok(resource)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FakeRow {
        org_id: Uuid,
    }

    impl OrgOwned for FakeRow {
        fn org_id(&self) -> Uuid {
            self.org_id
        }
    }

    #[test]
    fn none_returns_not_found() {
        let result = require_org_owned::<FakeRow>(None, Uuid::new_v4(), "widget");
        let err = result.unwrap_err();
        assert!(matches!(err, AppError::NotFound(msg) if msg == "widget not found"));
    }

    #[test]
    fn mismatched_org_returns_not_found() {
        let resource_org = Uuid::new_v4();
        let caller_org = Uuid::new_v4();
        let row = FakeRow {
            org_id: resource_org,
        };
        let result = require_org_owned(Some(row), caller_org, "widget");
        let err = result.unwrap_err();
        assert!(matches!(err, AppError::NotFound(msg) if msg == "widget not found"));
    }

    #[test]
    fn matching_org_returns_resource() {
        let org_id = Uuid::new_v4();
        let row = FakeRow { org_id };
        let result = require_org_owned(Some(row), org_id, "widget");
        let resource = result.unwrap();
        assert_eq!(resource.org_id, org_id);
    }
}
