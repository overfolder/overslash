use uuid::Uuid;

pub trait OrgOwned {
    fn org_id(&self) -> Uuid;
}

macro_rules! impl_org_owned {
    ($ty:ty) => {
        impl $crate::repos::OrgOwned for $ty {
            fn org_id(&self) -> Uuid {
                self.org_id
            }
        }
    };
}
pub(crate) use impl_org_owned;

pub mod api_key;
pub mod approval;
pub mod audit;
pub mod byoc_credential;
pub mod connection;
pub mod enabled_global_template;
pub mod enrollment_token;
pub mod group;
pub mod identity;
pub mod oauth_provider;
pub mod org;
pub mod org_bootstrap;
pub mod org_idp_config;
pub mod pending_enrollment;
pub mod permission_rule;
pub mod rate_limit;
pub mod secret;
pub mod service_instance;
pub mod service_template;
pub mod webhook;
