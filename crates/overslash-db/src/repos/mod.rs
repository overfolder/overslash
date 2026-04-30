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
pub mod billing;
pub mod byoc_credential;
pub mod connection;
pub mod enabled_global_template;
pub mod execution;
pub mod group;
pub mod identity;
pub mod mcp_client_agent_binding;
pub mod mcp_elicitation;
pub mod mcp_refresh_token;
pub mod mcp_upstream_connection;
pub mod mcp_upstream_flow;
pub mod mcp_upstream_token;
pub mod membership;
pub mod oauth_mcp_client;
pub mod oauth_provider;
pub mod org;
pub mod org_bootstrap;
pub mod org_idp_config;
pub mod permission_rule;
pub mod rate_limit;
pub mod secret;
pub mod secret_request;
pub mod service_action_embedding;
pub mod service_instance;
pub mod service_template;
pub mod user;
pub mod webhook;
