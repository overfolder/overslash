pub mod repos;
pub mod scopes;

pub use scopes::{AgentScope, OrgScope, SystemScope, UserScope};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
