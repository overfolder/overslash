pub mod repos;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
