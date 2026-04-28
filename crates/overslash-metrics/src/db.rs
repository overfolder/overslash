//! Database pool gauge. The API binary spawns a small task that polls its
//! `PgPool` every 30s and feeds the values here.

use metrics::gauge;

pub fn record_pool(active: u32, idle: u32) {
    gauge!("overslash_db_pool_connections", "state" => "active").set(f64::from(active));
    gauge!("overslash_db_pool_connections", "state" => "idle").set(f64::from(idle));
}
