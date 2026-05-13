//! Re-encrypt every ciphertext at rest under the active master key.
//!
//! Used as step 4 of the master-key rotation runbook: after the operator
//! has deployed with both `SECRETS_ENCRYPTION_KEY` and
//! `SECRETS_ENCRYPTION_KEY_PREVIOUS` set, this routine walks every
//! encrypted column and rewrites it under the active key.
//!
//! Concurrency with the live API:
//! - Reads are unaffected: every blob (old- or new-key) decrypts via the
//!   dual-key keyring throughout the rotation window.
//! - Writes are safe: each UPDATE here is a compare-and-swap on the
//!   original ciphertext. If a live write (new secret version, OAuth
//!   refresh, BYOC update) replaces a row between our SELECT and UPDATE,
//!   the CAS misses, we leave the fresh value in place, and count it as
//!   already-active (the live write went through the rotated keyring, so
//!   it's already tagged with the active key id).
//!
//! Dynamic SQL is intentional here: the loop iterates a static list of
//! `(table, column)` targets and runs the same `SELECT … LIMIT` /
//! `UPDATE … WHERE id = … AND col = …` shape against each. Pre-expanding
//! to 18 `sqlx::query!()` macros would obscure the structure without
//! adding type safety — every target shares the `(Uuid, Vec<u8>)` row
//! shape. Same trade-off as `services/embedding_backfill.rs`.
//!
//! Exposed as a library function so the CLI (`overslash admin reencrypt`)
//! and integration tests can drive the same loop.

#![allow(clippy::disallowed_methods)]

use anyhow::{Context, Result};
use overslash_core::crypto::{self, Keyring};
use sqlx::PgPool;
use uuid::Uuid;

/// One encrypted column on one table.
struct Target {
    table: &'static str,
    column: &'static str,
    nullable: bool,
}

const TARGETS: &[Target] = &[
    Target {
        table: "secret_versions",
        column: "encrypted_value",
        nullable: false,
    },
    Target {
        table: "connections",
        column: "encrypted_access_token",
        nullable: false,
    },
    Target {
        table: "connections",
        column: "encrypted_refresh_token",
        nullable: true,
    },
    Target {
        table: "byoc_credentials",
        column: "encrypted_client_id",
        nullable: false,
    },
    Target {
        table: "byoc_credentials",
        column: "encrypted_client_secret",
        nullable: false,
    },
    Target {
        table: "org_idp_configs",
        column: "encrypted_client_id",
        nullable: true,
    },
    Target {
        table: "org_idp_configs",
        column: "encrypted_client_secret",
        nullable: true,
    },
    Target {
        table: "mcp_upstream_tokens",
        column: "access_token_ciphertext",
        nullable: false,
    },
    Target {
        table: "mcp_upstream_tokens",
        column: "refresh_token_ciphertext",
        nullable: true,
    },
];

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub total: usize,
    pub already_active: usize,
    pub re_encrypted: usize,
    pub errors: usize,
}

impl Stats {
    fn add(&mut self, other: &Stats) {
        self.total += other.total;
        self.already_active += other.already_active;
        self.re_encrypted += other.re_encrypted;
        self.errors += other.errors;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub dry_run: bool,
    pub batch: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            dry_run: false,
            batch: 500,
        }
    }
}

/// Per-target callback emitted after each target completes. The CLI uses it
/// to print a progress line; tests can ignore it.
pub trait Reporter {
    fn target_done(&mut self, table: &str, column: &str, stats: &Stats);
}

pub struct NoopReporter;
impl Reporter for NoopReporter {
    fn target_done(&mut self, _table: &str, _column: &str, _stats: &Stats) {}
}

/// Drive the re-encrypt loop end-to-end. Refuses to run unless `keyring`
/// has a previous key — otherwise there's nothing to migrate from. Returns
/// aggregate stats; callers should treat `stats.errors > 0` as a partial
/// failure.
pub async fn run<R: Reporter>(
    pool: &PgPool,
    keyring: &Keyring,
    opts: Options,
    reporter: &mut R,
) -> Result<Stats> {
    if keyring.previous_id().is_none() {
        anyhow::bail!(
            "previous key is not set on the keyring — nothing to re-encrypt from. \
             Set SECRETS_ENCRYPTION_KEY_PREVIOUS during a rotation, then run again."
        );
    }

    let mut grand = Stats::default();
    for target in TARGETS {
        let stats = reencrypt_target(pool, keyring, target, opts).await?;
        reporter.target_done(target.table, target.column, &stats);
        grand.add(&stats);
    }
    Ok(grand)
}

async fn reencrypt_target(
    pool: &PgPool,
    keyring: &Keyring,
    target: &Target,
    opts: Options,
) -> Result<Stats> {
    let active_id = keyring.active_id();
    let mut stats = Stats::default();
    let mut after: Option<Uuid> = None;

    loop {
        let null_filter = if target.nullable {
            format!(" AND {col} IS NOT NULL", col = target.column)
        } else {
            String::new()
        };
        let rows: Vec<(Uuid, Vec<u8>)> = match after {
            Some(a) => {
                let sql = format!(
                    "SELECT id, {col} FROM {tbl} WHERE id > $1{null_filter} ORDER BY id LIMIT $2",
                    col = target.column,
                    tbl = target.table,
                    null_filter = null_filter,
                );
                sqlx::query_as(&sql)
                    .bind(a)
                    .bind(opts.batch as i64)
                    .fetch_all(pool)
                    .await
                    .with_context(|| format!("scan {}.{}", target.table, target.column))?
            }
            None => {
                let where_clause = if target.nullable {
                    format!(" WHERE {col} IS NOT NULL", col = target.column)
                } else {
                    String::new()
                };
                let sql = format!(
                    "SELECT id, {col} FROM {tbl}{where_clause} ORDER BY id LIMIT $1",
                    col = target.column,
                    tbl = target.table,
                );
                sqlx::query_as(&sql)
                    .bind(opts.batch as i64)
                    .fetch_all(pool)
                    .await
                    .with_context(|| format!("scan {}.{}", target.table, target.column))?
            }
        };

        if rows.is_empty() {
            break;
        }

        for (id, blob) in &rows {
            stats.total += 1;
            after = Some(*id);

            if blob.first().copied() == Some(active_id) {
                stats.already_active += 1;
                continue;
            }

            let plaintext = match crypto::decrypt(keyring, blob) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        table = target.table,
                        column = target.column,
                        row_id = %id,
                        error = %e,
                        "reencrypt: decrypt failed, skipping",
                    );
                    stats.errors += 1;
                    continue;
                }
            };

            let new_blob = match crypto::encrypt(keyring, &plaintext) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        table = target.table,
                        column = target.column,
                        row_id = %id,
                        error = %e,
                        "reencrypt: encrypt failed, skipping",
                    );
                    stats.errors += 1;
                    continue;
                }
            };

            if opts.dry_run {
                stats.re_encrypted += 1;
                continue;
            }

            // CAS on the original ciphertext: if the live API rewrote this
            // row between our SELECT and UPDATE (a new secret version, an
            // OAuth refresh, a BYOC update), the concurrent write already
            // went through the rotated keyring and is tagged with the
            // active key id — re-encrypting our stale plaintext on top of
            // it would silently lose the fresh value. With the `AND {col} =
            // $3` guard, rows_affected is 0 in that case and we treat the
            // row as already handled.
            let update_sql = format!(
                "UPDATE {tbl} SET {col} = $1 WHERE id = $2 AND {col} = $3",
                tbl = target.table,
                col = target.column,
            );
            match sqlx::query(&update_sql)
                .bind(&new_blob)
                .bind(id)
                .bind(blob)
                .execute(pool)
                .await
            {
                Ok(res) if res.rows_affected() == 1 => stats.re_encrypted += 1,
                Ok(_) => {
                    // Concurrent writer beat us to it; their value is
                    // already on the active key.
                    stats.already_active += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        table = target.table,
                        column = target.column,
                        row_id = %id,
                        error = %e,
                        "reencrypt: update failed, skipping",
                    );
                    stats.errors += 1;
                }
            }
        }

        if rows.len() < opts.batch {
            break;
        }
    }
    Ok(stats)
}
