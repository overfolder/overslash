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

/// What `classify_row` decided to do with a single blob. Extracted so the
/// pure decision logic — "tagged with active key?", "decrypts?", "what
/// would we write?" — can be unit-tested without a live Postgres.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RowDecision {
    /// Blob is already tagged with the active key id — skip the loop's
    /// write entirely (the fast path).
    AlreadyActive,
    /// Blob decrypted under the keyring and re-encrypted into `new_blob`.
    Rewrite { new_blob: Vec<u8> },
    /// Blob did not decrypt with either key — the loop logs and skips.
    DecryptError,
    /// Re-encrypt of the plaintext failed (vanishingly rare; AES-GCM
    /// encrypt is infallible once the key is valid).
    EncryptError,
}

/// Pure decision function for one row's blob. Reads byte 0 for the
/// fast-path skip, otherwise round-trips through the keyring.
///
/// The fast path also requires the blob to be at least `MIN_BLOB_LEN`
/// (1 version + 12 nonce + 16 GCM tag = 29 bytes). A truncated blob
/// whose first byte happens to equal the active key id — disk-level
/// corruption, partial write, manual SQL surgery — would otherwise be
/// silently skipped as "already on the active key" and stay in the
/// database undetected. Falling through to decrypt routes it to
/// `DecryptError` instead, so the operator sees a log line and an
/// error count.
pub(crate) fn classify_row(keyring: &Keyring, blob: &[u8]) -> RowDecision {
    if blob.len() >= crypto::MIN_BLOB_LEN && blob.first().copied() == Some(keyring.active_id()) {
        return RowDecision::AlreadyActive;
    }
    let plaintext = match crypto::decrypt(keyring, blob) {
        Ok(p) => p,
        Err(_) => return RowDecision::DecryptError,
    };
    match crypto::encrypt(keyring, &plaintext) {
        Ok(new_blob) => RowDecision::Rewrite { new_blob },
        Err(_) => RowDecision::EncryptError,
    }
}

async fn reencrypt_target(
    pool: &PgPool,
    keyring: &Keyring,
    target: &Target,
    opts: Options,
) -> Result<Stats> {
    let mut stats = Stats::default();
    // Keyset cursor. `Uuid::nil()` is `00000000-…-0000`, which sorts below
    // every gen_random_uuid() value, so the very first page reads from the
    // start without needing a separate "no-cursor" SQL variant.
    let mut after: Uuid = Uuid::nil();

    let null_filter = if target.nullable {
        format!(" AND {col} IS NOT NULL", col = target.column)
    } else {
        String::new()
    };
    let sql = format!(
        "SELECT id, {col} FROM {tbl} WHERE id > $1{null_filter} ORDER BY id LIMIT $2",
        col = target.column,
        tbl = target.table,
        null_filter = null_filter,
    );

    loop {
        let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(&sql)
            .bind(after)
            .bind(opts.batch as i64)
            .fetch_all(pool)
            .await
            .with_context(|| format!("scan {}.{}", target.table, target.column))?;

        if rows.is_empty() {
            break;
        }

        for (id, blob) in &rows {
            stats.total += 1;
            after = *id;

            let new_blob = match classify_row(keyring, blob) {
                RowDecision::AlreadyActive => {
                    stats.already_active += 1;
                    continue;
                }
                RowDecision::DecryptError => {
                    tracing::warn!(
                        table = target.table,
                        column = target.column,
                        row_id = %id,
                        "reencrypt: decrypt failed, skipping",
                    );
                    stats.errors += 1;
                    continue;
                }
                RowDecision::EncryptError => {
                    tracing::warn!(
                        table = target.table,
                        column = target.column,
                        row_id = %id,
                        "reencrypt: encrypt failed, skipping",
                    );
                    stats.errors += 1;
                    continue;
                }
                RowDecision::Rewrite { new_blob } => new_blob,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key_a() -> [u8; 32] {
        [0xAB; 32]
    }
    fn key_b() -> [u8; 32] {
        [0xCD; 32]
    }

    #[test]
    fn classify_row_skips_blob_already_on_active_key() {
        let kr = Keyring::dual(2, key_b(), 1, key_a()).unwrap();
        let blob = crypto::encrypt(&kr, b"already rotated").unwrap();
        assert_eq!(blob[0], 2, "encrypt writes the active key id");
        assert_eq!(classify_row(&kr, &blob), RowDecision::AlreadyActive);
    }

    #[test]
    fn classify_row_rewrites_blob_on_previous_key() {
        // Write with single-key (id=1), then rotate.
        let pre = Keyring::single(1, key_a()).unwrap();
        let legacy = crypto::encrypt(&pre, b"needs rotation").unwrap();
        assert_eq!(legacy[0], 1);

        let post = Keyring::dual(2, key_b(), 1, key_a()).unwrap();
        match classify_row(&post, &legacy) {
            RowDecision::Rewrite { new_blob } => {
                // New blob is tagged with the active id and decrypts to
                // the same plaintext under the rotated keyring.
                assert_eq!(new_blob[0], 2);
                let recovered = crypto::decrypt(&post, &new_blob).unwrap();
                assert_eq!(recovered, b"needs rotation");
            }
            other => panic!("expected Rewrite, got {other:?}"),
        }
    }

    #[test]
    fn classify_row_returns_decrypt_error_for_unknown_version() {
        let kr = Keyring::dual(2, key_b(), 1, key_a()).unwrap();
        // Hand-craft a blob with version=9 — neither slot's id.
        let mut blob = vec![9u8];
        blob.extend_from_slice(&[0u8; 12]); // nonce
        blob.extend_from_slice(&[0u8; 16]); // bogus tag-sized ct
        assert_eq!(classify_row(&kr, &blob), RowDecision::DecryptError);
    }

    #[test]
    fn classify_row_decrypt_error_for_corrupt_ciphertext_under_known_id() {
        let kr = Keyring::dual(2, key_b(), 1, key_a()).unwrap();
        // Blob carries a known version byte but the ciphertext bytes are
        // garbage — AEAD tag check fails inside decrypt.
        let mut blob = vec![1u8];
        blob.extend_from_slice(&[0u8; 12]);
        blob.extend_from_slice(&[0xFFu8; 16]);
        assert_eq!(classify_row(&kr, &blob), RowDecision::DecryptError);
    }

    #[test]
    fn classify_row_does_not_fast_path_truncated_blob_with_active_id_byte() {
        // Disk corruption / partial write scenario: a 5-byte row whose
        // first byte happens to equal the active key id. The fast-path
        // skip MUST NOT classify this as AlreadyActive — that would
        // leave the corrupt row in the DB undetected. Falling through
        // to decrypt routes it to DecryptError so the operator sees a
        // log line + an `errors` counter bump.
        let kr = Keyring::dual(2, key_b(), 1, key_a()).unwrap();
        let truncated = vec![2u8, 0u8, 0u8, 0u8, 0u8]; // 5 bytes, active id prefix
        assert_eq!(classify_row(&kr, &truncated), RowDecision::DecryptError);
    }

    #[test]
    fn stats_add_sums_each_counter() {
        let mut a = Stats {
            total: 1,
            already_active: 2,
            re_encrypted: 3,
            errors: 4,
        };
        let b = Stats {
            total: 10,
            already_active: 20,
            re_encrypted: 30,
            errors: 40,
        };
        a.add(&b);
        assert_eq!(a.total, 11);
        assert_eq!(a.already_active, 22);
        assert_eq!(a.re_encrypted, 33);
        assert_eq!(a.errors, 44);
    }

    #[test]
    fn options_default_is_live_write_batch_500() {
        let opts = Options::default();
        assert!(!opts.dry_run);
        assert_eq!(opts.batch, 500);
    }

    #[test]
    fn noop_reporter_does_not_panic() {
        let mut r = NoopReporter;
        r.target_done("t", "c", &Stats::default());
    }
}
