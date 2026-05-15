//! `overslash admin reencrypt` — thin shim that reads `DATABASE_URL` and the
//! keyring env vars, then dispatches to the library routine in
//! `overslash_api::services::key_rotation`. Keeping the body in the lib
//! lets integration tests drive the same loop against a test pool without
//! shelling out to the CLI.

use anyhow::{Context, Result};
use overslash_api::services::key_rotation::{self, Options, Reporter, Stats};
use overslash_core::crypto::Keyring;
use sqlx::PgPool;
use std::env;

struct StdoutReporter {
    dry_run: bool,
}

impl Reporter for StdoutReporter {
    fn target_done(&mut self, table: &str, column: &str, stats: &Stats) {
        println!(
            "{table}.{column}: {total} scanned ({already} already-active, {redo} re-encrypted, {err} errors){dry}",
            table = table,
            column = column,
            total = stats.total,
            already = stats.already_active,
            redo = stats.re_encrypted,
            err = stats.errors,
            dry = if self.dry_run { " [dry-run]" } else { "" },
        );
    }
}

pub async fn run(opts: Options) -> Result<()> {
    let database_url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let keyring = Keyring::from_env().context("failed to build Keyring from env")?;
    let pool = PgPool::connect(&database_url)
        .await
        .with_context(|| format!("connect to {database_url}"))?;

    let mut reporter = StdoutReporter {
        dry_run: opts.dry_run,
    };
    let grand = key_rotation::run(&pool, &keyring, opts, &mut reporter).await?;

    println!();
    println!(
        "total: {} scanned, {} re-encrypted, {} already-active, {} errors{}",
        grand.total,
        grand.re_encrypted,
        grand.already_active,
        grand.errors,
        if opts.dry_run { " [dry-run]" } else { "" },
    );

    if grand.errors > 0 {
        anyhow::bail!("re-encrypt finished with {} error(s)", grand.errors);
    }
    Ok(())
}
