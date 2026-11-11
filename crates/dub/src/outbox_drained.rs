// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! `dub --outbox-drained`: whether the People-lane outbox holds anything the
//! writer can still submit. The gate before enacting a People runtime upgrade
//! that changes `PeopleLite.attest`, with `INTAKE_PAUSED` set.

use anyhow::{bail, Context as _};
use device_attestation::chain::outbox;

/// Prints each non-terminal status that still has rows, and fails unless
/// there are none. Reads `DATABASE_URL`, and never migrates it.
pub async fn run() -> anyhow::Result<()> {
    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let pool = device_attestation::db::connect_without_migrating(&database_url).await?;
    let depths = outbox::depth_by_status(&pool)
        .await
        .context("reading the outbox depth by status")?;

    let undrained = outbox::undrained(&depths);
    if undrained.is_empty() {
        println!("drained: every People-lane row is ASSIGNED or FAILED_TERMINAL");
        return Ok(());
    }
    let mut total: i64 = 0;
    for (status, rows) in &undrained {
        println!("{} {rows}", status.as_str());
        total += rows;
    }
    bail!("not drained: {total} People-lane rows can still be submitted");
}
