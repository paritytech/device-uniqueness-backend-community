// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Context as _;

use device_attestation::queue::{self, AdvancerConfig};
use device_attestation::AssetHub;

pub async fn run() -> anyhow::Result<()> {
    http_common::telemetry::init("registration-queue");
    http_common::metrics::spawn("registration-queue");

    let config = AdvancerConfig::from_env().context("invalid registration-queue configuration")?;
    let pool = device_attestation::db::connect(&config.database_url).await?;
    // Asset Hub, not People: the advancer's only chain read is the balance
    // that decides a claim's priority group, and that is the same balance the
    // payment lane watches for deposits. Read-only — the shape assertion the
    // writer makes is not this process's concern.
    let chain = AssetHub::connect_read_only(&config.asset_hub_rpc_url).await?;
    queue::run_advancer(pool, chain, config).await;
    Ok(())
}
