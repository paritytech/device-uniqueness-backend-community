// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Context as _;

use device_attestation::queue::{self, AdvancerConfig};
use device_attestation::PeopleChain;

pub async fn run() -> anyhow::Result<()> {
    http_common::telemetry::init("registration-queue");
    http_common::metrics::spawn("registration-queue");

    let config = AdvancerConfig::from_env().context("invalid registration-queue configuration")?;
    let pool = device_attestation::db::connect(&config.database_url).await?;
    let chain = PeopleChain::connect(&config.people_rpc_url).await?;
    queue::run_advancer(pool, chain, config).await;
    Ok(())
}
