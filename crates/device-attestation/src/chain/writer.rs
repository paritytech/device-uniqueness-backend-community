// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::{Duration, Instant};

use anyhow::Context as _;
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::PgPool;
use subxt::utils::AccountId32;

use chain_client::WriterSigner;

use super::{
    asset_hub::{AssetHub, ValidityWindow},
    lease,
    outbox::Guard,
    people::PeopleChain,
};
mod dotns;
mod engine;
mod events;
#[cfg(test)]
mod fixtures;
mod lane;
mod observe;
mod people;
mod tx;

use dotns::{Dotns, Window};
use engine::{Cx, Drain};
use lane::Lane as _;
use observe::{
    record_outbox_gauges, record_spec_version, record_writer_info, zero_init_submit_outcomes,
};
use people::People;

/// The claim size a writer uses when `CHAIN_WRITER_BATCH_SIZE` is unset or
/// unusable. Also the AIMD ceiling every lane climbs back to.
const DEFAULT_BATCH_SIZE: u16 = 25;

/// Chain-writer configuration, loaded from the environment.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// password, so it is a secret.
    pub database_url: SecretString,
    pub people_rpc_url: String,
    /// SURI of the hot signing key (the proxy key, or the primary in dev).
    pub signer_suri: SecretString,
    /// Attester authority (`ATTESTER_ACCOUNT`), the account device-attestation-api also
    /// publishes. Proxying is derived from it — see
    /// [`WriterSigner::proxy_for`].
    pub attester: [u8; 32],
    pub holder_id: String,
    /// Lease row name (all writers of one account share it).
    pub lease_name: String,
    /// Lease TTL / heartbeat expiry.
    pub lease_ttl: Duration,
    /// Idle poll interval between outbox scans.
    pub poll_interval: Duration,
    /// **Maximum** rows claimed per scan, and the ceiling the adaptive batch
    /// size climbs back to. Not a fixed claim size: a whole-batch failure
    /// halves the size in use, a success grows it by one, floor 1.
    pub batch_size: u16,
    /// Per-submit finalization timeout.
    pub finalize_timeout: Duration,
    /// Max submit attempts before a row is failed terminally.
    pub max_attempts: i32,
    /// Whether the registration queue is enabled (`QUEUE_ENABLED` — must
    /// match device-attestation-api's value). On: `QUEUED` rows are never drained here;
    /// a dead advancer only raises the stranded-queue warning, keeping the
    /// free lane's throttle intact. Off: this writer is the janitor that
    /// drains leftover `QUEUED` rows so retiring the queue strands nothing.
    pub queue_enabled: bool,
    /// Janitor grace (queue disabled only): how long the advancer's lease may
    /// be expired before leftover `QUEUED` rows are drained — the window that
    /// lets a live advancer finish a fair drain during the retire sequence.
    /// Doubles as the warning cadence while the queue is enabled.
    pub queue_fallback_after: Duration,
    /// Cadence of the payment watch pass (deposit detection + expiry over
    /// `payment_requests`). Read-only on chain; a no-op while the payment
    /// lane has never quoted anything.
    pub payment_poll_interval: Duration,
    /// Cadence of the attester-resources pass: read the attestation allowance
    /// and the account balances that registration silently dies without.
    pub resource_poll_interval: Duration,
    /// WARN below this many remaining attestations.
    pub allowance_floor: u32,
    /// WARN below this signer free balance, in planck (transaction fees come
    /// from the signer, not the proxied primary).
    pub signer_balance_floor_planck: u128,
    /// Whether the dotNS gateway lane is live (`DOTNS_GATEWAY_ENABLED`). Must
    /// match device-attestation-api's value, which gates intake. When off, no Asset Hub
    /// connection is opened at all and `dotns_status` rows are left alone.
    pub dotns_gateway_enabled: bool,
    /// Asset Hub RPC endpoint. Required when the dotNS lane is enabled.
    pub asset_hub_rpc_url: Option<String>,
}

impl WriterConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = http_common::config::required_var("DEVICE_ATTESTATION_DATABASE_URL")?;
        let people_rpc_url = std::env::var("PEOPLE_RPC_URL")
            .unwrap_or_else(|_| "wss://previewnet.substrate.dev/people".to_string());
        let signer_suri = std::env::var("CHAIN_WRITER_SIGNER_SURI")
            .context("CHAIN_WRITER_SIGNER_SURI is required")?;
        let attester = crate::config::attester_account_from_env()?;
        let holder_id = match std::env::var("CHAIN_WRITER_HOLDER_ID") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => format!(
                "writer-{}-{:08x}",
                std::process::id(),
                rand::random::<u32>()
            ),
        };

        Ok(Self {
            database_url: SecretString::from(database_url),
            people_rpc_url,
            signer_suri: SecretString::from(signer_suri),
            attester,
            holder_id,
            lease_name: std::env::var("CHAIN_WRITER_LEASE_NAME")
                .unwrap_or_else(|_| "people-chain-writer".to_string()),
            lease_ttl: Duration::from_secs(env_u64("CHAIN_WRITER_LEASE_TTL_SECS", 30)),
            poll_interval: Duration::from_secs(env_u64("CHAIN_WRITER_POLL_SECS", 2)),
            batch_size: env_u16("CHAIN_WRITER_BATCH_SIZE", DEFAULT_BATCH_SIZE),
            finalize_timeout: Duration::from_secs(env_u64("CHAIN_WRITER_FINALIZE_SECS", 120)),
            max_attempts: env_u64("CHAIN_WRITER_MAX_ATTEMPTS", 8) as i32,
            queue_enabled: crate::config::env_bool("QUEUE_ENABLED", false)?,
            queue_fallback_after: Duration::from_secs(crate::queue::env_u64_strict(
                "QUEUE_FALLBACK_AFTER_SECS",
                60,
            )?),
            payment_poll_interval: Duration::from_secs(crate::queue::env_u64_strict(
                "PAYMENT_POLL_INTERVAL_SECS",
                30,
            )?),
            resource_poll_interval: Duration::from_secs(crate::queue::env_u64_strict(
                "ATTESTER_RESOURCE_POLL_SECS",
                60,
            )?),
            allowance_floor: u32::try_from(crate::queue::env_u64_strict(
                "ATTESTER_ALLOWANCE_FLOOR",
                100,
            )?)
            .context("ATTESTER_ALLOWANCE_FLOOR must fit a u32")?,
            signer_balance_floor_planck: u128::from(crate::queue::env_u64_strict(
                "ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK",
                10_000_000_000,
            )?),
            dotns_gateway_enabled: crate::config::env_bool("DOTNS_GATEWAY_ENABLED", false)?,
            asset_hub_rpc_url: match std::env::var("ASSET_HUB_RPC_URL") {
                Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
                _ => None,
            },
        })
    }
}

pub async fn run(config: WriterConfig) -> anyhow::Result<()> {
    tracing::info!(
        people_rpc = %config.people_rpc_url,
        attester = %hex_account(&config.attester),
        holder = %config.holder_id,
        "starting device-attestation-chain-writer"
    );
    let pool = crate::db::connect(config.database_url.expose_secret()).await?;
    let chain = PeopleChain::connect(&config.people_rpc_url).await?;
    let signer = WriterSigner::from_secret(config.signer_suri.expose_secret())?;
    let signer_account = AccountId32(signer.public_bytes());
    let proxy_for = signer
        .proxy_for(AccountId32(config.attester))
        .map(|primary| primary.0);

    let dotns_lane = match (config.dotns_gateway_enabled, &config.asset_hub_rpc_url) {
        (true, Some(url)) => {
            tracing::info!(
                asset_hub_rpc = %url,
                "dotns lane enabled; Asset Hub connects on the first pass"
            );
            DotnsLane::Enabled {
                rpc_url: url.clone(),
                connected: None,
                last_error: None,
                retry_at: None,
            }
        }
        (true, None) => anyhow::bail!(
            "DOTNS_GATEWAY_ENABLED is on but ASSET_HUB_RPC_URL is unset. device-attestation-api would \
             accept dotns blocks that nothing ever submits — set the RPC URL, or turn the \
             gateway off for this environment."
        ),
        (false, _) => {
            tracing::info!("dotns lane disabled");
            DotnsLane::Disabled
        }
    };
    tracing::info!(
        signer = %hex_account(&signer_account.0),
        attester = %hex_account(&config.attester),
        mode = if proxy_for.is_some() { "proxy" } else { "direct" },
        "device-attestation-chain-writer connected"
    );
    record_writer_info(&config, &signer_account);
    zero_init_submit_outcomes();
    http_common::metrics::spawn_readiness_probe(
        "device-attestation-chain-writer",
        (pool.clone(), chain.clone()),
        |(p, c)| crate::http::health::probe(p, c),
    );

    let batch_max = config.batch_size;
    let mut writer = Writer {
        pool,
        chain,
        dotns_lane,
        signer,
        signer_account,
        proxy_for,
        config,
        people: Drain::new(batch_max),
        dotns: Drain::new(batch_max),
    };
    writer.run_forever().await
}

struct Writer {
    pool: PgPool,
    chain: PeopleChain,
    dotns_lane: DotnsLane,
    signer: WriterSigner,
    signer_account: AccountId32,
    proxy_for: Option<[u8; 32]>,
    config: WriterConfig,
    people: Drain<People>,
    dotns: Drain<Dotns>,
}

const DOTNS_RECONNECT_INTERVAL: Duration = Duration::from_secs(30);

enum DotnsLane {
    Disabled,
    Enabled {
        rpc_url: String,
        connected: Option<(AssetHub, ValidityWindow)>,
        last_error: Option<String>,
        retry_at: Option<Instant>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DotnsDial {
    Ready,
    Dial,
    Skip,
}

impl DotnsLane {
    fn dial_state(&self, now: Instant) -> DotnsDial {
        match self {
            DotnsLane::Disabled => DotnsDial::Skip,
            DotnsLane::Enabled { connected, .. } if connected.is_some() => DotnsDial::Ready,
            DotnsLane::Enabled { retry_at, .. } => match retry_at {
                Some(at) if now < *at => DotnsDial::Skip,
                _ => DotnsDial::Dial,
            },
        }
    }

    fn record_dial_failure(&mut self, reason: String, now: Instant) -> bool {
        let DotnsLane::Enabled {
            last_error,
            retry_at,
            ..
        } = self
        else {
            return false;
        };
        *retry_at = Some(now + DOTNS_RECONNECT_INTERVAL);
        let is_new = last_error.as_deref() != Some(reason.as_str());
        if is_new {
            *last_error = Some(reason);
        }
        is_new
    }

    fn record_dial_success(&mut self, up: (AssetHub, ValidityWindow)) {
        if let DotnsLane::Enabled {
            connected,
            last_error,
            retry_at,
            ..
        } = self
        {
            *connected = Some(up);
            *last_error = None;
            *retry_at = None;
        }
    }
}

async fn connect_asset_hub(url: &str) -> anyhow::Result<(AssetHub, ValidityWindow)> {
    let client = AssetHub::connect(url).await?;
    let window = client.validity_window().await?;
    Ok((client, window))
}

impl Writer {
    async fn run_forever(&mut self) -> anyhow::Result<()> {
        loop {
            let guard = self.acquire_lease().await?;
            tracing::info!(epoch = guard.epoch, "acquired writer lease");
            self.people.reset_nonce();
            self.dotns.reset_nonce();
            if let Err(e) = {
                let cx = self.cx(&guard);
                self.people.reconcile_submitting(&cx, &self.chain).await
            } {
                tracing::warn!(error = %e, "startup reconcile failed");
            }
            if let Some((asset_hub, _)) = self.dotns_client().await {
                let cx = self.cx(&guard);
                if let Err(e) = self.dotns.reconcile_submitting(&cx, &asset_hub).await {
                    tracing::warn!(error = %e, "startup dotns reconcile failed");
                }
            }
            if let Err(e) = self.active_loop(&guard).await {
                tracing::warn!(error = %e, "writer loop exited; re-acquiring lease");
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    async fn acquire_lease(&self) -> anyhow::Result<Guard> {
        loop {
            let epoch = lease::try_acquire(
                &self.pool,
                &self.config.lease_name,
                &self.config.holder_id,
                self.config.lease_ttl,
            )
            .await?;
            if let Some(epoch) = epoch {
                return Ok(Guard {
                    lease_name: self.config.lease_name.clone(),
                    holder_id: self.config.holder_id.clone(),
                    epoch,
                });
            }
            tracing::info!("writer lease held by another instance; waiting");
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    async fn heartbeat(&self, guard: &Guard) -> anyhow::Result<bool> {
        Ok(lease::renew(
            &self.pool,
            &guard.lease_name,
            &guard.holder_id,
            guard.epoch,
            self.config.lease_ttl,
        )
        .await?)
    }

    async fn active_loop(&mut self, guard: &Guard) -> anyhow::Result<()> {
        let mut last_payment_pass: Option<std::time::Instant> = None;
        let mut last_stranded_check: Option<std::time::Instant> = None;
        let mut last_resource_pass: Option<std::time::Instant> = None;
        loop {
            if !self.heartbeat(guard).await? {
                anyhow::bail!("lost writer lease");
            }
            if last_resource_pass.is_none_or(|t| t.elapsed() >= self.config.resource_poll_interval)
            {
                last_resource_pass = Some(std::time::Instant::now());
                if let Err(e) = self.log_attester_resources().await {
                    tracing::warn!(error = %e, "attester resources read failed");
                }
                if let Err(e) = record_outbox_gauges(&self.pool).await {
                    tracing::warn!(error = %e, "outbox gauge pass failed");
                }
            }
            if self.config.queue_enabled {
                if last_stranded_check
                    .is_none_or(|t| t.elapsed() >= self.config.queue_fallback_after)
                {
                    last_stranded_check = Some(std::time::Instant::now());
                    match crate::queue::stranded_queued(&self.pool).await {
                        Ok(0) => {}
                        Ok(stranded) => tracing::warn!(
                            stranded,
                            "queue advancer is down with claims queued; holding the throttle \
                             (queue enabled — not draining). Restart registration-queue, or \
                             retire the queue by setting QUEUE_ENABLED=false everywhere."
                        ),
                        Err(e) => tracing::warn!(error = %e, "stranded-queue check failed"),
                    }
                }
            } else {
                match crate::queue::fallback_drain(&self.pool, self.config.queue_fallback_after)
                    .await
                {
                    Ok(0) => {}
                    Ok(drained) => tracing::warn!(
                        drained,
                        "queue disabled with advancer gone; promoted leftover queued claims"
                    ),
                    Err(e) => tracing::warn!(error = %e, "queue janitor drain failed"),
                }
            }
            if last_payment_pass.is_none_or(|t| t.elapsed() >= self.config.payment_poll_interval) {
                last_payment_pass = Some(std::time::Instant::now());
                match crate::payment::watch_pass(&self.pool, &self.chain).await {
                    Ok(stats) if stats.acted() => tracing::info!(
                        expired = stats.expired,
                        confirmed = stats.confirmed,
                        conflicted = stats.conflicted,
                        still_pending = stats.still_pending,
                        "payment watch pass"
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "payment watch pass failed"),
                }
            }
            let people_idle = self.people_pass(guard).await?;
            self.dotns_pass(guard).await?;
            if people_idle {
                tokio::time::sleep(self.config.poll_interval).await;
            }
        }
    }

    async fn dotns_client(&mut self) -> Option<(AssetHub, ValidityWindow)> {
        let now = Instant::now();
        match self.dotns_lane.dial_state(now) {
            DotnsDial::Skip => return None,
            DotnsDial::Ready => {
                let DotnsLane::Enabled {
                    connected: Some(up),
                    ..
                } = &self.dotns_lane
                else {
                    return None;
                };
                return Some(up.clone());
            }
            DotnsDial::Dial => {}
        }
        let DotnsLane::Enabled { rpc_url, .. } = &self.dotns_lane else {
            return None;
        };
        let rpc_url = rpc_url.clone();
        match connect_asset_hub(&rpc_url).await {
            Ok(up) => {
                tracing::info!(
                    asset_hub_rpc = %rpc_url,
                    max_validity_secs = up.1.max_validity_secs,
                    max_future_skew_secs = up.1.max_future_skew_secs,
                    "dotns lane connected"
                );
                metrics::gauge!("dub_dotns_lane_connected").set(1.0);
                self.dotns_lane.record_dial_success(up.clone());
                Some(up)
            }
            Err(e) => {
                let reason = format!("{e:#}");
                if self.dotns_lane.record_dial_failure(reason.clone(), now) {
                    tracing::warn!(
                        asset_hub_rpc = %rpc_url,
                        error = %reason,
                        retry_secs = DOTNS_RECONNECT_INTERVAL.as_secs(),
                        "dotns lane parked; People registration is unaffected"
                    );
                }
                metrics::gauge!("dub_dotns_lane_connected").set(0.0);
                None
            }
        }
    }

    fn cx<'a>(&'a self, guard: &'a Guard) -> Cx<'a> {
        Cx {
            pool: &self.pool,
            guard,
            signer: &self.signer,
            signer_account: &self.signer_account,
            proxy_for: self.proxy_for,
            max_attempts: self.config.max_attempts,
            batch_max: self.config.batch_size,
            finalize_timeout: self.config.finalize_timeout,
            lease_ttl: self.config.lease_ttl,
        }
    }

    /// One People pass. `Ok(true)` means nothing was due.
    async fn people_pass(&mut self, guard: &Guard) -> anyhow::Result<bool> {
        let due = People::claim(&self.pool, i64::from(self.people.size())).await?;
        let Writer {
            pool,
            chain,
            signer,
            signer_account,
            proxy_for,
            config,
            people,
            ..
        } = self;
        let cx = cx_of(pool, guard, signer, signer_account, *proxy_for, config);
        people.pass(&cx, chain, (), &due).await
    }

    async fn dotns_pass(&mut self, guard: &Guard) -> anyhow::Result<bool> {
        let Some((asset_hub, window)) = self.dotns_client().await else {
            return Ok(true);
        };
        let due = Dotns::claim(&self.pool, i64::from(self.dotns.size())).await?;
        let ctx = Window {
            window,
            attester: self.config.attester,
        };
        let Writer {
            pool,
            signer,
            signer_account,
            proxy_for,
            config,
            dotns,
            ..
        } = self;
        let cx = cx_of(pool, guard, signer, signer_account, *proxy_for, config);
        dotns.pass(&cx, &asset_hub, ctx, &due).await
    }

    async fn log_attester_resources(&mut self) -> anyhow::Result<()> {
        let allowance_account = self.config.attester;
        let allowance = self.chain.attestation_allowance(allowance_account).await?;
        let signer_balance = self.chain.free_balance(self.signer_account.0).await?;
        let primary_balance = match self.proxy_for {
            Some(primary) => Some(self.chain.free_balance(primary).await?),
            None => None,
        };

        tracing::info!(
            allowance,
            allowance_account = %hex_account(&allowance_account),
            signer = %hex_account(&self.signer_account.0),
            signer_balance_planck = signer_balance,
            primary_balance_planck = primary_balance,
            "attester_resources"
        );
        metrics::gauge!("dub_attester_allowance").set(allowance as f64);
        record_spec_version("people", self.chain.online()).await;
        metrics::gauge!(
            "dub_account_free_balance_planck",
            "role" => "signer",
            "chain" => "people"
        )
        .set(signer_balance as f64);
        if let Some(primary) = primary_balance {
            metrics::gauge!(
                "dub_account_free_balance_planck",
                "role" => "primary",
                "chain" => "people"
            )
            .set(primary as f64);
        }

        if allowance < self.config.allowance_floor {
            tracing::warn!(
                allowance,
                floor = self.config.allowance_floor,
                allowance_account = %hex_account(&allowance_account),
                "attestation allowance below floor; registration stops at zero"
            );
        }
        if signer_balance < self.config.signer_balance_floor_planck {
            tracing::warn!(
                signer_balance_planck = signer_balance,
                floor_planck = self.config.signer_balance_floor_planck,
                signer = %hex_account(&self.signer_account.0),
                "chain-writer signer balance below floor; registrations will fail to pay fees"
            );
        }

        if let Some((asset_hub, _)) = self.dotns_client().await {
            let allowance = asset_hub.attestation_allowance(allowance_account).await?;
            let ah_signer_balance = asset_hub.free_balance(self.signer_account.0).await?;
            tracing::info!(
                allowance,
                allowance_account = %hex_account(&allowance_account),
                signer_balance_planck = ah_signer_balance,
                "dotns_attester_resources"
            );
            metrics::gauge!("dub_dotns_attester_allowance").set(allowance as f64);
            record_spec_version("asset-hub", asset_hub.online()).await;
            metrics::gauge!(
                "dub_account_free_balance_planck",
                "role" => "signer",
                "chain" => "asset-hub"
            )
            .set(ah_signer_balance as f64);

            if allowance < self.config.allowance_floor {
                tracing::warn!(
                    allowance,
                    floor = self.config.allowance_floor,
                    allowance_account = %hex_account(&allowance_account),
                    "dotns gateway allowance below floor; reservations stop at zero"
                );
            }
            if ah_signer_balance < self.config.signer_balance_floor_planck {
                tracing::warn!(
                    signer_balance_planck = ah_signer_balance,
                    floor_planck = self.config.signer_balance_floor_planck,
                    signer = %hex_account(&self.signer_account.0),
                    "chain-writer signer balance on Asset Hub below floor; \
                     failed reservations will not pay their fees"
                );
            }
        }
        Ok(())
    }
}

fn hex_account(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn cx_of<'a>(
    pool: &'a PgPool,
    guard: &'a Guard,
    signer: &'a WriterSigner,
    signer_account: &'a AccountId32,
    proxy_for: Option<[u8; 32]>,
    config: &WriterConfig,
) -> Cx<'a> {
    Cx {
        pool,
        guard,
        signer,
        signer_account,
        proxy_for,
        max_attempts: config.max_attempts,
        batch_max: config.batch_size,
        finalize_timeout: config.finalize_timeout,
        lease_ttl: config.lease_ttl,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FROM_ENV_VARS: &[&str] = &[
        "DEVICE_ATTESTATION_DATABASE_URL",
        "PEOPLE_RPC_URL",
        "CHAIN_WRITER_SIGNER_SURI",
        "ATTESTER_ACCOUNT",
        "CHAIN_WRITER_HOLDER_ID",
        "CHAIN_WRITER_LEASE_NAME",
        "CHAIN_WRITER_LEASE_TTL_SECS",
        "CHAIN_WRITER_POLL_SECS",
        "CHAIN_WRITER_BATCH_SIZE",
        "CHAIN_WRITER_FINALIZE_SECS",
        "CHAIN_WRITER_MAX_ATTEMPTS",
        "QUEUE_ENABLED",
        "QUEUE_FALLBACK_AFTER_SECS",
        "PAYMENT_POLL_INTERVAL_SECS",
        "ATTESTER_RESOURCE_POLL_SECS",
        "ATTESTER_ALLOWANCE_FLOOR",
        "ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK",
    ];

    const REQUIRED_ENV: &[(&str, &str)] = &[
        (
            "DEVICE_ATTESTATION_DATABASE_URL",
            "postgres://writer:pw@localhost/device_attestation",
        ),
        ("CHAIN_WRITER_SIGNER_SURI", "//Writer"),
        ("ATTESTER_ACCOUNT", ALICE_SS58),
    ];

    const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    const ALICE_HEX: &str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

    fn from_env_with(vars: &[(&str, &str)]) -> anyhow::Result<WriterConfig> {
        for key in FROM_ENV_VARS {
            std::env::remove_var(key);
        }
        for (key, value) in vars {
            std::env::set_var(key, value);
        }
        let result = WriterConfig::from_env();
        for key in FROM_ENV_VARS {
            std::env::remove_var(key);
        }
        result
    }

    #[test]
    fn from_env_reads_and_validates_the_environment() {
        let _guard = crate::ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let config = from_env_with(&[
            (
                "DEVICE_ATTESTATION_DATABASE_URL",
                "postgres://writer:pw@localhost/device_attestation",
            ),
            ("PEOPLE_RPC_URL", "wss://people.example"),
            ("CHAIN_WRITER_SIGNER_SURI", "//Writer"),
            ("ATTESTER_ACCOUNT", ALICE_SS58),
            ("CHAIN_WRITER_HOLDER_ID", "writer-test-1"),
            ("CHAIN_WRITER_LEASE_NAME", "custom-lease"),
            ("CHAIN_WRITER_LEASE_TTL_SECS", "45"),
            ("CHAIN_WRITER_POLL_SECS", "3"),
            ("CHAIN_WRITER_BATCH_SIZE", "50"),
            ("CHAIN_WRITER_FINALIZE_SECS", "90"),
            ("CHAIN_WRITER_MAX_ATTEMPTS", "4"),
            ("QUEUE_ENABLED", "yes"),
            ("QUEUE_FALLBACK_AFTER_SECS", " 90 "),
            ("PAYMENT_POLL_INTERVAL_SECS", "15"),
            ("ATTESTER_RESOURCE_POLL_SECS", "120"),
            ("ATTESTER_ALLOWANCE_FLOOR", "250"),
            ("ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK", "123456789012"),
        ])
        .unwrap();
        assert_eq!(
            config.database_url.expose_secret(),
            "postgres://writer:pw@localhost/device_attestation"
        );
        assert_eq!(config.people_rpc_url, "wss://people.example");
        assert_eq!(config.signer_suri.expose_secret(), "//Writer");
        let alice: [u8; 32] = hex::decode(ALICE_HEX).unwrap().try_into().unwrap();
        assert_eq!(config.attester, alice);
        assert_eq!(config.holder_id, "writer-test-1");
        assert_eq!(config.lease_name, "custom-lease");
        assert_eq!(config.lease_ttl, Duration::from_secs(45));
        assert_eq!(config.poll_interval, Duration::from_secs(3));
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.finalize_timeout, Duration::from_secs(90));
        assert_eq!(config.max_attempts, 4);
        assert!(config.queue_enabled);
        assert_eq!(config.queue_fallback_after, Duration::from_secs(90));
        assert_eq!(config.payment_poll_interval, Duration::from_secs(15));
        assert_eq!(config.resource_poll_interval, Duration::from_secs(120));
        assert_eq!(config.allowance_floor, 250);
        assert_eq!(config.signer_balance_floor_planck, 123_456_789_012);

        let config = from_env_with(REQUIRED_ENV).unwrap();
        assert_eq!(
            config.people_rpc_url,
            "wss://previewnet.substrate.dev/people"
        );
        assert!(
            config
                .holder_id
                .starts_with(&format!("writer-{}-", std::process::id())),
            "unexpected default holder id {:?}",
            config.holder_id
        );
        assert_eq!(config.lease_name, "people-chain-writer");
        assert_eq!(config.lease_ttl, Duration::from_secs(30));
        assert_eq!(config.poll_interval, Duration::from_secs(2));
        assert_eq!(config.batch_size, 25);
        assert_eq!(config.finalize_timeout, Duration::from_secs(120));
        assert_eq!(config.max_attempts, 8);
        assert!(!config.queue_enabled);
        assert_eq!(config.queue_fallback_after, Duration::from_secs(60));
        assert_eq!(config.payment_poll_interval, Duration::from_secs(30));
        assert_eq!(config.resource_poll_interval, Duration::from_secs(60));
        assert_eq!(config.allowance_floor, 100);
        assert_eq!(config.signer_balance_floor_planck, 10_000_000_000);

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("CHAIN_WRITER_HOLDER_ID", "   "));
        let config = from_env_with(&vars).unwrap();
        assert!(config.holder_id.starts_with("writer-"));

        let err = from_env_with(&[("CHAIN_WRITER_SIGNER_SURI", "//Writer")]).unwrap_err();
        assert!(
            err.to_string().contains("DEVICE_ATTESTATION_DATABASE_URL"),
            "{err}"
        );
        let err =
            from_env_with(&[("DEVICE_ATTESTATION_DATABASE_URL", "postgres://x")]).unwrap_err();
        assert!(
            err.to_string()
                .contains("CHAIN_WRITER_SIGNER_SURI is required"),
            "{err}"
        );

        let mut vars = vec![
            (
                "DEVICE_ATTESTATION_DATABASE_URL",
                "postgres://writer:pw@localhost/device_attestation",
            ),
            ("CHAIN_WRITER_SIGNER_SURI", "//Writer"),
        ];
        vars.push(("ATTESTER_ACCOUNT", "not-an-account"));
        let err = from_env_with(&vars).unwrap_err();
        assert!(err.to_string().contains("ATTESTER_ACCOUNT"), "{err}");

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("QUEUE_ENABLED", "maybe"));
        let err = from_env_with(&vars).unwrap_err();
        assert!(err.to_string().contains("QUEUE_ENABLED"), "{err}");

        for key in [
            "QUEUE_FALLBACK_AFTER_SECS",
            "PAYMENT_POLL_INTERVAL_SECS",
            "ATTESTER_RESOURCE_POLL_SECS",
            "ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK",
        ] {
            let mut vars = REQUIRED_ENV.to_vec();
            vars.push((key, "30s"));
            let err = from_env_with(&vars).unwrap_err();
            assert!(err.to_string().contains(key), "{key}: {err}");
        }

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("ATTESTER_ALLOWANCE_FLOOR", "4294967296"));
        let err = from_env_with(&vars).unwrap_err();
        assert!(
            err.to_string()
                .contains("ATTESTER_ALLOWANCE_FLOOR must fit a u32"),
            "{err}"
        );

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("CHAIN_WRITER_LEASE_TTL_SECS", "garbage"));
        vars.push(("CHAIN_WRITER_BATCH_SIZE", "lots"));
        let config = from_env_with(&vars).unwrap();
        assert_eq!(config.lease_ttl, Duration::from_secs(30));
        assert_eq!(config.batch_size, 25);
    }

    #[test]
    fn a_parked_dotns_lane_backs_off_and_logs_each_cause_once() {
        let t0 = Instant::now();
        let mut lane = DotnsLane::Enabled {
            rpc_url: "wss://example.invalid".to_string(),
            connected: None,
            last_error: None,
            retry_at: None,
        };

        assert_eq!(lane.dial_state(t0), DotnsDial::Dial);

        assert!(lane.record_dial_failure("unreachable".to_string(), t0));
        assert_eq!(lane.dial_state(t0), DotnsDial::Skip);
        assert_eq!(
            lane.dial_state(t0 + DOTNS_RECONNECT_INTERVAL - Duration::from_secs(1)),
            DotnsDial::Skip
        );
        let t1 = t0 + DOTNS_RECONNECT_INTERVAL;
        assert_eq!(lane.dial_state(t1), DotnsDial::Dial);

        assert!(!lane.record_dial_failure("unreachable".to_string(), t1));
        assert_eq!(lane.dial_state(t1), DotnsDial::Skip);

        let t2 = t1 + DOTNS_RECONNECT_INTERVAL;
        assert!(lane.record_dial_failure("reserve_name shape mismatch".to_string(), t2));
        let t3 = t2 + DOTNS_RECONNECT_INTERVAL;
        assert!(lane.record_dial_failure("unreachable".to_string(), t3));

        assert_eq!(DotnsLane::Disabled.dial_state(t0), DotnsDial::Skip);
        assert!(!DotnsLane::Disabled.record_dial_failure("ignored".to_string(), t0));
    }
}
