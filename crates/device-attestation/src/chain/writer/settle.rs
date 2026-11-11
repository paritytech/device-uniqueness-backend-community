// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Settling dotNS pending claims from the writer's Asset Hub signer.
//!
//! The gateway mints from a Root origin, which pallet-revive does not let
//! deploy a contract, so a name whose owner has no `LabelStore` yet is kept by
//! `DotnsPopController` as a pending claim. It stays pending until a signed
//! origin calls `settlePendingClaims(user, limit)`, which deploys the store and
//! writes the label. That call is permissionless and its signer pays the fee
//! and the store's deposit. Lite users hold no Asset Hub funds, so nobody else
//! makes it.
//!
//! Settlement runs in the dotNS lane, between its passes and on its nonce, so
//! it never races a reservation submission. Each step walks one page of the
//! controller's own set of accounts with pending claims, dry-runs each
//! settlement, and submits the ones that would go through as one
//! `Utility.force_batch` of `Revive.call`s, never proxied.

use std::time::Duration;

use anyhow::Result;
use chain_types::{AssetHubConfig, AssetHubExtrinsicParamsBuilder};
use subxt::dynamic::Value;
use subxt::extrinsics::ExtrinsicEvents;
use subxt::metadata::ArcMetadata;
use subxt::tx::DynamicPayload;
use subxt::utils::{AccountId32, H160};

use super::dotns::Dotns;
use super::engine::{finalize, Cx, Drain};
use super::events::item_results;
use super::passes::Ticker;
use super::tx::{build_contract_batch_tx, build_map_account_tx, ContractCall};
use crate::chain::asset_hub::AssetHub;
use crate::chain::dotns::Settlement;

/// Every value `dub_dotns_settle_total`'s `outcome` label takes.
const SETTLE_OUTCOMES: [&str; 3] = ["ok", "failed", "revert"];

/// When and how much the writer settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SettleConfig {
    /// Whether the writer settles at all (`DOTNS_SETTLE_ENABLED`).
    pub enabled: bool,
    /// The least time between two settlement steps
    /// (`DOTNS_SETTLE_INTERVAL_SECS`).
    pub interval: Duration,
    /// Pending claims settled per account per call
    /// (`DOTNS_SETTLE_CLAIM_LIMIT`).
    pub claim_limit: u64,
    /// Accounts settled per step, all in one extrinsic
    /// (`DOTNS_SETTLE_MAX_ACCOUNTS`).
    pub max_accounts: u64,
}

/// The settlement step's state between passes.
pub(super) struct Settler {
    config: SettleConfig,
    ticker: Ticker,
    /// Where the next page of pending accounts starts. An account whose
    /// settlement would revert stays in the set, so the cursor steps past it,
    /// and returns to the start once a page comes back empty.
    cursor: u64,
}

impl Settler {
    /// A settler whose first step is due at once.
    pub(super) fn new(config: SettleConfig) -> Self {
        for outcome in SETTLE_OUTCOMES {
            metrics::counter!("dub_dotns_settle_total", "outcome" => outcome).absolute(0);
        }
        Self {
            config,
            ticker: Ticker::new(config.interval),
            cursor: 0,
        }
    }

    /// Settle one page of pending accounts, if settlement is on and due.
    pub(super) async fn step(&mut self, drain: &mut Drain<Dotns>, cx: &Cx<'_>) {
        if !self.config.enabled || !self.ticker.due() {
            return;
        }
        drain
            .aside(cx, "dotns settlement", async |chain, nonce| {
                self.settle(cx, chain, nonce).await
            })
            .await;
    }

    /// One settlement step with `nonce`. `Ok(true)` when it submitted.
    async fn settle(&mut self, cx: &Cx<'_>, chain: &AssetHub, nonce: u64) -> Result<bool> {
        let signer = cx.signer_account.0;
        if !chain.is_revive_mapped(&signer).await? {
            tracing::info!("mapping the writer's signer in pallet-revive before it settles");
            submit(cx, chain, nonce, &build_map_account_tx()).await?;
            return Ok(true);
        }

        let at = chain.online().at_current_block().await?;
        let contracts = chain.dotns_contracts(&at).await?;
        let pending = contracts.pending_claim_users(&at).await?;
        metrics::gauge!("dub_dotns_pending_claim_accounts").set(pending as f64);
        let page = contracts
            .pending_claim_page(&at, self.cursor, self.config.max_accounts)
            .await?;
        if page.is_empty() {
            self.cursor = 0;
            return Ok(false);
        }

        let dry_runs = page.iter().map(|user| {
            contracts.dry_run_settlement(&at, AccountId32(signer), *user, self.config.claim_limit)
        });
        let settlements: Vec<Settlement> = futures::future::try_join_all(dry_runs)
            .await?
            .into_iter()
            .flatten()
            .collect();
        let skipped = page.len() - settlements.len();
        metrics::counter!("dub_dotns_settle_total", "outcome" => "revert")
            .increment(skipped as u64);
        self.cursor = next_cursor(self.cursor, skipped);

        let budget = budget_of(chain.max_extrinsic_weight().await?);
        let calls = pack(contracts.controller(), &settlements, budget);
        if calls.is_empty() {
            if !settlements.is_empty() {
                tracing::warn!(
                    budget = ?budget,
                    "a single dotns settlement does not fit the extrinsic budget"
                );
            }
            return Ok(false);
        }
        // `pack` takes a leading run, so these are the settlements submitted.
        let submitted = &settlements[..calls.len()];
        let (events, metadata) = submit(cx, chain, nonce, &build_contract_batch_tx(&calls)).await?;
        let items = item_results(&events, &metadata)?;
        if items.len() != submitted.len() {
            // The nonce was spent, so the step counts as submitted; the
            // controller's own count shows what settled on the next step.
            tracing::warn!(
                items = items.len(),
                calls = submitted.len(),
                "dotns settlement batch results do not line up with its calls"
            );
            return Ok(true);
        }
        let failed = items.iter().filter(|item| item.is_err()).count();
        let settled = items.len() - failed;
        metrics::counter!("dub_dotns_settle_total", "outcome" => "ok").increment(settled as u64);
        metrics::counter!("dub_dotns_settle_total", "outcome" => "failed").increment(failed as u64);
        for (settlement, item) in submitted.iter().zip(&items) {
            if let Err(error) = item {
                tracing::warn!(user = ?settlement.user, %error, "dotns settlement failed");
            }
        }
        tracing::info!(
            settled,
            failed,
            skipped,
            pending,
            "dotns pending claims settled"
        );
        Ok(true)
    }
}

/// Sign `payload` with the writer's signer at `nonce`, submit it, and await
/// finalization.
async fn submit(
    cx: &Cx<'_>,
    chain: &AssetHub,
    nonce: u64,
    payload: &DynamicPayload<Vec<Value>>,
) -> Result<(ExtrinsicEvents<AssetHubConfig>, ArcMetadata)> {
    let params = AssetHubExtrinsicParamsBuilder::new().nonce(nonce).build();
    let at = chain.online().at_current_block().await?;
    let signed = chain_client::create_signed_v4(&at, payload, cx.signer, params).await?;
    finalize(cx, signed.submit_and_watch().await?).await
}

/// The weight limit for a call whose dry run required `weight`: a quarter more,
/// since the state may move between the dry run and the block.
#[must_use]
fn weight_limit((ref_time, proof_size): (u64, u64)) -> (u64, u64) {
    let grow = |part: u64| part.saturating_add(part / 4);
    (grow(ref_time), grow(proof_size))
}

/// The storage-deposit limit for a call whose dry run charged `deposit`: a
/// tenth more, for the same reason.
#[must_use]
fn deposit_limit(deposit: u128) -> u128 {
    deposit.saturating_add(deposit / 10)
}

/// The weight one settlement extrinsic may use: half of what a normal
/// extrinsic may, so one never fills a block the dotNS lane also needs.
#[must_use]
fn budget_of((ref_time, proof_size): (u64, u64)) -> (u64, u64) {
    (ref_time / 2, proof_size / 2)
}

/// The leading `settlements` whose weight limits fit `budget` together, as
/// calls on `controller`. The rest stay pending for a later step.
#[must_use]
fn pack(controller: H160, settlements: &[Settlement], budget: (u64, u64)) -> Vec<ContractCall<'_>> {
    let mut used = (0u64, 0u64);
    let mut calls = Vec::new();
    for settlement in settlements {
        let limit = weight_limit(settlement.weight);
        let next = (
            used.0.saturating_add(limit.0),
            used.1.saturating_add(limit.1),
        );
        if next.0 > budget.0 || next.1 > budget.1 {
            break;
        }
        used = next;
        calls.push(ContractCall {
            dest: controller,
            weight_limit: limit,
            storage_deposit_limit: deposit_limit(settlement.deposit),
            data: &settlement.data,
        });
    }
    calls
}

/// Where the next page starts, after `skipped` accounts at `cursor` would
/// revert. Settled accounts leave the set, so only the skipped ones are passed.
#[must_use]
fn next_cursor(cursor: u64, skipped: usize) -> u64 {
    cursor.saturating_add(u64::try_from(skipped).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_leave_headroom_over_the_dry_run() {
        assert_eq!(weight_limit((400, 80)), (500, 100), "a quarter more weight");
        assert_eq!(deposit_limit(1_000), 1_100, "a tenth more deposit");
        assert_eq!(deposit_limit(0), 0, "a refund needs no deposit");
        assert_eq!(
            weight_limit((u64::MAX, 0)),
            (u64::MAX, 0),
            "saturates instead of overflowing"
        );
    }

    fn settlement(proof_size: u64) -> Settlement {
        Settlement {
            user: H160::repeat_byte(1),
            data: vec![1],
            weight: (100, proof_size),
            deposit: 10,
        }
    }

    #[test]
    fn a_settlement_extrinsic_takes_half_the_extrinsic_limit() {
        assert_eq!(
            budget_of((1_600, 8_388_608)),
            (800, 4_194_304),
            "half of each part"
        );
    }

    #[test]
    fn settlements_are_packed_until_the_budget_is_spent() {
        // The paseo-next dry run: about 1.17 MB of proof each, 1.46 MB with
        // headroom, so two fit half of the 8 MiB extrinsic limit.
        let settlements = vec![settlement(1_166_006); 5];
        let calls = pack(H160::zero(), &settlements, budget_of((u64::MAX, 8_388_608)));
        assert_eq!(calls.len(), 2, "two settlements fit the proof budget");
        assert_eq!(
            calls[0].weight_limit,
            weight_limit((100, 1_166_006)),
            "each call carries its own headroom"
        );
        assert_eq!(
            calls[0].storage_deposit_limit, 11,
            "and its deposit headroom"
        );

        assert!(
            pack(H160::zero(), &settlements, (u64::MAX, 1_000)).is_empty(),
            "one that never fits is not sent"
        );
    }

    #[test]
    fn the_cursor_steps_past_skipped_accounts_only() {
        assert_eq!(next_cursor(0, 0), 0, "a fully settled page leaves the set");
        assert_eq!(next_cursor(0, 2), 2, "two reverting accounts stay ahead");
        assert_eq!(next_cursor(u64::MAX, 1), u64::MAX, "saturates");
    }
}
