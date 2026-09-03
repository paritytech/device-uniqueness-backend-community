// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! One claimed set of one lane, drained onto its chain.
//!
//! Written once over [`Lane`] and run twice. Everything that decides *how* a
//! row moves is here; everything that decides *where* it is written is the
//! lane's.
//!
//! The invariant this file exists to protect: a row is recorded as landed only
//! when the chain says so — through an item result whose positional mapping was
//! checked against the calls submitted, or through a direct ownership read. A
//! mapping that does not line up is discarded, never guessed at.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::time::Duration;

use anyhow::Result;
use chain_client::WriterSigner;
use sqlx::PgPool;
use subxt::{
    client::OnlineClientAtBlockT, extrinsics::ExtrinsicEvents, metadata::ArcMetadata,
    tx::TransactionProgress, utils::AccountId32,
};
use time::OffsetDateTime;

use super::lane::{BatchLane, Defer, Gate, Lane, Outcome};
use crate::chain::{
    lease,
    outbox::{Guard, Reservation},
    registry::NameRegistry as _,
};

/// The shared backoff for rows re-queued by a *reconcile*, as opposed to a
/// whole-batch failure. The batch did submit, so there is no failure run to
/// escalate against; the rows only need long enough for the chain state that
/// decided them to settle.
const BATCH_RECONCILE_BACKOFF: time::Duration = time::Duration::seconds(10);

/// How many `SUBMITTING` rows one startup-reconcile owner read covers. A writer
/// that died mid-drain can leave far more than a batch's worth, and a single
/// unbounded read over all of them is one point of failure for the whole
/// reconcile.
const RECONCILE_READ_CHUNK: usize = 50;

/// Everything a pass needs that is not lane-specific. Borrowed for the duration
/// of one pass, so both lanes share one signer, one lease and one config.
pub(super) struct Cx<'a> {
    pub pool: &'a PgPool,
    pub guard: &'a Guard,
    pub signer: &'a WriterSigner,
    pub signer_account: &'a AccountId32,
    /// The attester authority to proxy for, or `None` when the signer *is* it.
    pub proxy_for: Option<[u8; 32]>,
    pub max_attempts: i32,
    /// The ceiling every lane's adaptive batch size climbs back to.
    pub batch_max: u16,
    pub finalize_timeout: Duration,
    pub lease_ttl: Duration,
}

impl Cx<'_> {
    pub(super) async fn heartbeat(&self) -> Result<bool> {
        Ok(lease::renew(
            self.pool,
            &self.guard.lease_name,
            &self.guard.holder_id,
            self.guard.epoch,
            self.lease_ttl,
        )
        .await?)
    }

    async fn hold(&self) -> Result<()> {
        if !self.heartbeat().await? {
            anyhow::bail!("lost writer lease");
        }
        Ok(())
    }
}

/// Await finalization, renewing the lease while it waits.
///
/// Finalization can outlast the lease TTL, and a writer that let its lease
/// lapse mid-flight would come back to a row a second writer had already moved.
pub(super) async fn finalize<T, C>(
    cx: &Cx<'_>,
    progress: TransactionProgress<T, C>,
    what: &'static str,
) -> Result<(ExtrinsicEvents<T>, ArcMetadata)>
where
    T: subxt::Config,
    C: OnlineClientAtBlockT<T>,
{
    let wait = async {
        let in_block = progress.wait_for_finalized().await?;
        let events = in_block.wait_for_success().await?;
        let metadata = in_block.at().await?.metadata();
        anyhow::Ok((events, metadata))
    };
    let watched = async {
        tokio::pin!(wait);
        let mut renew = tokio::time::interval(cx.lease_ttl / 3);
        renew.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                result = &mut wait => return result,
                _ = renew.tick() => {
                    if !cx.heartbeat().await? {
                        anyhow::bail!("lost writer lease during {what}");
                    }
                }
            }
        }
    };
    tokio::time::timeout(cx.finalize_timeout, watched)
        .await
        .map_err(|_| anyhow::anyhow!("finalization timed out"))?
}

/// The only gate reconciliation applies: a row already `SUBMITTING` is past
/// every other one, and re-running them would fail rows the chain may well have
/// accepted.
pub(super) fn parse_candidate(r: &Reservation) -> Result<[u8; 32], Gate> {
    use std::str::FromStr as _;

    AccountId32::from_str(&r.candidate_account_id)
        .map(|a| a.0)
        .map_err(|_| Gate::Failed("invalid candidate SS58".to_string()))
}

/// One lane's drain, and the state that persists between its passes.
pub(super) struct Drain<L: Lane> {
    /// This lane's adaptive size and failure run. Deliberately per-lane: the
    /// two chains' weight budgets and call costs are unrelated, so one shared
    /// number would be wrong for both.
    batch: BatchLane,
    /// Cached account nonce on this lane's chain. Cleared after any submission
    /// that errored, because the nonce it consumed is then unknown.
    nonce: Option<u64>,
    lane: PhantomData<L>,
}

impl<L: Lane> Drain<L> {
    pub(super) fn new(batch_max: u16) -> Self {
        Self {
            batch: BatchLane::new(L::NAME, batch_max),
            nonce: None,
            lane: PhantomData,
        }
    }

    /// Forget the cached nonce. A new lease means a new claim on the account:
    /// whatever nonce the previous holder reached is not ours to assume.
    pub(super) fn reset_nonce(&mut self) {
        self.nonce = None;
    }

    pub(super) fn size(&self) -> u16 {
        self.batch.size
    }

    /// Drain one claimed set. `Ok(true)` means there was nothing due.
    ///
    /// Triage decides each row's fate offline and against one batched owner
    /// read; whatever is left is submitted as **one** extrinsic. A single-row
    /// set stays a bare call — one registration should not pay for a
    /// `force_batch` wrapper, and its dispatch result is a genuine per-row
    /// verdict rather than a positional guess.
    pub(super) async fn pass(
        &mut self,
        cx: &Cx<'_>,
        chain: &L::Chain,
        ctx: L::Ctx,
        due: &[Reservation],
    ) -> Result<bool> {
        if due.is_empty() {
            return Ok(true);
        }
        cx.hold().await?;
        let submittable = self.triage(cx, chain, ctx, due).await?;
        match submittable.len() {
            0 => {}
            1 => {
                let (r, candidate) = submittable[0];
                self.one(cx, chain, r, candidate).await?;
            }
            _ => self.batch(cx, chain, &submittable).await?,
        }
        Ok(false)
    }

    /// Resolve every row decidable without submitting anything, and return the
    /// rest paired with their parsed candidate accounts.
    ///
    /// The offline gates run per row **before** the batch is built, so a row
    /// that cannot be submitted never spends an item slot or a share of the
    /// fee. Survivors are checked against one batched owner read: owned by the
    /// candidate → already landed, owned by anyone else → terminal, unowned →
    /// submit.
    ///
    /// One read covers the whole claimed set, so a bad response is a
    /// whole-batch fault rather than any row's — spending an attempt each would
    /// walk an entire set to terminal over a flapping RPC, and unknown is never
    /// read as free.
    async fn triage<'r>(
        &mut self,
        cx: &Cx<'_>,
        chain: &L::Chain,
        ctx: L::Ctx,
        due: &'r [Reservation],
    ) -> Result<Vec<(&'r Reservation, [u8; 32])>> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut gated = Vec::with_capacity(due.len());
        for r in due {
            match L::gate(r, ctx, now) {
                Ok(candidate) => gated.push((r, candidate)),
                Err(gate) => L::record(cx.pool, cx.guard, r, gate.outcome()).await?,
            }
        }
        if gated.is_empty() {
            return Ok(Vec::new());
        }

        let names: Vec<&str> = gated
            .iter()
            .map(|(r, _)| r.full_username.as_str())
            .collect();
        let owners = match chain.owners(&names).await {
            Ok(owners) => owners,
            Err(e) => {
                self.retry_batch(cx, &gated, &format!("owner read failed: {e}"))
                    .await?;
                return Ok(Vec::new());
            }
        };

        let mut submittable = Vec::with_capacity(gated.len());
        for (r, candidate) in gated {
            match owners.get(&r.full_username) {
                Some(owner) if *owner == candidate => {
                    L::record(cx.pool, cx.guard, r, Outcome::Observed).await?
                }
                Some(_) => {
                    L::record(cx.pool, cx.guard, r, Outcome::Failed(L::OWNED_ELSEWHERE)).await?
                }
                None => submittable.push((r, candidate)),
            }
        }
        Ok(submittable)
    }

    /// Submit one row on its own. Chain failures are recorded on the row; only
    /// a lost lease returns `Err`.
    async fn one(
        &mut self,
        cx: &Cx<'_>,
        chain: &L::Chain,
        r: &Reservation,
        candidate: [u8; 32],
    ) -> Result<()> {
        let nonce = match self.next_nonce(cx, chain).await {
            Ok(n) => n,
            Err(e) => {
                let reason = format!("{}: {e}", L::NONCE_FETCH);
                return L::record(cx.pool, cx.guard, r, Outcome::Retry(&reason)).await;
            }
        };

        match L::submit_one(cx, chain, nonce, r, candidate).await {
            Ok(()) => {
                self.nonce = Some(nonce + 1);
                // A lone row still proves the lane works, so it grows the size
                // back toward the max after a halving search.
                self.batch.succeeded(cx.batch_max);
                L::record(cx.pool, cx.guard, r, Outcome::Landed).await
            }
            Err(e) => {
                self.nonce = None;
                let reason = e.to_string();
                let observed = chain.owner(&r.full_username).await.ok().flatten();
                self.settle(cx, r, candidate, observed, &reason).await
            }
        }
    }

    /// Submit a whole claimed set as one extrinsic.
    ///
    /// Everything that can go wrong splits in two, and the split is the point:
    /// a **whole-batch** failure (nonce, signing, transport, a proxy rejection
    /// of the batch itself) is nobody's row's fault and re-queues the set at an
    /// unchanged attempt; a **per-item** failure is that row's own and spends
    /// its attempt budget exactly as a single submission would.
    async fn batch(
        &mut self,
        cx: &Cx<'_>,
        chain: &L::Chain,
        rows: &[(&Reservation, [u8; 32])],
    ) -> Result<()> {
        let nonce = match self.next_nonce(cx, chain).await {
            Ok(n) => n,
            Err(e) => {
                return self
                    .retry_batch(cx, rows, &format!("{}: {e}", L::NONCE_FETCH))
                    .await
            }
        };

        match L::submit_batch(cx, chain, nonce, rows).await {
            Ok(items) => {
                self.nonce = Some(nonce + 1);
                self.batch.succeeded(cx.batch_max);
                self.apply(cx, chain, rows, items).await
            }
            Err(e) => {
                // Reset the cached nonce; re-fetch on the next attempt.
                self.nonce = None;
                self.retry_batch(cx, rows, &e.to_string()).await
            }
        }
    }

    /// Decide each row from its own item result.
    ///
    /// The count guard is the safety valve: landed may never be inferred from a
    /// positional mapping that does not line up with the calls submitted,
    /// because that is the one failure mode that would mark a row registered
    /// when it never landed.
    async fn apply(
        &mut self,
        cx: &Cx<'_>,
        chain: &L::Chain,
        rows: &[(&Reservation, [u8; 32])],
        items: Vec<Result<(), String>>,
    ) -> Result<()> {
        if items.len() != rows.len() {
            tracing::error!(
                lane = L::NAME,
                items = items.len(),
                calls = rows.len(),
                "force_batch reported a different number of items than calls submitted; \
                 discarding the positional mapping and reconciling against chain state"
            );
            return self
                .reconcile_batch(
                    cx,
                    chain,
                    rows,
                    "batch item events did not match the calls submitted",
                )
                .await;
        }

        // One read for every item the chain rejected: an already-registered
        // name is success, and only chain state can tell that from a failure.
        let failed: Vec<&str> = rows
            .iter()
            .zip(&items)
            .filter(|(_, item)| item.is_err())
            .map(|((r, _), _)| r.full_username.as_str())
            .collect();
        metrics::counter!("dub_chain_batch_item_failed_total", "lane" => L::NAME)
            .increment(failed.len() as u64);
        let owners = match chain.owners(&failed).await {
            Ok(owners) => owners,
            Err(e) => {
                // Best-effort, exactly as the single-submit path's reconcile
                // read is: an unread owner simply means the row retries.
                tracing::warn!(
                    lane = L::NAME,
                    error = %e,
                    "post-batch owner read failed; failed items will retry"
                );
                HashMap::new()
            }
        };

        for ((r, candidate), item) in rows.iter().zip(items) {
            let Err(reason) = item else {
                L::record(cx.pool, cx.guard, r, Outcome::Landed).await?;
                continue;
            };
            let observed = owners.get(&r.full_username).copied();
            self.settle(cx, r, *candidate, observed, &reason).await?;
        }
        Ok(())
    }

    /// Record one row's failed submission, from what the chain shows and how
    /// many attempts it has left.
    async fn settle(
        &self,
        cx: &Cx<'_>,
        r: &Reservation,
        candidate: [u8; 32],
        observed: Option<[u8; 32]>,
        reason: &str,
    ) -> Result<()> {
        match classify_submit_failure(
            reason,
            observed,
            candidate,
            L::attempt(r) + 1,
            cx.max_attempts,
        ) {
            SubmitFailureAction::Assign => L::record(cx.pool, cx.guard, r, Outcome::Landed).await,
            SubmitFailureAction::Park => {
                L::record(cx.pool, cx.guard, r, Outcome::Park(reason)).await
            }
            SubmitFailureAction::Retry => {
                L::record(cx.pool, cx.guard, r, Outcome::Retry(reason)).await
            }
            SubmitFailureAction::Fail => {
                L::record(
                    cx.pool,
                    cx.guard,
                    r,
                    Outcome::Failed(&terminal_reason(reason)),
                )
                .await
            }
        }
    }

    /// Resolve a batch whose per-item outcomes cannot be trusted, from chain
    /// state alone. Rows the chain shows as owned by their candidate have
    /// landed; the rest are re-queued at an unchanged attempt, because nothing
    /// here is attributable to a row.
    async fn reconcile_batch(
        &mut self,
        cx: &Cx<'_>,
        chain: &L::Chain,
        rows: &[(&Reservation, [u8; 32])],
        reason: &str,
    ) -> Result<()> {
        let names: Vec<&str> = rows.iter().map(|(r, _)| r.full_username.as_str()).collect();
        let owners = match chain.owners(&names).await {
            Ok(owners) => owners,
            Err(e) => {
                return self
                    .defer_reconciled(cx, rows, &format!("{reason}; owner read failed: {e}"))
                    .await
            }
        };

        let mut unlanded = Vec::new();
        for (r, candidate) in rows {
            if owners.get(&r.full_username) == Some(candidate) {
                L::record(cx.pool, cx.guard, r, Outcome::Landed).await?;
            } else {
                unlanded.push((*r, *candidate));
            }
        }
        if unlanded.is_empty() {
            return Ok(());
        }
        self.defer_reconciled(cx, &unlanded, reason).await
    }

    /// Re-queue a whole batch **without** spending anyone's attempt, on one
    /// shared backoff, and halve the lane's size.
    ///
    /// The backoff is shared deliberately: a per-row `2^attempt` would put the
    /// entire set back into the very next pass simultaneously, which is the
    /// same batch failing the same way.
    async fn retry_batch(
        &mut self,
        cx: &Cx<'_>,
        rows: &[(&Reservation, [u8; 32])],
        reason: &str,
    ) -> Result<()> {
        let backoff = self.batch.failed(cx.batch_max);
        tracing::warn!(
            lane = L::NAME,
            batch = rows.len(),
            backoff_secs = backoff.whole_seconds(),
            next_batch_size = self.batch.size,
            reason,
            "batch failed as a whole; re-queued without spending an attempt"
        );
        self.defer(cx, rows, backoff, reason).await
    }

    /// Re-queue rows from a batch that **submitted** but whose per-item outcome
    /// had to be read from chain state instead.
    ///
    /// Deliberately not [`Drain::retry_batch`]: this path is only reachable
    /// after a submission returned `Ok` and the lane already recorded a
    /// success, so halving the size and counting a whole-batch failure would
    /// grow and then shrink the lane over one good submission and report a
    /// chain rejection that never happened — exactly the reading
    /// `docs/operations.md` gives `dub_chain_batch_failed_total`.
    async fn defer_reconciled(
        &self,
        cx: &Cx<'_>,
        rows: &[(&Reservation, [u8; 32])],
        reason: &str,
    ) -> Result<()> {
        metrics::counter!("dub_chain_batch_reconciled_total", "lane" => L::NAME)
            .increment(rows.len() as u64);
        tracing::warn!(
            lane = L::NAME,
            batch = rows.len(),
            backoff_secs = BATCH_RECONCILE_BACKOFF.whole_seconds(),
            reason,
            "batch reconciled from chain state; \
             rows that did not land re-queued without spending an attempt"
        );
        self.defer(cx, rows, BATCH_RECONCILE_BACKOFF, reason).await
    }

    /// Re-queue a set of rows at an unchanged attempt, on one shared
    /// `not_before`. The lane accounting is the caller's.
    async fn defer(
        &self,
        cx: &Cx<'_>,
        rows: &[(&Reservation, [u8; 32])],
        backoff: time::Duration,
        reason: &str,
    ) -> Result<()> {
        let until = OffsetDateTime::now_utc() + backoff;
        for (r, _) in rows {
            let outcome = Outcome::Defer {
                until,
                reason,
                cause: Defer::Batch,
            };
            L::record(cx.pool, cx.guard, r, outcome).await?;
        }
        Ok(())
    }

    async fn next_nonce(&mut self, cx: &Cx<'_>, chain: &L::Chain) -> Result<u64> {
        if let Some(n) = self.nonce {
            return Ok(n);
        }
        let n = L::account_nonce(chain, cx.signer_account).await?;
        self.nonce = Some(n);
        Ok(n)
    }

    /// Drain rows a previous writer left `SUBMITTING`: reconcile each against
    /// chain state — owned by its candidate → landed, otherwise re-queued.
    ///
    /// Chunked, and a failed chunk does not abandon the rest. A writer that
    /// died mid-batch can leave far more than a batch's worth, and one
    /// unbounded read over all of them would make every stuck row hostage to a
    /// single timeout or unanswered key — and the rows it left behind would
    /// wait for the next *lease acquisition*, which the active loop may not
    /// reach for a long time.
    ///
    /// Rows in a chunk that could not be read stay `SUBMITTING`: unknown is
    /// never read as not-yet-landed.
    pub(super) async fn reconcile_submitting(&self, cx: &Cx<'_>, chain: &L::Chain) -> Result<()> {
        let stuck = L::submitting(cx.pool).await?;
        let mut parsed = Vec::with_capacity(stuck.len());
        for r in &stuck {
            match parse_candidate(r) {
                Ok(candidate) => parsed.push((r, candidate)),
                Err(gate) => L::record(cx.pool, cx.guard, r, gate.outcome()).await?,
            }
        }
        if parsed.is_empty() {
            return Ok(());
        }

        let mut unread = 0usize;
        for chunk in parsed.chunks(RECONCILE_READ_CHUNK) {
            let names: Vec<&str> = chunk
                .iter()
                .map(|(r, _)| r.full_username.as_str())
                .collect();
            let owners = match chain.owners(&names).await {
                Ok(owners) => owners,
                Err(e) => {
                    tracing::warn!(
                        lane = L::NAME,
                        error = %e,
                        rows = chunk.len(),
                        "reconcile owner read failed; those rows stay SUBMITTING"
                    );
                    unread += chunk.len();
                    continue;
                }
            };
            for (r, candidate) in chunk {
                if owners.get(&r.full_username) == Some(candidate) {
                    L::record(cx.pool, cx.guard, r, Outcome::Observed).await?;
                } else {
                    L::record(cx.pool, cx.guard, r, Outcome::Retry(L::RECONCILED)).await?;
                }
            }
        }
        if unread > 0 {
            anyhow::bail!(
                "reconcile could not read {unread} of {} SUBMITTING rows",
                parsed.len()
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubmitFailureAction {
    Assign,
    Park,
    Retry,
    Fail,
}

/// The one runtime error that *is* success: the username is already registered
/// to the candidate, so the row is on chain and belongs in `ASSIGNED`.
const ALREADY_REGISTERED: &str = "PeopleLite::AlreadyRegistered";

const UNFUNDED_SIGNER: &str = "Inability to pay some fees";

pub(super) const UNFUNDED_PARK_BACKOFF_SECS: i64 = 300;

const DETERMINISTIC_REJECTIONS: &[&str] = &["Resources::UsernameReservationTaken"];

fn is_deterministic_rejection(reason: &str) -> bool {
    DETERMINISTIC_REJECTIONS
        .iter()
        .any(|rejection| reason.contains(rejection))
}

pub(super) fn terminal_reason(reason: &str) -> String {
    if is_deterministic_rejection(reason) {
        format!("rejected deterministically, not retried: {reason}")
    } else {
        format!("max attempts reached: {reason}")
    }
}

pub(super) fn classify_submit_failure(
    reason: &str,
    observed_owner: Option<[u8; 32]>,
    candidate: [u8; 32],
    completed_attempts: i32,
    max_attempts: i32,
) -> SubmitFailureAction {
    if observed_owner == Some(candidate) || reason.contains(ALREADY_REGISTERED) {
        SubmitFailureAction::Assign
    } else if reason.contains(UNFUNDED_SIGNER) {
        SubmitFailureAction::Park
    } else if is_deterministic_rejection(reason) || completed_attempts >= max_attempts {
        SubmitFailureAction::Fail
    } else {
        SubmitFailureAction::Retry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNFUNDED_ERROR: &str = "max attempts reached: Error during transaction progress: \
         The transaction is not valid: Invalid transaction: Inability to pay some fees \
         (e.g. account balance too low)";

    #[test]
    fn failed_attest_retries_then_fails_without_becoming_assigned() {
        let candidate = [7; 32];
        let reason = "PeopleLite.InvalidAttestationSignature";

        assert_eq!(
            classify_submit_failure(reason, None, candidate, 1, 3),
            SubmitFailureAction::Retry
        );
        assert_eq!(
            classify_submit_failure(reason, None, candidate, 3, 3),
            SubmitFailureAction::Fail
        );
    }

    #[test]
    fn an_unfunded_signer_parks_and_never_becomes_terminal() {
        let candidate = [7; 32];

        assert_eq!(
            classify_submit_failure(UNFUNDED_ERROR, None, candidate, 1, 3),
            SubmitFailureAction::Park
        );
        assert_eq!(
            classify_submit_failure(UNFUNDED_ERROR, None, candidate, 99, 3),
            SubmitFailureAction::Park
        );
        assert_eq!(
            classify_submit_failure(UNFUNDED_ERROR, Some(candidate), candidate, 99, 3),
            SubmitFailureAction::Assign
        );
    }

    #[test]
    fn a_deterministic_rejection_fails_on_the_first_pass() {
        let candidate = [7; 32];
        let reason = "proxied call failed: Resources::UsernameReservationTaken";

        assert_eq!(
            classify_submit_failure(reason, None, candidate, 1, 8),
            SubmitFailureAction::Fail
        );
        assert_eq!(
            classify_submit_failure(reason, Some(candidate), candidate, 1, 8),
            SubmitFailureAction::Assign
        );
        assert_eq!(
            classify_submit_failure(
                "proxied call failed: Resources::Whatever",
                None,
                candidate,
                1,
                8
            ),
            SubmitFailureAction::Retry
        );
    }

    #[test]
    fn terminal_text_names_the_rule_that_ended_the_row() {
        assert!(terminal_reason("Resources::UsernameReservationTaken")
            .starts_with("rejected deterministically, not retried"));
        assert!(terminal_reason("dispatch failed").starts_with("max attempts reached"));
    }

    #[test]
    fn submit_error_assigns_only_after_successful_reconciliation() {
        let candidate = [7; 32];

        assert_eq!(
            classify_submit_failure("finalization timed out", Some(candidate), candidate, 1, 3),
            SubmitFailureAction::Assign
        );
        assert_eq!(
            classify_submit_failure(ALREADY_REGISTERED, None, candidate, 1, 3),
            SubmitFailureAction::Assign
        );
        assert_eq!(
            classify_submit_failure("dispatch failed", Some([8; 32]), candidate, 1, 3),
            SubmitFailureAction::Retry
        );
    }

    #[test]
    fn rendered_already_registered_still_assigns() {
        assert_eq!(
            classify_submit_failure(
                "proxied call failed: PeopleLite::AlreadyRegistered",
                None,
                [7; 32],
                1,
                3
            ),
            SubmitFailureAction::Assign
        );
        assert_eq!(
            classify_submit_failure(
                "proxied call failed: DotnsGateway::AlreadyRegistered",
                None,
                [7; 32],
                1,
                3
            ),
            SubmitFailureAction::Retry
        );
    }
}
