// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use futures::{FutureExt as _, Stream, StreamExt as _};
use serde::Serialize;
use sqlx::{PgPool, Row as _};
use time::OffsetDateTime;

use crate::chain::PeopleChain;
use crate::config::Config;
use crate::incremental::{index_finalized_range_to, IndexError, IndexReport};

const BACKOFF_BASE_SECS: u64 = 1;
const BACKOFF_MAX_SECS: u64 = 60;

/// A point-in-time view of the projection's finalized-sync freshness.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshnessSnapshot {
    /// Finalized block number observed by the last successful sync.
    pub last_finalized_number: u64,
    /// Wall-clock time the last successful sync completed.
    #[serde(with = "time::serde::rfc3339")]
    pub last_synced_at: OffsetDateTime,
    /// Records persisted during the last successful sync.
    pub records_indexed: u64,
    /// Malformed records skipped during the last successful sync.
    pub decode_failures: u64,
}

/// Shared, cheaply-cloneable holder for the latest [`FreshnessSnapshot`].
///
/// The sync loop updates it after every successful snapshot; readiness reads it
/// without blocking. `None` until the first successful sync completes.
#[derive(Clone, Default)]
pub struct Freshness(Arc<RwLock<Option<FreshnessSnapshot>>>);

impl Freshness {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&self, snapshot: FreshnessSnapshot) {
        *self.0.write().expect("freshness lock poisoned") = Some(snapshot);
    }

    /// Read the latest freshness view, or `None` before the first sync.
    pub fn snapshot(&self) -> Option<FreshnessSnapshot> {
        *self.0.read().expect("freshness lock poisoned")
    }
}

/// Load the persisted checkpoint as a freshness snapshot, if the projection has
/// already been seeded. Used at startup to seed freshness when a full bootstrap
/// is skipped because a checkpoint already exists.
pub async fn checkpoint_freshness(pool: &PgPool) -> Result<Option<FreshnessSnapshot>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT last_finalized_number, last_synced_at, records_indexed, decode_failures
         FROM sync_state WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(FreshnessSnapshot {
        last_finalized_number: u64::try_from(row.try_get::<i64, _>("last_finalized_number")?)
            .unwrap_or(0),
        last_synced_at: row.try_get("last_synced_at")?,
        records_indexed: u64::try_from(row.try_get::<i64, _>("records_indexed")?).unwrap_or(0),
        decode_failures: u64::try_from(row.try_get::<i64, _>("decode_failures")?).unwrap_or(0),
    }))
}

/// What woke a sync pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wake {
    /// Finalized headers arrived; the payload is the highest number drained.
    Block(u64),
    /// The fallback timer fired without a header.
    Timer,
    /// The subscription ended or failed.
    Resubscribe,
}

impl Wake {
    fn as_str(self) -> &'static str {
        match self {
            Wake::Block(_) => "block",
            Wake::Timer => "timer",
            Wake::Resubscribe => "resubscribe",
        }
    }

    /// The finalized head this wake already knows, saving the pass a round-trip.
    ///
    /// A subscribed header number is a *lower bound* on the finalized head —
    /// the subscription cannot run ahead of finality — so indexing up to it is
    /// always safe, and the next header closes any gap. `Resubscribe` yields
    /// nothing on purpose: a number from a stream that just died is not one to
    /// index against.
    fn head(self) -> Option<u64> {
        match self {
            Wake::Block(number) => Some(number),
            Wake::Timer | Wake::Resubscribe => None,
        }
    }
}

/// Run the incremental finalized resync loop until the task is dropped.
///
/// Driven by a finalized-header subscription, so a registration reaches search
/// within a block of finality instead of within `sync_interval_secs`. Headers
/// are only a *signal*: every pass re-reads the checkpoint and indexes up to
/// the head, so a coalesced or dropped header costs nothing. The interval
/// survives as the fallback timer — the safety net for a subscription that goes
/// quiet without erroring.
///
/// A failed pass logs and waits a bounded exponential backoff, never advancing
/// the checkpoint. A dropped subscription backs off on the same counter, so a
/// node that accepts a subscription and closes it immediately cannot spin.
pub async fn run(pool: PgPool, chain: PeopleChain, config: Config, freshness: Freshness) {
    let fallback = Duration::from_secs(config.sync_interval_secs.into());
    let mut consecutive_failures = 0_u32;

    loop {
        let blocks = match chain.finalized_blocks().await {
            Ok(blocks) => blocks,
            Err(error) => {
                metrics::gauge!("dub_indexer_subscribed").set(0.0);
                consecutive_failures = consecutive_failures.saturating_add(1);
                let delay = backoff(consecutive_failures);
                tracing::warn!(
                    error = ?error,
                    consecutive_failures,
                    backoff_secs = delay.as_secs(),
                    "subscribing to finalized blocks failed; retrying"
                );
                tokio::time::sleep(delay).await;
                continue;
            }
        };
        // Only the number is ever read, and keeping the block would pin a
        // `BlockRef` the node is asked to hold unpruned. The error is boxed
        // because `BlocksError` is far larger than the number beside it.
        let mut headers = blocks.map(|item| item.map(|block| block.number()).map_err(Box::new));
        // Subscribing is not yet evidence of a working subscription, so the
        // failure counter is left alone; a completed pass is what clears it.
        metrics::gauge!("dub_indexer_subscribed").set(1.0);
        tracing::info!(
            fallback_secs = fallback.as_secs(),
            "subscribed to finalized block headers"
        );

        loop {
            let wake = wait_for_wake(&mut headers, fallback).await;

            // The stream died rather than delivered, so there is nothing new to
            // index. Back off here instead of after a pointless pass: a pass
            // would succeed with zero blocks, clear the counter, and turn a
            // subscription that dies on arrival into a hot loop.
            if wake == Wake::Resubscribe {
                metrics::counter!("dub_indexer_resubscribes_total").increment(1);
                consecutive_failures = consecutive_failures.saturating_add(1);
                let delay = backoff(consecutive_failures);
                tracing::warn!(
                    consecutive_failures,
                    backoff_secs = delay.as_secs(),
                    "finalized block subscription dropped; resubscribing"
                );
                tokio::time::sleep(delay).await;
                break;
            }

            let started = Instant::now();
            match pass(&pool, &chain, wake.head()).await {
                Ok(Some(report)) => {
                    consecutive_failures = 0;
                    freshness.update(FreshnessSnapshot {
                        last_finalized_number: report.to_block,
                        last_synced_at: OffsetDateTime::now_utc(),
                        records_indexed: report.accounts_upserted,
                        decode_failures: report.decode_failures,
                    });
                    if report.blocks_processed > 0 {
                        tracing::info!(
                            wake = wake.as_str(),
                            from_block = report.from_block,
                            to_block = report.to_block,
                            blocks_processed = report.blocks_processed,
                            accounts_upserted = report.accounts_upserted,
                            accounts_deleted = report.accounts_deleted,
                            decode_failures = report.decode_failures,
                            duration_ms = started.elapsed().as_millis() as u64,
                            "finalized resync complete"
                        );
                    } else {
                        tracing::debug!(
                            wake = wake.as_str(),
                            to_block = report.to_block,
                            "finalized resync found no new blocks"
                        );
                    }
                }
                Ok(None) => {
                    consecutive_failures = 0;
                    tracing::debug!(
                        "another instance holds the projection lock; skipping this pass"
                    );
                }
                Err(error) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let delay = backoff(consecutive_failures);
                    tracing::warn!(
                        error = ?error,
                        wake = wake.as_str(),
                        consecutive_failures,
                        backoff_secs = delay.as_secs(),
                        "finalized resync failed; retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }

        metrics::gauge!("dub_indexer_subscribed").set(0.0);
    }
}

/// Wait for the next reason to run a pass.
///
/// Returns as soon as one header is available, then drains whatever the
/// subscription already holds, so a burst — a catch-up after a backoff, or
/// finality advancing several blocks at once — costs one pass rather than one
/// per block. Generic over the header stream so the whole state machine is
/// testable without a chain.
///
/// Both drops are safe: `StreamExt::next` is cancel-safe, so neither the
/// `select!` losing the race nor `now_or_never` finding the stream pending can
/// swallow a header.
async fn wait_for_wake<S, E>(headers: &mut S, fallback: Duration) -> Wake
where
    S: Stream<Item = Result<u64, E>> + Unpin,
    E: std::fmt::Debug,
{
    let first = tokio::select! {
        item = headers.next() => item,
        () = tokio::time::sleep(fallback) => return Wake::Timer,
    };
    let mut head = match first {
        Some(Ok(number)) => number,
        Some(Err(error)) => {
            tracing::warn!(error = ?error, "finalized block subscription failed");
            return Wake::Resubscribe;
        }
        None => {
            tracing::warn!("finalized block subscription ended");
            return Wake::Resubscribe;
        }
    };

    while let Some(ready) = headers.next().now_or_never() {
        match ready {
            Some(Ok(number)) => head = head.max(number),
            Some(Err(error)) => {
                tracing::warn!(error = ?error, "finalized block subscription failed");
                return Wake::Resubscribe;
            }
            None => {
                tracing::warn!("finalized block subscription ended");
                return Wake::Resubscribe;
            }
        }
    }

    Wake::Block(head)
}

/// Record the lag gauges, then index everything up to the finalized head.
///
/// `known_head` is the number the subscription already delivered. Without one —
/// the fallback timer, which is also how a quiet stream recovers — the head
/// costs an `at_current_block` round-trip, so the hot path avoids it.
async fn pass(
    pool: &PgPool,
    chain: &PeopleChain,
    known_head: Option<u64>,
) -> Result<Option<IndexReport>, IndexError> {
    let head = match known_head {
        Some(number) => number,
        None => chain.finalized_head_number().await?,
    };
    if let Err(error) = record_lag_gauges(pool, head).await {
        tracing::warn!(error = ?error, "checkpoint lag gauge pass failed");
    }
    index_finalized_range_to(pool, chain, head).await
}

/// Record the finalized head, the checkpoint, and the gap between them.
///
/// The gap is the projection's real staleness — search answers from the
/// checkpoint, so it can grow while every individual pass reports success.
async fn record_lag_gauges(pool: &PgPool, head: u64) -> Result<(), sqlx::Error> {
    metrics::gauge!("dub_chain_finalized_head_block").set(head as f64);

    let Some(snapshot) = checkpoint_freshness(pool).await? else {
        return Ok(());
    };
    let checkpoint = snapshot.last_finalized_number;
    metrics::gauge!("dub_indexer_checkpoint_block").set(checkpoint as f64);
    metrics::gauge!("dub_indexer_checkpoint_lag_blocks")
        .set(head.saturating_sub(checkpoint) as f64);
    Ok(())
}

/// Bounded exponential backoff: `BASE * 2^(failures - 1)`, capped at
/// [`BACKOFF_MAX_SECS`]. `failures` is the count of consecutive failures,
/// starting at 1 for the first.
fn backoff(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(16);
    let secs = BACKOFF_BASE_SECS
        .saturating_mul(1_u64 << shift)
        .min(BACKOFF_MAX_SECS);
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::channel::mpsc;
    use time::macros::datetime;

    use super::{backoff, wait_for_wake, Freshness, FreshnessSnapshot, Wake, BACKOFF_MAX_SECS};

    const FALLBACK: Duration = Duration::from_secs(30);

    /// One finalized header, or the subscription failing to produce it.
    type Header = Result<u64, String>;

    /// A header channel standing in for the finalized subscription. Dropping the
    /// sender ends the stream the way a closed subscription does.
    fn headers() -> (
        mpsc::UnboundedSender<Header>,
        mpsc::UnboundedReceiver<Header>,
    ) {
        mpsc::unbounded()
    }

    #[tokio::test]
    async fn a_burst_of_headers_costs_one_pass_at_the_highest_number() {
        let (sender, mut stream) = headers();
        for number in [7, 8, 9] {
            sender.unbounded_send(Ok(number)).expect("send header");
        }

        let wake = wait_for_wake(&mut stream, FALLBACK).await;
        assert_eq!(wake, Wake::Block(9));
        // The pass indexes checkpoint+1..=9 in one go rather than three times.
        assert_eq!(wake.head(), Some(9));
    }

    #[tokio::test]
    async fn a_quiet_subscription_falls_back_to_the_timer() {
        let (_sender, mut stream) = headers();

        // Real elapsed time, so it is deliberately short: `tokio`'s clock
        // control lives behind the `test-util` feature this workspace does not
        // enable, and the fallback duration is a parameter either way.
        let wake = wait_for_wake(&mut stream, Duration::from_millis(10)).await;
        assert_eq!(wake, Wake::Timer);
        // No header means no head; the pass reads one over RPC instead.
        assert_eq!(wake.head(), None);
    }

    #[tokio::test]
    async fn an_ended_subscription_asks_to_resubscribe() {
        let (sender, mut stream) = headers();
        drop(sender);

        assert_eq!(
            wait_for_wake(&mut stream, FALLBACK).await,
            Wake::Resubscribe
        );
    }

    #[tokio::test]
    async fn a_failed_header_asks_to_resubscribe() {
        let (sender, mut stream) = headers();
        sender
            .unbounded_send(Err("connection reset".to_string()))
            .expect("send failure");

        assert_eq!(
            wait_for_wake(&mut stream, FALLBACK).await,
            Wake::Resubscribe
        );
    }

    #[tokio::test]
    async fn a_failure_while_draining_outranks_the_headers_before_it() {
        let (sender, mut stream) = headers();
        sender.unbounded_send(Ok(5)).expect("send header");
        sender
            .unbounded_send(Err("connection reset".to_string()))
            .expect("send failure");

        // Block 5 is not lost — the next pass indexes up to the head it reads
        // for itself. Carrying the number forward from a dead stream is what
        // would be wrong.
        let wake = wait_for_wake(&mut stream, FALLBACK).await;
        assert_eq!(wake, Wake::Resubscribe);
        assert_eq!(wake.head(), None);
    }

    #[test]
    fn backoff_grows_exponentially_then_caps() {
        assert_eq!(backoff(0).as_secs(), 1);
        assert_eq!(backoff(1).as_secs(), 1);
        assert_eq!(backoff(2).as_secs(), 2);
        assert_eq!(backoff(3).as_secs(), 4);
        assert_eq!(backoff(7).as_secs(), 60);
        assert_eq!(backoff(1000).as_secs(), BACKOFF_MAX_SECS);
    }

    #[test]
    fn freshness_starts_empty_and_reports_latest_update() {
        let freshness = Freshness::new();
        assert!(freshness.snapshot().is_none());

        let first = FreshnessSnapshot {
            last_finalized_number: 10,
            last_synced_at: datetime!(2026-07-11 10:00 UTC),
            records_indexed: 3,
            decode_failures: 0,
        };
        freshness.update(first);
        let stored = freshness.snapshot().expect("snapshot present");
        assert_eq!(stored.last_finalized_number, 10);
        assert_eq!(stored.records_indexed, 3);

        freshness.update(FreshnessSnapshot {
            last_finalized_number: 11,
            last_synced_at: datetime!(2026-07-11 10:01 UTC),
            records_indexed: 4,
            decode_failures: 1,
        });
        let latest = freshness.snapshot().expect("snapshot present");
        assert_eq!(latest.last_finalized_number, 11);
        assert_eq!(latest.decode_failures, 1);
    }
}
