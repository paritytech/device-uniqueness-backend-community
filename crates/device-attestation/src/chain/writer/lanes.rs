// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::{convert::Infallible, future::Future, time::Duration};

use tokio::sync::Notify;

use super::{error::Op, WriterError};

/// Run one lane's passes until it fails or the lease is lost.
pub(super) async fn drive(
    mut heartbeat: impl AsyncFnMut() -> Result<bool, WriterError>,
    mut pass: impl AsyncFnMut() -> Result<bool, WriterError>,
    mut idle: impl AsyncFnMut(),
) -> WriterError {
    loop {
        match heartbeat().await {
            Ok(true) => {}
            Ok(false) => return WriterError::LeaseLost(Op::Draining),
            Err(e) => return e,
        }
        match pass().await {
            Ok(true) => idle().await,
            Ok(false) => {}
            Err(e) => return e,
        }
    }
}

pub(super) async fn supervise<S>(
    lane: &'static str,
    state: &mut S,
    mut restart: impl AsyncFnMut(&mut S) -> Result<(), WriterError>,
    mut run: impl AsyncFnMut(&mut S) -> WriterError,
    mut backoff: impl AsyncFnMut(),
) -> WriterError {
    loop {
        if let Err(e) = restart(state).await {
            return e;
        }
        let e = run(state).await;
        if e.is_lease_lost() {
            return e;
        }
        tracing::warn!(lane, error = %e, "lane failed; restarting it");
        backoff().await;
    }
}

/// Wait out `period`, or less if `wake` is notified first.
pub(super) async fn sleep_or_wake(period: Duration, wake: &Notify) {
    tokio::select! {
        () = tokio::time::sleep(period) => {}
        () = wake.notified() => {}
    }
}

pub(super) async fn every(mut tick: impl AsyncFnMut(), mut wait: impl AsyncFnMut()) -> Infallible {
    loop {
        tick().await;
        wait().await;
    }
}

/// Handle lanes losing lease; the periodic passes stop with them.
pub(super) async fn until_lease_lost(
    people: impl Future<Output = WriterError>,
    dotns: impl Future<Output = WriterError>,
    periodic: impl Future<Output = Infallible>,
) -> WriterError {
    tokio::select! {
        e = people => e,
        e = dotns => e,
        never = periodic => match never {},
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    async fn held() -> Result<bool, WriterError> {
        Ok(true)
    }

    fn db_error() -> WriterError {
        WriterError::Db(sqlx::Error::PoolTimedOut)
    }

    fn bump(c: &Cell<u32>) -> u32 {
        c.set(c.get() + 1);
        c.get()
    }

    #[tokio::test]
    async fn a_busy_pass_loops_without_idling() {
        let (passes, idles) = (Cell::new(0), Cell::new(0));

        let e = drive(
            held,
            async || match bump(&passes) {
                3 => Err(db_error()),
                _ => Ok(false),
            },
            async || {
                bump(&idles);
            },
        )
        .await;

        assert!(matches!(e, WriterError::Db(_)));
        assert_eq!(passes.get(), 3);
        assert_eq!(idles.get(), 0, "a pass that did work must not wait");
    }

    #[tokio::test]
    async fn an_idle_pass_waits_before_the_next() {
        let (passes, idles) = (Cell::new(0), Cell::new(0));

        drive(
            held,
            async || match bump(&passes) {
                3 => Err(db_error()),
                _ => Ok(true),
            },
            async || {
                bump(&idles);
            },
        )
        .await;

        assert_eq!((passes.get(), idles.get()), (3, 2));
    }

    #[tokio::test]
    async fn a_lost_heartbeat_is_lease_lost_and_runs_no_pass() {
        let passes = Cell::new(0);

        let e = drive(
            async || Ok(false),
            async || {
                bump(&passes);
                Ok(false)
            },
            async || {},
        )
        .await;

        assert!(matches!(e, WriterError::LeaseLost(Op::Draining)));
        assert_eq!(passes.get(), 0);
    }

    #[tokio::test]
    async fn a_failed_heartbeat_is_returned() {
        let e = drive(async || Err(db_error()), async || Ok(false), async || {}).await;
        assert!(matches!(e, WriterError::Db(_)));
    }

    #[tokio::test]
    async fn a_lane_error_restarts_only_that_lane() {
        let (restarts, runs, backoffs) = (Cell::new(0), Cell::new(0), Cell::new(0));

        let e = supervise(
            "test",
            &mut (),
            async |_| {
                bump(&restarts);
                Ok(())
            },
            async |_| match bump(&runs) {
                3 => WriterError::LeaseLost(Op::Landing),
                _ => db_error(),
            },
            async || {
                bump(&backoffs);
            },
        )
        .await;

        assert!(matches!(e, WriterError::LeaseLost(Op::Landing)));
        assert_eq!(
            (restarts.get(), runs.get(), backoffs.get()),
            (3, 3, 2),
            "every failure but the lease loss is followed by a backoff and a restart"
        );
    }

    #[tokio::test]
    async fn a_lease_lost_during_restart_does_not_run_the_lane() {
        let runs = Cell::new(0);

        let e = supervise(
            "test",
            &mut (),
            async |_| Err(WriterError::LeaseLost(Op::Landing)),
            async |_| {
                bump(&runs);
                db_error()
            },
            async || {},
        )
        .await;

        assert!(e.is_lease_lost());
        assert_eq!(runs.get(), 0);
    }

    #[tokio::test]
    async fn one_lane_failing_does_not_restart_the_other() {
        let (a_runs, b_restarts, b_passes) = (Cell::new(0), Cell::new(0), Cell::new(0));
        let (mut a_state, mut b_state) = ((), ());

        let a = supervise(
            "a",
            &mut a_state,
            async |_| Ok(()),
            async |_| match bump(&a_runs) {
                3 => WriterError::LeaseLost(Op::Draining),
                _ => db_error(),
            },
            tokio::task::yield_now,
        );
        let b = supervise(
            "b",
            &mut b_state,
            async |_| {
                bump(&b_restarts);
                Ok(())
            },
            async |_| {
                drive(
                    held,
                    async || {
                        bump(&b_passes);
                        tokio::task::yield_now().await;
                        Ok(false)
                    },
                    async || {},
                )
                .await
            },
            async || {},
        );

        let e = until_lease_lost(a, b, std::future::pending()).await;

        assert!(e.is_lease_lost());
        assert_eq!(a_runs.get(), 3);
        assert_eq!(b_restarts.get(), 1, "b must not restart for a's errors");
        assert!(b_passes.get() >= 1, "b kept passing while a restarted");
    }

    #[tokio::test]
    async fn a_lease_loss_cancels_a_lane_stuck_mid_pass() {
        let mut state = ();
        let stuck = supervise(
            "stuck",
            &mut state,
            async |_| Ok(()),
            async |_| std::future::pending().await,
            async || {},
        );
        let losing = async { WriterError::LeaseLost(Op::Finalizing) };

        let e = until_lease_lost(stuck, losing, std::future::pending()).await;

        assert!(matches!(e, WriterError::LeaseLost(Op::Finalizing)));
    }

    #[tokio::test]
    async fn the_periodic_passes_run_while_a_lane_is_stuck_mid_pass() {
        let ticks = Cell::new(0);
        let stuck = std::future::pending();
        let waiting = async {
            while ticks.get() < 3 {
                tokio::task::yield_now().await;
            }
            WriterError::LeaseLost(Op::Draining)
        };
        let periodic = every(
            async || {
                bump(&ticks);
            },
            tokio::task::yield_now,
        );

        let e = until_lease_lost(waiting, stuck, periodic).await;

        assert!(e.is_lease_lost());
        assert!(
            ticks.get() >= 3,
            "a stuck dotNS lane must not hold the passes"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_wait_runs_its_full_period_unwoken() {
        let start = tokio::time::Instant::now();
        sleep_or_wake(Duration::from_secs(2), &Notify::new()).await;
        assert_eq!(start.elapsed(), Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_wake_ends_an_idle_wait_early() {
        let wake = Notify::new();
        let start = tokio::time::Instant::now();

        tokio::join!(sleep_or_wake(Duration::from_secs(2), &wake), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            wake.notify_one();
        });

        assert_eq!(start.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn a_wake_sent_before_the_wait_is_not_lost() {
        let wake = Notify::new();
        wake.notify_one();
        let start = tokio::time::Instant::now();

        sleep_or_wake(Duration::from_secs(2), &wake).await;

        assert_eq!(start.elapsed(), Duration::ZERO);
    }
}
