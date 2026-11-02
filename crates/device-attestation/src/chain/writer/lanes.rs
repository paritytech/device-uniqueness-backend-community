// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::future::Future;

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

/// Handle lanes losing lease.
pub(super) async fn until_lease_lost(
    people: impl Future<Output = WriterError>,
    dotns: impl Future<Output = WriterError>,
) -> WriterError {
    tokio::select! {
        e = people => e,
        e = dotns => e,
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

        let e = until_lease_lost(a, b).await;

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

        let e = until_lease_lost(stuck, losing).await;

        assert!(matches!(e, WriterError::LeaseLost(Op::Finalizing)));
    }
}
