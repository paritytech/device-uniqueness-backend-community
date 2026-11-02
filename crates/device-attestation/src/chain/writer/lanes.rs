// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::atomic::{AtomicBool, Ordering};

use super::{error::Op, WriterError};

/// Run one lane's passes until it fails, the lease is lost, or `stop` is
/// raised.
pub(super) async fn drive(
    stop: &AtomicBool,
    mut heartbeat: impl AsyncFnMut() -> Result<bool, WriterError>,
    mut pass: impl AsyncFnMut() -> Result<bool, WriterError>,
    mut idle: impl AsyncFnMut(),
) -> Result<(), WriterError> {
    let result = async {
        while !stop.load(Ordering::Relaxed) {
            if !heartbeat().await? {
                return Err(WriterError::LeaseLost(Op::Draining));
            }
            if pass().await? {
                idle().await;
            }
        }
        Ok(())
    }
    .await;
    stop.store(true, Ordering::Relaxed);
    result
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

    #[tokio::test]
    async fn a_busy_pass_loops_without_idling() {
        let stop = AtomicBool::new(false);
        let (passes, idles) = (Cell::new(0), Cell::new(0));

        let result = drive(
            &stop,
            held,
            async || {
                passes.set(passes.get() + 1);
                if passes.get() == 3 {
                    stop.store(true, Ordering::Relaxed);
                }
                Ok(false)
            },
            async || idles.set(idles.get() + 1),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(passes.get(), 3);
        assert_eq!(idles.get(), 0, "a pass that did work must not wait");
    }

    #[tokio::test]
    async fn an_idle_pass_waits_before_the_next() {
        let stop = AtomicBool::new(false);
        let (passes, idles) = (Cell::new(0), Cell::new(0));

        drive(
            &stop,
            held,
            async || {
                passes.set(passes.get() + 1);
                Ok(true)
            },
            async || {
                idles.set(idles.get() + 1);
                if idles.get() == 2 {
                    stop.store(true, Ordering::Relaxed);
                }
            },
        )
        .await
        .unwrap();

        assert_eq!((passes.get(), idles.get()), (2, 2));
    }

    #[tokio::test]
    async fn a_lost_heartbeat_is_lease_lost_and_runs_no_pass() {
        let stop = AtomicBool::new(false);
        let passes = Cell::new(0);

        let result = drive(
            &stop,
            async || Ok(false),
            async || {
                passes.set(passes.get() + 1);
                Ok(false)
            },
            async || {},
        )
        .await;

        assert!(matches!(result, Err(WriterError::LeaseLost(Op::Draining))));
        assert_eq!(passes.get(), 0);
        assert!(stop.load(Ordering::Relaxed), "the other lane must be told");
    }

    #[tokio::test]
    async fn a_failed_pass_is_returned_and_raises_stop() {
        let stop = AtomicBool::new(false);

        let result = drive(&stop, held, async || Err(db_error()), async || {}).await;

        assert!(matches!(result, Err(WriterError::Db(_))));
        assert!(stop.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn a_raised_stop_ends_the_lane_before_its_next_pass() {
        let stop = AtomicBool::new(true);
        let passes = Cell::new(0);

        let result = drive(
            &stop,
            held,
            async || {
                passes.set(passes.get() + 1);
                Ok(false)
            },
            async || {},
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(passes.get(), 0);
    }
}
