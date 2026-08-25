// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};

type Blake2b256 = Blake2b<U32>;

/// Separates this digest from any other use of the same member key.
const LABEL: &[u8] = b"dub/turn-credential/v1";

/// Why a submitted request was not accepted as fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FreshnessError {
    /// The timestamp is further from server time than the accepted skew.
    #[error("timestamp outside the accepted window")]
    OutsideWindow,
}

/// Derives and bounds the message a proof must be made over.
#[derive(Debug)]
pub struct Freshness {
    max_skew_secs: u64,
}

impl Freshness {
    /// Bind to an accepted clock skew.
    pub fn new(max_skew_secs: u64) -> Self {
        Self { max_skew_secs }
    }

    /// The message a proof for `timestamp` must be made over.
    pub fn message(&self, timestamp: u64) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(LABEL);
        hasher.update(timestamp.to_be_bytes());
        hasher.finalize().into()
    }

    /// Accept `timestamp` only within the configured skew of `now_unix`.
    pub fn check(&self, timestamp: u64, now_unix: u64) -> Result<(), FreshnessError> {
        if now_unix.abs_diff(timestamp) > self.max_skew_secs {
            return Err(FreshnessError::OutsideWindow);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn freshness() -> Freshness {
        Freshness::new(60)
    }

    #[test]
    fn the_timestamp_changes_the_message() {
        let f = freshness();
        assert_ne!(f.message(1_000), f.message(1_001));
    }

    #[test]
    fn the_message_is_deterministic() {
        let f = freshness();
        assert_eq!(f.message(1_000), f.message(1_000));
    }

    #[test]
    fn the_window_is_symmetric_and_inclusive() {
        let f = freshness();
        assert_eq!(f.check(1_000, 1_000), Ok(()));
        assert_eq!(f.check(1_000, 1_060), Ok(()));
        assert_eq!(f.check(1_060, 1_000), Ok(()));
        assert_eq!(f.check(1_000, 1_061), Err(FreshnessError::OutsideWindow));
        assert_eq!(f.check(1_061, 1_000), Err(FreshnessError::OutsideWindow));
    }
}
