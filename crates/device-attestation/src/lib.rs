// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

mod auth;
pub mod chain;
pub mod config;
pub mod db;
pub mod device_check;
pub mod dotns;
pub mod eligibility;
pub mod http;
pub mod openapi;
pub mod queue;
pub mod usernames;
pub mod widevine;

use std::fmt::Debug;

pub use chain::PeopleChain;
pub use config::Config;
pub use http::routes;
pub use http::state::AppState;
pub use jwt_verify::Jwt;

/// Test-only surface for the live-Postgres suite (`tests/auth_live.rs`); not
/// part of the crate's API.
#[doc(hidden)]
pub use auth::app_attest::store as app_attest_store;

/// Serializes tests that mutate process-global environment variables
/// (`Config::from_env`, `WriterConfig::from_env`): cargo runs `#[test]`s on
/// parallel threads, so unlocked env mutation races across modules.
#[cfg(test)]
pub(crate) static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The connected used pallet's registration call is not the extrinsic this writer
/// builds.
#[derive(Debug)]
pub(crate) enum Pallet {
    DotnsGateway,
    PeopleLite,
}

impl std::fmt::Display for Pallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DotnsGateway => write!(f, "DotnsGateway::reserve_name"),
            Self::PeopleLite => write!(f, "PeopleLite::attest"),
        }
    }
}

/// The connected used pallet's call is not the extrinsic this writer
/// builds.
#[derive(Debug, thiserror::Error)]
#[error(
    "{pallet} shape mismatch: this writer builds [{expected}], \
     the connected runtime's {pallet} declares [{found}]. This chain runs a different \
     runtime version; point relevant network rpc(PEOPLE_RPC_URL,ASSET_HUB_RPC_URL) at one with the signed_at variant."
)]
pub struct PalletCallArgsShapeError {
    /// Pallet used by the call
    pallet: Pallet,
    /// Comma-separated argument names this writer encodes.
    expected: String,
    /// Comma-separated argument names the connected runtime declares.
    found: String,
}

/// Checks the pallet call arguments shape
///
/// Names, in order. A positional-only check would accept a runtime that renamed
/// an argument. A set check would accept one that reordered it.
pub(crate) fn check_pallet_call_args<T: PartialEq>(
    reserve_name_fields: &[T],
    pallet: Pallet,
    fields: &[T],
    extractor: fn(&T) -> String,
) -> Result<(), PalletCallArgsShapeError> {
    let matches = fields.len() == reserve_name_fields.len()
        && fields
            .iter()
            .zip(reserve_name_fields)
            .all(|(found, expected)| found == expected);
    if matches {
        return Ok(());
    }
    Err(PalletCallArgsShapeError {
        pallet,
        expected: reserve_name_fields
            .iter()
            .map(extractor)
            .collect::<Vec<_>>()
            .join(", "),
        found: fields.iter().map(extractor).collect::<Vec<_>>().join(", "),
    })
}
