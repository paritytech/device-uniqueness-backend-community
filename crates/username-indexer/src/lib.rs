// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod bootstrap;
pub mod chain;
pub mod config;
pub mod db;
pub mod gateway;
pub mod http;
pub mod incremental;
pub mod openapi;
pub mod poc;
pub mod projection;
pub mod search;
pub mod ss58;
pub mod sync;

pub use bootstrap::{ensure_seeded, BootstrapError, BootstrapReport, BootstrapTrigger};
pub use chain::{AssetHubChain, ChainError, PeopleChain};
pub use config::{Config, ConfigError};
pub use gateway::ingest::{GatewayIndexReport, GatewayReport, GatewayTrigger};
pub use gateway::GatewayError;
pub use http::{routes, AppState};
pub use incremental::{
    index_finalized_range, index_finalized_range_to, index_speculative_window, try_projection_lock,
    IndexError, IndexReport, ProjectionLock, SpeculativeCache, SpeculativeReport,
    MAX_SPECULATIVE_WINDOW,
};
pub use projection::{clear_speculative, AssignedUsername, Source};
pub use sync::{run as run_sync, Freshness, FreshnessSnapshot};
