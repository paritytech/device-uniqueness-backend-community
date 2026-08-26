// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;

/// There is **no chain client here**: the claim path is DB + signing only. All
/// chain interaction lives in the single-instance pool-maintainer binary.
#[derive(Clone)]
pub struct AppState {
    /// Postgres pool (this service's own `invite_tickets` database).
    pub pool: PgPool,
    /// Verify-only JWT verifier (shared `jwt-verify` crate).
    pub verifier: Arc<jwt_verify::Verifier>,
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Self {
        Self {
            pool,
            verifier: Arc::new(config.jwt_verifier.clone()),
            config: Arc::new(config),
        }
    }
}

impl http_common::HasJwtVerifier for AppState {
    fn jwt_verifier(&self) -> &jwt_verify::Verifier {
        &self.verifier
    }
}
