// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use http_common::RateLimiter;
use jwt_verify::Verifier;

use crate::provider::PushProvider;

#[derive(Clone)]
pub struct AppState {
    /// Verify-only Ed25519 JWT validator.
    pub verifier: Verifier,
    pub apns: Arc<dyn PushProvider>,
    pub fcm: Arc<dyn PushProvider>,
    /// In-memory per-subject rate limiter for `/api/v1/notify`.
    pub limiter: RateLimiter,
}

impl AppState {
    pub fn new(
        verifier: Verifier,
        apns: Arc<dyn PushProvider>,
        fcm: Arc<dyn PushProvider>,
        limiter: RateLimiter,
    ) -> Self {
        Self {
            verifier,
            apns,
            fcm,
            limiter,
        }
    }
}

impl http_common::HasJwtVerifier for AppState {
    fn jwt_verifier(&self) -> &Verifier {
        &self.verifier
    }
}
