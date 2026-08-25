// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod error;
pub mod state;

use axum::routing::post;
use axum::Router;
use http_common::{health, layers};

pub use self::state::AppState;

/// This service's own paths and nothing else: no health routes, no fallback, no
/// middleware stack — that is what makes it mergeable in the `all-in-one` role.
///
/// **This surface answers a different 404 from its siblings.** With no
/// `fallback`, an unmatched path answers axum's empty 404 and a wrong method
/// answers 405, where every sibling answers the JSON `{"error": "Not found"}`.
/// That is the live contract for `/api/v1/notify*`, so a merged router must
/// reproduce it inside this prefix.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/notify", post(crate::notify::handle))
        .with_state(state)
}

/// Assemble the full standalone service: [`router`] plus health at root and the
/// production middleware stack. No `fallback` — see [`router`].
pub fn routes(state: AppState) -> Router {
    let health = health::router("notifications", readiness).with_state(state.clone());
    layers::standard_layers(Router::new().merge(health).merge(router(state)))
}

/// Stateless and DB-free: if the process serves, it is ready — no external probe.
pub async fn readiness(_state: AppState) -> health::Readiness {
    Ok(&[])
}
