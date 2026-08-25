// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use utoipa::OpenApi;

/// The username-indexer OpenAPI document (public read endpoints).
#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "Usernames", description = "Public username search over the finalized chain projection. Served to callers with an device-attestation JWT or, when proof of compute is enabled, a solved puzzle; rate-limited per subject or client IP."),
        (name = "Proof of compute", description = "Puzzle issuance for callers that hold no bearer token. Mounted only when `POC_ENABLED=true`.")
    ),
    paths(crate::http::search_usernames, crate::http::issue_puzzle),
    components(schemas(
        crate::search::SearchResponse,
        crate::search::SearchUsername,
        crate::poc::Puzzle,
    ))
)]
pub struct ApiDoc;
