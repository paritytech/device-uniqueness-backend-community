// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

/// `{ regionHint? }` — the issue command (the hint is reserved and ignored).
#[derive(Deserialize, ToSchema)]
#[allow(dead_code)] // documentation-only mirror of the wire shape
pub struct IssueRequest {
    /// Optional region hint (reserved for future use; accepted and ignored).
    #[serde(rename = "regionHint")]
    #[schema(rename = "regionHint", example = "eu-west", nullable)]
    pub region_hint: Option<String>,
}

/// The 201 body: the ephemeral credential Cloudflare Realtime TURN minted for
/// this request, plus the ICE server list it returned.
#[derive(Serialize, ToSchema)]
#[allow(dead_code)] // documentation-only mirror of the wire shape
pub struct IssueResponse {
    /// Every ICE server URL Cloudflare returned (`stun:` / `turn:` / `turns:`
    /// forms), flattened into one list in response order.
    #[schema(example = json!([
        "stun:stun.cloudflare.com:3478",
        "turn:turn.cloudflare.com:3478?transport=udp",
        "turn:turn.cloudflare.com:3478?transport=tcp",
        "turns:turn.cloudflare.com:5349?transport=tcp"
    ]))]
    pub servers: Vec<String>,
    /// The username Cloudflare minted for this request. Opaque: it carries no
    /// structure to parse, and nothing derived from the caller's identity.
    #[schema(example = "d2f4a1c6b8e05379")]
    pub username: String,
    /// The matching credential Cloudflare minted. Opaque.
    #[schema(example = "9f83b1e6c0a74d25b3f8e1a70c4d69b2")]
    pub password: String,
    /// Seconds of life remaining on this credential. Normally the TTL granted
    /// by Cloudflare; lower if a cached credential was served because
    /// Cloudflare was briefly unreachable.
    #[schema(example = 1800)]
    pub ttl: u64,
}

/// Adds the shared `bearer_jwt` security scheme referenced by the issue route.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::default);
        components.add_security_scheme(
            "bearer_jwt",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some("Access JWT issued by POST /api/v1/auth/token."))
                    .build(),
            ),
        );
    }
}

/// The turn OpenAPI document (merged into the workspace reference by
/// `apidoc-gen`).
#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "TURN",
         description = "Short-lived TURN credentials for WebRTC ICE negotiation, issued by \
Cloudflare Realtime TURN. Each request gets its own credential, so callers are mutually \
unlinkable; nothing is stored beyond the last response, which is served if Cloudflare is \
briefly unreachable. Issuance is authorized either by an access JWT (`/issue`) or, when \
enabled, by a personhood ring-VRF proof over a client-timestamped message \
(`/issue-with-proof`).")
    ),
    paths(
        crate::http::issue_credentials,
        crate::http::proof_routes::issue_with_proof,
    ),
    components(schemas(
        IssueRequest,
        IssueResponse,
        crate::http::proof_routes::IssueWithProofBody,
    )),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;
