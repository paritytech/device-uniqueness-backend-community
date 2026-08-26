// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub(crate) mod app_attest;
pub(crate) mod challenge;
pub(crate) mod key_attest;
pub(crate) mod play_integrity;
mod proof;
pub(crate) mod refresh;
pub(crate) mod token;
mod x509;

use axum::http::HeaderMap;
use axum::routing::post;
use axum::Router;
use base64::Engine as _;

use crate::http::error::{AppError, AppResult};
use crate::http::state::AppState;

const B64_STD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Build the auth router with the rate-limit layer applied to the whole group.
pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/challenges", post(challenge::issue))
        .route("/app-attest/attestations", post(app_attest::register))
        .route("/token", post(token::issue))
        // The single clean refresh path; the prod double-mount is not reproduced.
        .route("/token/refresh", post(refresh::rotate))
        .with_state(state)
}

/// Decode a required base64 header into raw bytes.
pub(crate) fn decode_header(headers: &HeaderMap, name: &str) -> AppResult<Vec<u8>> {
    let raw = headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::bad_request(format!("missing or invalid header {name}")))?;
    B64_STD
        .decode(raw.trim())
        .map_err(|_| AppError::bad_request(format!("header {name} is not valid base64")))
}

/// Decode a required base64 header into a fixed-size byte array.
pub(crate) fn decode_header_fixed<const N: usize>(
    headers: &HeaderMap,
    name: &str,
) -> AppResult<[u8; N]> {
    decode_header(headers, name)?
        .try_into()
        .map_err(|_| AppError::bad_request(format!("header {name} must decode to {N} bytes")))
}

/// Derive the platform claim from the optional package headers.
pub(crate) fn detect_platform(headers: &HeaderMap) -> Option<&'static str> {
    if headers.contains_key("auth-ios-package") {
        Some("ios")
    } else if headers.contains_key("auth-android-package") {
        Some("android")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn mobile_auth_headers_keep_the_shipping_names_and_shapes() {
        let mut headers = HeaderMap::new();
        headers.insert("auth-challenge", HeaderValue::from_static("AQID"));
        headers.insert("auth-clientid", HeaderValue::from_static("BQUH"));
        headers.insert("auth-clientproof", HeaderValue::from_static("CAkK"));

        assert_eq!(
            decode_header(&headers, "auth-challenge").unwrap(),
            [1, 2, 3]
        );
        assert_eq!(decode_header(&headers, "auth-clientid").unwrap(), [5, 5, 7]);
        assert_eq!(
            decode_header(&headers, "auth-clientproof").unwrap(),
            [8, 9, 10]
        );
    }

    #[test]
    fn mobile_package_headers_select_the_platform_claim() {
        let mut ios = HeaderMap::new();
        ios.insert(
            "auth-ios-package",
            HeaderValue::from_static("io.pcf.polkadotapp"),
        );
        assert_eq!(detect_platform(&ios), Some("ios"));

        let mut android = HeaderMap::new();
        android.insert(
            "auth-android-package",
            HeaderValue::from_static("io.novasama.polkadot"),
        );
        android.insert(
            "auth-attestation-type",
            HeaderValue::from_static("play-integrity"),
        );
        android.insert("auth-payload", HeaderValue::from_static("integrity-token"));
        assert_eq!(detect_platform(&android), Some("android"));
        assert_eq!(android["auth-attestation-type"], "play-integrity");
        assert_eq!(android["auth-payload"], "integrity-token");
    }
}
