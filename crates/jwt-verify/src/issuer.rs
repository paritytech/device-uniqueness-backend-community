// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use ed25519_dalek::{pkcs8::EncodePrivateKey, SigningKey};
use jsonwebtoken::{EncodingKey, Header};
use serde::Serialize;

/// Access-token claims.
///
/// `sub` and `accountId` both carry the `0x`-hex sr25519 public key: `sub` for
/// JWT-standard consumers, `accountId` for the shape the app/spec names. `plt`
/// and `appFromOfficialStore` mirror the current backend.
#[derive(Serialize)]
struct ClaimsSer<'a> {
    iss: &'a str,
    sub: &'a str,
    #[serde(rename = "accountId")]
    account_id: &'a str,
    #[serde(rename = "appFromOfficialStore")]
    app_from_official_store: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    plt: Option<&'a str>,
    iat: u64,
    exp: u64,
}

pub(crate) struct Issuer {
    pub encoding_key: EncodingKey,
    pub header: Header,
    pub issuer: String,
}
impl Issuer {
    pub fn new(kp: &SigningKey, kid: &str, issuer: String) -> Self {
        let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some(kid.to_owned());
        Self {
            issuer,
            encoding_key: EncodingKey::from_ed_der(
                kp.to_pkcs8_der()
                    .expect("invalid signing key supplied")
                    .as_bytes(),
            ),
            header,
        }
    }
    pub fn issue(
        &self,
        account_id: &str,
        app_from_official_store: bool,
        platform: Option<&str>,
        ttl: std::time::Duration,
    ) -> String {
        let now = jsonwebtoken::get_current_timestamp();
        let claims = ClaimsSer {
            iss: &self.issuer,
            sub: account_id,
            account_id,
            app_from_official_store,
            plt: platform,
            iat: now,
            exp: now + ttl.as_secs(),
        };

        jsonwebtoken::encode(&self.header, &claims, &self.encoding_key).expect("Shouldn't happen unless we run out of memory or there's an internal issue inside the implementation")
    }
}
