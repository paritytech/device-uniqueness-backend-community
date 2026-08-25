// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! The cross-service JWT contract: issuance, verification, and the JWKS
//! document that ties them together.
//!
//! Both halves live here, which the crate name predates. They are separated by
//! CAPABILITY rather than by crate: [`Issuer`] cannot be constructed without an
//! `ed25519_dalek::SigningKey`, and only `device-attestation` is given
//! `JWT_ED25519_SECRET`. Every other service builds a [`Verifier`] from a JWKS
//! document or a pinned public key and is structurally unable to mint a token.
//! That is what keeps "device-attestation is the sole issuer" true even though
//! the code to issue is linked into every role.

use base64::Engine;
use ed25519_dalek::SigningKey;
pub use error::JwtError;
use issuer::Issuer;
use jsonwebtoken::jwk::{CommonParameters, Jwk, JwkSet, KeyAlgorithm, OctetKeyPairParameters};
use sha2::{Digest, Sha256};
pub use verifier::{VerifiedClaims, Verifier};

const B64: base64::engine::GeneralPurpose = base64::prelude::BASE64_URL_SAFE_NO_PAD;

pub mod error;
pub mod issuer;
pub mod verifier;

pub struct Jwt {
    issuer: Issuer,
    verifier: Verifier,
    signing_kp: SigningKey,
}

impl Jwt {
    pub fn new(seed: &[u8; 32], issuer: String) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let pubkey = signing.verifying_key().to_bytes();
        let digest = Sha256::digest(pubkey);
        let kid = hex::encode(&digest[..8]);
        let issuer = Issuer::new(&signing, &kid, issuer);
        let verifier = Verifier::from_public_key(Some(kid.to_owned()), &pubkey);
        Self {
            issuer,
            verifier,
            signing_kp: signing,
        }
    }

    pub fn verify(&self, token: &str) -> Result<VerifiedClaims, JwtError> {
        self.verifier.verify(token)
    }

    pub fn verifier(&self) -> &Verifier {
        &self.verifier
    }

    pub fn jwks(&self) -> JwkSet {
        let x = B64.encode(self.signing_kp.verifying_key().to_bytes());

        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: None,
                key_operations: None,
                key_algorithm: Some(KeyAlgorithm::EdDSA),
                key_id: self.issuer.header.kid.clone(),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(
                OctetKeyPairParameters {
                    key_type: jsonwebtoken::jwk::OctetKeyPairType::OctetKeyPair,
                    curve: jsonwebtoken::jwk::EllipticCurve::Ed25519,
                    x,
                },
            ),
        };
        JwkSet { keys: vec![jwk] }
    }

    /// Issue a signed access token for `account_id` (`0x`-hex sr25519 pubkey).
    pub fn issue(
        &self,
        account_id: &str,
        app_from_official_store: bool,
        platform: Option<&str>,
        ttl: std::time::Duration,
    ) -> String {
        self.issuer
            .issue(account_id, app_from_official_store, platform, ttl)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ed25519_dalek::Verifier as _;

    use super::*;

    #[test]
    fn siblings_verify_issued_tokens_via_jwks() {
        let jwt = Jwt::new(&[7u8; 32], "polkadot-app".to_string());
        let token = jwt.issue("0xabcdef", true, None, Duration::from_secs(3600));

        let sibling = Verifier::from_jwks(&serde_json::to_string(&jwt.jwks()).unwrap()).unwrap();
        assert_eq!(sibling.verify(&token).unwrap().account_id, "0xabcdef");
        assert_eq!(jwt.verify(&token).unwrap().account_id, "0xabcdef");
    }

    #[test]
    fn issues_verifiable_token_with_account_id() {
        let jwt = Jwt::new(&[7u8; 32], "polkadot-app".to_string());
        let account = "0xabcdef";
        let token = jwt.issue(account, true, Some("ios"), Duration::from_secs(3600));

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWS has three segments");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes: [u8; 64] = B64.decode(parts[2]).unwrap().try_into().unwrap();
        let vk = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        vk.verify(
            signing_input.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&sig_bytes),
        )
        .expect("signature verifies");

        let claims: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["accountId"], account);
        assert_eq!(claims["sub"], account);
        assert_eq!(claims["appFromOfficialStore"], true);
        assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());

        let header: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(
            header["kid"],
            serde_json::to_value(jwt.jwks()).unwrap()["keys"][0]["kid"]
        );
    }
}
