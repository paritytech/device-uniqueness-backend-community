// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use jsonwebtoken::{
    jwk::{AlgorithmParameters, EllipticCurve, OctetKeyPairParameters, OctetKeyPairType},
    Algorithm, DecodingKey, Validation,
};
use serde::{Deserialize, Serialize};

use crate::error::{JwksError, JwtError};

/// Verifies bearer tokens issued by device-attestation against its public keys.
#[derive(Clone)]
pub struct Verifier {
    /// Published keys; `kid` is `None` only for pinned keys loaded without one.
    keys: Vec<(Option<String>, DecodingKey)>,
}

/// Claims read back from a verified token.
///
/// `accountId` is the shape the app/spec names; it duplicates `sub` on the
/// wire, so only `accountId` is decoded here.
#[derive(Debug, Deserialize, Serialize)]
pub struct VerifiedClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    /// `0x`-hex sr25519 public key of the authenticated account.
    #[serde(rename = "accountId")]
    pub account_id: String,
    /// Whether attestation judged the app an official-store install
    /// (`appFromOfficialStore` claim, set server-side from real attestation
    /// evidence). `None` when the issuer omitted it (old tokens, no-op
    /// posture) — consumers choose their own default per posture.
    #[serde(rename = "appFromOfficialStore", default)]
    pub app_from_official_store: Option<bool>,
    /// Client platform (`"ios"`/`"android"`) from the token's `plt` claim,
    /// set server-side at attestation. Absent when the issuer omitted it.
    #[serde(rename = "plt", default)]
    pub platform: Option<String>,
    pub iat: Option<u64>,
    /// Expiry (unix seconds).
    pub exp: u64,
}

impl Verifier {
    /// Load keys from a JWKS document (the body of `/.well-known/jwks.json`).
    ///
    /// Keys that are not `OKP`/`Ed25519` or carry undecodable material are
    /// skipped; an empty usable set is [`JwksError::NoUsableKey`].
    pub fn from_jwks(jwks_json: &str) -> Result<Self, JwksError> {
        let doc: jsonwebtoken::jwk::JwkSet =
            serde_json::from_str(jwks_json).map_err(|_| JwksError::Malformed)?;
        let keys: Vec<(Option<String>, DecodingKey)> = doc
            .keys
            .into_iter()
            .filter_map(|k| {
                if let AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                    key_type: OctetKeyPairType::OctetKeyPair,
                    curve: EllipticCurve::Ed25519,
                    x,
                }) = k.algorithm
                {
                    DecodingKey::from_ed_components(&x)
                        .ok()
                        .map(|x| (k.common.key_id, x))
                } else {
                    None
                }
            })
            .collect();
        if keys.is_empty() {
            return Err(JwksError::NoUsableKey);
        }
        Ok(Self { keys })
    }

    /// Build a verifier around one pinned public key (no JWKS fetch).
    ///
    /// Tokens naming any `kid` still verify — a pinned key has no id to
    /// mismatch. device-attestation uses this to verify its own tokens.
    pub fn from_verifying_key(kid: Option<String>, key: DecodingKey) -> Self {
        Self {
            keys: vec![(kid, key)],
        }
    }

    /// [`Verifier::from_verifying_key`] over raw 32-byte Ed25519 key bytes.
    pub fn from_public_key(kid: Option<String>, key: &[u8]) -> Self {
        Self {
            keys: vec![(kid, DecodingKey::from_ed_der(key))],
        }
    }

    /// Verify a bearer token and return its claims.
    ///
    /// Checks (in order): JWS shape, `alg == EdDSA`, `kid` known (when both the
    /// token and the keys carry one), Ed25519 signature, `exp` in the future.
    pub fn verify(&self, token: &str) -> Result<VerifiedClaims, JwtError> {
        let header = jsonwebtoken::decode_header(token)?;

        if header.alg != Algorithm::EdDSA {
            return Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into());
        }
        let candidates = {
            let keys = self.keys.iter();

            let keys = match &header.kid {
                Some(token_kid) => keys
                    .filter(|kid| kid.0.as_ref() == Some(token_kid) || kid.0.is_none())
                    .map(|(_, key)| key)
                    .collect::<Vec<&DecodingKey>>(),
                None => keys.map(|(_, key)| key).collect::<Vec<&DecodingKey>>(),
            };

            if keys.is_empty() {
                return Err(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat.into());
            } else {
                keys
            }
        };
        let mut iter = candidates.iter().peekable();
        while let Some(decoding_key) = iter.next() {
            match jsonwebtoken::decode::<VerifiedClaims>(
                token,
                decoding_key,
                &Validation::new(jsonwebtoken::Algorithm::EdDSA),
            ) {
                Ok(x) => return Ok(x.claims),
                Err(err) => {
                    if candidates.len() == 1 || iter.peek().is_none() {
                        return Err(err);
                    }
                }
            }
        }
        Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use ed25519_dalek::{Signer as _, SigningKey};
    use jsonwebtoken::errors::ErrorKind;

    use super::*;

    fn issue(seed: &[u8; 32], kid: Option<&str>, alg: &str, exp: u64) -> String {
        let signing = SigningKey::from_bytes(seed);
        let header = match kid {
            Some(kid) => format!(r#"{{"alg":"{alg}","typ":"JWT","kid":"{kid}"}}"#),
            None => format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#),
        };
        let claims = format!(
            r#"{{"accountId":"0xabcdef","iat":{},"exp":{exp}}}"#,
            jsonwebtoken::get_current_timestamp()
        );
        let signing_input = format!("{}.{}", B64.encode(header), B64.encode(claims));
        let signature = signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(signature.to_bytes()))
    }

    fn jwks_for(seed: &[u8; 32], kid: &str) -> String {
        let x = B64.encode(SigningKey::from_bytes(seed).verifying_key().to_bytes());
        format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"{kid}","x":"{x}"}}]}}"#
        )
    }

    #[test]
    fn verifies_token_against_jwks_keys() {
        let seed = [7u8; 32];
        let kid = "issuer-kid";
        let verifier = Verifier::from_jwks(&jwks_for(&seed, kid)).unwrap();

        let token = issue(
            &seed,
            Some(kid),
            "EdDSA",
            jsonwebtoken::get_current_timestamp() + 3600,
        );
        let claims = verifier.verify(&token).unwrap();
        assert_eq!(claims.account_id, "0xabcdef");
        assert_eq!(claims.exp, jsonwebtoken::get_current_timestamp() + 3600);
        assert_eq!(claims.platform, None);
        assert_eq!(claims.app_from_official_store, None);
    }

    #[test]
    fn decodes_the_optional_attestation_claims() {
        let seed = [7u8; 32];
        let kid = "issuer-kid";
        let verifier = Verifier::from_jwks(&jwks_for(&seed, kid)).unwrap();

        let signing = SigningKey::from_bytes(&seed);
        let header = format!(r#"{{"alg":"EdDSA","typ":"JWT","kid":"{kid}"}}"#);
        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        let claims = format!(
            r#"{{"accountId":"0xabcdef","plt":"android","appFromOfficialStore":false,"exp":{exp}}}"#
        );
        let signing_input = format!("{}.{}", B64.encode(header), B64.encode(claims));
        let signature = signing.sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", B64.encode(signature.to_bytes()));

        let claims = verifier.verify(&token).unwrap();
        assert_eq!(claims.platform.as_deref(), Some("android"));
        assert_eq!(claims.app_from_official_store, Some(false));
    }

    #[test]
    fn verifies_token_without_kid_against_pinned_key() {
        let seed = [9u8; 32];
        let verifier = Verifier::from_public_key(
            None,
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        );
        let token = issue(
            &seed,
            None,
            "EdDSA",
            jsonwebtoken::get_current_timestamp() + 60,
        );
        assert!(verifier.verify(&token).is_ok());
    }

    #[test]
    fn rejects_non_eddsa_alg_before_signature_check() {
        let seed = [7u8; 32];
        let verifier = Verifier::from_public_key(
            None,
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        );
        let token = issue(
            &seed,
            None,
            "HS256",
            jsonwebtoken::get_current_timestamp() + 3600,
        );
        assert_eq!(
            verifier.verify(&token).err().unwrap().kind(),
            &jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
        );

        let token = issue(
            &seed,
            None,
            "none",
            jsonwebtoken::get_current_timestamp() + 3600,
        );
        assert!(matches!(
            verifier.verify(&token).err().unwrap().kind(),
            jsonwebtoken::errors::ErrorKind::Json(_)
        ));
    }

    #[test]
    fn rejects_expired_token() {
        let seed = [7u8; 32];
        let verifier = Verifier::from_public_key(
            None,
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        );
        let token = issue(
            &seed,
            None,
            "EdDSA",
            jsonwebtoken::get_current_timestamp() - 100,
        );
        assert_eq!(
            verifier.verify(&token).err().unwrap(),
            jsonwebtoken::errors::ErrorKind::ExpiredSignature.into()
        );
    }

    #[test]
    fn rejects_token_signed_by_another_key() {
        let seed = [7u8; 32];
        let verifier = Verifier::from_public_key(
            None,
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        );
        let token = issue(
            &[8u8; 32],
            None,
            "EdDSA",
            jsonwebtoken::get_current_timestamp() + 3600,
        );
        assert_eq!(
            verifier.verify(&token).err().unwrap(),
            jsonwebtoken::errors::ErrorKind::InvalidSignature.into()
        );
    }

    #[test]
    fn rejects_unknown_kid() {
        let seed = [7u8; 32];
        let verifier = Verifier::from_jwks(&jwks_for(&seed, "known-kid")).unwrap();
        let token = issue(
            &seed,
            Some("other-kid"),
            "EdDSA",
            jsonwebtoken::get_current_timestamp() + 3600,
        );
        assert_eq!(
            verifier.verify(&token).err().unwrap(),
            jsonwebtoken::errors::ErrorKind::InvalidKeyFormat.into()
        );
    }

    #[test]
    fn rejects_malformed_tokens() {
        let seed = [7u8; 32];
        let verifier = Verifier::from_public_key(
            None,
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        );
        for token in ["", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert!(matches!(
                verifier.verify(token).err().unwrap().kind(),
                ErrorKind::Base64(_) | ErrorKind::InvalidToken
            ));
        }
    }

    #[test]
    fn rejects_jwks_without_usable_keys() {
        assert_eq!(
            Verifier::from_jwks(r#"{"keys":[]}"#).err(),
            Some(JwksError::NoUsableKey)
        );
        assert_eq!(
            Verifier::from_jwks(r#"{"keys":[{"kty":"RSA","kid":"a"}]}"#).err(),
            Some(JwksError::Malformed)
        );
        assert_eq!(
            Verifier::from_jwks("not json").err(),
            Some(JwksError::Malformed)
        );
    }
}
