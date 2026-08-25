// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub(crate) mod google;
pub(crate) mod token;
pub(crate) mod verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayIntegrityMode {
    Strict,
    RelaxedDevice,
    RelaxedAll,
}

impl std::str::FromStr for PlayIntegrityMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "strict" => Ok(Self::Strict),
            "relaxed_device" => Ok(Self::RelaxedDevice),
            "relaxed_all" => Ok(Self::RelaxedAll),
            other => Err(format!(
                "{other:?} is not one of strict, relaxed_device, relaxed_all"
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PlayIntegrityError {
    #[error("malformed integrity token: {0}")]
    Malformed(String),
    #[error("integrity token decryption failed: {0}")]
    Decrypt(String),
    #[error("integrity token signature invalid")]
    Signature,
    #[error("integrity token nonce mismatch")]
    Nonce,
    #[error("integrity verdicts rejected: {}", .0.join(","))]
    Rejected(Vec<&'static str>),
}

pub struct VerifyParams<'a> {
    pub decryption_key: &'a [u8; 32],
    pub verification_key_der: &'a [u8],
    pub policy: PolicyParams<'a>,
}

pub struct PolicyParams<'a> {
    pub expected_nonce: &'a [u8; 32],
    pub mode: PlayIntegrityMode,
    pub package_names: &'a [String],
    pub playstore_digest: &'a [u8; 32],
    pub website_digest: &'a [u8; 32],
}

pub fn verify_token(
    integrity_token: &str,
    params: &VerifyParams<'_>,
) -> Result<bool, PlayIntegrityError> {
    let payload = token::decrypt_and_verify(
        integrity_token,
        params.decryption_key,
        params.verification_key_der,
    )?;
    check_payload(&payload, &params.policy)
}

pub fn check_payload(
    payload: &token::TokenPayload,
    policy: &PolicyParams<'_>,
) -> Result<bool, PlayIntegrityError> {
    let nonce = payload
        .request_details
        .as_ref()
        .and_then(|d| d.nonce.as_deref())
        .ok_or(PlayIntegrityError::Nonce)?;
    let nonce_bytes = token::b64url(nonce).map_err(|_| PlayIntegrityError::Nonce)?;
    if nonce_bytes != policy.expected_nonce {
        return Err(PlayIntegrityError::Nonce);
    }

    verdict::validate(payload, policy)
}

#[cfg(test)]
mod tests;
