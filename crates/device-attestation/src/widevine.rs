// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Widevine device-uniqueness evidence on `POST /api/v1/usernames` (PoUD).
//!
//! Binds a Widevine device identifier to a specific username claim, signed by
//! a hardware-attested key, so the backend can enforce one free registration
//! per physical Android device. Wire contract: three optional body fields —
//! `attestationChain`, `deviceEnvelope`, `envelopeSignature` — present
//! together or not at all; the envelope is canonical CBOR ([`envelope`])
//! signed by the leaf key of the attestation chain, which is verified by the
//! existing key-attestation policy (`auth::key_attest::verify`).
//!
//! Privacy invariant: the raw `widevineId` is never stored, logged, or traced
//! — only `HMAC-SHA256(k_epoch, "poud:v1" ‖ namespace ‖ widevineId)` reaches
//! the database ([`store`]). L1 and GrapheneOS-L3 devices live in separate
//! namespaces that are never merged.
//!
//! Gating: `WIDEVINE_DEDUP_ENABLED` recognises the fields (soft mode —
//! verify and log the would-be outcome, routing unchanged);
//! `WIDEVINE_DEDUP_ENFORCE` makes the dedup routing live;
//! `WIDEVINE_L3_GRAPHENEOS_ENABLED` opens the isolated L3 lane. All decided
//! in the route ([`crate::usernames::register`]); this module is IO-free
//! except [`store`].

pub mod envelope;
pub mod store;

use std::collections::HashSet;

use base64::Engine as _;
use hmac::Mac as _;
use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::DecodePublicKey as _;
use secrecy::ExposeSecret as _;
use serde_json::Value;

use crate::auth::key_attest;
use crate::config::{Config, WidevineConfig};

/// Dedup namespace for measured Widevine L1 devices.
pub const NAMESPACE_L1: &str = "widevine_l1";
/// Dedup namespace for the GrapheneOS L3 lane.
pub const NAMESPACE_L3: &str = "widevine_l3";

/// HMAC domain-separation context.
const HMAC_CONTEXT: &[u8] = b"poud:v1";

/// Maximum decoded envelope size on the wire.
const MAX_ENVELOPE_BYTES: usize = 512;
/// Maximum future window for the envelope `expiry` (unix seconds).
const MAX_EXPIRY_WINDOW_SECS: i64 = 600;

/// `attestationChain` bounds — the same limits as the `/auth/token` contract.
const MIN_CHAIN_ENTRIES: usize = 2;
const MAX_CHAIN_ENTRIES: usize = 10;
const MAX_ENTRY_CHARS: usize = 8192;

/// Why device evidence was rejected. In enforced mode the route maps
/// `Malformed` to `DEVICE_EVIDENCE_MALFORMED` (400) and `Invalid` to
/// `DEVICE_EVIDENCE_INVALID` (403); in soft mode both are logged verdicts.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// Structural failure: partial fields, bad base64, size bounds,
    /// non-canonical CBOR, unknown domain/version, invalid level.
    #[error("malformed device evidence: {0}")]
    Malformed(String),
    /// Verification failure: chain policy, signature, challenge binding,
    /// candidate mismatch, expiry.
    #[error("invalid device evidence: {0}")]
    Invalid(String),
}

/// The three wire fields, decoded but not yet verified.
pub struct RawEvidence {
    /// Leaf-first DER chain from `attestationChain`.
    pub chain_der: Vec<Vec<u8>>,
    /// Exact envelope bytes as transmitted (the signature covers these).
    pub envelope: Vec<u8>,
    /// ASN.1/DER ECDSA signature over the envelope bytes.
    pub signature_der: Vec<u8>,
}

/// Extract the evidence fields from the (already parsed) request body.
/// `Ok(None)` = no evidence; partial presence or bound violations are
/// [`EvidenceError::Malformed`].
pub fn extract(body: &Value) -> Result<Option<RawEvidence>, EvidenceError> {
    let chain = body.get("attestationChain");
    let envelope = body.get("deviceEnvelope");
    let signature = body.get("envelopeSignature");
    let (chain, envelope, signature) = match (chain, envelope, signature) {
        (None, None, None) => return Ok(None),
        (Some(c), Some(e), Some(s)) => (c, e, s),
        _ => {
            return Err(EvidenceError::Malformed(
                "attestationChain, deviceEnvelope and envelopeSignature must be \
                 present together"
                    .to_string(),
            ))
        }
    };

    let malformed = EvidenceError::Malformed;
    let b64 = base64::engine::general_purpose::STANDARD;

    let entries = chain
        .as_array()
        .ok_or_else(|| malformed("attestationChain must be an array of strings".to_string()))?;
    if entries.len() < MIN_CHAIN_ENTRIES || entries.len() > MAX_CHAIN_ENTRIES {
        return Err(malformed(format!(
            "attestationChain has {} entries, expected {MIN_CHAIN_ENTRIES}..={MAX_CHAIN_ENTRIES}",
            entries.len()
        )));
    }
    let chain_der = entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let raw = entry
                .as_str()
                .ok_or_else(|| malformed(format!("attestationChain[{i}] must be a string")))?;
            if raw.len() > MAX_ENTRY_CHARS {
                return Err(malformed(format!(
                    "attestationChain[{i}] exceeds {MAX_ENTRY_CHARS} chars"
                )));
            }
            b64.decode(raw.trim())
                .map_err(|_| malformed(format!("attestationChain[{i}] is not valid base64")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let envelope = envelope
        .as_str()
        .ok_or_else(|| malformed("deviceEnvelope must be a string".to_string()))
        .and_then(|raw| {
            b64.decode(raw.trim())
                .map_err(|_| malformed("deviceEnvelope is not valid base64".to_string()))
        })?;
    if envelope.is_empty() || envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(malformed(format!(
            "deviceEnvelope is {} bytes, expected 1..={MAX_ENVELOPE_BYTES}",
            envelope.len()
        )));
    }

    let signature_der = signature
        .as_str()
        .ok_or_else(|| malformed("envelopeSignature must be a string".to_string()))
        .and_then(|raw| {
            b64.decode(raw.trim())
                .map_err(|_| malformed("envelopeSignature is not valid base64".to_string()))
        })?;

    Ok(Some(RawEvidence {
        chain_der,
        envelope,
        signature_der,
    }))
}

/// One epoch's device HMAC.
pub struct DeviceHmac {
    /// Epoch label (e.g. `v1`).
    pub epoch: String,
    /// `HMAC-SHA256(k_epoch, "poud:v1" ‖ namespace ‖ widevineId)`.
    pub hmac: [u8; 32],
}

/// Fully verified device evidence, ready for the dedup gate.
pub struct VerifiedEvidence {
    /// Dedup namespace the device belongs to.
    pub namespace: &'static str,
    /// Measured level (`1` or `3`).
    pub level: u64,
    /// Envelope challenge — the caller consumes it (single-use) from the
    /// challenge store before acting on the evidence.
    pub challenge: [u8; 32],
    /// HMACs per configured epoch, active epoch first. Every entry is looked
    /// up; only the first is written with a new record.
    pub hmacs: Vec<DeviceHmac>,
}

/// Everything [`verify`] needs besides the evidence itself. No IO — the
/// caller fetches the CRL and supplies the clock.
pub struct VerifyParams<'a> {
    /// Service config (package allow-list + signing digests).
    pub config: &'a Config,
    /// The enabled Widevine block (HMAC keys + L3 gate).
    pub widevine: &'a WidevineConfig,
    /// Revoked serials from the attestation CRL.
    pub revoked_serials: &'a HashSet<String>,
    /// The authenticated account's sr25519 public key (the JWT subject).
    pub subject_pubkey: &'a [u8; 32],
    /// Verification time (unix seconds).
    pub now_unix: i64,
}

/// Verify the evidence end to end: canonical envelope decode, candidate and
/// expiry binding, attestation-chain policy (which binds the leaf key to the
/// envelope challenge), envelope signature by the attested leaf key, and the
/// level policy. `Ok(None)` = structurally valid L3 evidence while the
/// GrapheneOS lane is off — routed as evidence-absent, not an error.
///
/// Deliberately does **not** consume the challenge or touch the dedup store;
/// the route owns those side effects.
pub fn verify(
    evidence: &RawEvidence,
    params: &VerifyParams<'_>,
) -> Result<Option<VerifiedEvidence>, EvidenceError> {
    let env = envelope::decode(&evidence.envelope).map_err(EvidenceError::Malformed)?;

    if env.candidate != *params.subject_pubkey {
        return Err(EvidenceError::Invalid(
            "envelope candidate does not match the authenticated account".to_string(),
        ));
    }

    let expiry = i64::try_from(env.expiry)
        .map_err(|_| EvidenceError::Invalid("envelope expiry out of range".to_string()))?;
    if expiry < params.now_unix {
        return Err(EvidenceError::Invalid("envelope expired".to_string()));
    }
    if expiry > params.now_unix + MAX_EXPIRY_WINDOW_SECS {
        return Err(EvidenceError::Invalid(
            "envelope expiry too far in the future".to_string(),
        ));
    }

    let (Some(playstore_digest), Some(website_digest)) = (
        params.config.android_signing_digest_playstore.as_ref(),
        params.config.android_signing_digest_website.as_ref(),
    ) else {
        return Err(EvidenceError::Invalid(
            "android signing digests are not configured".to_string(),
        ));
    };
    let chain_params = key_attest::verify::VerifyParams {
        // The leaf's attestationChallenge must equal envelope key 2 — the
        // key and the envelope were created for the same session.
        challenge: &env.challenge,
        package_names: &params.config.android_package_names,
        playstore_digest,
        website_digest,
        trusted_roots_der: &key_attest::verify::google_roots_der(),
        trusted_verified_boot_keys: key_attest::verify::GRAPHENEOS_VERIFIED_BOOT_KEYS,
        revoked_serials: params.revoked_serials,
        now_unix: params.now_unix,
    };
    let verified_chain = key_attest::verify::verify_chain(&evidence.chain_der, &chain_params)
        .map_err(|e| EvidenceError::Invalid(e.to_string()))?;

    // The signature covers the exact envelope bytes as transmitted, verified
    // against the attested leaf key (SHA256withECDSA, ASN.1/DER).
    let leaf_key = p256::ecdsa::VerifyingKey::from_public_key_der(&verified_chain.leaf_spki_der)
        .map_err(|_| EvidenceError::Invalid("attested leaf key is not EC P-256".to_string()))?;
    let signature = p256::ecdsa::Signature::from_der(&evidence.signature_der).map_err(|_| {
        EvidenceError::Malformed("envelopeSignature is not a DER ECDSA signature".to_string())
    })?;
    leaf_key
        .verify(&evidence.envelope, &signature)
        .map_err(|_| EvidenceError::Invalid("envelope signature does not verify".to_string()))?;

    let namespace = match env.level {
        1 => NAMESPACE_L1,
        3 => {
            if !verified_chain.grapheneos_verified_boot {
                return Err(EvidenceError::Invalid(
                    "level 3 requires an official GrapheneOS verified boot".to_string(),
                ));
            }
            if !params.widevine.l3_grapheneos_enabled {
                return Ok(None);
            }
            NAMESPACE_L3
        }
        // The decoder only admits 1 or 3.
        other => {
            return Err(EvidenceError::Malformed(format!(
                "level {other} is not 1 or 3"
            )))
        }
    };

    let hmacs = params
        .widevine
        .hmac_keys
        .iter()
        .map(|k| DeviceHmac {
            epoch: k.epoch.clone(),
            hmac: device_hmac(k.key.expose_secret(), namespace, &env.widevine_id),
        })
        .collect();

    Ok(Some(VerifiedEvidence {
        namespace,
        level: env.level,
        challenge: env.challenge,
        hmacs,
    }))
}

/// `HMAC-SHA256(key, "poud:v1" ‖ namespace ‖ widevineId)`.
fn device_hmac(key: &[u8; 32], namespace: &str, widevine_id: &[u8]) -> [u8; 32] {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC takes any length");
    mac.update(HMAC_CONTEXT);
    mac.update(namespace.as_bytes());
    mac.update(widevine_id);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn full_body() -> Value {
        json!({
            "attestationChain": ["AQID", "BAUG"],
            "deviceEnvelope": "oQA=",
            "envelopeSignature": "AQID"
        })
    }

    #[test]
    fn extract_requires_all_three_fields_or_none() {
        assert!(extract(&json!({})).expect("no evidence").is_none());

        let raw = extract(&full_body()).expect("valid").expect("present");
        assert_eq!(raw.chain_der, vec![vec![1, 2, 3], vec![4, 5, 6]]);
        assert_eq!(raw.envelope, vec![0xA1, 0x00]);
        assert_eq!(raw.signature_der, vec![1, 2, 3]);

        // Every partial combination is malformed.
        for missing in ["attestationChain", "deviceEnvelope", "envelopeSignature"] {
            let mut body = full_body();
            body.as_object_mut().unwrap().remove(missing);
            assert!(
                matches!(extract(&body), Err(EvidenceError::Malformed(_))),
                "missing {missing}"
            );
        }
    }

    #[test]
    fn extract_enforces_the_wire_bounds() {
        use base64::Engine as _;

        // Chain too short.
        let mut body = full_body();
        body["attestationChain"] = json!(["AQID"]);
        assert!(matches!(extract(&body), Err(EvidenceError::Malformed(_))));

        // Chain entry not a string.
        let mut body = full_body();
        body["attestationChain"] = json!(["AQID", 7]);
        assert!(matches!(extract(&body), Err(EvidenceError::Malformed(_))));

        // Envelope over the 512-byte cap.
        let mut body = full_body();
        body["deviceEnvelope"] = json!(
            base64::engine::general_purpose::STANDARD.encode(vec![0u8; MAX_ENVELOPE_BYTES + 1])
        );
        assert!(matches!(extract(&body), Err(EvidenceError::Malformed(_))));

        // Bad base64 signature.
        let mut body = full_body();
        body["envelopeSignature"] = json!("!!!");
        assert!(matches!(extract(&body), Err(EvidenceError::Malformed(_))));
    }

    #[test]
    fn device_hmac_separates_namespaces_and_keys() {
        let id = [9u8; 32];
        let l1 = device_hmac(&[1u8; 32], NAMESPACE_L1, &id);
        let l3 = device_hmac(&[1u8; 32], NAMESPACE_L3, &id);
        let other_key = device_hmac(&[2u8; 32], NAMESPACE_L1, &id);
        // The same physical id never matches across namespaces or epochs.
        assert_ne!(l1, l3);
        assert_ne!(l1, other_key);
        // Deterministic for the same inputs.
        assert_eq!(l1, device_hmac(&[1u8; 32], NAMESPACE_L1, &id));
    }
}
