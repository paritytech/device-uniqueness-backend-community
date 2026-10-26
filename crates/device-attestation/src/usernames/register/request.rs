// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::str::FromStr as _;

use http_common::error::{expected, must_match, received_name, type_name};
use serde::{Deserialize, Deserializer};
use serde_json::{Number, Value};
use utoipa::ToSchema;

use crate::config::Config;
use crate::usernames::{
    error::{FieldError, UsernamesError},
    MAX_BASE_LEN,
};

const MSG_DIGITS: &str = "Digits must be between 01-99";
const MSG_INVALID_SS58: &str = "Invalid ss58 address.";
const MSG_INVALID_SIGNATURE: &str = "Invalid signature.";
const MAX_DOTNS_LABEL_LEN: usize = 32;
const PATTERN_BASE: &str = "^([a-z]{6,})$";
const PATTERN_HEX_STRING: &str = "^(0x)?[a-fA-F0-9]+$";

/// The flat registration request.
#[derive(Default, Deserialize, ToSchema)]
#[schema(
    description = "The flat registration request. Every field is read as received and\n\
                   checked afterwards, so a `400` can report all failing fields at once."
)]
pub struct RegisterRequest {
    /// SS58 beneficiary account that will own the username.
    #[serde(default, rename = "candidateAccountId")]
    #[schema(
        rename = "candidateAccountId",
        value_type = String,
        required,
        example = "5FbRAkhDvNVecNzHLFxBNXFXNwvBaV69S1W3nfBbnxYypkkT"
    )]
    candidate_account_id: Field,
    /// Base username (lowercase ASCII letters, 6..=29 chars).
    #[serde(default)]
    #[schema(value_type = String, required, example = "tallesx")]
    username: Field,
    /// Optional two-digit suffix, e.g. `"07"`; random-free if omitted.
    #[serde(default, rename = "preferredDigits")]
    #[schema(rename = "preferredDigits", value_type = Option<String>, example = "07")]
    preferred_digits: Field,
    /// `0x`-hex 64-byte sr25519 signature proving control of the candidate.
    #[serde(default, rename = "candidateSignature")]
    #[schema(
        rename = "candidateSignature",
        value_type = String,
        required,
        example = "0x...64 bytes..."
    )]
    candidate_signature: Field,
    /// `0x`-hex ring VRF key.
    #[serde(default, rename = "ringVrfKey")]
    #[schema(rename = "ringVrfKey", value_type = String, required, example = "0x...")]
    ring_vrf_key: Field,
    /// `0x`-hex 64-byte ownership proof.
    #[serde(default, rename = "proofOfOwnership")]
    #[schema(
        rename = "proofOfOwnership",
        value_type = String,
        required,
        example = "0x...64 bytes..."
    )]
    proof_of_ownership: Field,
    /// `0x`-hex 64-byte consumer registration signature.
    #[serde(default, rename = "consumerRegistrationSignature")]
    #[schema(
        rename = "consumerRegistrationSignature",
        value_type = String,
        required,
        example = "0x...64 bytes..."
    )]
    consumer_registration_signature: Field,
    /// `0x`-hex 65-byte identifier key.
    #[serde(default, rename = "identifierKey")]
    #[schema(
        rename = "identifierKey",
        value_type = String,
        required,
        example = "0x...65 bytes..."
    )]
    identifier_key: Field,
    /// The format of the payloads this claim's signatures cover.
    /// An unsupported version is a 400 before anything is stored. Omitted
    /// means `1`, the only format today.
    #[serde(default, rename = "payloadVersion")]
    #[schema(
        rename = "payloadVersion",
        value_type = Option<u16>,
        example = 1,
        minimum = 1,
        default = 1
    )]
    payload_version: Field,
    /// Optional single-use registration voucher (the INSTANT lane): bypasses
    /// the PoUD gate and the registration queue. Ignored unless
    /// `REGISTRATION_VOUCHERS_ENABLED`.
    #[serde(default, rename = "lifetimePoUDVoucher")]
    #[schema(
        rename = "lifetimePoUDVoucher",
        value_type = Option<String>,
        example = "base64url-voucher-key"
    )]
    lifetime_poud_voucher: Field,
    /// Optional Android device-uniqueness evidence (Widevine PoUD): leaf-first
    /// base64 DER attestation chain, 2-10 entries, whose leaf key was created
    /// with `attestationChallenge = SHA-256(domain ‖ deviceChallenge ‖
    /// accountKey ‖ deviceId)`. All three evidence fields are present
    /// together or not at all; ignored unless `WIDEVINE_DEDUP_ENABLED`.
    /// Sent only when the app measured Widevine L1.
    #[serde(default, rename = "attestationChain")]
    #[schema(
        rename = "attestationChain",
        value_type = Option<Vec<String>>,
        example = json!(["base64-der-leaf", "base64-der-root"])
    )]
    #[allow(dead_code)] // `widevine::extract` reads the evidence fields.
    attestation_chain: Field,
    /// Base64 32-byte single-use challenge from `/auth/challenges`, bound
    /// into the leaf key's attestation challenge.
    #[serde(default, rename = "deviceChallenge")]
    #[schema(
        rename = "deviceChallenge",
        value_type = Option<String>,
        example = "base64-32-byte-challenge"
    )]
    #[allow(dead_code)]
    device_challenge: Field,
    /// Base64 32-byte device pseudonym:
    /// `SHA-256("dub/poud/widevine-id/v1" ‖ rawWidevineId)`, computed on the
    /// device — the raw id never leaves it.
    #[serde(default, rename = "deviceId")]
    #[schema(
        rename = "deviceId",
        value_type = Option<String>,
        example = "base64-32-byte-device-id"
    )]
    #[allow(dead_code)]
    device_id: Field,
    /// Optional DotNS reservation block.
    #[serde(default)]
    #[schema(value_type = Option<Dotns>)]
    dotns: Field,
}

/// Optional DotNS reservation, parking a base label for later personhood use.
#[derive(Default, Deserialize, ToSchema)]
pub(crate) struct Dotns {
    /// `0x`-hex 64-byte signature.
    #[serde(default)]
    #[schema(value_type = String, required, example = "0x...64 bytes...")]
    signature: Field,
    /// Unix timestamp the reservation was signed at.
    #[serde(default, rename = "signedAt")]
    #[schema(rename = "signedAt", value_type = i64, required, example = 1780000000i64)]
    signed_at: Field,
    /// The bare personhood name to reserve. Its own name on chain — it need
    /// not be `username`, and availability is checked against *this* name, not
    /// against the base of the lite username in the same claim.
    #[serde(default, rename = "reservedUsername")]
    #[schema(
        rename = "reservedUsername",
        value_type = Option<String>,
        example = "reservedname"
    )]
    reserved_username: Field,
}

/// One body field exactly as received.
#[derive(Default)]
struct Field(Option<Value>);

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Value::deserialize(deserializer).map(|value| Self(Some(value)))
    }
}

impl Field {
    /// A required string: absent or anything else is a type error.
    fn string(&self, field: &str, report: &mut Report) -> Option<&str> {
        match &self.0 {
            Some(Value::String(s)) => Some(s),
            other => {
                report.abort(field, expected("string", received_name(other.as_ref())));
                None
            }
        }
    }

    /// An optional string: absent is `None`, anything else a type error.
    fn optional_string(&self, field: &str, report: &mut Report) -> Option<&str> {
        match &self.0 {
            None => None,
            Some(Value::String(s)) => Some(s),
            Some(other) => {
                report.abort(field, expected("string", type_name(other)));
                None
            }
        }
    }

    fn hex<const N: usize>(&self, field: &str, report: &mut Report) -> Option<Hex<N>> {
        let value = self.string(field, report)?;
        report.flagged(field, Hex::try_from(value))
    }
}

struct Report {
    errors: Vec<FieldError>,
    refine: bool,
}

impl Report {
    /// Record a failure that lets the refinement run.
    fn flag(&mut self, field: &str, message: impl Into<String>) {
        self.errors.push(FieldError {
            message: message.into(),
            field: field.to_string(),
        });
    }

    /// Record a failure that cancels the refinement.
    fn abort(&mut self, field: &str, message: impl Into<String>) {
        self.flag(field, message);
        self.refine = false;
    }

    /// The checked value, or `None` with its failure [flagged](Self::flag).
    fn flagged<T>(&mut self, field: &str, checked: Result<T, String>) -> Option<T> {
        checked.map_err(|message| self.flag(field, message)).ok()
    }

    /// The checked value, or `None` with its failure [aborted](Self::abort).
    fn aborted<T>(&mut self, field: &str, checked: Result<T, String>) -> Option<T> {
        checked.map_err(|message| self.abort(field, message)).ok()
    }
}

struct Hex<const N: usize>([u8; N]);

impl<const N: usize> TryFrom<&str> for Hex<N> {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, String> {
        let mut bytes = [0u8; N];
        value
            .strip_prefix("0x")
            .filter(|digits| digits.len() == 2 * N)
            .and_then(|digits| hex::decode_to_slice(digits, &mut bytes).ok())
            .map(|()| Self(bytes))
            .ok_or_else(|| format!("Must be a hexadecimal string of exactly {N} bytes."))
    }
}

impl<const N: usize> From<Hex<N>> for Vec<u8> {
    fn from(hex: Hex<N>) -> Self {
        hex.0.to_vec()
    }
}

struct RingVrfKey(Vec<u8>);

impl TryFrom<&str> for RingVrfKey {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, String> {
        let digits = value.strip_prefix("0x").unwrap_or(value);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(must_match(PATTERN_HEX_STRING));
        }
        // An odd digit count matches the pattern but is not whole bytes. It
        // decodes to an empty key, as it always has, and the candidate
        // signature is then checked against that empty key.
        Ok(Self(hex::decode(digits).unwrap_or_default()))
    }
}

struct BaseName(String);

impl TryFrom<&str> for BaseName {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, String> {
        if value.len() >= 6 && value.bytes().all(|b| b.is_ascii_lowercase()) {
            Ok(Self(value.to_string()))
        } else {
            Err(must_match(PATTERN_BASE))
        }
    }
}

struct PreferredDigits(u8);

impl TryFrom<&str> for PreferredDigits {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, String> {
        match value.as_bytes() {
            [tens @ b'0'..=b'9', ones @ b'0'..=b'9'] if [*tens, *ones] != *b"00" => {
                Ok(Self((tens - b'0') * 10 + (ones - b'0')))
            }
            _ => Err(MSG_DIGITS.to_string()),
        }
    }
}

struct SignedAt(i64);

impl TryFrom<&Number> for SignedAt {
    type Error = String;

    fn try_from(value: &Number) -> Result<Self, String> {
        match value.as_f64() {
            Some(f) if f.fract() == 0.0 && f >= 0.0 => Ok(Self(f as i64)),
            Some(f) if f.fract() != 0.0 => Err(expected("integer", "number")),
            _ => Err("must be greater than or equal to 0".to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PayloadVersion {
    V1,
}

impl PayloadVersion {
    const SUPPORTED: [Self; 1] = [Self::V1];

    fn unsupported() -> String {
        let supported = Self::SUPPORTED.map(|v| u16::from(v).to_string()).join(", ");
        format!("Unsupported payload version. Supported: {supported}.")
    }
}

impl From<PayloadVersion> for u16 {
    fn from(version: PayloadVersion) -> Self {
        match version {
            PayloadVersion::V1 => 1,
        }
    }
}

impl TryFrom<u64> for PayloadVersion {
    type Error = String;

    fn try_from(version: u64) -> Result<Self, String> {
        Self::SUPPORTED
            .into_iter()
            .find(|v| u64::from(u16::from(*v)) == version)
            .ok_or_else(Self::unsupported)
    }
}

/// The fully-validated registration request, decoded.
pub(super) struct ParsedRegister {
    pub(super) candidate_account_id: String,
    pub(super) username: String,
    pub(super) preferred_digits: Option<u8>,
    pub(super) candidate_signature: Vec<u8>,
    pub(super) ring_vrf_key: Vec<u8>,
    pub(super) proof_of_ownership: Vec<u8>,
    pub(super) consumer_registration_signature: Vec<u8>,
    pub(super) identifier_key: Vec<u8>,
    pub(super) payload_version: PayloadVersion,
    pub(super) voucher: Option<String>,
    pub(super) dotns: Option<ParsedDotns>,
}

pub(super) struct ParsedDotns {
    pub(super) signature: Vec<u8>,
    pub(super) signed_at: i64,
    pub(super) reserved_username: Option<String>,
}

pub(super) fn reserved_name(parsed: &ParsedRegister) -> Option<&str> {
    parsed.dotns.as_ref()?.reserved_username.as_deref()
}

impl RegisterRequest {
    fn from_body(body: &Value) -> Self {
        match body {
            Value::Object(_) => Self::deserialize(body).unwrap_or_default(),
            _ => Self::default(),
        }
    }
}

struct CheckedDotns {
    signature: Option<Hex<64>>,
    signed_at: Option<SignedAt>,
    reserved_username: Option<BaseName>,
}

impl Dotns {
    fn check(&self, report: &mut Report) -> CheckedDotns {
        let signature = self.signature.hex("dotns.signature", report);
        let signed_at = match &self.signed_at.0 {
            Some(Value::Number(n)) => report.aborted("dotns.signedAt", SignedAt::try_from(n)),
            other => {
                report.abort(
                    "dotns.signedAt",
                    expected("number", received_name(other.as_ref())),
                );
                None
            }
        };
        let reserved_username = self
            .reserved_username
            .optional_string("dotns.reservedUsername", report)
            .and_then(|name| report.aborted("dotns.reservedUsername", BaseName::try_from(name)));
        CheckedDotns {
            signature,
            signed_at,
            reserved_username,
        }
    }
}

impl CheckedDotns {
    fn complete(self) -> Option<ParsedDotns> {
        Some(ParsedDotns {
            signature: self.signature?.into(),
            signed_at: self.signed_at?.0,
            reserved_username: self.reserved_username.map(|name| name.0),
        })
    }
}

/// Validate a request body.
pub(super) fn validate_register(
    body: &Value,
    config: &Config,
) -> Result<ParsedRegister, UsernamesError> {
    let request = RegisterRequest::from_body(body);
    let mut report = Report {
        errors: Vec::new(),
        refine: true,
    };
    let r = &mut report;

    // --- field checks, in field order ------------------------------------
    let candidate_account_id = request.candidate_account_id.string("candidateAccountId", r);
    let username = request
        .username
        .string("username", r)
        .and_then(|name| r.aborted("username", BaseName::try_from(name)));
    // Nothing later reads the suffix, so a malformed one lets the
    // refinement run.
    let preferred_digits = request
        .preferred_digits
        .optional_string("preferredDigits", r)
        .and_then(|digits| r.flagged("preferredDigits", PreferredDigits::try_from(digits)));
    let candidate_signature = request
        .candidate_signature
        .hex::<64>("candidateSignature", r);
    let ring_vrf_key = request
        .ring_vrf_key
        .string("ringVrfKey", r)
        .and_then(|key| r.aborted("ringVrfKey", RingVrfKey::try_from(key)));
    let proof_of_ownership = request.proof_of_ownership.hex::<64>("proofOfOwnership", r);
    let consumer_registration_signature = request
        .consumer_registration_signature
        .hex::<64>("consumerRegistrationSignature", r);
    let identifier_key = request.identifier_key.hex::<65>("identifierKey", r);

    let payload_version = match &request.payload_version.0 {
        None => Some(PayloadVersion::V1),
        Some(Value::Number(n)) if n.is_u64() || n.is_i64() => {
            let version = n.as_u64().map_or_else(
                || Err(PayloadVersion::unsupported()),
                PayloadVersion::try_from,
            );
            r.flagged("payloadVersion", version)
        }
        Some(other) => {
            r.flag("payloadVersion", expected("integer", type_name(other)));
            None
        }
    };

    let dotns = match &request.dotns.0 {
        None => None,
        Some(block @ Value::Object(_)) => {
            Some(Dotns::deserialize(block).unwrap_or_default().check(r))
        }
        Some(other) => {
            r.abort("dotns", expected("object", type_name(other)));
            None
        }
    };

    let voucher = if config.registration_vouchers_enabled {
        request
            .lifetime_poud_voucher
            .optional_string("lifetimePoUDVoucher", r)
            .filter(|voucher| !voucher.is_empty())
            .map(str::to_string)
    } else {
        None
    };

    // --- refinement ------------------------------------------------------
    if r.refine {
        match candidate_account_id.map(subxt::utils::AccountId32::from_str) {
            Some(Ok(candidate)) => {
                if let (Some(signature), Some(ring), Some(version)) =
                    (&candidate_signature, &ring_vrf_key, payload_version)
                {
                    if !verify_candidate_signature(version, &candidate.0, &signature.0, &ring.0) {
                        r.flag("candidateSignature", MSG_INVALID_SIGNATURE);
                    }
                }
            }
            _ => r.flag("candidateAccountId", MSG_INVALID_SS58),
        }

        if let Some(BaseName(name)) = &username {
            if name.len() > MAX_BASE_LEN {
                r.flag(
                    "username",
                    format!("Username sum exceeds the maximum length: ({MAX_BASE_LEN})."),
                );
            }
        }

        if let Some(dotns) = &dotns {
            if let Some(SignedAt(signed_at)) = dotns.signed_at {
                let now = time::OffsetDateTime::now_utc().unix_timestamp();
                let skew = config.dotns_max_future_skew_secs as i64;
                let max_age = config.dotns_intake_freshness_max_age_secs as i64;
                if signed_at > now + skew {
                    r.flag(
                        "dotns.signedAt",
                        format!("signedAt is in the future (tolerance {skew}s)."),
                    );
                }
                if now - signed_at > max_age {
                    r.flag(
                        "dotns.signedAt",
                        format!(
                            "signedAt is older than the intake freshness bound ({max_age}s). \
                             Re-sign with a fresh timestamp and resubmit."
                        ),
                    );
                }
            }

            if let Some(BaseName(reserved)) = &dotns.reserved_username {
                if reserved.len() > MAX_DOTNS_LABEL_LEN {
                    r.flag(
                        "dotns.reservedUsername",
                        format!(
                            "reservedUsername exceeds the maximum label length: \
                             ({MAX_DOTNS_LABEL_LEN})."
                        ),
                    );
                }
            }
        }
    }

    let dotns = match dotns {
        None => Some(None),
        Some(dotns) => dotns.complete().map(Some),
    };
    match (
        candidate_account_id,
        username,
        candidate_signature,
        ring_vrf_key,
        proof_of_ownership,
        consumer_registration_signature,
        identifier_key,
        payload_version,
        dotns,
    ) {
        (
            Some(candidate_account_id),
            Some(BaseName(username)),
            Some(candidate_signature),
            Some(RingVrfKey(ring_vrf_key)),
            Some(proof_of_ownership),
            Some(consumer_registration_signature),
            Some(identifier_key),
            Some(payload_version),
            Some(dotns),
        ) if report.errors.is_empty() => Ok(ParsedRegister {
            candidate_account_id: candidate_account_id.to_string(),
            username,
            preferred_digits: preferred_digits.map(|PreferredDigits(digits)| digits),
            candidate_signature: candidate_signature.into(),
            ring_vrf_key,
            proof_of_ownership: proof_of_ownership.into(),
            consumer_registration_signature: consumer_registration_signature.into(),
            identifier_key: identifier_key.into(),
            payload_version,
            voucher,
            dotns,
        }),
        _ => Err(UsernamesError::InvalidBody(report.errors)),
    }
}

/// The message prefix the People Chain reconstructs for `PeopleLite.attest`;
/// `candidateSignature` (and `proofOfOwnership`) cover
/// `POP_REGISTER_PREFIX || candidatePubkey || ringVrfKey`.
const POP_REGISTER_PREFIX: &[u8] = b"pop:people-lite:register using";

/// Verifies the caller controls `candidate_pubkey`.
fn verify_candidate_signature(
    version: PayloadVersion,
    candidate_pubkey: &[u8; 32],
    candidate_signature: &[u8],
    ring_vrf_key: &[u8],
) -> bool {
    let Ok(signature) = <[u8; 64]>::try_from(candidate_signature) else {
        return false;
    };
    let message = match version {
        PayloadVersion::V1 => [
            POP_REGISTER_PREFIX,
            candidate_pubkey.as_slice(),
            ring_vrf_key,
        ]
        .concat(),
    };
    subxt_signer::sr25519::verify(
        &subxt_signer::sr25519::Signature(signature),
        message,
        &subxt_signer::sr25519::PublicKey(*candidate_pubkey),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> crate::config::Config {
        crate::config::Config::test_default()
    }

    fn valid_body() -> serde_json::Value {
        use std::str::FromStr as _;
        use subxt_signer::sr25519::Keypair;
        use subxt_signer::SecretUri;

        let keypair = Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap();
        let candidate = keypair.public_key();
        let ring = [7u8; 32];
        let mut message = Vec::new();
        message.extend_from_slice(POP_REGISTER_PREFIX);
        message.extend_from_slice(&candidate.0);
        message.extend_from_slice(&ring);
        let signature = keypair.sign(&message).0;

        json!({
            "candidateAccountId": candidate.to_account_id().to_string(),
            "username": "aliceuser",
            "candidateSignature": format!("0x{}", hex::encode(signature)),
            "ringVrfKey": format!("0x{}", hex::encode(ring)),
            "proofOfOwnership": format!("0x{}", "03".repeat(64)),
            "consumerRegistrationSignature": format!("0x{}", "04".repeat(64)),
            "identifierKey": format!("0x{}", "05".repeat(65))
        })
    }

    fn errors_of(value: serde_json::Value) -> Vec<(String, String)> {
        match validate_register(&value, &config()) {
            Err(UsernamesError::InvalidBody(errors)) => {
                errors.into_iter().map(|e| (e.field, e.message)).collect()
            }
            other => panic!("expected InvalidBody, got {other:?}", other = other.err()),
        }
    }

    #[test]
    fn accepts_a_genuinely_signed_request() {
        let parsed = validate_register(&valid_body(), &config()).expect("valid");
        assert_eq!(parsed.username, "aliceuser");
        assert_eq!(parsed.candidate_signature.len(), 64);
    }

    #[test]
    fn empty_object_reports_every_required_field_in_order() {
        let pointers: Vec<String> = errors_of(json!({}))
            .into_iter()
            .map(|(pointer, _)| pointer)
            .collect();
        assert_eq!(
            pointers,
            [
                "candidateAccountId",
                "username",
                "candidateSignature",
                "ringVrfKey",
                "proofOfOwnership",
                "consumerRegistrationSignature",
                "identifierKey",
            ]
        );
    }

    #[test]
    fn wrong_signature_is_a_400_with_the_captured_message() {
        let mut body = valid_body();
        body["candidateSignature"] = json!(format!("0x{}", "ab".repeat(64)));
        assert_eq!(
            errors_of(body),
            [(
                "candidateSignature".to_string(),
                "Invalid signature.".to_string()
            )]
        );
    }

    #[test]
    fn pattern_failed_signature_is_a_400() {
        for bad in ["nothex", &format!("0x{}", "ab".repeat(63))] {
            let mut body = valid_body();
            body["candidateSignature"] = json!(bad);
            assert_eq!(
                errors_of(body),
                [(
                    "candidateSignature".to_string(),
                    "Must be a hexadecimal string of exactly 64 bytes.".to_string()
                )],
                "{bad}"
            );
        }
    }

    #[test]
    fn abort_fields_suppress_the_refinement() {
        let mut body = valid_body();
        body["ringVrfKey"] = json!("nothex!");
        assert_eq!(
            errors_of(body),
            [(
                "ringVrfKey".to_string(),
                http_common::error::must_match(PATTERN_HEX_STRING)
            )]
        );

        let mut body = valid_body();
        body["username"] = json!("Abcdef");
        assert_eq!(
            errors_of(body),
            [(
                "username".to_string(),
                http_common::error::must_match(PATTERN_BASE)
            )]
        );
    }

    #[test]
    fn type_errors_suppress_the_refinement() {
        let body = json!({
            "candidateAccountId": 5, "username": 6, "candidateSignature": 7,
            "ringVrfKey": 8, "proofOfOwnership": 9,
            "consumerRegistrationSignature": 10, "identifierKey": 11
        });
        let errors = errors_of(body);
        assert_eq!(errors.len(), 7);
        assert!(errors
            .iter()
            .all(|(_, detail)| detail == "expected string, received number"));
    }

    #[test]
    fn refinement_issues_use_the_captured_messages() {
        let mut body = valid_body();
        body["candidateAccountId"] = json!("not-an-address");
        assert_eq!(
            errors_of(body),
            [(
                "candidateAccountId".to_string(),
                "Invalid ss58 address.".to_string()
            )]
        );

        let mut body = valid_body();
        body["username"] = json!("a".repeat(30));
        assert_eq!(
            errors_of(body),
            [(
                "username".to_string(),
                "Username sum exceeds the maximum length: (29).".to_string()
            )]
        );
    }

    #[test]
    fn preferred_digits_and_identifier_checks_collect_in_field_order() {
        let mut body = valid_body();
        body["preferredDigits"] = json!("00");
        body["identifierKey"] = json!(format!("0x{}", "ab".repeat(64)));
        assert_eq!(
            errors_of(body),
            [
                (
                    "preferredDigits".to_string(),
                    "Digits must be between 01-99".to_string()
                ),
                (
                    "identifierKey".to_string(),
                    "Must be a hexadecimal string of exactly 65 bytes.".to_string()
                ),
            ]
        );
    }

    #[test]
    fn dotns_freshness_uses_the_captured_messages() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let enabled = config();
        let mut future = valid_body();
        future["dotns"] =
            json!({ "signature": format!("0x{}", "ab".repeat(64)), "signedAt": now + 700 });
        assert_eq!(
            match validate_register(&future, &enabled) {
                Err(UsernamesError::InvalidBody(errors)) => errors[0].message.clone(),
                other => panic!("{other:?}", other = other.err()),
            },
            "signedAt is in the future (tolerance 600s)."
        );

        let mut stale = valid_body();
        stale["dotns"] =
            json!({ "signature": format!("0x{}", "ab".repeat(64)), "signedAt": now - 700 });
        assert_eq!(
            match validate_register(&stale, &enabled) {
                Err(UsernamesError::InvalidBody(errors)) => errors[0].message.clone(),
                other => panic!("{other:?}", other = other.err()),
            },
            "signedAt is older than the intake freshness bound (600s). \
             Re-sign with a fresh timestamp and resubmit."
        );

        let mut valid = valid_body();
        valid["dotns"] = dotns_block(now, Some("reservedname"), &enabled);
        let parsed = validate_register(&valid, &enabled).expect("valid dotns");
        let dotns = parsed.dotns.expect("dotns parsed");
        assert_eq!(dotns.reserved_username.as_deref(), Some("reservedname"));
    }

    #[test]
    fn only_a_claim_that_asks_for_the_full_name_is_preflighted() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let plain = validate_register(&valid_body(), &config).expect("valid");
        assert_eq!(
            reserved_name(&plain),
            None,
            "no dotns block means no reservation leg"
        );

        let mut without = valid_body();
        without["dotns"] = dotns_block(now, None, &config);
        assert_eq!(
            reserved_name(&validate_register(&without, &config).expect("valid")),
            None
        );

        let mut with = valid_body();
        with["dotns"] = dotns_block(now, Some("aliceuser"), &config);
        assert_eq!(
            reserved_name(&validate_register(&with, &config).expect("valid")),
            Some("aliceuser")
        );
    }

    #[test]
    fn the_reserved_name_is_read_from_the_dotns_block_not_the_username() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut body = valid_body();
        assert_eq!(body["username"], json!("aliceuser"));
        body["dotns"] = dotns_block(now, Some("reservedname"), &config);

        let parsed = validate_register(&body, &config).expect("valid");
        assert_eq!(reserved_name(&parsed), Some("reservedname"));
    }

    fn dotns_block(
        signed_at: i64,
        reserved: Option<&str>,
        config: &crate::config::Config,
    ) -> serde_json::Value {
        use subxt_signer::sr25519::Keypair;
        use subxt_signer::SecretUri;

        let keypair = Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap();
        let message = crate::dotns::reservation_message(
            &keypair.public_key().0,
            &config.attester_account,
            b"aliceuser",
            &[5u8; 65],
            reserved.map(str::as_bytes),
            signed_at as u64,
        );
        let mut block = json!({
            "signature": format!("0x{}", hex::encode(keypair.sign(&message).0)),
            "signedAt": signed_at,
        });
        if let Some(reserved) = reserved {
            block["reservedUsername"] = json!(reserved);
        }
        block
    }

    #[test]
    fn an_unverifiable_dotns_signature_still_yields_a_username() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut junk = valid_body();
        junk["dotns"] = json!({ "signature": format!("0x{}", "ab".repeat(64)), "signedAt": now });
        let parsed = validate_register(&junk, &config).expect("junk dotns signature is accepted");
        assert_eq!(parsed.username, "aliceuser");
        assert!(
            parsed.dotns.is_some(),
            "the block is stored, so the writer decides its fate"
        );

        let mut other_attester = self::config();
        other_attester.attester_account = [0xbb; 32];
        let mut wrong = valid_body();
        wrong["dotns"] = dotns_block(now, None, &other_attester);
        assert!(validate_register(&wrong, &config).is_ok());

        let mut reserved_mismatch = valid_body();
        let mut block = dotns_block(now, Some("reservedname"), &config);
        block.as_object_mut().unwrap().remove("reservedUsername");
        reserved_mismatch["dotns"] = block;
        assert!(validate_register(&reserved_mismatch, &config).is_ok());
    }

    #[test]
    fn a_malformed_dotns_block_is_still_rejected() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut too_long = valid_body();
        too_long["dotns"] = json!({
            "signature": format!("0x{}", "ab".repeat(64)),
            "signedAt": now,
            "reservedUsername": "x".repeat(MAX_DOTNS_LABEL_LEN + 1),
        });
        assert_eq!(
            errors_of(too_long)
                .into_iter()
                .map(|(pointer, _)| pointer)
                .collect::<Vec<_>>(),
            ["dotns.reservedUsername".to_string()]
        );

        let mut stale = valid_body();
        stale["dotns"] = json!({
            "signature": format!("0x{}", "ab".repeat(64)),
            "signedAt": now - 86_400,
        });
        assert_eq!(
            errors_of(stale)
                .into_iter()
                .map(|(pointer, _)| pointer)
                .collect::<Vec<_>>(),
            ["dotns.signedAt".to_string()]
        );
    }

    #[test]
    fn an_oversized_reserved_username_is_rejected_before_the_signature_check() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let oversized = "a".repeat(MAX_DOTNS_LABEL_LEN + 1);

        let mut body = valid_body();
        body["dotns"] = dotns_block(now, Some(&oversized), &config);
        assert_eq!(
            errors_of(body),
            [(
                "dotns.reservedUsername".to_string(),
                format!(
                    "reservedUsername exceeds the maximum label length: ({MAX_DOTNS_LABEL_LEN})."
                )
            )]
        );

        let mut at_bound = valid_body();
        let exact = "a".repeat(MAX_DOTNS_LABEL_LEN);
        at_bound["dotns"] = dotns_block(now, Some(&exact), &config);
        assert!(validate_register(&at_bound, &config).is_ok());
    }

    #[test]
    fn voucher_field_is_ignored_when_the_feature_is_off() {
        let mut body = valid_body();
        body["lifetimePoUDVoucher"] = json!("some-voucher-key");
        let parsed = validate_register(&body, &config()).expect("valid");
        assert_eq!(parsed.voucher, None);

        let mut body = valid_body();
        body["lifetimePoUDVoucher"] = json!(42);
        assert!(validate_register(&body, &config()).is_ok());
    }

    #[test]
    fn voucher_field_is_recognised_when_the_feature_is_on() {
        let mut on = config();
        on.registration_vouchers_enabled = true;

        let mut body = valid_body();
        body["lifetimePoUDVoucher"] = json!("some-voucher-key");
        let parsed = validate_register(&body, &on).expect("valid");
        assert_eq!(parsed.voucher.as_deref(), Some("some-voucher-key"));

        assert_eq!(validate_register(&valid_body(), &on).unwrap().voucher, None);
        let mut empty = valid_body();
        empty["lifetimePoUDVoucher"] = json!("");
        assert_eq!(validate_register(&empty, &on).unwrap().voucher, None);

        let mut bad = valid_body();
        bad["lifetimePoUDVoucher"] = json!(42);
        match validate_register(&bad, &on) {
            Err(UsernamesError::InvalidBody(errors)) => {
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].field, "lifetimePoUDVoucher");
                assert_eq!(errors[0].message, "expected string, received number");
            }
            other => panic!("expected InvalidBody, got {other:?}", other = other.err()),
        }
    }

    #[test]
    fn an_undeclared_payload_version_is_format_one() {
        let parsed = validate_register(&valid_body(), &config()).expect("valid");
        assert_eq!(parsed.payload_version, PayloadVersion::V1);

        let mut declared = valid_body();
        declared["payloadVersion"] = json!(1);
        let parsed = validate_register(&declared, &config()).expect("valid");
        assert_eq!(parsed.payload_version, PayloadVersion::V1);
    }

    #[test]
    fn an_unsupported_payload_version_is_a_400_not_an_invalid_signature() {
        for version in [json!(0), json!(2), json!(-1), json!(65_536)] {
            let mut body = valid_body();
            body["payloadVersion"] = version;
            assert_eq!(
                errors_of(body),
                [(
                    "payloadVersion".to_string(),
                    "Unsupported payload version. Supported: 1.".to_string()
                )]
            );
        }
    }

    #[test]
    fn a_non_integer_payload_version_is_a_type_error() {
        for (version, received) in [
            (json!("1"), "string"),
            (json!(1.5), "number"),
            (json!(null), "null"),
        ] {
            let mut body = valid_body();
            body["payloadVersion"] = version;
            assert_eq!(
                errors_of(body),
                [(
                    "payloadVersion".to_string(),
                    http_common::error::expected("integer", received)
                )]
            );
        }
    }

    #[test]
    fn candidate_signature_verifies_control_of_beneficiary() {
        use std::str::FromStr as _;
        use subxt_signer::sr25519::Keypair;
        use subxt_signer::SecretUri;

        let keypair = Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap();
        let candidate = keypair.public_key().0;
        let ring_vrf_key = [7u8; 32];

        let mut message = Vec::new();
        message.extend_from_slice(POP_REGISTER_PREFIX);
        message.extend_from_slice(&candidate);
        message.extend_from_slice(&ring_vrf_key);
        let signature = keypair.sign(&message).0;

        assert!(verify_candidate_signature(
            PayloadVersion::V1,
            &candidate,
            &signature,
            &ring_vrf_key
        ));
        assert!(!verify_candidate_signature(
            PayloadVersion::V1,
            &candidate,
            &signature,
            &[9u8; 32]
        ));
        let other = Keypair::from_uri(&SecretUri::from_str("//Bob").unwrap())
            .unwrap()
            .public_key()
            .0;
        assert!(!verify_candidate_signature(
            PayloadVersion::V1,
            &other,
            &signature,
            &ring_vrf_key
        ));
        assert!(!verify_candidate_signature(
            PayloadVersion::V1,
            &candidate,
            &[0u8; 10],
            &ring_vrf_key
        ));
    }
}
