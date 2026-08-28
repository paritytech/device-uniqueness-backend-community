// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use super::token::TokenPayload;
use super::{PlayIntegrityError, PlayIntegrityMode, PolicyParams};

pub const APP_INTEGRITY_FAILED: &str = "APP_INTEGRITY_FAILED";
pub const DEVICE_INTEGRITY_FAILED: &str = "DEVICE_INTEGRITY_FAILED";
pub const LICENSE_CHECK_FAILED: &str = "LICENSE_CHECK_FAILED";
pub const APK_FINGERPRINT_MISMATCH: &str = "APK_FINGERPRINT_MISMATCH";
pub const PACKAGE_NAME_MISMATCH: &str = "PACKAGE_NAME_MISMATCH";

struct ModePolicy {
    accept_app_recognition: &'static [&'static str],
    accept_device_recognition: &'static [&'static str],
    accept_empty_device_recognition: bool,
    accept_app_licensing: &'static [&'static str],
    accept_missing_app_integrity: bool,
}

const STRICT: ModePolicy = ModePolicy {
    accept_app_recognition: &["PLAY_RECOGNIZED"],
    accept_device_recognition: &["MEETS_STRONG_INTEGRITY", "MEETS_DEVICE_INTEGRITY"],
    accept_empty_device_recognition: false,
    accept_app_licensing: &["LICENSED"],
    accept_missing_app_integrity: false,
};

const RELAXED_DEVICE: ModePolicy = ModePolicy {
    accept_app_recognition: &["PLAY_RECOGNIZED"],
    accept_device_recognition: &[
        "MEETS_DEVICE_INTEGRITY",
        "MEETS_BASIC_INTEGRITY",
        "MEETS_STRONG_INTEGRITY",
    ],
    accept_empty_device_recognition: false,
    accept_app_licensing: &["LICENSED"],
    accept_missing_app_integrity: false,
};

const RELAXED_ALL: ModePolicy = ModePolicy {
    accept_app_recognition: &["PLAY_RECOGNIZED", "UNRECOGNIZED_VERSION", "UNEVALUATED"],
    accept_device_recognition: &[
        "MEETS_DEVICE_INTEGRITY",
        "MEETS_BASIC_INTEGRITY",
        "MEETS_STRONG_INTEGRITY",
        "MEETS_VIRTUAL_INTEGRITY",
    ],
    accept_empty_device_recognition: true,
    accept_app_licensing: &["LICENSED", "UNLICENSED", "UNEVALUATED"],
    accept_missing_app_integrity: true,
};

const KNOWN_APP_RECOGNITION: &[&str] = &["PLAY_RECOGNIZED", "UNRECOGNIZED_VERSION", "UNEVALUATED"];
const KNOWN_DEVICE_RECOGNITION: &[&str] = &[
    "MEETS_DEVICE_INTEGRITY",
    "MEETS_BASIC_INTEGRITY",
    "MEETS_STRONG_INTEGRITY",
    "MEETS_VIRTUAL_INTEGRITY",
];
const KNOWN_APP_LICENSING: &[&str] = &["LICENSED", "UNLICENSED", "UNEVALUATED"];

fn policy(mode: PlayIntegrityMode) -> &'static ModePolicy {
    match mode {
        PlayIntegrityMode::Strict => &STRICT,
        PlayIntegrityMode::RelaxedDevice => &RELAXED_DEVICE,
        PlayIntegrityMode::RelaxedAll => &RELAXED_ALL,
    }
}

fn known<'a>(value: Option<&'a str>, known_values: &[&str]) -> Option<&'a str> {
    value.filter(|v| known_values.contains(v))
}

pub fn validate(
    payload: &TokenPayload,
    params: &PolicyParams<'_>,
) -> Result<bool, PlayIntegrityError> {
    let policy = policy(params.mode);
    let mut codes: Vec<&'static str> = Vec::new();

    let app_recognition = known(
        payload
            .app_integrity
            .as_ref()
            .and_then(|a| a.app_recognition_verdict.as_deref()),
        KNOWN_APP_RECOGNITION,
    );
    match app_recognition {
        Some(verdict) if policy.accept_app_recognition.contains(&verdict) => {}
        _ => codes.push(APP_INTEGRITY_FAILED),
    }

    let device_verdicts: Vec<&str> = payload
        .device_integrity
        .as_ref()
        .and_then(|d| d.device_recognition_verdict.as_ref())
        .map(|list| {
            list.iter()
                .map(String::as_str)
                .filter(|v| KNOWN_DEVICE_RECOGNITION.contains(v))
                .collect()
        })
        .unwrap_or_default();
    let device_ok = if device_verdicts.is_empty() {
        policy.accept_empty_device_recognition
    } else {
        device_verdicts
            .iter()
            .any(|v| policy.accept_device_recognition.contains(v))
    };
    if !device_ok {
        codes.push(DEVICE_INTEGRITY_FAILED);
    }

    let licensing = known(
        payload
            .account_details
            .as_ref()
            .and_then(|a| a.app_licensing_verdict.as_deref()),
        KNOWN_APP_LICENSING,
    );
    match licensing {
        Some(verdict) if policy.accept_app_licensing.contains(&verdict) => {}
        _ => codes.push(LICENSE_CHECK_FAILED),
    }

    let token_digests: Vec<Vec<u8>> = payload
        .app_integrity
        .as_ref()
        .and_then(|a| a.certificate_sha256_digest.as_ref())
        .map(|list| {
            list.iter()
                .filter_map(|d| super::token::b64url(d).ok())
                .collect()
        })
        .unwrap_or_default();
    let matches_expected = |digest: &[u8]| {
        digest == params.playstore_digest.as_slice() || digest == params.website_digest.as_slice()
    };
    if token_digests.is_empty() {
        if !policy.accept_missing_app_integrity {
            codes.push(APK_FINGERPRINT_MISMATCH);
        }
    } else if !token_digests.iter().any(|d| matches_expected(d)) {
        codes.push(APK_FINGERPRINT_MISMATCH);
    }

    let package_name = payload
        .app_integrity
        .as_ref()
        .and_then(|a| a.package_name.as_deref());
    match package_name {
        Some(name) => {
            if !params.package_names.iter().any(|p| p == name) {
                codes.push(PACKAGE_NAME_MISMATCH);
            }
        }
        None => {
            if !policy.accept_missing_app_integrity {
                codes.push(PACKAGE_NAME_MISMATCH);
            }
        }
    }

    if !codes.is_empty() {
        return Err(PlayIntegrityError::Rejected(codes));
    }

    // appFromOfficialStore: the Play signing digest only identifies our app —
    // a sideloaded APK carries the same certificate. Play's own verdicts are
    // the part that establishes Play distributed this install, and the relaxed
    // modes admit an unrecognized or unlicensed app, so both are required
    // here. Strict already demands both, so its verdict is unchanged.
    let play_distributed =
        app_recognition == Some("PLAY_RECOGNIZED") && licensing == Some("LICENSED");
    Ok(play_distributed
        && token_digests
            .iter()
            .any(|d| d == params.playstore_digest.as_slice()))
}
