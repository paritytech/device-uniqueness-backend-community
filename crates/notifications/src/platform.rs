// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Apple Push Notification service.
    Ios,
    /// Firebase Cloud Messaging.
    Android,
}

/// Detect the platform from a device token, honoring an explicit hint first.
///
/// Mirrors the legacy `detectFromDeviceToken`: a hint is authoritative; without
/// one, a 32–128 char hex string is iOS, otherwise Android.
pub fn detect(device_token: &str, hint: Option<Platform>) -> Platform {
    if let Some(hint) = hint {
        return hint;
    }
    let len = device_token.len();
    let is_ios = (32..=128).contains(&len) && device_token.bytes().all(|b| b.is_ascii_hexdigit());
    if is_ios {
        Platform::Ios
    } else {
        Platform::Android
    }
}

#[cfg(test)]
mod tests {
    use super::{detect, Platform};

    #[test]
    fn hint_takes_precedence() {
        let fcm = "f991KszkPdZEwIblAIh1bx:APA91bH";
        assert_eq!(detect(fcm, Some(Platform::Ios)), Platform::Ios);
        let ios = "a".repeat(64);
        assert_eq!(detect(&ios, Some(Platform::Android)), Platform::Android);
    }

    #[test]
    fn hex_length_boundaries() {
        assert_eq!(detect(&"a".repeat(31), None), Platform::Android);
        assert_eq!(detect(&"a".repeat(32), None), Platform::Ios);
        assert_eq!(detect(&"a".repeat(128), None), Platform::Ios);
        assert_eq!(detect(&"a".repeat(129), None), Platform::Android);
    }

    #[test]
    fn non_hex_characters_are_android() {
        assert_eq!(detect("aa:bb", None), Platform::Android);
        assert_eq!(detect("aa_bb", None), Platform::Android);
        assert_eq!(detect("aa-bb", None), Platform::Android);
    }
}
