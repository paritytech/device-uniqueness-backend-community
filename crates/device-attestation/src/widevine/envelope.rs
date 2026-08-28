// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Strict canonical-CBOR decoding of the Widevine device envelope.
//!
//! The wire contract (envelope wire spec v1) is one definite-length CBOR map
//! with integer keys 0..=6 in ascending order, encoded core-deterministically
//! (RFC 8949 §4.2.1). The decoder is hand-rolled and rejects everything
//! outside that shape — indefinite lengths, non-shortest integer arguments,
//! unsorted/duplicate/unknown keys, trailing bytes — so an accepted envelope
//! has exactly one byte form and the signature always covers it. Same
//! rationale as the DER reader in `auth::key_attest::extension`: the input is
//! attacker-controlled, every read is bounds-checked, nothing recurses.

/// Envelope `domain` (key 0).
pub const DOMAIN: &str = "dub/poud/android/v1";
/// Envelope `version` (key 1).
pub const VERSION: u64 = 1;

/// Widevine device id bounds (key 4): raw `PROPERTY_DEVICE_UNIQUE_ID` bytes.
const MIN_WIDEVINE_ID_LEN: usize = 1;
const MAX_WIDEVINE_ID_LEN: usize = 64;

/// The decoded device envelope.
#[derive(Debug)]
pub struct Envelope {
    /// Fresh 32-byte challenge from `/auth/challenges` (key 2); also the
    /// leaf key's `setAttestationChallenge` value.
    pub challenge: [u8; 32],
    /// sr25519 public key of the claiming account (key 3) — must equal the
    /// JWT subject.
    pub candidate: [u8; 32],
    /// Raw Widevine device id bytes, untransformed (key 4).
    pub widevine_id: Vec<u8>,
    /// Measured security level (key 5): `1` (L1) or `3` (GrapheneOS lane).
    pub level: u64,
    /// Unix-seconds expiry (key 6).
    pub expiry: u64,
}

/// Decode a canonical envelope. Any deviation from the wire contract is an
/// error (mapped to `DEVICE_EVIDENCE_MALFORMED` by the caller).
pub fn decode(bytes: &[u8]) -> Result<Envelope, String> {
    let mut reader = Reader { input: bytes };

    let (major, len) = reader.header()?;
    if major != MAJOR_MAP {
        return Err("envelope is not a CBOR map".to_string());
    }
    if len != 7 {
        return Err(format!("envelope map has {len} entries, expected 7"));
    }

    // Keys 0..=6, each a canonical uint, in ascending order — which also
    // rules out duplicates and unknown keys.
    expect_key(&mut reader, 0)?;
    let domain = reader.text()?;
    if domain != DOMAIN {
        return Err(format!("unknown domain {domain:?}"));
    }

    expect_key(&mut reader, 1)?;
    let version = reader.uint()?;
    if version != VERSION {
        return Err(format!("unknown version {version}"));
    }

    expect_key(&mut reader, 2)?;
    let challenge: [u8; 32] = reader
        .bytes()?
        .try_into()
        .map_err(|_| "challenge must be exactly 32 bytes".to_string())?;

    expect_key(&mut reader, 3)?;
    let candidate: [u8; 32] = reader
        .bytes()?
        .try_into()
        .map_err(|_| "candidate must be exactly 32 bytes".to_string())?;

    expect_key(&mut reader, 4)?;
    let widevine_id = reader.bytes()?.to_vec();
    if widevine_id.len() < MIN_WIDEVINE_ID_LEN || widevine_id.len() > MAX_WIDEVINE_ID_LEN {
        return Err(format!(
            "widevineId is {} bytes, expected {MIN_WIDEVINE_ID_LEN}..={MAX_WIDEVINE_ID_LEN}",
            widevine_id.len()
        ));
    }

    expect_key(&mut reader, 5)?;
    let level = reader.uint()?;
    if level != 1 && level != 3 {
        return Err(format!("level {level} is not 1 or 3"));
    }

    expect_key(&mut reader, 6)?;
    let expiry = reader.uint()?;

    if !reader.input.is_empty() {
        return Err("trailing bytes after envelope".to_string());
    }

    Ok(Envelope {
        challenge,
        candidate,
        widevine_id,
        level,
        expiry,
    })
}

const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_MAP: u8 = 5;

struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        let (&first, rest) = self
            .input
            .split_first()
            .ok_or_else(|| "truncated envelope".to_string())?;
        self.input = rest;
        Ok(first)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.input.len() < n {
            return Err("truncated envelope".to_string());
        }
        let (taken, rest) = self.input.split_at(n);
        self.input = rest;
        Ok(taken)
    }

    /// Read one data-item header: `(major type, argument)`, enforcing the
    /// core-deterministic shortest-form argument encoding.
    fn header(&mut self) -> Result<(u8, u64), String> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1F;
        let argument = match info {
            0..=23 => u64::from(info),
            24 => {
                let value = u64::from(self.byte()?);
                if value < 24 {
                    return Err("non-shortest CBOR argument".to_string());
                }
                value
            }
            25 => {
                let raw: [u8; 2] = self.take(2)?.try_into().expect("length checked");
                let value = u64::from(u16::from_be_bytes(raw));
                if value <= u64::from(u8::MAX) {
                    return Err("non-shortest CBOR argument".to_string());
                }
                value
            }
            26 => {
                let raw: [u8; 4] = self.take(4)?.try_into().expect("length checked");
                let value = u64::from(u32::from_be_bytes(raw));
                if value <= u64::from(u16::MAX) {
                    return Err("non-shortest CBOR argument".to_string());
                }
                value
            }
            27 => {
                let raw: [u8; 8] = self.take(8)?.try_into().expect("length checked");
                let value = u64::from_be_bytes(raw);
                if value <= u64::from(u32::MAX) {
                    return Err("non-shortest CBOR argument".to_string());
                }
                value
            }
            _ => return Err("indefinite or reserved CBOR encoding".to_string()),
        };
        Ok((major, argument))
    }

    /// A definite-length byte string.
    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let (major, len) = self.header()?;
        if major != MAJOR_BYTES {
            return Err("expected a byte string".to_string());
        }
        let len = usize::try_from(len).map_err(|_| "byte string too long".to_string())?;
        self.take(len)
    }

    /// A definite-length UTF-8 text string.
    fn text(&mut self) -> Result<&'a str, String> {
        let (major, len) = self.header()?;
        if major != MAJOR_TEXT {
            return Err("expected a text string".to_string());
        }
        let len = usize::try_from(len).map_err(|_| "text string too long".to_string())?;
        std::str::from_utf8(self.take(len)?).map_err(|_| "text string is not UTF-8".to_string())
    }

    /// An unsigned integer data item.
    fn uint(&mut self) -> Result<u64, String> {
        let (major, value) = self.header()?;
        if major != MAJOR_UINT {
            return Err("expected an unsigned integer".to_string());
        }
        Ok(value)
    }
}

/// The next data item must be the uint map key `expected`.
fn expect_key(reader: &mut Reader<'_>, expected: u64) -> Result<(), String> {
    let key = reader.uint()?;
    if key != expected {
        return Err(format!("expected map key {expected}, got {key}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical CBOR builders for the tests.
    fn uint(value: u64) -> Vec<u8> {
        head(0, value)
    }
    fn bstr(content: &[u8]) -> Vec<u8> {
        let mut out = head(2, content.len() as u64);
        out.extend_from_slice(content);
        out
    }
    fn tstr(content: &str) -> Vec<u8> {
        let mut out = head(3, content.len() as u64);
        out.extend_from_slice(content.as_bytes());
        out
    }
    fn head(major: u8, argument: u64) -> Vec<u8> {
        let m = major << 5;
        if argument < 24 {
            vec![m | argument as u8]
        } else if argument <= u64::from(u8::MAX) {
            vec![m | 24, argument as u8]
        } else if argument <= u64::from(u16::MAX) {
            let mut out = vec![m | 25];
            out.extend_from_slice(&(argument as u16).to_be_bytes());
            out
        } else if argument <= u64::from(u32::MAX) {
            let mut out = vec![m | 26];
            out.extend_from_slice(&(argument as u32).to_be_bytes());
            out
        } else {
            let mut out = vec![m | 27];
            out.extend_from_slice(&argument.to_be_bytes());
            out
        }
    }

    fn envelope_with(domain: &str, level: u64) -> Vec<u8> {
        let mut out = vec![0xA7]; // map(7)
        out.extend(uint(0));
        out.extend(tstr(domain));
        out.extend(uint(1));
        out.extend(uint(VERSION));
        out.extend(uint(2));
        out.extend(bstr(&[0x11; 32]));
        out.extend(uint(3));
        out.extend(bstr(&[0x22; 32]));
        out.extend(uint(4));
        out.extend(bstr(&[0x33; 32]));
        out.extend(uint(5));
        out.extend(uint(level));
        out.extend(uint(6));
        out.extend(uint(1_780_000_000));
        out
    }

    fn valid_envelope() -> Vec<u8> {
        envelope_with(DOMAIN, 1)
    }

    #[test]
    fn canonical_envelope_decodes() {
        let envelope = decode(&valid_envelope()).expect("valid envelope");
        assert_eq!(envelope.challenge, [0x11; 32]);
        assert_eq!(envelope.candidate, [0x22; 32]);
        assert_eq!(envelope.widevine_id, vec![0x33; 32]);
        assert_eq!(envelope.level, 1);
        assert_eq!(envelope.expiry, 1_780_000_000);
    }

    #[test]
    fn wrong_domain_version_and_level_are_rejected() {
        // The superseded ibv2 domain string must not verify.
        let wrong_domain = envelope_with("ibv2/poud/android/v1", 1);
        assert!(decode(&wrong_domain).unwrap_err().contains("domain"));

        // level = 2 is explicitly invalid; level 3 is accepted at decode.
        assert!(decode(&envelope_with(DOMAIN, 2))
            .unwrap_err()
            .contains("level"));
        assert_eq!(decode(&envelope_with(DOMAIN, 3)).expect("valid").level, 3);
    }

    #[test]
    fn non_canonical_encodings_are_rejected() {
        // Trailing byte.
        let mut trailing = valid_envelope();
        trailing.push(0x00);
        assert!(decode(&trailing).unwrap_err().contains("trailing"));

        // Non-shortest argument: expiry 100 as a two-byte uint (0x19 0x00 0x64).
        let mut non_shortest = valid_envelope();
        // Replace the final expiry item (0x1A + 4 bytes) with 0x19 0x00 0x64.
        non_shortest.truncate(non_shortest.len() - 5);
        non_shortest.extend_from_slice(&[0x19, 0x00, 0x64]);
        assert!(decode(&non_shortest).unwrap_err().contains("non-shortest"));

        // Indefinite-length map.
        assert!(decode(&[0xBF]).unwrap_err().contains("indefinite"));

        // Keys out of order (1 before 0).
        let mut unordered = vec![0xA7];
        unordered.extend(uint(1));
        unordered.extend(uint(VERSION));
        assert!(decode(&unordered).unwrap_err().contains("map key"));

        // Wrong entry count.
        assert!(decode(&[0xA6]).unwrap_err().contains("entries"));

        // Truncated.
        let mut truncated = valid_envelope();
        truncated.truncate(truncated.len() - 1);
        assert!(decode(&truncated).unwrap_err().contains("truncated"));
    }

    #[test]
    fn field_bounds_are_enforced() {
        // 31-byte challenge.
        let mut short_challenge = vec![0xA7];
        short_challenge.extend(uint(0));
        short_challenge.extend(tstr(DOMAIN));
        short_challenge.extend(uint(1));
        short_challenge.extend(uint(VERSION));
        short_challenge.extend(uint(2));
        short_challenge.extend(bstr(&[0x11; 31]));
        assert!(decode(&short_challenge).unwrap_err().contains("challenge"));

        // Empty widevineId.
        let mut empty_id = vec![0xA7];
        empty_id.extend(uint(0));
        empty_id.extend(tstr(DOMAIN));
        empty_id.extend(uint(1));
        empty_id.extend(uint(VERSION));
        empty_id.extend(uint(2));
        empty_id.extend(bstr(&[0x11; 32]));
        empty_id.extend(uint(3));
        empty_id.extend(bstr(&[0x22; 32]));
        empty_id.extend(uint(4));
        empty_id.extend(bstr(&[]));
        assert!(decode(&empty_id).unwrap_err().contains("widevineId"));
    }
}
