// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub const ANDROID_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

const TAG_ATTESTATION_APPLICATION_ID: u32 = 709;
const TAG_ROOT_OF_TRUST: u32 = 704;

#[derive(Debug)]
pub struct KeyDescription {
    pub attestation_security_level: u64,
    pub key_security_level: u64,
    pub attestation_challenge: Vec<u8>,
    pub package_names: Vec<String>,
    pub signing_digests: Vec<Vec<u8>>,
    pub root_of_trust: Option<RootOfTrust>,
}

#[derive(Debug)]
pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: u64,
}

struct Tlv<'a> {
    class: u8,
    constructed: bool,
    number: u32,
    content: &'a [u8],
}

const TAG_BOOLEAN: u32 = 1;
const TAG_OCTET_STRING: u32 = 4;
const TAG_ENUMERATED: u32 = 10;
const TAG_SEQUENCE: u32 = 16;
const TAG_SET: u32 = 17;

impl Tlv<'_> {
    fn expect_primitive(&self, number: u32, what: &str) -> Result<(), String> {
        if self.class != 0 || self.constructed || self.number != number {
            return Err(format!("{what}: unexpected DER type"));
        }
        Ok(())
    }

    fn expect_constructed(&self, number: u32, what: &str) -> Result<(), String> {
        if self.class != 0 || !self.constructed || self.number != number {
            return Err(format!("{what}: unexpected DER type"));
        }
        Ok(())
    }
}

fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), String> {
    let b0 = *input.first().ok_or("truncated tag")?;
    let class = b0 >> 6;
    let constructed = b0 & 0x20 != 0;
    let mut idx = 1usize;
    let mut number = u32::from(b0 & 0x1F);
    if number == 0x1F {
        number = 0;
        let mut first = true;
        loop {
            let b = *input.get(idx).ok_or("truncated high-form tag")?;
            idx += 1;
            if first && b & 0x7F == 0 {
                return Err("non-minimal high-form tag".to_string());
            }
            first = false;
            number = number
                .checked_mul(128)
                .and_then(|n| n.checked_add(u32::from(b & 0x7F)))
                .ok_or("tag number overflow")?;
            if b & 0x80 == 0 {
                break;
            }
        }
        if number < 31 {
            return Err("non-minimal high-form tag".to_string());
        }
    }

    let l0 = *input.get(idx).ok_or("truncated length")?;
    idx += 1;
    let len = if l0 & 0x80 == 0 {
        usize::from(l0)
    } else {
        let n = usize::from(l0 & 0x7F);
        if n == 0 || n > 4 {
            return Err("unsupported DER length form".to_string());
        }
        let mut len = 0usize;
        for i in 0..n {
            let b = *input.get(idx).ok_or("truncated long-form length")?;
            idx += 1;
            if i == 0 && b == 0 {
                return Err("non-minimal long-form length".to_string());
            }
            len = (len << 8) | usize::from(b);
        }
        if len < 128 {
            return Err("non-minimal long-form length".to_string());
        }
        len
    };

    let end = idx.checked_add(len).ok_or("length overflow")?;
    let content = input.get(idx..end).ok_or("truncated content")?;
    Ok((
        Tlv {
            class,
            constructed,
            number,
            content,
        },
        &input[end..],
    ))
}

fn children(mut content: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (tlv, rest) = read_tlv(content)?;
        out.push(tlv);
        content = rest;
    }
    Ok(out)
}

fn as_u64(tlv: &Tlv<'_>) -> Result<u64, String> {
    if tlv.content.is_empty() || tlv.content.len() > 8 {
        return Err("integer out of range".to_string());
    }
    let mut value = 0u64;
    for &b in tlv.content {
        value = (value << 8) | u64::from(b);
    }
    Ok(value)
}

fn as_bool(tlv: &Tlv<'_>) -> Result<bool, String> {
    match tlv.content {
        [0x00] => Ok(false),
        [0xFF] => Ok(true),
        _ => Err("non-canonical DER BOOLEAN".to_string()),
    }
}

pub fn parse(extension_value: &[u8]) -> Result<KeyDescription, String> {
    let (top, rest) = read_tlv(extension_value)?;
    if !rest.is_empty() {
        return Err("trailing bytes after KeyDescription".to_string());
    }
    top.expect_constructed(TAG_SEQUENCE, "KeyDescription")?;
    let fields = children(top.content)?;
    if fields.len() < 8 {
        return Err(format!(
            "KeyDescription has {} fields, expected at least 8",
            fields.len()
        ));
    }

    fields[1].expect_primitive(TAG_ENUMERATED, "attestationSecurityLevel")?;
    let attestation_security_level = as_u64(&fields[1])?;
    fields[3].expect_primitive(TAG_ENUMERATED, "keymasterSecurityLevel")?;
    let key_security_level = as_u64(&fields[3])?;
    fields[4].expect_primitive(TAG_OCTET_STRING, "attestationChallenge")?;
    let attestation_challenge = fields[4].content.to_vec();

    let software = parse_authorization_list(&fields[6])?;
    let hardware = parse_authorization_list(&fields[7])?;

    let app_id_der = software
        .application_id
        .or(hardware.application_id)
        .ok_or("missing attestationApplicationId")?;
    let (package_names, signing_digests) = parse_application_id(app_id_der)?;

    Ok(KeyDescription {
        attestation_security_level,
        key_security_level,
        attestation_challenge,
        package_names,
        signing_digests,
        root_of_trust: hardware.root_of_trust,
    })
}

struct AuthorizationList<'a> {
    application_id: Option<&'a [u8]>,
    root_of_trust: Option<RootOfTrust>,
}

fn parse_authorization_list<'a>(list: &Tlv<'a>) -> Result<AuthorizationList<'a>, String> {
    list.expect_constructed(TAG_SEQUENCE, "AuthorizationList")?;
    let mut application_id = None;
    let mut root_of_trust = None;
    for entry in children(list.content)? {
        // Context-specific EXPLICIT tags: the content wraps the inner TLV.
        if entry.class != 2 {
            continue;
        }
        match entry.number {
            TAG_ATTESTATION_APPLICATION_ID => {
                let (inner, rest) = read_tlv(entry.content)?;
                if !rest.is_empty() {
                    return Err("attestationApplicationId: trailing bytes".to_string());
                }
                inner.expect_primitive(TAG_OCTET_STRING, "attestationApplicationId")?;
                application_id = Some(inner.content);
            }
            TAG_ROOT_OF_TRUST => {
                let (inner, rest) = read_tlv(entry.content)?;
                if !rest.is_empty() {
                    return Err("rootOfTrust: trailing bytes".to_string());
                }
                inner.expect_constructed(TAG_SEQUENCE, "rootOfTrust")?;
                root_of_trust = Some(parse_root_of_trust(inner.content)?);
            }
            _ => {}
        }
    }
    Ok(AuthorizationList {
        application_id,
        root_of_trust,
    })
}

fn parse_root_of_trust(content: &[u8]) -> Result<RootOfTrust, String> {
    let fields = children(content)?;
    if fields.len() < 3 {
        return Err("rootOfTrust has fewer than 3 fields".to_string());
    }
    fields[0].expect_primitive(TAG_OCTET_STRING, "verifiedBootKey")?;
    fields[1].expect_primitive(TAG_BOOLEAN, "deviceLocked")?;
    fields[2].expect_primitive(TAG_ENUMERATED, "verifiedBootState")?;
    Ok(RootOfTrust {
        verified_boot_key: fields[0].content.to_vec(),
        device_locked: as_bool(&fields[1])?,
        verified_boot_state: as_u64(&fields[2])?,
    })
}

fn parse_application_id(der: &[u8]) -> Result<(Vec<String>, Vec<Vec<u8>>), String> {
    let (top, rest) = read_tlv(der)?;
    if !rest.is_empty() {
        return Err("AttestationApplicationId: trailing bytes".to_string());
    }
    top.expect_constructed(TAG_SEQUENCE, "AttestationApplicationId")?;
    let sets = children(top.content)?;
    if sets.len() != 2 {
        return Err("AttestationApplicationId does not have 2 sets".to_string());
    }
    sets[0].expect_constructed(TAG_SET, "packageInfos")?;
    sets[1].expect_constructed(TAG_SET, "signatureDigests")?;

    let mut package_names = Vec::new();
    for info in children(sets[0].content)? {
        info.expect_constructed(TAG_SEQUENCE, "packageInfo")?;
        let fields = children(info.content)?;
        let name = fields.first().ok_or("packageInfo missing name")?;
        name.expect_primitive(TAG_OCTET_STRING, "packageName")?;
        package_names.push(
            String::from_utf8(name.content.to_vec())
                .map_err(|_| "package name is not UTF-8".to_string())?,
        );
    }

    let mut signing_digests = Vec::new();
    for digest in children(sets[1].content)? {
        digest.expect_primitive(TAG_OCTET_STRING, "signature digest")?;
        signing_digests.push(digest.content.to_vec());
    }

    Ok((package_names, signing_digests))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 128, "test builder supports short form only");
        let mut out = vec![tag, content.len() as u8];
        out.extend_from_slice(content);
        out
    }
    fn integer(v: u8) -> Vec<u8> {
        tlv(0x02, &[v])
    }
    fn enumerated(v: u8) -> Vec<u8> {
        tlv(0x0A, &[v])
    }
    fn octet(content: &[u8]) -> Vec<u8> {
        tlv(0x04, content)
    }
    fn boolean(byte: u8) -> Vec<u8> {
        tlv(0x01, &[byte])
    }
    fn constructed(tag: u8, parts: &[Vec<u8>]) -> Vec<u8> {
        let content: Vec<u8> = parts.concat();
        let mut out = vec![tag];
        if content.len() < 128 {
            out.push(content.len() as u8);
        } else {
            assert!(content.len() < 256);
            out.extend_from_slice(&[0x81, content.len() as u8]);
        }
        out.extend(content);
        out
    }
    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        constructed(0x30, parts)
    }
    fn set(parts: &[Vec<u8>]) -> Vec<u8> {
        constructed(0x31, parts)
    }
    fn ctx(number: u32, inner: &[u8]) -> Vec<u8> {
        let mut out = vec![0xBF];
        assert!((128..16384).contains(&number));
        out.push(0x80 | (number / 128) as u8);
        out.push((number % 128) as u8);
        assert!(inner.len() < 128);
        out.push(inner.len() as u8);
        out.extend_from_slice(inner);
        out
    }

    fn application_id(package: &str) -> Vec<u8> {
        sequence(&[
            set(&[sequence(&[octet(package.as_bytes()), integer(1)])]),
            set(&[octet(&[0x11; 32])]),
        ])
    }

    fn key_description(security: Vec<u8>, challenge_field: Vec<u8>, locked: Vec<u8>) -> Vec<u8> {
        let root_of_trust = sequence(&[octet(&[0x22; 32]), locked, enumerated(0)]);
        sequence(&[
            integer(100),
            security.clone(),
            integer(100),
            security,
            challenge_field,
            octet(&[]),
            sequence(&[ctx(
                TAG_ATTESTATION_APPLICATION_ID,
                &octet(&application_id("io.pcf.polkadotapp")),
            )]),
            sequence(&[ctx(TAG_ROOT_OF_TRUST, &root_of_trust)]),
        ])
    }

    #[test]
    fn synthetic_key_description_parses_and_enforces_types() {
        let valid = key_description(enumerated(1), octet(b"challenge"), boolean(0xFF));
        let parsed = parse(&valid).expect("valid synthetic description");
        assert_eq!(parsed.attestation_security_level, 1);
        assert_eq!(parsed.attestation_challenge, b"challenge");
        assert_eq!(parsed.package_names, vec!["io.pcf.polkadotapp".to_string()]);
        assert!(parsed.root_of_trust.expect("root of trust").device_locked);

        let wrong_type = key_description(integer(1), octet(b"challenge"), boolean(0xFF));
        assert!(parse(&wrong_type).is_err());

        let wrong_challenge = key_description(enumerated(1), integer(7), boolean(0xFF));
        assert!(parse(&wrong_challenge).is_err());

        let sloppy_bool = key_description(enumerated(1), octet(b"challenge"), boolean(0x01));
        assert!(parse(&sloppy_bool).is_err());
    }

    #[test]
    fn non_minimal_der_encodings_are_rejected() {
        assert!(parse(&[0x30, 0x81, 0x05, 0x02, 0x01, 0x01, 0x04, 0x00]).is_err());
        assert!(read_tlv(&[0x1F, 0x05, 0x00]).is_err());
        assert!(read_tlv(&[0xBF, 0x80, 0x85, 0x45, 0x00]).is_err());
        assert!(parse(&[0x30, 0x05, 0x02, 0x01]).is_err());
        assert!(parse(&[0x30, 0x00, 0x00]).is_err());
    }
}
