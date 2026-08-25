// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use rsa::pkcs1::DecodeRsaPublicKey as _;
use sha2::{Digest as _, Sha256, Sha384};
use x509_parser::certificate::X509Certificate;

const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";

const CURVE_P256: &str = "1.2.840.10045.3.1.7";
const CURVE_P384: &str = "1.3.132.0.34";

pub(crate) fn check_validity(cert: &X509Certificate<'_>, now_unix: i64) -> Result<(), String> {
    let at = x509_parser::time::ASN1Time::from_timestamp(now_unix)
        .map_err(|e| format!("timestamp: {e}"))?;
    if cert.validity().is_valid_at(at) {
        Ok(())
    } else {
        Err("certificate outside validity window".to_string())
    }
}

pub(crate) fn verify_signed_by(
    child: &X509Certificate<'_>,
    parent: &X509Certificate<'_>,
) -> Result<(), String> {
    let sig_alg = child.signature_algorithm.algorithm.to_id_string();
    let tbs = child.tbs_certificate.as_ref();
    let prehash: Vec<u8> = match sig_alg.as_str() {
        ECDSA_WITH_SHA256 | SHA256_WITH_RSA => Sha256::digest(tbs).to_vec(),
        ECDSA_WITH_SHA384 | SHA384_WITH_RSA => Sha384::digest(tbs).to_vec(),
        other => return Err(format!("unsupported signature alg {other}")),
    };
    let signature_der = &child.signature_value.data;

    let spki = &parent.public_key();
    let key_bytes = &spki.subject_public_key.data;

    let verified = if matches!(sig_alg.as_str(), SHA256_WITH_RSA | SHA384_WITH_RSA) {
        let key = rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
            .map_err(|e| format!("parent RSA key: {e}"))?;
        let scheme = match sig_alg.as_str() {
            SHA256_WITH_RSA => rsa::Pkcs1v15Sign::new::<Sha256>(),
            _ => rsa::Pkcs1v15Sign::new::<Sha384>(),
        };
        key.verify(scheme, &prehash, signature_der).is_ok()
    } else {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|oid| oid.to_id_string())
            .ok_or_else(|| "parent key has no curve".to_string())?;
        match curve.as_str() {
            CURVE_P256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                    .map_err(|e| format!("parent P-256 key: {e}"))?;
                let sig = p256::ecdsa::Signature::from_der(signature_der)
                    .map_err(|e| format!("signature: {e}"))?;
                key.verify_prehash(&prehash, &sig).is_ok()
            }
            CURVE_P384 => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                    .map_err(|e| format!("parent P-384 key: {e}"))?;
                let sig = p384::ecdsa::Signature::from_der(signature_der)
                    .map_err(|e| format!("signature: {e}"))?;
                key.verify_prehash(&prehash, &sig).is_ok()
            }
            other => return Err(format!("unsupported curve {other}")),
        }
    };

    if verified {
        Ok(())
    } else {
        Err("signature verification failed".to_string())
    }
}
