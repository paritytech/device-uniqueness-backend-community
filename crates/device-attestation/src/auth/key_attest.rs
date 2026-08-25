// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub(crate) mod crl;
pub(crate) mod extension;
pub(crate) mod verify;

use base64::Engine as _;

const MIN_CHAIN_ENTRIES: usize = 2;
const MAX_CHAIN_ENTRIES: usize = 10;
const MAX_ENTRY_CHARS: usize = 8192;

pub(crate) fn chain_from_body(body: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    #[derive(serde::Deserialize)]
    struct Body {
        #[serde(rename = "attestationChain")]
        attestation_chain: Option<Vec<String>>,
    }

    let body: Body =
        serde_json::from_slice(body).map_err(|e| format!("body is not valid JSON: {e}"))?;
    let chain = body
        .attestation_chain
        .ok_or("body has no attestationChain field")?;
    if chain.len() < MIN_CHAIN_ENTRIES || chain.len() > MAX_CHAIN_ENTRIES {
        return Err(format!(
            "attestationChain has {} entries, expected {MIN_CHAIN_ENTRIES}..={MAX_CHAIN_ENTRIES}",
            chain.len()
        ));
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    chain
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            if entry.len() > MAX_ENTRY_CHARS {
                return Err(format!(
                    "attestationChain[{i}] exceeds {MAX_ENTRY_CHARS} chars"
                ));
            }
            b64.decode(entry.trim())
                .map_err(|_| format!("attestationChain[{i}] is not valid base64"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_from_body_enforces_the_legacy_contract() {
        assert!(chain_from_body(b"{}").is_err());
        assert!(chain_from_body(b"not json").is_err());
        assert!(chain_from_body(br#"{"attestationChain": "AAAA"}"#).is_err());

        assert!(chain_from_body(br#"{"attestationChain": ["AAAA"]}"#).is_err());
        let eleven = format!(
            r#"{{"attestationChain": [{}]}}"#,
            ["\"AAAA\""; 11].join(",")
        );
        assert!(chain_from_body(eleven.as_bytes()).is_err());
        let oversized = format!(
            r#"{{"attestationChain": ["{}", "AAAA"]}}"#,
            "A".repeat(8193)
        );
        assert!(chain_from_body(oversized.as_bytes()).is_err());
        assert!(chain_from_body(br#"{"attestationChain": ["!!!", "AAAA"]}"#).is_err());

        let decoded = chain_from_body(br#"{"attestationChain": ["AQID", "BAUG"], "extra": 1}"#)
            .expect("valid body");
        assert_eq!(decoded, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    }
}
