// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use sha2::{Digest as _, Sha256};
use subxt_signer::sr25519::{PublicKey, Signature};

pub(crate) fn client_data_hash(challenge: &[u8], client_id: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let body_hash = Sha256::digest(body);
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(client_id);
    hasher.update(body_hash);
    hasher.finalize().into()
}

pub fn verify(challenge: &[u8], client_id: &[u8; 32], body: &[u8], proof: &[u8; 64]) -> bool {
    let message = client_data_hash(challenge, client_id, body);
    subxt_signer::sr25519::verify(&Signature(*proof), message, &PublicKey(*client_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr as _;
    use subxt_signer::sr25519::Keypair;
    use subxt_signer::SecretUri;

    #[test]
    fn accepts_shipping_mobile_body_variants() {
        let keypair = Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap();
        let client_id = keypair.public_key().0;
        let challenge = b"challenge-bytes";
        let ios_and_play_integrity_body = b"{}";

        let message = client_data_hash(challenge, &client_id, ios_and_play_integrity_body);
        let proof = keypair.sign(&message).0;

        assert!(verify(
            challenge,
            &client_id,
            ios_and_play_integrity_body,
            &proof
        ));
        assert!(!verify(challenge, &client_id, b"tampered", &proof));

        let key_attestation_body = b"{\"attestationChain\":[\"certificate\"]}";
        let message = client_data_hash(challenge, &client_id, key_attestation_body);
        let proof = keypair.sign(&message).0;
        assert!(verify(challenge, &client_id, key_attestation_body, &proof));
    }
}
