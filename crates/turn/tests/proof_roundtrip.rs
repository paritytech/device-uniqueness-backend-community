// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use subxt::ext::codec::{Decode as _, Encode as _};
use verifiable::ring::ark_vrf::ring::SrsLookup as _;
use verifiable::ring::bandersnatch::{BandersnatchProverCache, BandersnatchVrfVerifiable};
use verifiable::ring::{ProverCache as _, RingDomainSize, StaticChunk};
use verifiable::GenerateVerifiable as _;

type Member = <BandersnatchVrfVerifiable as verifiable::GenerateVerifiable>::Member;
type Members = <BandersnatchVrfVerifiable as verifiable::GenerateVerifiable>::Members;
type Proof = <BandersnatchVrfVerifiable as verifiable::GenerateVerifiable>::Proof;

const DOMAIN: RingDomainSize = RingDomainSize::Domain11;
const CONTEXT: &[u8] = b"example-product-context/turn";
const MESSAGE: &[u8] = b"turn-credential-request";

fn build_ring(members: &[Member]) -> Members {
    let setup = BandersnatchProverCache::ring_setup(DOMAIN);
    let (_, pcs_params) = setup.verifier_key_builder();
    let mut intermediate = BandersnatchVrfVerifiable::start_members(DOMAIN);
    BandersnatchVrfVerifiable::push_members(&mut intermediate, members.iter().cloned(), |range| {
        (&pcs_params)
            .lookup(range)
            .map(|points| points.into_iter().map(StaticChunk).collect())
            .ok_or(())
    })
    .expect("members fit the ring and the embedded SRS covers them");
    BandersnatchVrfVerifiable::finish_members(intermediate)
}

#[test]
fn proof_roundtrip_verifies_and_rejects_tampering() {
    let secrets: Vec<_> = (0u8..5)
        .map(|i| BandersnatchVrfVerifiable::new_secret([i; 32]))
        .collect();
    let members: Vec<_> = secrets
        .iter()
        .map(BandersnatchVrfVerifiable::member_from_secret)
        .collect();
    let commitment = build_ring(&members);

    let (secret, member) = (&secrets[2], &members[2]);
    let opening = BandersnatchVrfVerifiable::open(DOMAIN, member, members.iter().cloned())
        .expect("member is in the ring");
    let (proof, alias) = BandersnatchVrfVerifiable::create(opening, secret, CONTEXT, MESSAGE)
        .expect("proof creation succeeds");

    let validated =
        BandersnatchVrfVerifiable::validate(DOMAIN, &proof, &commitment, CONTEXT, MESSAGE)
            .expect("genuine proof verifies");
    assert_eq!(validated, alias);
    assert_eq!(
        BandersnatchVrfVerifiable::alias_in_context(secret, CONTEXT).expect("alias derivation"),
        alias
    );

    assert!(BandersnatchVrfVerifiable::validate(
        DOMAIN,
        &proof,
        &commitment,
        b"other-context",
        MESSAGE
    )
    .is_err());
    assert_ne!(
        BandersnatchVrfVerifiable::alias_in_context(secret, b"other-context")
            .expect("alias derivation"),
        alias
    );

    assert!(BandersnatchVrfVerifiable::validate(
        DOMAIN,
        &proof,
        &commitment,
        CONTEXT,
        b"tampered-message"
    )
    .is_err());

    let mut bytes = proof.encode();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let tampered = Proof::decode(&mut &bytes[..]);
    let rejected = match tampered {
        Err(_) => true,
        Ok(tampered) => {
            BandersnatchVrfVerifiable::validate(DOMAIN, &tampered, &commitment, CONTEXT, MESSAGE)
                .is_err()
        }
    };
    assert!(rejected, "tampered proof must not verify");
}

#[test]
fn proof_against_a_different_ring_fails() {
    let secrets: Vec<_> = (0u8..4)
        .map(|i| BandersnatchVrfVerifiable::new_secret([i; 32]))
        .collect();
    let members: Vec<_> = secrets
        .iter()
        .map(BandersnatchVrfVerifiable::member_from_secret)
        .collect();

    let opening = BandersnatchVrfVerifiable::open(DOMAIN, &members[0], members.iter().cloned())
        .expect("member is in the ring");
    let (proof, _) = BandersnatchVrfVerifiable::create(opening, &secrets[0], CONTEXT, MESSAGE)
        .expect("proof creation succeeds");

    let other_members: Vec<_> = (10u8..14)
        .map(|i| {
            BandersnatchVrfVerifiable::member_from_secret(&BandersnatchVrfVerifiable::new_secret(
                [i; 32],
            ))
        })
        .collect();
    let other_ring = build_ring(&other_members);
    assert!(
        BandersnatchVrfVerifiable::validate(DOMAIN, &proof, &other_ring, CONTEXT, MESSAGE).is_err()
    );
}
