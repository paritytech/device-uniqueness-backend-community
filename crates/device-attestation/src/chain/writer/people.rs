// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;
use chain_types::{PeopleConfig, PeopleExtrinsicParamsBuilder};
use sqlx::PgPool;
use subxt::{dynamic::Value, tx::DynamicPayload, utils::AccountId32};
use time::OffsetDateTime;

use super::link::PeopleRuntime;
use super::{
    engine::{finalize, parse_candidate, Cx, UNFUNDED_PARK_BACKOFF_SECS},
    error::{Op, WriterError},
    events::{check_proxied_call, item_results},
    lane::{observe_defer, park_until, row_backoff, Gate, Lane, Outcome},
    link::PeopleLink,
    observe::record_submit_outcome,
    tx::{build_registration_batch_tx, build_registration_tx},
};
use crate::chain::attest::PayloadVersion;
use crate::chain::{
    lease,
    outbox::{self, Guard, Reservation},
    people::PeopleChain,
};
use crate::signature::verify_candidate_signature;

/// The gate's verdict on a candidate signature the runtime would reject as
/// `InvalidAttestationSignature`. Terminal: only the client can re-sign.
const BAD_CANDIDATE_SIGNATURE: &str = "candidate signature does not verify";

/// How long a row signed for a runtime that is not live yet waits before the
/// gate looks again. Long enough not to spin a pass on it, short enough that
/// the row follows an upgrade within a couple of minutes.
const PENDING_RUNTIME_DEFER_SECS: i64 = 60;

/// The payload-version half of the gate: whether a row signed in `declared`
/// can be submitted to a runtime that takes `accepted`.
///
/// An older format than the runtime takes is terminal: the consumer signature
/// covers fields the call no longer carries, and only the client can re-sign.
/// A newer one waits: it was accepted for a runtime upgrade that is not
/// enacted here yet, and becomes submittable when it is.
fn check_payload_version(declared: u16, accepted: PayloadVersion, now: i64) -> Result<(), Gate> {
    let declared = PayloadVersion::try_from(declared)
        .map_err(|_| Gate::Failed(format!("unsupported payload version {declared}")))?;
    match (declared, accepted) {
        (PayloadVersion::V1, PayloadVersion::V1) | (PayloadVersion::V2, PayloadVersion::V2) => {
            Ok(())
        }
        (PayloadVersion::V1, PayloadVersion::V2) => Err(Gate::Failed(format!(
            "payload version {declared} is no longer accepted: the runtime takes {accepted}"
        ))),
        (PayloadVersion::V2, PayloadVersion::V1) => Err(Gate::NotYet {
            until: OffsetDateTime::from_unix_timestamp(now + PENDING_RUNTIME_DEFER_SECS)
                .unwrap_or_else(|_| OffsetDateTime::now_utc()),
            reason: format!(
                "payload version {declared} awaits the runtime upgrade: \
                 the runtime takes {accepted}"
            ),
        }),
    }
}

pub(super) struct People;

impl Lane for People {
    type Link = PeopleLink;
    type Chain = PeopleChain;
    type Ctx = PeopleRuntime;

    const NAME: &'static str = "people";
    const OWNED_ELSEWHERE: &'static str = "username owned by another account";
    const RECONCILED: &'static str = "reconcile: not yet on-chain, re-queued";
    const NONCE_FETCH: &'static str = "nonce fetch";

    fn attempt(r: &Reservation) -> i32 {
        r.attempt
    }

    async fn claim(pool: &PgPool, limit: i64) -> Result<Vec<Reservation>, sqlx::Error> {
        outbox::claim_due(pool, limit).await
    }

    async fn submitting(pool: &PgPool) -> Result<Vec<Reservation>, sqlx::Error> {
        outbox::submitting(pool).await
    }

    /// Checks the row against the runtime at this pass, offline, so a row the
    /// chain would reject never spends an attempt or a fee: its payload
    /// version must be the one `attest`'s shape takes, and its candidate
    /// signature must verify in the form the runtime accepts.
    ///
    /// Passing the gate is what lets the transaction builder take the
    /// `attest` shape from the row's payload version.
    fn gate(r: &Reservation, runtime: PeopleRuntime, now: i64) -> Result<[u8; 32], Gate> {
        check_payload_version(
            r.payload_version,
            runtime.attest_shape.payload_version(),
            now,
        )?;
        let candidate = parse_candidate(r)?;
        if !verify_candidate_signature(
            &candidate,
            &r.candidate_signature,
            &r.ring_vrf_key,
            &runtime.signature_form,
        ) {
            return Err(Gate::Failed(BAD_CANDIDATE_SIGNATURE.to_string()));
        }
        Ok(candidate)
    }

    fn tx(
        rows: &[(&Reservation, [u8; 32])],
        proxy_for: Option<&[u8; 32]>,
    ) -> DynamicPayload<Vec<Value>> {
        match rows {
            [(r, candidate)] => build_registration_tx(r, candidate, proxy_for),
            _ => build_registration_batch_tx(rows, proxy_for),
        }
    }

    async fn account_nonce(chain: &PeopleChain, signer: &AccountId32) -> Result<u64> {
        chain.next_nonce(signer).await
    }

    async fn submit_one(
        cx: &Cx<'_>,
        chain: &PeopleChain,
        nonce: u64,
        r: &Reservation,
        candidate: [u8; 32],
    ) -> Result<()> {
        let signed = sign(cx, chain, nonce, &[(r, candidate)]).await?;
        let tx_hash = format!("{:?}", signed.hash());
        mark(cx, r, &tx_hash, nonce).await?;
        tracing::info!(id = r.id, username = %r.full_username, nonce, tx = %tx_hash, "submitting registration");

        let (events, metadata) = finalize(cx, signed.submit_and_watch().await?).await?;
        check_proxied_call(&events, &metadata)
    }

    async fn submit_batch(
        cx: &Cx<'_>,
        chain: &PeopleChain,
        nonce: u64,
        rows: &[(&Reservation, [u8; 32])],
    ) -> Result<Vec<Result<(), String>>> {
        let signed = sign(cx, chain, nonce, rows).await?;
        let tx_hash = format!("{:?}", signed.hash());
        for (r, _) in rows {
            mark(cx, r, &tx_hash, nonce).await?;
        }
        tracing::info!(
            batch = rows.len(),
            nonce,
            tx = %tx_hash,
            "submitting registration batch"
        );
        metrics::histogram!("dub_chain_batch_items", "lane" => Self::NAME)
            .record(rows.len() as f64);

        let (events, metadata) = finalize(cx, signed.submit_and_watch().await?).await?;
        check_proxied_call(&events, &metadata)?;
        item_results(&events, &metadata)
    }

    async fn record(
        pool: &PgPool,
        guard: &Guard,
        r: &Reservation,
        outcome: Outcome<'_>,
    ) -> Result<(), WriterError> {
        match outcome {
            Outcome::Landed | Outcome::Observed => {
                let mut tx = pool.begin().await?;
                if !lease::fence(&mut tx, &guard.lease_name, &guard.holder_id, guard.epoch).await? {
                    return Err(WriterError::LeaseLost(Op::Landing));
                }
                if !outbox::mark_assigned(&mut *tx, guard, r.id).await? {
                    return Err(WriterError::LeaseLost(Op::Landing));
                }
                crate::widevine::store::consume_for_reservation(&mut *tx, r.id).await?;
                tx.commit().await?;
                record_submit_outcome(Self::NAME, "ok");
                let waited = (OffsetDateTime::now_utc() - r.created_at).as_seconds_f64();
                if outcome == Outcome::Landed {
                    metrics::histogram!("dub_registration_latency_seconds").record(waited.max(0.0));
                }
                tracing::info!(
                    id = r.id,
                    username = %r.full_username,
                    waited_secs = waited,
                    observed = outcome == Outcome::Observed,
                    "registration assigned on-chain"
                );
            }
            Outcome::Retry(reason) => {
                let attempt = r.attempt + 1;
                let backoff = row_backoff(attempt);
                let not_before = OffsetDateTime::now_utc() + backoff;
                if !outbox::mark_retry(pool, guard, r.id, not_before, attempt, reason).await? {
                    return Err(WriterError::LeaseLost(Op::Retrying));
                }
                record_submit_outcome(Self::NAME, "retry");
                tracing::warn!(
                    id = r.id,
                    attempt,
                    backoff_secs = backoff.whole_seconds(),
                    payload_version = r.payload_version,
                    reason,
                    "registration retry scheduled"
                );
            }
            Outcome::Park(reason) => {
                if !outbox::mark_retry(pool, guard, r.id, park_until(), r.attempt, reason).await? {
                    return Err(WriterError::LeaseLost(Op::Parking));
                }
                record_submit_outcome(Self::NAME, "parked");
                tracing::warn!(
                    id = r.id,
                    username = %r.full_username,
                    attempt = r.attempt,
                    backoff_secs = UNFUNDED_PARK_BACKOFF_SECS,
                    reason,
                    "registration parked without spending an attempt; the signer cannot pay fees"
                );
            }
            Outcome::Defer {
                until,
                reason,
                cause,
            } => {
                if !outbox::mark_retry(pool, guard, r.id, until, r.attempt, reason).await? {
                    return Err(WriterError::LeaseLost(Op::Deferring));
                }
                observe_defer(Self::NAME, r, until, reason, cause);
            }
            Outcome::Failed(reason) | Outcome::Expired(reason) => {
                let mut tx = pool.begin().await?;
                if !lease::fence(&mut tx, &guard.lease_name, &guard.holder_id, guard.epoch).await? {
                    return Err(WriterError::LeaseLost(Op::Failing));
                }
                if !outbox::mark_failed(&mut *tx, guard, r.id, reason).await? {
                    return Err(WriterError::LeaseLost(Op::Failing));
                }
                let released =
                    crate::widevine::store::release_for_reservation(&mut *tx, r.id).await?;
                tx.commit().await?;
                if released {
                    tracing::info!(
                        id = r.id,
                        "widevine device record released with the failed claim"
                    );
                }
                record_submit_outcome(Self::NAME, "terminal");
                tracing::warn!(
                    id = r.id,
                    username = %r.full_username,
                    payload_version = r.payload_version,
                    reason,
                    "registration failed terminally"
                );
            }
        }
        Ok(())
    }
}

async fn sign(
    cx: &Cx<'_>,
    chain: &PeopleChain,
    nonce: u64,
    rows: &[(&Reservation, [u8; 32])],
) -> Result<
    subxt::tx::SubmittableTransaction<
        PeopleConfig,
        subxt::client::OnlineClientAtBlockImpl<PeopleConfig>,
    >,
> {
    let payload = People::tx(rows, cx.proxy_for.as_ref());
    let params = PeopleExtrinsicParamsBuilder::new().nonce(nonce).build();
    let at = chain.online().at_current_block().await?;
    Ok(chain_client::create_signed_v4(&at, &payload, cx.signer, params).await?)
}

async fn mark(cx: &Cx<'_>, r: &Reservation, tx_hash: &str, nonce: u64) -> Result<(), WriterError> {
    if !outbox::mark_submitting(
        cx.pool,
        cx.guard,
        r.id,
        tx_hash,
        nonce as i64,
        r.attempt + 1,
    )
    .await?
    {
        return Err(WriterError::LeaseLost(Op::Submitting));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::attest::AttestShape;
    use crate::chain::writer::fixtures::{reservation, signed_people_reservation};
    use crate::signature::AccountSignatureForm;

    fn runtime(signature_form: AccountSignatureForm) -> PeopleRuntime {
        PeopleRuntime {
            signature_form,
            attest_shape: AttestShape::WithUsername,
        }
    }

    fn upgraded(signature_form: AccountSignatureForm) -> PeopleRuntime {
        PeopleRuntime {
            signature_form,
            attest_shape: AttestShape::WithoutUsername,
        }
    }

    fn failure(gate: Result<[u8; 32], Gate>) -> String {
        match gate {
            Err(Gate::Failed(reason)) => reason,
            Ok(_) => panic!("gate passed"),
            Err(_) => panic!("gate did not fail terminally"),
        }
    }

    #[test]
    fn a_genuinely_signed_registration_passes_the_gate() {
        // Candidate signed the attest message over the plain form.
        let (r, candidate) = signed_people_reservation();

        // The People runtime accepts the plain form.
        assert_eq!(
            People::gate(&r, runtime(AccountSignatureForm::Plain), 0).ok(),
            Some(candidate)
        );
    }

    #[test]
    fn a_registration_the_runtime_would_reject_fails_before_submission() {
        let (r, _) = signed_people_reservation();

        // The runtime moved to the signing context; the plain signature no
        // longer verifies.
        assert_eq!(
            failure(People::gate(
                &r,
                runtime(AccountSignatureForm::InContext([9; 32])),
                0
            )),
            BAD_CANDIDATE_SIGNATURE
        );

        // A tampered signature fails in the form it was made for.
        let mut tampered = r.clone();
        tampered.candidate_signature[0] ^= 1;
        assert_eq!(
            failure(People::gate(
                &tampered,
                runtime(AccountSignatureForm::Plain),
                0
            )),
            BAD_CANDIDATE_SIGNATURE
        );

        // A row without a parseable candidate fails on that first.
        assert_eq!(
            failure(People::gate(
                &reservation(),
                runtime(AccountSignatureForm::Plain),
                0
            )),
            "invalid candidate SS58"
        );
    }

    #[test]
    fn a_row_in_the_format_the_runtime_takes_passes() {
        let (mut r, candidate) = signed_people_reservation();
        assert_eq!(
            People::gate(&r, runtime(AccountSignatureForm::Plain), 0).ok(),
            Some(candidate),
            "a format-1 row on a runtime that takes the username"
        );

        r.payload_version = 2;
        assert_eq!(
            People::gate(&r, upgraded(AccountSignatureForm::Plain), 0).ok(),
            Some(candidate),
            "a format-2 row on a runtime without the username"
        );
    }

    #[test]
    fn a_username_signed_row_fails_once_the_runtime_dropped_the_username() {
        let (r, _) = signed_people_reservation();
        assert_eq!(r.payload_version, 1, "the fixture is a format-1 row");

        assert_eq!(
            failure(People::gate(&r, upgraded(AccountSignatureForm::Plain), 0)),
            "payload version 1 is no longer accepted: the runtime takes 2",
            "only the client can re-sign the consumer payload, so retrying is futile"
        );
    }

    #[test]
    fn a_row_signed_ahead_of_the_upgrade_waits_without_failing() {
        let (mut r, _) = signed_people_reservation();
        r.payload_version = 2;
        let now = 1_750_000_000;

        let Err(Gate::NotYet { until, reason }) =
            People::gate(&r, runtime(AccountSignatureForm::Plain), now)
        else {
            panic!("a format-2 row must be deferred on a runtime that takes the username");
        };
        assert_eq!(
            until.unix_timestamp(),
            now + PENDING_RUNTIME_DEFER_SECS,
            "the row is looked at again after the defer interval"
        );
        assert_eq!(
            reason,
            "payload version 2 awaits the runtime upgrade: the runtime takes 1"
        );
    }

    #[test]
    fn an_unknown_stored_payload_version_fails() {
        let (mut r, _) = signed_people_reservation();
        r.payload_version = 9;

        assert_eq!(
            failure(People::gate(&r, runtime(AccountSignatureForm::Plain), 0)),
            "unsupported payload version 9",
            "intake never stores it, so a row carrying one is corrupt"
        );
    }

    #[test]
    fn the_version_is_checked_before_the_signature() {
        let (mut r, _) = signed_people_reservation();
        r.candidate_signature[0] ^= 1;

        assert_eq!(
            failure(People::gate(&r, upgraded(AccountSignatureForm::Plain), 0)),
            "payload version 1 is no longer accepted: the runtime takes 2",
            "a row failing both checks is reported for its version, since re-signing \
             in the old format would not help"
        );
    }
}
