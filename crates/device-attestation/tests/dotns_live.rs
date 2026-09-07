// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use device_attestation::chain::lease;
use device_attestation::chain::outbox::{self, DotnsStatus, Guard, NewReservation, Status};
use sqlx::{Connection as _, PgConnection, PgPool, Row as _};
use std::time::Duration;

const LEASE: &str = "dotns-live-test-writer";

const EXCLUSIVE_LOCK: i64 = 0x0d07_1553;

async fn lock_exclusive(database_url: &str) -> PgConnection {
    let mut conn = PgConnection::connect(database_url)
        .await
        .expect("connect for advisory lock");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(EXCLUSIVE_LOCK)
        .execute(&mut conn)
        .await
        .expect("take the exclusive test lock");
    conn
}

fn reservation(base: &str, digits: &str, with_dotns: bool) -> NewReservation {
    NewReservation {
        account_id: format!("dotns-subject-{digits}"),
        candidate_account_id: "test-candidate".to_string(),
        base: base.to_string(),
        digits: digits.to_string(),
        full_username: format!("{base}.{digits}"),
        candidate_signature: vec![1; 64],
        ring_vrf_key: vec![2; 32],
        proof_of_ownership: vec![3; 64],
        consumer_registration_signature: vec![4; 64],
        identifier_key: vec![5; 65],
        dotns_signature: with_dotns.then(|| vec![6; 64]),
        dotns_signed_at: with_dotns.then_some(1_750_000_000),
        dotns_expires_at: None,
        reserved_username: None,
    }
}

async fn dotns_status(pool: &PgPool, id: i64) -> Option<String> {
    sqlx::query("SELECT dotns_status FROM username_reservations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read dotns_status")
        .try_get::<Option<String>, _>("dotns_status")
        .expect("decode dotns_status")
}

async fn people_status(pool: &PgPool, id: i64) -> String {
    sqlx::query("SELECT status FROM username_reservations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read status")
        .try_get("status")
        .expect("decode status")
}

async fn set_people_status(pool: &PgPool, id: i64, status: Status) {
    sqlx::query("UPDATE username_reservations SET status = $1 WHERE id = $2")
        .bind(status.as_str())
        .bind(id)
        .execute(pool)
        .await
        .expect("set people status");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn the_dotns_lane_leads_and_claims_reserved_rows() {
    let database_url = std::env::var("DEVICE_ATTESTATION_TEST_DATABASE_URL")
        .expect("DEVICE_ATTESTATION_TEST_DATABASE_URL is required");
    let _exclusive = lock_exclusive(&database_url).await;
    let pool = device_attestation::db::connect(&database_url)
        .await
        .expect("connect and migrate");
    let base = format!("dotnstest{}", std::process::id());

    sqlx::query("DELETE FROM username_reservations WHERE dotns_status IS NOT NULL OR base LIKE 'dotnstest%'")
        .execute(&pool)
        .await
        .expect("pre-clean reservations");
    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(LEASE)
        .execute(&pool)
        .await
        .expect("pre-clean lease");

    let in_lane = outbox::insert(&pool, &reservation(&base, "11", true))
        .await
        .expect("insert with dotns");
    let no_block = outbox::insert(&pool, &reservation(&base, "12", false))
        .await
        .expect("insert without dotns");
    let still_queued = outbox::insert_queued(&pool, &reservation(&base, "13", true), 1)
        .await
        .expect("insert queued with dotns");

    assert_eq!(
        dotns_status(&pool, in_lane).await.as_deref(),
        Some(DotnsStatus::Pending.as_str())
    );
    assert_eq!(dotns_status(&pool, no_block).await, None);

    let due = outbox::claim_dotns_due(&pool, 50).await.expect("claim");
    assert_eq!(due.iter().map(|r| r.id).collect::<Vec<_>>(), vec![in_lane]);
    assert!(!due.iter().any(|r| r.id == no_block));
    assert!(!due.iter().any(|r| r.id == still_queued));

    let claimed = &due[0];
    assert_eq!(claimed.dotns_signature.as_deref(), Some(&[6u8; 64][..]));
    assert_eq!(claimed.dotns_signed_at, Some(1_750_000_000));
    assert_eq!(claimed.dotns_attempt, 0);
    assert_eq!(
        people_status(&pool, in_lane).await,
        Status::Reserved.as_str()
    );

    let epoch = lease::try_acquire(&pool, LEASE, "holder-a", Duration::from_secs(30))
        .await
        .expect("acquire lease")
        .expect("lease is free");
    let guard = Guard {
        lease_name: LEASE.to_string(),
        holder_id: "holder-a".to_string(),
        epoch,
    };

    assert!(
        outbox::mark_dotns_submitting(&pool, &guard, in_lane, "0xdeadbeef", 1)
            .await
            .expect("mark submitting")
    );
    assert_eq!(
        dotns_status(&pool, in_lane).await.as_deref(),
        Some(DotnsStatus::Submitting.as_str())
    );
    assert_eq!(
        outbox::dotns_submitting(&pool)
            .await
            .expect("submitting scan")
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        vec![in_lane]
    );

    assert!(
        outbox::mark_dotns_failed(&pool, &guard, in_lane, "dotns signature does not verify")
            .await
            .expect("mark failed")
    );
    assert_eq!(
        dotns_status(&pool, in_lane).await.as_deref(),
        Some(DotnsStatus::FailedTerminal.as_str())
    );
    assert_eq!(
        people_status(&pool, in_lane).await,
        Status::Abandoned.as_str(),
        "no authoritative name means the People half is never attempted"
    );
    assert!(outbox::claim_dotns_due(&pool, 50)
        .await
        .expect("claim")
        .is_empty());

    let stale = Guard {
        lease_name: LEASE.to_string(),
        holder_id: "holder-b".to_string(),
        epoch: epoch + 99,
    };
    assert!(!outbox::mark_dotns_reserved(&pool, &stale, in_lane)
        .await
        .expect("stale write"));
    assert_eq!(
        dotns_status(&pool, in_lane).await.as_deref(),
        Some(DotnsStatus::FailedTerminal.as_str())
    );

    set_people_status(&pool, still_queued, Status::Reserved).await;
    assert!(
        outbox::mark_dotns_expired(&pool, &guard, still_queued, "signature expired")
            .await
            .expect("mark expired")
    );
    assert_eq!(
        dotns_status(&pool, still_queued).await.as_deref(),
        Some(DotnsStatus::Expired.as_str())
    );
    assert_eq!(
        people_status(&pool, still_queued).await,
        Status::Abandoned.as_str(),
        "an expired reservation abandons the claim outright"
    );

    let depths = outbox::dotns_depth_by_status(&pool)
        .await
        .expect("dotns depths");
    assert_eq!(depths.len(), DotnsStatus::ALL.len());
    let total: i64 = depths.iter().map(|(_, d)| d.depth).sum();
    assert_eq!(total, 2, "only the two rows carrying a dotns block");

    sqlx::query("DELETE FROM username_reservations WHERE base = $1")
        .bind(&base)
        .execute(&pool)
        .await
        .expect("clean up");
    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(LEASE)
        .execute(&pool)
        .await
        .expect("clean up lease");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn a_terminal_dotns_failure_abandons_every_open_people_state() {
    let database_url = std::env::var("DEVICE_ATTESTATION_TEST_DATABASE_URL")
        .expect("DEVICE_ATTESTATION_TEST_DATABASE_URL is required");
    let _exclusive = lock_exclusive(&database_url).await;
    let pool = device_attestation::db::connect(&database_url)
        .await
        .expect("connect and migrate");
    let base = format!("dotnsdead{}", std::process::id());

    sqlx::query("DELETE FROM username_reservations WHERE base LIKE 'dotnsdead%'")
        .execute(&pool)
        .await
        .expect("pre-clean");
    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(LEASE)
        .execute(&pool)
        .await
        .expect("pre-clean lease");

    let queued = outbox::insert_queued(&pool, &reservation(&base, "31", true), 1)
        .await
        .expect("insert queued");
    let reserved = outbox::insert(&pool, &reservation(&base, "32", true))
        .await
        .expect("insert reserved");
    let retrying = outbox::insert(&pool, &reservation(&base, "33", true))
        .await
        .expect("insert retrying");
    let submitting = outbox::insert(&pool, &reservation(&base, "34", true))
        .await
        .expect("insert submitting");
    let assigned = outbox::insert(&pool, &reservation(&base, "35", true))
        .await
        .expect("insert assigned");

    let epoch = lease::try_acquire(&pool, LEASE, "holder-a", Duration::from_secs(30))
        .await
        .expect("acquire lease")
        .expect("lease is free");
    let guard = Guard {
        lease_name: LEASE.to_string(),
        holder_id: "holder-a".to_string(),
        epoch,
    };

    set_people_status(&pool, retrying, Status::RetryAfter).await;
    set_people_status(&pool, submitting, Status::Submitting).await;
    set_people_status(&pool, assigned, Status::Assigned).await;
    sqlx::query(
        "UPDATE username_reservations SET not_before = now() + interval '1 hour' WHERE id = $1",
    )
    .bind(retrying)
    .execute(&pool)
    .await
    .expect("gate the retry");

    for id in [queued, reserved, retrying, submitting, assigned] {
        assert!(
            outbox::mark_dotns_failed(&pool, &guard, id, "label owned by another account")
                .await
                .expect("fail on dotns")
        );
        assert_eq!(
            dotns_status(&pool, id).await.as_deref(),
            Some(DotnsStatus::FailedTerminal.as_str())
        );
    }

    for id in [queued, reserved, retrying] {
        assert_eq!(
            people_status(&pool, id).await,
            Status::Abandoned.as_str(),
            "an open People state is closed out with the dotNS failure"
        );
    }
    assert_eq!(
        people_status(&pool, submitting).await,
        Status::Submitting.as_str(),
        "a row with an extrinsic in flight is left for reconciliation"
    );
    assert_eq!(
        people_status(&pool, assigned).await,
        Status::Assigned.as_str(),
        "a landed consumer record is never rewritten"
    );

    let reason: Option<String> =
        sqlx::query("SELECT last_error FROM username_reservations WHERE id = $1")
            .bind(queued)
            .fetch_one(&pool)
            .await
            .expect("read last_error")
            .try_get("last_error")
            .expect("decode last_error");
    assert_eq!(
        reason.as_deref(),
        Some("dotNS reservation failed terminally; People registration never attempted")
    );
    let not_before: Option<time::OffsetDateTime> =
        sqlx::query("SELECT not_before FROM username_reservations WHERE id = $1")
            .bind(retrying)
            .fetch_one(&pool)
            .await
            .expect("read not_before")
            .try_get("not_before")
            .expect("decode not_before");
    assert!(
        not_before.is_none(),
        "an abandoned row is not waiting on a backoff"
    );

    let depths = outbox::depth_by_status(&pool).await.expect("people depths");
    let depth_of = |status: Status| {
        depths
            .iter()
            .find(|(s, _)| *s == status)
            .map(|(_, d)| d.depth)
            .expect("every status is reported")
    };
    assert_eq!(depth_of(Status::Abandoned), 3);
    assert_eq!(depth_of(Status::Queued), 0);

    sqlx::query("DELETE FROM username_reservations WHERE base = $1")
        .bind(&base)
        .execute(&pool)
        .await
        .expect("clean up");
    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(LEASE)
        .execute(&pool)
        .await
        .expect("clean up lease");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn rows_predating_the_lane_are_never_submitted() {
    let database_url = std::env::var("DEVICE_ATTESTATION_TEST_DATABASE_URL")
        .expect("DEVICE_ATTESTATION_TEST_DATABASE_URL is required");
    let _exclusive = lock_exclusive(&database_url).await;
    let pool = device_attestation::db::connect(&database_url)
        .await
        .expect("connect and migrate");
    let base = format!("dotnsold{}", std::process::id());

    sqlx::query("DELETE FROM username_reservations WHERE base LIKE 'dotnsold%'")
        .execute(&pool)
        .await
        .expect("pre-clean");

    let id = outbox::insert(&pool, &reservation(&base, "21", true))
        .await
        .expect("insert");
    sqlx::query(
        "UPDATE username_reservations SET dotns_status = NULL, status = 'ASSIGNED' WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .expect("clear dotns_status");

    assert!(
        !outbox::claim_dotns_due(&pool, 50)
            .await
            .expect("claim")
            .iter()
            .any(|r| r.id == id),
        "a NULL dotns_status row must never enter the lane"
    );

    sqlx::query("DELETE FROM username_reservations WHERE base = $1")
        .bind(&base)
        .execute(&pool)
        .await
        .expect("clean up");
}
