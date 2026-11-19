// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeSet;

use device_attestation::chain::outbox::{
    self, InsertError, NewReservation, Status, FAILED_DISCRIMINATOR_HOLD,
};
use sqlx::PgPool;

async fn connect() -> PgPool {
    let database_url = std::env::var("DEVICE_ATTESTATION_TEST_DATABASE_URL")
        .expect("DEVICE_ATTESTATION_TEST_DATABASE_URL is required");
    device_attestation::db::connect(&database_url)
        .await
        .expect("connect and migrate")
}

fn reservation(base: &str, digits: &str) -> NewReservation {
    NewReservation {
        account_id: "test-subject".to_string(),
        candidate_account_id: "test-candidate".to_string(),
        base: base.to_string(),
        digits: digits.to_string(),
        full_username: format!("{base}.{digits}"),
        candidate_signature: vec![1; 64],
        ring_vrf_key: vec![2; 32],
        proof_of_ownership: vec![3; 64],
        consumer_registration_signature: vec![4; 64],
        identifier_key: vec![5; 65],
        dotns_signature: None,
        dotns_signed_at: None,
        reserved_username: None,
        payload_version: 1,
    }
}

/// Put row `id` in `status`, as last updated `age` ago.
async fn set_status(pool: &PgPool, id: i64, status: Status, age: time::Duration) {
    sqlx::query(
        "UPDATE username_reservations \
         SET status = $1, updated_at = now() - make_interval(secs => $2::float8) \
         WHERE id = $3",
    )
    .bind(status.as_str())
    .bind(age.whole_seconds())
    .bind(id)
    .execute(pool)
    .await
    .expect("set status");
}

async fn clean(pool: &PgPool, base: &str) {
    sqlx::query("DELETE FROM username_reservations WHERE base = $1")
        .bind(base)
        .execute(pool)
        .await
        .expect("clean test rows");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn rows_that_can_land_and_recent_failures_stay_allocated() {
    let pool = connect().await;
    let base = format!("allocationtest{}", std::process::id());
    let long_ago = FAILED_DISCRIMINATOR_HOLD * 2;

    for (digits, status, age) in [
        ("10", Status::Queued, long_ago),
        ("11", Status::Reserved, long_ago),
        ("12", Status::Submitting, long_ago),
        ("13", Status::Assigned, long_ago),
        ("14", Status::RetryAfter, long_ago),
        ("15", Status::FailedTerminal, time::Duration::ZERO),
        ("16", Status::FailedTerminal, long_ago),
    ] {
        let id = outbox::insert(&pool, &reservation(&base, digits))
            .await
            .expect("insert");
        set_status(&pool, id, status, age).await;
    }

    let allocated = outbox::allocated_discriminators(&pool, &base)
        .await
        .expect("read allocations");
    assert_eq!(
        allocated,
        BTreeSet::from([10, 11, 12, 13, 14, 15]),
        "a row that can still land holds its digits however old it is; a failed \
         row holds them only for FAILED_DISCRIMINATOR_HOLD"
    );

    clean(&pool, &base).await;
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn a_failed_row_does_not_block_its_username_being_claimed_again() {
    let pool = connect().await;
    let base = format!("reclaimtest{}", std::process::id());

    let failed = outbox::insert(&pool, &reservation(&base, "21"))
        .await
        .expect("first claim");
    set_status(
        &pool,
        failed,
        Status::FailedTerminal,
        FAILED_DISCRIMINATOR_HOLD * 2,
    )
    .await;

    let reclaimed = outbox::insert(&pool, &reservation(&base, "21"))
        .await
        .expect("a failed row leaves its username free to claim again");
    assert_ne!(reclaimed, failed);

    assert!(
        matches!(
            outbox::insert(&pool, &reservation(&base, "21")).await,
            Err(InsertError::Conflict)
        ),
        "two rows that can both still land never share a username"
    );

    clean(&pool, &base).await;
}

fn cap(n: u16) -> Option<std::num::NonZeroU16> {
    std::num::NonZeroU16::new(n)
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn a_base_takes_no_more_open_claims_than_its_cap() {
    let pool = connect().await;
    let base = format!("captest{}", std::process::id());

    let mut ids = Vec::new();
    for digits in ["31", "32", "33"] {
        ids.push(
            outbox::insert_capped(&pool, &reservation(&base, digits), None, cap(3))
                .await
                .expect("under the cap"),
        );
    }
    assert!(
        matches!(
            outbox::insert_capped(&pool, &reservation(&base, "34"), Some(1), cap(3)).await,
            Err(InsertError::BaseBusy)
        ),
        "a fourth open claim is refused, on the queued lane too"
    );
    assert_eq!(outbox::open_claims(&pool, &base).await.unwrap(), 3);

    // A claim that lands frees its slot.
    set_status(&pool, ids[0], Status::Assigned, time::Duration::ZERO).await;
    outbox::insert_capped(&pool, &reservation(&base, "34"), None, cap(3))
        .await
        .expect("an assigned claim no longer counts");

    // A claim that fails keeps its slot while it keeps its discriminator, so
    // failing fast does not let one party cycle more claims through a base.
    set_status(&pool, ids[1], Status::FailedTerminal, time::Duration::ZERO).await;
    assert!(
        matches!(
            outbox::insert_capped(&pool, &reservation(&base, "35"), Some(1), cap(3)).await,
            Err(InsertError::BaseBusy)
        ),
        "a failed claim inside FAILED_DISCRIMINATOR_HOLD still counts"
    );
    assert_eq!(outbox::open_claims(&pool, &base).await.unwrap(), 3);
    set_status(
        &pool,
        ids[1],
        Status::FailedTerminal,
        FAILED_DISCRIMINATOR_HOLD * 2,
    )
    .await;
    outbox::insert_capped(&pool, &reservation(&base, "35"), Some(1), cap(3))
        .await
        .expect("a failed claim past the hold no longer counts");
    assert!(matches!(
        outbox::insert_capped(&pool, &reservation(&base, "36"), None, cap(3)).await,
        Err(InsertError::BaseBusy)
    ));

    // Another base is unaffected, and no cap means no limit.
    let other = format!("{base}x");
    outbox::insert_capped(&pool, &reservation(&other, "31"), None, cap(3))
        .await
        .expect("caps are per base");
    outbox::insert_capped(&pool, &reservation(&base, "36"), None, None)
        .await
        .expect("an uncapped insert ignores the count");

    clean(&pool, &base).await;
    clean(&pool, &other).await;
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn concurrent_claims_never_exceed_the_cap() {
    let pool = connect().await;
    let base = format!("capracetest{}", std::process::id());

    let attempts = (40..60u8).map(|digits| {
        let pool = pool.clone();
        let new = reservation(&base, &digits.to_string());
        tokio::spawn(async move { outbox::insert_capped(&pool, &new, None, cap(5)).await })
    });
    let mut stored = 0;
    let mut refused = 0;
    for attempt in attempts {
        match attempt.await.expect("task") {
            Ok(_) => stored += 1,
            Err(InsertError::BaseBusy) => refused += 1,
            Err(e) => panic!("unexpected insert error: {e}"),
        }
    }
    assert_eq!((stored, refused), (5, 15));
    assert_eq!(outbox::open_claims(&pool, &base).await.unwrap(), 5);

    clean(&pool, &base).await;
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn a_refused_claim_leaves_the_callers_transaction_usable() {
    let pool = connect().await;
    let base = format!("captxtest{}", std::process::id());
    outbox::insert_capped(&pool, &reservation(&base, "51"), None, cap(1))
        .await
        .expect("first claim");

    let mut tx = pool.begin().await.expect("begin");
    assert!(matches!(
        outbox::insert_capped(&mut *tx, &reservation(&base, "52"), None, cap(1)).await,
        Err(InsertError::BaseBusy)
    ));
    // The refusal rolled back only its savepoint.
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut *tx)
        .await
        .expect("the outer transaction is still usable");
    assert_eq!(one, 1);
    tx.commit().await.expect("commit");

    clean(&pool, &base).await;
}
