// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use device_attestation::chain::lease;
use device_attestation::chain::outbox::{self, NewReservation};
use device_attestation::queue;
use sqlx::{Connection as _, PgConnection, Row as _};

const EXCLUSIVE_LOCK: i64 = 0x0d07_15e0;

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

fn reservation(base: &str, digits: &str, account: &str) -> NewReservation {
    NewReservation {
        account_id: account.to_string(),
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
        dotns_expires_at: None,
        reserved_username: None,
    }
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn advancer_promotes_by_slot_rules_until_the_queue_drains() {
    let database_url = std::env::var("DEVICE_ATTESTATION_TEST_DATABASE_URL")
        .expect("DEVICE_ATTESTATION_TEST_DATABASE_URL is required");
    let _exclusive = lock_exclusive(&database_url).await;
    let pool = device_attestation::db::connect(&database_url)
        .await
        .expect("connect and migrate");
    let base = format!("queuetest{}", std::process::id());

    sqlx::query(
        "DELETE FROM username_reservations WHERE status = 'QUEUED' OR base LIKE 'queuetest%'",
    )
    .execute(&pool)
    .await
    .expect("pre-clean reservations");
    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(queue::ADVANCER_LEASE_NAME)
        .execute(&pool)
        .await
        .expect("pre-clean advancer lease");

    let groups: [i32; 6] = [1, 2, 3, 4, 4, 1];
    let mut ids = Vec::new();
    for (index, group) in groups.into_iter().enumerate() {
        let digits = format!("{:02}", index + 11);
        let account = format!("queue-subject-{index}");
        let id = outbox::insert_queued(&pool, &reservation(&base, &digits, &account), group)
            .await
            .expect("insert queued");
        ids.push(id);
    }

    let snapshot: Vec<_> = queue::queued_snapshot(&pool)
        .await
        .expect("snapshot")
        .into_iter()
        .filter(|entry| ids.contains(&entry.id))
        .collect();
    assert_eq!(
        snapshot.iter().map(|e| (e.id, e.group)).collect::<Vec<_>>(),
        ids.iter()
            .zip(groups)
            .map(|(&id, group)| (id, group as u8))
            .collect::<Vec<_>>()
    );

    let first = queue::advance_iteration(&pool).await.expect("iteration 1");
    assert_eq!(
        first.iter().map(|p| p.id).collect::<Vec<_>>(),
        [ids[3], ids[2], ids[1], ids[0]]
    );

    let second = queue::advance_iteration(&pool).await.expect("iteration 2");
    assert_eq!(
        second.iter().map(|p| p.id).collect::<Vec<_>>(),
        [ids[4], ids[5]]
    );
    assert_eq!(second[0].slot, 1);
    assert_eq!(second[1].slot, 4);

    let observed: Vec<(i64, u32)> = first
        .iter()
        .map(|p| (p.id, 1))
        .chain(second.iter().map(|p| (p.id, 2)))
        .collect();
    for (index, (id, iteration)) in observed.iter().enumerate() {
        let estimate = queue::drain_estimate(&snapshot, *id).expect("was queued");
        assert_eq!(
            estimate.position,
            index as u32 + 1,
            "simulation position matches the SQL promotion order for id {id}"
        );
        assert_eq!(
            estimate.iterations, *iteration,
            "simulation iteration matches the SQL iteration for id {id}"
        );
    }

    let statuses = sqlx::query("SELECT DISTINCT status FROM username_reservations WHERE base = $1")
        .bind(&base)
        .fetch_all(&pool)
        .await
        .expect("statuses");
    assert_eq!(statuses.len(), 1);
    assert_eq!(
        statuses[0].try_get::<String, _>("status").expect("status"),
        "RESERVED"
    );

    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(queue::ADVANCER_LEASE_NAME)
        .execute(&pool)
        .await
        .expect("clear advancer lease");
    assert!(!queue::advancer_alive(&pool).await.expect("probe"));

    let stranded = outbox::insert_queued(&pool, &reservation(&base, "17", "queue-subject-x"), 3)
        .await
        .expect("insert stranded");
    assert!(
        queue::stranded_queued(&pool).await.expect("stranded count") >= 1,
        "a queued row behind an absent lease counts as stranded"
    );
    queue::fallback_drain(&pool, std::time::Duration::from_secs(60))
        .await
        .expect("janitor drain");
    let status: String = sqlx::query("SELECT status FROM username_reservations WHERE id = $1")
        .bind(stranded)
        .fetch_one(&pool)
        .await
        .expect("stranded row")
        .try_get("status")
        .expect("status");
    assert_eq!(
        status, "RESERVED",
        "queue-disabled janitor drains rows behind an absent lease"
    );

    let epoch = lease::try_acquire(
        &pool,
        queue::ADVANCER_LEASE_NAME,
        "queue-live-test",
        std::time::Duration::from_secs(60),
    )
    .await
    .expect("acquire advancer lease")
    .expect("lease free");
    assert!(queue::advancer_alive(&pool).await.expect("probe"));

    let waiting = outbox::insert_queued(&pool, &reservation(&base, "18", "queue-subject-y"), 2)
        .await
        .expect("insert waiting");
    assert_eq!(
        queue::stranded_queued(&pool).await.expect("stranded count"),
        0,
        "a live advancer lease means queued rows are draining, not stranded"
    );
    queue::fallback_drain(&pool, std::time::Duration::from_secs(60))
        .await
        .expect("fallback drain with live lease");
    let status: String = sqlx::query("SELECT status FROM username_reservations WHERE id = $1")
        .bind(waiting)
        .fetch_one(&pool)
        .await
        .expect("waiting row")
        .try_get("status")
        .expect("status");
    assert_eq!(status, "QUEUED", "live queue service keeps claims queued");

    sqlx::query(
        "UPDATE writer_lease SET expires_at = now() - interval '10 seconds' WHERE name = $1",
    )
    .bind(queue::ADVANCER_LEASE_NAME)
    .execute(&pool)
    .await
    .expect("expire advancer lease");
    assert!(!queue::advancer_alive(&pool).await.expect("probe"));
    assert!(
        queue::stranded_queued(&pool).await.expect("stranded count") >= 1,
        "a queued row behind an expired lease counts as stranded"
    );
    assert!(
        !lease::renew(
            &pool,
            queue::ADVANCER_LEASE_NAME,
            "queue-live-test",
            epoch,
            std::time::Duration::from_secs(60),
        )
        .await
        .expect("renew attempt"),
        "renew must refuse an expired lease"
    );

    queue::fallback_drain(&pool, std::time::Duration::from_secs(60))
        .await
        .expect("drain within grace");
    let status: String = sqlx::query("SELECT status FROM username_reservations WHERE id = $1")
        .bind(waiting)
        .fetch_one(&pool)
        .await
        .expect("waiting row")
        .try_get("status")
        .expect("status");
    assert_eq!(status, "QUEUED", "expired within grace: queue holds");

    queue::fallback_drain(&pool, std::time::Duration::from_secs(5))
        .await
        .expect("drain beyond grace");
    let status: String = sqlx::query("SELECT status FROM username_reservations WHERE id = $1")
        .bind(waiting)
        .fetch_one(&pool)
        .await
        .expect("waiting row")
        .try_get("status")
        .expect("status");
    assert_eq!(status, "RESERVED", "expired beyond grace: queue drains");

    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(queue::ADVANCER_LEASE_NAME)
        .execute(&pool)
        .await
        .expect("clean advancer lease");
    sqlx::query("DELETE FROM username_reservations WHERE base = $1")
        .bind(&base)
        .execute(&pool)
        .await
        .expect("clean test rows");
}

/// A dotns-carrying reservation whose signature dies `validity` from now.
fn expiring(base: &str, digits: &str, account: &str, validity: time::Duration) -> NewReservation {
    let now = time::OffsetDateTime::now_utc();
    NewReservation {
        dotns_signature: Some(vec![6; 64]),
        dotns_signed_at: Some(now.unix_timestamp()),
        dotns_expires_at: Some(now + validity),
        ..reservation(base, digits, account)
    }
}

async fn statuses(pool: &sqlx::PgPool, id: i64) -> (String, Option<String>) {
    let row = sqlx::query("SELECT status, dotns_status FROM username_reservations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read row");
    (
        row.try_get("status").expect("status"),
        row.try_get("dotns_status").expect("dotns_status"),
    )
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn a_reservation_that_died_in_the_queue_is_swept_not_promoted() {
    let database_url = std::env::var("DEVICE_ATTESTATION_TEST_DATABASE_URL")
        .expect("DEVICE_ATTESTATION_TEST_DATABASE_URL is required");
    let _exclusive = lock_exclusive(&database_url).await;
    let pool = device_attestation::db::connect(&database_url)
        .await
        .expect("connect and migrate");
    let base = format!("queueexpiry{}", std::process::id());

    sqlx::query(
        "DELETE FROM username_reservations WHERE status = 'QUEUED' OR base LIKE 'queueexpiry%'",
    )
    .execute(&pool)
    .await
    .expect("pre-clean");

    let dead = outbox::insert_queued(
        &pool,
        &expiring(&base, "11", "sub-dead", time::Duration::seconds(-1)),
        4,
    )
    .await
    .expect("insert dead");
    let live = outbox::insert_queued(
        &pool,
        &expiring(&base, "12", "sub-live", time::Duration::hours(48)),
        4,
    )
    .await
    .expect("insert live");
    let undated = outbox::insert_queued(&pool, &reservation(&base, "13", "sub-undated"), 4)
        .await
        .expect("insert undated");

    let swept = queue::expire_queued(&pool).await.expect("sweep");
    assert_eq!(swept, 1, "only the row past its deadline");

    assert_eq!(
        statuses(&pool, dead).await,
        ("ABANDONED".to_string(), Some("EXPIRED".to_string())),
        "an expired reservation is terminal for the whole claim"
    );
    assert_eq!(
        statuses(&pool, live).await.0,
        "QUEUED",
        "a live claim keeps its place"
    );
    assert_eq!(
        statuses(&pool, undated).await.0,
        "QUEUED",
        "a row carrying no dotns block has no deadline to miss"
    );

    // The swept row must not consume a promotion slot.
    let promoted = queue::advance_iteration(&pool).await.expect("advance");
    let ids: Vec<i64> = promoted.iter().map(|p| p.id).collect();
    assert!(!ids.contains(&dead), "a doomed row never takes a slot");
    assert!(ids.contains(&live) && ids.contains(&undated));

    sqlx::query("DELETE FROM username_reservations WHERE base = $1")
        .bind(&base)
        .execute(&pool)
        .await
        .expect("clean up");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn a_claim_about_to_expire_outranks_balance_priority() {
    let database_url = std::env::var("DEVICE_ATTESTATION_TEST_DATABASE_URL")
        .expect("DEVICE_ATTESTATION_TEST_DATABASE_URL is required");
    let _exclusive = lock_exclusive(&database_url).await;
    let pool = device_attestation::db::connect(&database_url)
        .await
        .expect("connect and migrate");
    let base = format!("queueatrisk{}", std::process::id());

    sqlx::query(
        "DELETE FROM username_reservations WHERE status = 'QUEUED' OR base LIKE 'queueatrisk%'",
    )
    .execute(&pool)
    .await
    .expect("pre-clean");

    // Enqueued first, richest group: without the deadline rule these would
    // take every slot.
    let mut wealthy = Vec::new();
    for digits in ["21", "22", "23", "24"] {
        wealthy.push(
            outbox::insert_queued(&pool, &reservation(&base, digits, "sub-wealthy"), 4)
                .await
                .expect("insert wealthy"),
        );
    }
    // Enqueued last, poorest group, but minutes from expiry.
    let at_risk = outbox::insert_queued(
        &pool,
        &expiring(&base, "25", "sub-atrisk", time::Duration::minutes(5)),
        1,
    )
    .await
    .expect("insert at risk");

    let promoted = queue::advance_iteration_within(&pool, std::time::Duration::from_secs(3600))
        .await
        .expect("advance");
    let ids: Vec<i64> = promoted.iter().map(|p| p.id).collect();

    assert_eq!(
        ids.first().copied(),
        Some(at_risk),
        "the claim about to stop existing goes first"
    );
    assert_eq!(promoted.len(), 4, "the budget is reordered, not widened");
    assert_eq!(
        ids.iter().filter(|id| wealthy.contains(id)).count(),
        3,
        "the at-risk row took one of the four slots"
    );

    // With no horizon the ordering is the original balance-priority FIFO.
    let promoted = queue::advance_iteration(&pool).await.expect("advance");
    assert_eq!(
        promoted.first().map(|p| p.id),
        Some(wealthy[3]),
        "without a horizon the deadline rule is inert"
    );

    sqlx::query("DELETE FROM username_reservations WHERE base = $1")
        .bind(&base)
        .execute(&pool)
        .await
        .expect("clean up");
}
