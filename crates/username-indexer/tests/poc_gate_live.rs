// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use sqlx::postgres::PgPoolOptions;
use username_indexer::poc::puzzle::{checksum_hex, derive_secret};
use username_indexer::poc::solution::mine;
use username_indexer::poc::{now_millis, Poc, Rejection, Solution};
use uuid::Uuid;

const IKM: &str = "test-poc-ikm";
const DIFFICULTY: u8 = 8;

fn gate() -> Poc {
    let verifying_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    Poc::new(
        derive_secret(IKM),
        DIFFICULTY,
        jwt_verify::Verifier::from_public_key(None, verifying_key.as_bytes()),
    )
}

fn solved(timestamp_ms: i64) -> Solution {
    let session_id = Uuid::new_v4();
    Solution::new(
        session_id,
        timestamp_ms,
        DIFFICULTY,
        mine(session_id, timestamp_ms, DIFFICULTY),
        checksum_hex(&derive_secret(IKM), session_id, timestamp_ms, DIFFICULTY),
    )
}

#[tokio::test]
#[ignore = "requires a live DATABASE_URL Postgres; run manually with --ignored"]
async fn a_solved_puzzle_is_consumed_exactly_once() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset; skipping live proof-of-compute test");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("connect to live Postgres");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations apply");

    let now = now_millis();
    let solution = solved(now);

    assert_eq!(
        gate()
            .verify(&pool, &solution, now)
            .await
            .expect("no database error"),
        Ok(())
    );

    assert_eq!(
        gate()
            .verify(&pool, &solution, now)
            .await
            .expect("no database error"),
        Err(Rejection::Replayed)
    );

    let other = solved(now);
    assert_eq!(
        gate()
            .verify(&pool, &other, now)
            .await
            .expect("no database error"),
        Ok(())
    );

    let retained = username_indexer::poc::store::prune_expired(&pool)
        .await
        .expect("prune runs");
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM spent_puzzles")
        .fetch_one(&pool)
        .await
        .expect("count rows");
    assert!(
        remaining >= 2,
        "the two fresh sessions must survive pruning (pruned {retained}, remaining {remaining})"
    );

    sqlx::query("DELETE FROM spent_puzzles WHERE session_id = ANY($1)")
        .bind(vec![solution.session_id(), other.session_id()])
        .execute(&pool)
        .await
        .expect("cleanup");
}
