// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use sqlx::{Connection as _, PgConnection, Row as _};
use username_indexer::{AssignedUsername, Source};

const EXCLUSIVE_LOCK: i64 = 0x0d07_5011;

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

fn record(account: u8, name: &str, source: Source) -> AssignedUsername {
    let (base, digits) = name.rsplit_once('.').expect("lite label");
    AssignedUsername {
        account_id: [account; 32],
        account_id_ss58: format!("ss58-{account}"),
        identifier_key: [0u8; 65],
        lite_username: name.to_string(),
        lite_base: base.to_string(),
        lite_digits: digits.to_string(),
        full_username: None,
        display_username: name.to_string(),
        snapshot_hash: [1u8; 32],
        snapshot_number: 1,
        source,
    }
}

async fn stored(pool: &sqlx::PgPool, account: u8) -> Option<(String, String)> {
    let row = sqlx::query(
        "SELECT display_username, source FROM assigned_usernames WHERE account_id = $1",
    )
    .bind([account; 32].as_slice())
    .fetch_optional(pool)
    .await
    .expect("read row")?;
    Some((
        row.try_get("display_username").expect("display"),
        row.try_get("source").expect("source"),
    ))
}

#[tokio::test]
#[ignore = "requires Postgres; set DATABASE_URL and run with --ignored"]
async fn a_gateway_row_outranks_a_people_row_in_one_direction_only() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required");
    let _exclusive = lock_exclusive(&database_url).await;
    let pool = username_indexer::db::connect(&database_url)
        .await
        .expect("connect and migrate");

    sqlx::query("DELETE FROM assigned_usernames WHERE account_id = ANY($1)")
        .bind(vec![[7u8; 32].to_vec(), [8u8; 32].to_vec()])
        .execute(&pool)
        .await
        .expect("pre-clean");

    // An account the People ingest saw first.
    let mut tx = pool.begin().await.expect("begin");
    username_indexer::projection::upsert(&mut tx, &record(7, "legacy.11", Source::People), 1)
        .await
        .expect("people upsert");
    tx.commit().await.expect("commit");
    assert_eq!(
        stored(&pool, 7).await,
        Some(("legacy.11".to_string(), "people".to_string()))
    );

    // The gateway answers for it later: the gateway's name wins.
    let mut tx = pool.begin().await.expect("begin");
    username_indexer::projection::upsert(&mut tx, &record(7, "gateway.22", Source::AssetHub), 2)
        .await
        .expect("gateway upsert");
    tx.commit().await.expect("commit");
    assert_eq!(
        stored(&pool, 7).await,
        Some(("gateway.22".to_string(), "asset-hub".to_string())),
        "the name authority replaces the legacy row"
    );

    // The People ingest re-reads the same account and must not win it back.
    let mut tx = pool.begin().await.expect("begin");
    username_indexer::projection::upsert(&mut tx, &record(7, "legacy.33", Source::People), 3)
        .await
        .expect("people upsert");
    tx.commit().await.expect("commit");
    assert_eq!(
        stored(&pool, 7).await,
        Some(("gateway.22".to_string(), "asset-hub".to_string())),
        "People must never overwrite the name authority"
    );

    // Nor may it retract one: an account vanishing from `Consumers` says
    // nothing about whether it still holds a gateway label.
    let mut tx = pool.begin().await.expect("begin");
    username_indexer::projection::delete_account(&mut tx, &[7u8; 32], Source::People)
        .await
        .expect("people delete");
    tx.commit().await.expect("commit");
    assert!(
        stored(&pool, 7).await.is_some(),
        "the People pass must not delete a gateway row"
    );

    // The gateway may retract its own.
    let mut tx = pool.begin().await.expect("begin");
    username_indexer::projection::delete_account(&mut tx, &[7u8; 32], Source::AssetHub)
        .await
        .expect("gateway delete");
    tx.commit().await.expect("commit");
    assert_eq!(stored(&pool, 7).await, None);

    // And People still fully owns an account the gateway has never seen.
    let mut tx = pool.begin().await.expect("begin");
    username_indexer::projection::upsert(&mut tx, &record(8, "peopleonly.44", Source::People), 1)
        .await
        .expect("people upsert");
    username_indexer::projection::upsert(&mut tx, &record(8, "peopleonly.55", Source::People), 2)
        .await
        .expect("people re-upsert");
    tx.commit().await.expect("commit");
    assert_eq!(
        stored(&pool, 8).await,
        Some(("peopleonly.55".to_string(), "people".to_string())),
        "the legacy population is still fully writable by its own ingest"
    );

    sqlx::query("DELETE FROM assigned_usernames WHERE account_id = ANY($1)")
        .bind(vec![[7u8; 32].to_vec(), [8u8; 32].to_vec()])
        .execute(&pool)
        .await
        .expect("clean up");
}
