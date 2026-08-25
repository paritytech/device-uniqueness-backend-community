// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use sqlx::{PgPool, Row as _};

pub async fn try_acquire(
    pool: &PgPool,
    name: &str,
    holder_id: &str,
    ttl: Duration,
) -> Result<Option<i64>, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO writer_lease (name, holder_id, lease_epoch, expires_at, heartbeat_at) \
         VALUES ($1, $2, 1, now() + ($3 * interval '1 second'), now()) \
         ON CONFLICT (name) DO UPDATE \
           SET holder_id = EXCLUDED.holder_id, \
               lease_epoch = writer_lease.lease_epoch + 1, \
               expires_at = now() + ($3 * interval '1 second'), \
               heartbeat_at = now() \
           WHERE writer_lease.expires_at < now() OR writer_lease.holder_id = $2 \
         RETURNING lease_epoch",
    )
    .bind(name)
    .bind(holder_id)
    .bind(ttl.as_secs() as i64)
    .fetch_optional(pool)
    .await?;
    row.map(|row| row.try_get("lease_epoch")).transpose()
}

pub async fn renew(
    pool: &PgPool,
    name: &str,
    holder_id: &str,
    epoch: i64,
    ttl: Duration,
) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE writer_lease \
         SET expires_at = now() + ($4 * interval '1 second'), heartbeat_at = now() \
         WHERE name = $1 AND holder_id = $2 AND lease_epoch = $3 AND expires_at > now()",
    )
    .bind(name)
    .bind(holder_id)
    .bind(epoch)
    .bind(ttl.as_secs() as i64)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
}

pub async fn alive(pool: &PgPool, name: &str) -> Result<bool, sqlx::Error> {
    let row =
        sqlx::query("SELECT 1 AS held FROM writer_lease WHERE name = $1 AND expires_at > now()")
            .bind(name)
            .fetch_optional(pool)
            .await?;
    Ok(row.is_some())
}
