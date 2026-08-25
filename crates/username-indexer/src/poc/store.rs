// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Record `session_id` as spent, retained until `retain_until_ms`.
///
/// Returns `true` when this call consumed the puzzle and `false` when it was
/// already spent (the replay case).
pub async fn consume(
    pool: &PgPool,
    session_id: Uuid,
    retain_until_ms: i64,
) -> Result<bool, sqlx::Error> {
    // Unreachable for a puzzle that passed checksum verification: the timestamp
    // came from this server's own clock. Clamping instead would silently store a
    // 1970 row that the pruner drops on sight, reopening the replay it guards.
    let expires_at =
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(retain_until_ms) * 1_000_000)
            .expect("a verified puzzle timestamp is a representable instant");

    let result = sqlx::query(
        "INSERT INTO spent_puzzles (session_id, expires_at) \
         VALUES ($1, $2) ON CONFLICT (session_id) DO NOTHING",
    )
    .bind(session_id)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() == 1)
}

/// Grace period added on top of a row's validity window before it is pruned.
///
/// Expiry is checked against the process clock before the consume insert, so a
/// request crossing the boundary (or a replica whose clock lags Postgres) could
/// insert while a pruner deletes the row — letting the puzzle be spent twice.
const PRUNE_GRACE: &str = "10 minutes";

/// Delete spent-puzzle rows whose validity window passed more than
/// [`PRUNE_GRACE`] ago.
///
/// Safe to run from any replica at any time.
pub async fn prune_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(&format!(
        "DELETE FROM spent_puzzles WHERE expires_at < now() - interval '{PRUNE_GRACE}'"
    ))
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
