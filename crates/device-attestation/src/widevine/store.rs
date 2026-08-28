// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Postgres store for Widevine device dedup records.
//!
//! One row per `(namespace, hmac)` — the pseudonymized device identity. The
//! raw `widevineId` never reaches this table (privacy invariant: HMAC only).
//! Lifecycle: `PENDING` is reserved atomically with the username reservation
//! (same transaction), the chain-writer marks it `CONSUMED` on on-chain
//! success, and a terminal claim failure releases the reservation by deleting
//! the `PENDING` row so the device can claim again.

use sqlx::PgPool;

/// A device record to reserve alongside a claim (the active-epoch HMAC).
#[derive(Debug, Clone)]
pub struct PendingDevice {
    /// Dedup namespace: `widevine_l1` or `widevine_l3` (never merged).
    pub namespace: &'static str,
    /// HMAC key epoch the record was computed with (e.g. `v1`).
    pub epoch: String,
    /// `HMAC-SHA256(k_epoch, "poud:v1" ‖ namespace ‖ widevineId)`.
    pub hmac: [u8; 32],
}

/// Why the `PENDING` insert failed.
#[derive(Debug, thiserror::Error)]
pub enum InsertDeviceError {
    /// The device is already recorded (`PENDING` or `CONSUMED`) — a lost
    /// race, resolved as the payment outcome like any seen device.
    #[error("device already recorded")]
    Seen,
    /// Any other database failure.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Whether any of the epoch HMACs is already recorded in `namespace`
/// (`PENDING` or `CONSUMED` both count — a pending claim holds the slot).
pub async fn seen(
    pool: &PgPool,
    namespace: &str,
    hmacs: &[super::DeviceHmac],
) -> Result<bool, sqlx::Error> {
    let values: Vec<Vec<u8>> = hmacs.iter().map(|h| h.hmac.to_vec()).collect();
    let row = sqlx::query(
        "SELECT 1 FROM widevine_devices WHERE namespace = $1 AND hmac = ANY($2) LIMIT 1",
    )
    .bind(namespace)
    .bind(&values)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// Insert the `PENDING` device record tied to `reservation_id`. Generic over
/// the executor so it runs inside the reservation's transaction — the atomic
/// reserve the spec requires. A unique violation on `(namespace, hmac)` maps
/// to [`InsertDeviceError::Seen`] (a concurrent claim recorded the device
/// first).
pub async fn insert_pending<'e, E>(
    executor: E,
    device: &PendingDevice,
    reservation_id: i64,
) -> Result<(), InsertDeviceError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO widevine_devices (namespace, hmac, key_epoch, status, reservation_id) \
         VALUES ($1, $2, $3, 'PENDING', $4)",
    )
    .bind(device.namespace)
    .bind(&device.hmac[..])
    .bind(&device.epoch)
    .bind(reservation_id)
    .execute(executor)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => InsertDeviceError::Seen,
        _ => InsertDeviceError::Db(e),
    })?;
    Ok(())
}

/// Mark the reservation's `PENDING` device record `CONSUMED` (on-chain
/// success). Returns the number of rows advanced (0 when the claim carried no
/// device evidence).
pub async fn consume_for_reservation(
    pool: &PgPool,
    reservation_id: i64,
) -> Result<u64, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE widevine_devices SET status = 'CONSUMED', updated_at = now() \
         WHERE reservation_id = $1 AND status = 'PENDING'",
    )
    .bind(reservation_id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected())
}

/// Release the reservation's `PENDING` device record (terminal claim
/// failure): the row is deleted so the device can claim again. `CONSUMED`
/// rows are never released. Returns the number of rows released.
pub async fn release_for_reservation(
    pool: &PgPool,
    reservation_id: i64,
) -> Result<u64, sqlx::Error> {
    let done = sqlx::query(
        "DELETE FROM widevine_devices WHERE reservation_id = $1 AND status = 'PENDING'",
    )
    .bind(reservation_id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected())
}
