// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use chain_types::people;
use chain_types::people::runtime_types::indiv_pallet_resources::types::ConsumerInfo;
use sqlx::{PgPool, Row as _};
use subxt::utils::AccountId32;

use crate::chain::{BoxError, ChainError, PeopleChain};
use crate::projection::{self, AssignedUsername, PROJECTION_LOCK_ID};
use crate::ss58::Ss58Error;

/// Why a full finalized scan ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapTrigger {
    /// No checkpoint existed — a first boot against an empty database.
    FreshDatabase,
    /// A checkpoint existed but belonged to a different chain, so the
    /// projection built from it was discarded. See [`ensure_seeded`].
    ChainChanged,
}

/// Result of one complete finalized bootstrap scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapReport {
    /// Number of records persisted.
    pub indexed: u64,
    /// Number of malformed iterator entries skipped.
    pub skipped: u64,
    /// Finalized block number used for the whole scan.
    pub snapshot_number: u64,
    pub trigger: BootstrapTrigger,
}

/// Fatal bootstrap failure.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// A chain snapshot operation failed.
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// Subxt rejected a storage or constant operation.
    #[error("reading finalized People Chain storage: {0}")]
    Storage(#[source] BoxError),
    /// The chain's SS58 prefix could not encode account identifiers.
    #[error(transparent)]
    Ss58(#[from] Ss58Error),
    #[error("finalized block number {0} exceeds the database range")]
    SnapshotNumber(u64),
    #[error("writing username projection: {0}")]
    Database(#[from] sqlx::Error),
    /// The storage iterator failed before row-level decoding completed.
    #[error("finalized storage scan was incomplete after {iterator_errors} iterator errors")]
    IncompleteScan { iterator_errors: u64 },
}

/// State of the stored checkpoint once it has been checked against the chain
/// this process is actually connected to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointState {
    /// No checkpoint row — nothing has been indexed yet.
    Absent,
    /// A checkpoint for this chain; incremental catch-up can resume from it.
    Usable,
    /// A checkpoint for a different chain; it and the projection were deleted.
    Discarded,
}

/// Seed the projection from a full finalized snapshot only when there is no
/// usable checkpoint for this chain; otherwise leave it for incremental
/// catch-up. `None` means a checkpoint was found.
///
/// Serialized on [`PROJECTION_LOCK_ID`] so replicas cannot both bootstrap.
/// "Usable" is a claim about the chain, not the row: see
/// [`reconcile_chain_identity`].
pub async fn ensure_seeded(
    pool: &PgPool,
    chain: &PeopleChain,
    page_size: u32,
) -> Result<Option<BootstrapReport>, BootstrapError> {
    let mut lock_connection = pool.acquire().await?;
    lock_connection.close_on_drop();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(PROJECTION_LOCK_ID)
        .execute(&mut *lock_connection)
        .await?;

    let trigger = match reconcile_chain_identity(pool, chain).await? {
        CheckpointState::Usable => return Ok(None),
        CheckpointState::Absent => BootstrapTrigger::FreshDatabase,
        CheckpointState::Discarded => BootstrapTrigger::ChainChanged,
    };

    bootstrap_locked(pool, chain, page_size, trigger)
        .await
        .map(Some)
}

/// Clear the stored checkpoint and the projection built from it when the
/// connected chain's genesis hash differs from the one it was stamped with.
///
/// Catching up cannot fix it: `ensure_seeded` skips the scan while the row
/// exists, so the dead chain's rows would persist behind the new chain's tail.
/// Safe because the projection is derived — the next bootstrap rebuilds it.
///
/// A NULL `genesis_hash` predates the column and is adopted rather than
/// treated as a mismatch. Both writes share one transaction.
async fn reconcile_chain_identity(
    pool: &PgPool,
    chain: &PeopleChain,
) -> Result<CheckpointState, BootstrapError> {
    let live_genesis = chain.online().genesis_hash().0;

    let Some(row) = sqlx::query("SELECT genesis_hash FROM sync_state WHERE id = 1")
        .fetch_optional(pool)
        .await?
    else {
        return Ok(CheckpointState::Absent);
    };

    let stored: Option<Vec<u8>> = row.try_get("genesis_hash")?;
    let Some(stored) = stored else {
        sqlx::query("UPDATE sync_state SET genesis_hash = $1, updated_at = now() WHERE id = 1")
            .bind(live_genesis.as_slice())
            .execute(pool)
            .await?;
        tracing::info!(
            genesis_hash = %hex::encode(live_genesis),
            "adopted an unstamped checkpoint; projection kept"
        );
        return Ok(CheckpointState::Usable);
    };

    if stored == live_genesis.as_slice() {
        return Ok(CheckpointState::Usable);
    }

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM sync_state WHERE id = 1")
        .execute(&mut *tx)
        .await?;
    let discarded = sqlx::query("DELETE FROM assigned_usernames")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;

    tracing::warn!(
        stored_genesis = %hex::encode(&stored),
        live_genesis = %hex::encode(live_genesis),
        discarded_rows = discarded,
        "connected chain is not the one this projection was built from; discarded it, re-bootstrapping"
    );
    Ok(CheckpointState::Discarded)
}

async fn bootstrap_locked(
    pool: &PgPool,
    chain: &PeopleChain,
    page_size: u32,
    trigger: BootstrapTrigger,
) -> Result<BootstrapReport, BootstrapError> {
    let at = chain
        .online()
        .at_current_block()
        .await
        .map_err(|source| ChainError::Query(Box::new(source)))?;
    let snapshot_hash = at.block_hash().0;
    let snapshot_number = at.block_number();
    let snapshot_number_db = i64::try_from(snapshot_number)
        .map_err(|_| BootstrapError::SnapshotNumber(snapshot_number))?;
    let ss58_prefix = crate::ss58::validate_prefix(
        at.constants()
            .entry(people::constants().system().ss58_prefix())
            .map_err(|source| BootstrapError::Storage(Box::new(source)))?,
    )?;

    let address = people::storage().resources().consumers();
    let mut entries = at
        .storage()
        .entry(address)
        .map_err(|source| BootstrapError::Storage(Box::new(source)))?
        .iter(())
        .await
        .map_err(|source| BootstrapError::Storage(Box::new(source)))?;
    let mut batch = Vec::with_capacity(page_size as usize);
    let mut indexed = 0_u64;
    let mut skipped = 0_u64;
    let mut iterator_errors = 0_u64;

    while let Some(entry) = entries.next().await {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                skipped += 1;
                iterator_errors += 1;
                tracing::warn!(stage = "iterator", error = ?error, "skipping malformed consumer");
                continue;
            }
        };
        let (account_id,): (AccountId32,) = match entry.key().and_then(|key| key.decode()) {
            Ok(key) => key,
            Err(error) => {
                skipped += 1;
                tracing::warn!(stage = "key", error = ?error, "skipping malformed consumer");
                continue;
            }
        };
        let consumer: ConsumerInfo = match entry.value().decode() {
            Ok(value) => value,
            Err(error) => {
                skipped += 1;
                tracing::warn!(stage = "value", account_id = ?account_id, error = ?error, "skipping malformed consumer");
                continue;
            }
        };

        match projection::decode_consumer(
            account_id.0,
            consumer.identifier_key,
            consumer.lite_username.0,
            consumer.full_username.map(|username| username.0),
            ss58_prefix,
            snapshot_hash,
            snapshot_number,
        ) {
            Ok(record) => batch.push(record),
            Err(error) => {
                skipped += 1;
                tracing::warn!(stage = "username", account_id = ?account_id, error = ?error, "skipping malformed consumer");
            }
        }

        if batch.len() == page_size as usize {
            upsert_batch(pool, &batch, snapshot_number_db).await?;
            indexed += batch.len() as u64;
            batch.clear();
        }
    }

    if !batch.is_empty() {
        upsert_batch(pool, &batch, snapshot_number_db).await?;
        indexed += batch.len() as u64;
    }

    if iterator_errors != 0 {
        return Err(BootstrapError::IncompleteScan { iterator_errors });
    }

    sqlx::query("DELETE FROM assigned_usernames WHERE snapshot_hash <> $1")
        .bind(snapshot_hash.as_slice())
        .execute(pool)
        .await?;

    let genesis_hash = chain.online().genesis_hash().0;
    write_checkpoint(
        pool,
        snapshot_number_db,
        snapshot_hash,
        genesis_hash,
        indexed,
        skipped,
    )
    .await?;

    Ok(BootstrapReport {
        indexed,
        skipped,
        snapshot_number,
        trigger,
    })
}

/// Persist the resumable finalized checkpoint after a full snapshot commits.
///
/// Written last in the success path, so the checkpoint advances only when the
/// whole snapshot landed; idempotent. `genesis_hash` is stamped here because
/// bootstrap is the only writer that establishes the row, and a row without it
/// reads as pre-guard and is adopted ([`reconcile_chain_identity`]).
async fn write_checkpoint(
    pool: &PgPool,
    snapshot_number: i64,
    snapshot_hash: [u8; 32],
    genesis_hash: [u8; 32],
    indexed: u64,
    skipped: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sync_state (
            id, last_finalized_number, last_finalized_hash, genesis_hash,
            last_synced_at, records_indexed, decode_failures, updated_at
         ) VALUES (1, $1, $2, $3, now(), $4, $5, now())
         ON CONFLICT (id) DO UPDATE SET
            last_finalized_number = EXCLUDED.last_finalized_number,
            last_finalized_hash = EXCLUDED.last_finalized_hash,
            genesis_hash = EXCLUDED.genesis_hash,
            last_synced_at = EXCLUDED.last_synced_at,
            records_indexed = EXCLUDED.records_indexed,
            decode_failures = EXCLUDED.decode_failures,
            updated_at = now()",
    )
    .bind(snapshot_number)
    .bind(snapshot_hash.as_slice())
    .bind(genesis_hash.as_slice())
    .bind(indexed as i64)
    .bind(skipped as i64)
    .execute(pool)
    .await?;
    Ok(())
}

async fn upsert_batch(
    pool: &PgPool,
    records: &[AssignedUsername],
    snapshot_number: i64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for record in records {
        projection::upsert(&mut tx, record, snapshot_number).await?;
    }
    tx.commit().await
}
