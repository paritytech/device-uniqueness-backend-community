// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeMap;
use std::time::Duration;

use chain_types::people;
use sqlx::{PgPool, Row as _};
use subxt::utils::AccountId32;

use super::{
    decode_reservation, observations_from_events, scan_lite_labels, GatewayError, Registration,
    Reservation,
};
use crate::chain::{AssetHubChain, ChainError, PeopleChain};
use crate::projection::{self, PROJECTION_LOCK_ID};

/// Why a gateway census ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayTrigger {
    /// The gateway checkpoint was absent — this projection has never indexed
    /// Asset Hub.
    FreshProjection,
    /// The checkpoint belonged to a different Asset Hub, so the rows built
    /// from it were discarded.
    ChainChanged,
}

/// Result of one complete gateway census.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayReport {
    pub indexed: u64,
    /// Labels whose owner has no People consumer record, so no chat key could
    /// be recovered. See [`ensure_seeded`].
    pub skipped_without_chat_key: u64,
    /// Labels that did not decode into a projection row.
    pub skipped_malformed: u64,
    pub snapshot_number: u64,
    pub trigger: GatewayTrigger,
}

/// Result of one incremental gateway pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayIndexReport {
    pub from_block: u64,
    pub to_block: u64,
    pub blocks_processed: u64,
    pub accounts_upserted: u64,
    pub observations_skipped: u64,
}

impl GatewayIndexReport {
    fn idle(block: u64) -> Self {
        Self {
            from_block: block,
            to_block: block,
            blocks_processed: 0,
            accounts_upserted: 0,
            observations_skipped: 0,
        }
    }
}

pub async fn ensure_seeded(
    pool: &PgPool,
    asset_hub: &AssetHubChain,
    people: &PeopleChain,
) -> Result<Option<GatewayReport>, GatewayError> {
    let mut lock_connection = pool.acquire().await?;
    lock_connection.close_on_drop();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(PROJECTION_LOCK_ID)
        .execute(&mut *lock_connection)
        .await?;

    let trigger = match reconcile_chain_identity(pool, asset_hub).await? {
        CheckpointState::Usable => return Ok(None),
        CheckpointState::Absent => GatewayTrigger::FreshProjection,
        CheckpointState::Discarded => GatewayTrigger::ChainChanged,
    };

    let ss58_prefix = super::ss58_prefix(asset_hub).await?;
    let (reservations, snapshot_hash, snapshot_number) = scan_lite_labels(asset_hub).await?;
    let chat_keys = people_chat_keys(people).await?;

    let mut report = GatewayReport {
        indexed: 0,
        skipped_without_chat_key: 0,
        skipped_malformed: 0,
        snapshot_number,
        trigger,
    };

    let mut tx = pool.begin().await?;
    for reservation in &reservations {
        let Some(identifier_key) = chat_keys.get(&reservation.account_id).copied() else {
            report.skipped_without_chat_key += 1;
            continue;
        };
        match decode_reservation(
            reservation,
            identifier_key,
            None,
            ss58_prefix,
            snapshot_hash,
            snapshot_number,
        ) {
            Ok(record) => {
                projection::upsert(&mut tx, &record, snapshot_number_db(snapshot_number)?).await?;
                report.indexed += 1;
            }
            Err(error) => {
                report.skipped_malformed += 1;
                tracing::warn!(
                    label = %reservation.lite_label,
                    error = ?error,
                    "skipping undecodable gateway lite label"
                );
            }
        }
    }
    // Any gateway row this census did not see no longer exists on the gateway.
    // Scoped to `asset-hub`, so the People population is untouched.
    sqlx::query(
        "DELETE FROM assigned_usernames \
         WHERE source = 'asset-hub' AND snapshot_hash <> $1",
    )
    .bind(snapshot_hash.as_slice())
    .execute(&mut *tx)
    .await?;
    write_checkpoint(
        &mut tx,
        snapshot_number_db(snapshot_number)?,
        &snapshot_hash,
        &asset_hub.online().genesis_hash().0,
    )
    .await?;
    tx.commit().await?;

    Ok(Some(report))
}

pub async fn index_finalized_range(
    pool: &PgPool,
    asset_hub: &AssetHubChain,
) -> Result<Option<GatewayIndexReport>, GatewayError> {
    let Some(_lock) = crate::incremental::try_projection_lock(pool).await? else {
        return Ok(None);
    };
    let Some(checkpoint) = read_checkpoint(pool).await? else {
        return Ok(Some(GatewayIndexReport::idle(0)));
    };
    let head = asset_hub.finalized_head_number().await?;
    if head <= checkpoint {
        return Ok(Some(GatewayIndexReport::idle(checkpoint)));
    }

    let ss58_prefix = super::ss58_prefix(asset_hub).await?;
    let mut report = GatewayIndexReport {
        from_block: checkpoint + 1,
        to_block: head,
        blocks_processed: 0,
        accounts_upserted: 0,
        observations_skipped: 0,
    };
    for number in (checkpoint + 1)..=head {
        index_block(pool, asset_hub, number, ss58_prefix, &mut report).await?;
        report.blocks_processed += 1;
    }
    Ok(Some(report))
}

async fn index_block(
    pool: &PgPool,
    asset_hub: &AssetHubChain,
    number: u64,
    ss58_prefix: u16,
    report: &mut GatewayIndexReport,
) -> Result<(), GatewayError> {
    let at = asset_hub
        .online()
        .at_block(number)
        .await
        .map_err(|source| ChainError::Query(Box::new(source)))?;
    let block_hash = at.block_hash().0;
    let block_number = at.block_number();
    let block_number_db = snapshot_number_db(block_number)?;

    let events = at
        .events()
        .fetch()
        .await
        .map_err(|source| ChainError::Query(Box::new(source)))?;
    let observations = observations_from_events(&events)?;

    if observations.is_empty() {
        let mut tx = pool.begin().await?;
        advance_checkpoint(&mut tx, block_number_db, &block_hash).await?;
        tx.commit().await?;
        return Ok(());
    }

    let reservations = observations.reservation_by_account();
    let registrations = observations.registration_by_account();

    let mut tx = pool.begin().await?;
    for account in observations.accounts() {
        let existing = existing_gateway_row(pool, &account).await?;
        let Some(built) = build_row(
            &account,
            reservations.get(&account).copied(),
            registrations.get(&account).copied(),
            existing.as_ref(),
        ) else {
            report.observations_skipped += 1;
            tracing::warn!(
                account = ?account,
                block = block_number,
                "gateway observation has no reservation to attach to; \
                 the next census will pick it up"
            );
            continue;
        };

        match super::lite_label_owner(&at, &built.reservation.lite_label).await? {
            Some(owner) if owner == account => {}
            _ => {
                report.observations_skipped += 1;
                tracing::warn!(
                    account = ?account,
                    label = %built.reservation.lite_label,
                    block = block_number,
                    "gateway label owner disagrees with the event; skipping"
                );
                continue;
            }
        }

        match decode_reservation(
            &built.reservation,
            built.identifier_key,
            built.full_username,
            ss58_prefix,
            block_hash,
            block_number,
        ) {
            Ok(record) => {
                projection::upsert(&mut tx, &record, block_number_db).await?;
                report.accounts_upserted += 1;
            }
            Err(error) => {
                report.observations_skipped += 1;
                tracing::warn!(account = ?account, error = ?error, "undecodable gateway observation");
            }
        }
    }
    advance_checkpoint(&mut tx, block_number_db, &block_hash).await?;
    tx.commit().await?;
    Ok(())
}

/// What the projection already holds for one gateway account.
struct ExistingRow {
    identifier_key: [u8; 65],
    lite_username: String,
    full_username: Option<String>,
}

struct BuiltRow {
    reservation: Reservation,
    identifier_key: [u8; 65],
    full_username: Option<String>,
}

fn build_row(
    account: &[u8; 32],
    reservation: Option<&Reservation>,
    registration: Option<&Registration>,
    existing: Option<&ExistingRow>,
) -> Option<BuiltRow> {
    let full_username = registration
        .map(|registration| registration.label.clone())
        .or_else(|| existing.and_then(|row| row.full_username.clone()));

    match reservation {
        Some(reservation) => {
            let identifier_key = reservation
                .chat_key
                .or_else(|| existing.map(|row| row.identifier_key))?;
            Some(BuiltRow {
                reservation: reservation.clone(),
                identifier_key,
                full_username,
            })
        }
        None => {
            let existing = existing?;
            Some(BuiltRow {
                reservation: Reservation {
                    account_id: *account,
                    lite_label: existing.lite_username.clone(),
                    chat_key: Some(existing.identifier_key),
                },
                identifier_key: existing.identifier_key,
                full_username,
            })
        }
    }
}

async fn existing_gateway_row(
    pool: &PgPool,
    account: &[u8; 32],
) -> Result<Option<ExistingRow>, GatewayError> {
    let row = sqlx::query(
        "SELECT identifier_key, lite_username, full_username FROM assigned_usernames \
         WHERE account_id = $1 AND source = 'asset-hub'",
    )
    .bind(account.as_slice())
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let identifier_key: Vec<u8> = row.try_get("identifier_key")?;
    let Ok(identifier_key) = <[u8; 65]>::try_from(identifier_key.as_slice()) else {
        return Ok(None);
    };
    Ok(Some(ExistingRow {
        identifier_key,
        lite_username: row.try_get("lite_username")?,
        full_username: row.try_get("full_username")?,
    }))
}

/// Every People consumer's chat key, by account.
async fn people_chat_keys(
    people: &PeopleChain,
) -> Result<BTreeMap<[u8; 32], [u8; 65]>, GatewayError> {
    let at = people
        .online()
        .at_current_block()
        .await
        .map_err(|source| ChainError::Query(Box::new(source)))?;
    let mut entries = at
        .storage()
        .entry(people::storage().resources().consumers())
        .map_err(|source| GatewayError::Storage(Box::new(source)))?
        .iter(())
        .await
        .map_err(|source| GatewayError::Storage(Box::new(source)))?;

    let mut out = BTreeMap::new();
    while let Some(entry) = futures::StreamExt::next(&mut entries).await {
        let entry = entry.map_err(|source| GatewayError::Storage(Box::new(source)))?;
        let Ok((AccountId32(account),)) = entry.key().and_then(|key| key.decode()) else {
            continue;
        };
        let Ok(consumer) = entry.value().decode() else {
            continue;
        };
        out.insert(account, consumer.identifier_key);
    }
    Ok(out)
}

enum CheckpointState {
    Usable,
    Absent,
    Discarded,
}

async fn reconcile_chain_identity(
    pool: &PgPool,
    asset_hub: &AssetHubChain,
) -> Result<CheckpointState, GatewayError> {
    let live_genesis = asset_hub.online().genesis_hash().0;

    let row = sqlx::query(
        "SELECT ah_genesis_hash, ah_last_finalized_number FROM sync_state WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(CheckpointState::Absent);
    };
    let number: Option<i64> = row.try_get("ah_last_finalized_number")?;
    if number.is_none() {
        return Ok(CheckpointState::Absent);
    }
    let stamped: Option<Vec<u8>> = row.try_get("ah_genesis_hash")?;
    match stamped {
        Some(stamped) if stamped.as_slice() != live_genesis.as_slice() => {
            let mut tx = pool.begin().await?;
            sqlx::query("DELETE FROM assigned_usernames WHERE source = 'asset-hub'")
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE sync_state SET ah_last_finalized_number = NULL, \
                 ah_last_finalized_hash = NULL, ah_genesis_hash = NULL, updated_at = now() \
                 WHERE id = 1",
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            tracing::warn!("Asset Hub genesis changed; discarded the gateway projection");
            Ok(CheckpointState::Discarded)
        }
        _ => Ok(CheckpointState::Usable),
    }
}

async fn read_checkpoint(pool: &PgPool) -> Result<Option<u64>, GatewayError> {
    let number: Option<Option<i64>> =
        sqlx::query_scalar("SELECT ah_last_finalized_number FROM sync_state WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    Ok(number.flatten().map(|number| number.max(0) as u64))
}

async fn write_checkpoint(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    number: i64,
    hash: &[u8; 32],
    genesis: &[u8; 32],
) -> Result<(), GatewayError> {
    sqlx::query(
        "INSERT INTO sync_state (
            id, last_finalized_number, last_finalized_hash, last_synced_at,
            records_indexed, decode_failures,
            ah_last_finalized_number, ah_last_finalized_hash, ah_genesis_hash
         ) VALUES (1, 0, $2, now(), 0, 0, $1, $2, $3)
         ON CONFLICT (id) DO UPDATE SET
            ah_last_finalized_number = EXCLUDED.ah_last_finalized_number,
            ah_last_finalized_hash = EXCLUDED.ah_last_finalized_hash,
            ah_genesis_hash = EXCLUDED.ah_genesis_hash,
            updated_at = now()",
    )
    .bind(number)
    .bind(hash.as_slice())
    .bind(genesis.as_slice())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn advance_checkpoint(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    number: i64,
    hash: &[u8; 32],
) -> Result<(), GatewayError> {
    sqlx::query(
        "UPDATE sync_state SET ah_last_finalized_number = $1, ah_last_finalized_hash = $2, \
         updated_at = now() WHERE id = 1",
    )
    .bind(number)
    .bind(hash.as_slice())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn snapshot_number_db(number: u64) -> Result<i64, GatewayError> {
    i64::try_from(number).map_err(|_| GatewayError::SnapshotNumber(number))
}

pub async fn run(pool: PgPool, asset_hub: AssetHubChain, interval: Duration) {
    let mut consecutive_failures = 0_u32;
    loop {
        tokio::time::sleep(interval).await;
        match index_finalized_range(&pool, &asset_hub).await {
            Ok(Some(report)) if report.blocks_processed > 0 => {
                consecutive_failures = 0;
                metrics::gauge!("dub_gateway_checkpoint_block").set(report.to_block as f64);
                metrics::counter!("dub_gateway_accounts_upserted_total")
                    .increment(report.accounts_upserted);
                metrics::counter!("dub_gateway_observations_skipped_total")
                    .increment(report.observations_skipped);
                tracing::info!(
                    from_block = report.from_block,
                    to_block = report.to_block,
                    blocks = report.blocks_processed,
                    upserted = report.accounts_upserted,
                    skipped = report.observations_skipped,
                    "gateway pass complete"
                );
            }
            // Nothing new, or another replica holds the projection lock.
            Ok(_) => consecutive_failures = 0,
            Err(error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                let delay = backoff(consecutive_failures);
                metrics::counter!("dub_gateway_pass_failures_total").increment(1);
                tracing::warn!(
                    error = ?error,
                    consecutive_failures,
                    backoff_secs = delay.as_secs(),
                    "gateway pass failed; the People projection is unaffected"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Bounded exponential backoff, matching the People sync loop's shape so an
/// operator reading two logs side by side sees the same cadence.
fn backoff(consecutive_failures: u32) -> Duration {
    const MAX: u64 = 60;
    let secs = 1_u64
        .checked_shl(consecutive_failures.saturating_sub(1).min(6))
        .unwrap_or(MAX)
        .min(MAX);
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::Source;

    fn reservation(label: &str) -> Reservation {
        Reservation {
            account_id: [3u8; 32],
            lite_label: label.to_string(),
            chat_key: Some([9u8; 65]),
        }
    }

    fn existing() -> ExistingRow {
        ExistingRow {
            identifier_key: [4u8; 65],
            lite_username: "stored.42".to_string(),
            full_username: Some("stored".to_string()),
        }
    }

    #[test]
    fn backoff_grows_then_holds_at_a_minute() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(7), Duration::from_secs(60));
        assert_eq!(backoff(99), Duration::from_secs(60));
    }

    /// The precedence this whole module depends on: the gateway is the name
    /// authority, so it overwrites a People row, and People never overwrites it.
    #[test]
    fn gateway_rows_outrank_people_rows_in_one_direction_only() {
        assert!(Source::AssetHub.may_overwrite(Source::People));
        assert!(Source::AssetHub.may_overwrite(Source::AssetHub));
        assert!(Source::People.may_overwrite(Source::People));
        assert!(!Source::People.may_overwrite(Source::AssetHub));
    }

    #[test]
    fn a_reservation_event_carries_its_own_chat_key() {
        let built = build_row(&[3u8; 32], Some(&reservation("new.07")), None, None).unwrap();
        assert_eq!(built.reservation.lite_label, "new.07");
        assert_eq!(built.identifier_key, [9u8; 65]);
        assert_eq!(built.full_username, None);
    }

    #[test]
    fn a_registration_alone_updates_the_stored_reservation() {
        let registration = Registration {
            account_id: [3u8; 32],
            label: "promoted".to_string(),
        };
        let built = build_row(&[3u8; 32], None, Some(&registration), Some(&existing())).unwrap();
        // The lite label and chat key come from the row already held.
        assert_eq!(built.reservation.lite_label, "stored.42");
        assert_eq!(built.identifier_key, [4u8; 65]);
        assert_eq!(built.full_username.as_deref(), Some("promoted"));
    }

    #[test]
    fn a_registration_with_nothing_to_attach_to_is_skipped() {
        let registration = Registration {
            account_id: [3u8; 32],
            label: "orphan".to_string(),
        };
        assert!(build_row(&[3u8; 32], None, Some(&registration), None).is_none());
    }

    #[test]
    fn a_new_reservation_keeps_a_full_name_already_registered() {
        let built = build_row(
            &[3u8; 32],
            Some(&reservation("new.07")),
            None,
            Some(&existing()),
        )
        .unwrap();
        assert_eq!(built.reservation.lite_label, "new.07");
        assert_eq!(
            built.full_username.as_deref(),
            Some("stored"),
            "re-reserving a lite label must not drop the full name"
        );
    }
}
