// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! The Asset Hub `DotnsGateway` ingest — the authoritative half of the
//! projection.
//!
//! Shaped differently from the People ingest next door, because the chain data
//! is shaped differently. There, an event is a *pointer*: it names an affected
//! account and the indexer re-reads `Resources::Consumers` at the block for the
//! authoritative value. Here the events carry the values themselves, and there
//! is no storage row to re-read them from:
//!
//! - `LiteLabelOwner` is keyed by **label**, not account, and holds only the
//!   owner. It is a complete lite-label census and nothing more.
//! - The chat key is never written to pallet storage at all. `reserve_name`
//!   forwards it to the gateway contract and emits it.
//! - Full-person label strings are not in pallet storage either:
//!   `AliasRegistration` stores `{ collection, account }`, with no label.
//!
//! So the events are the only chain-native source for two of the projection's
//! columns. Storage is still used for what it *can* confirm — the lite label's
//! owner at the block — and the rest is taken from the event that produced it.
//!
//! Everything is decoded dynamically. `chain-types` vendors People metadata
//! only, and the chain-writer already reads `DotnsGateway` dynamically for the
//! same reason: a second vendored blob would pin an Asset Hub runtime version
//! nothing else here tracks.

pub mod ingest;

use std::collections::BTreeMap;

use subxt::utils::AccountId32;

use crate::chain::{AssetHubChain, BoxError, ChainError};
use crate::projection::{AssignedUsername, Source};
use crate::ss58::{self, Ss58Error};

const PALLET: &str = "DotnsGateway";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reservation {
    pub account_id: [u8; 32],
    pub lite_label: String,
    /// `None` when recovered from a `LiteLabelOwner` scan rather than an event,
    /// which is the only place the chat key appears.
    pub chat_key: Option<[u8; 65]>,
}

/// A full-person name observed on the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Registration {
    pub account_id: [u8; 32],
    pub label: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum GatewayDecodeError {
    #[error("lite label must be <base>.<digits>")]
    LabelFormat,
    #[error("label contains a NUL byte")]
    NulByte,
    #[error("full label must not be empty")]
    EmptyFull,
}

pub(crate) fn decode_reservation(
    reservation: &Reservation,
    identifier_key: [u8; 65],
    full_username: Option<String>,
    ss58_prefix: u16,
    snapshot_hash: [u8; 32],
    snapshot_number: u64,
) -> Result<AssignedUsername, GatewayDecodeError> {
    let lite_username = reservation.lite_label.clone();
    let (lite_base, lite_digits) = lite_username
        .rsplit_once('.')
        .ok_or(GatewayDecodeError::LabelFormat)?;
    // Mirrors the pallet's `BaseLabel::is_valid_lite` (`<stem>.<2+ digits>`),
    if lite_base.is_empty()
        || lite_digits.is_empty()
        || !lite_digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(GatewayDecodeError::LabelFormat);
    }
    if full_username.as_deref() == Some("") {
        return Err(GatewayDecodeError::EmptyFull);
    }
    if lite_username.contains('\0')
        || full_username
            .as_deref()
            .is_some_and(|full| full.contains('\0'))
    {
        return Err(GatewayDecodeError::NulByte);
    }
    let display_username = full_username
        .clone()
        .unwrap_or_else(|| lite_username.clone());
    let account_id_ss58 = ss58::encode(&reservation.account_id, ss58_prefix)
        .expect("validated SS58 prefix must encode an account");

    Ok(AssignedUsername {
        account_id: reservation.account_id,
        account_id_ss58,
        identifier_key,
        lite_base: lite_base.to_string(),
        lite_digits: lite_digits.to_string(),
        lite_username,
        full_username,
        display_username,
        snapshot_hash,
        snapshot_number,
        source: Source::AssetHub,
    })
}

/// Everything one block said about gateway names.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct BlockObservations {
    pub reservations: Vec<Reservation>,
    pub registrations: Vec<Registration>,
}

impl BlockObservations {
    pub fn is_empty(&self) -> bool {
        self.reservations.is_empty() && self.registrations.is_empty()
    }

    /// Every account the block touched, deduplicated and ordered so per-block
    /// reads are stable.
    pub fn accounts(&self) -> Vec<[u8; 32]> {
        self.reservations
            .iter()
            .map(|r| r.account_id)
            .chain(self.registrations.iter().map(|r| r.account_id))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The reservation seen for each account, keyed for lookup during the
    /// per-account write.
    pub fn reservation_by_account(&self) -> BTreeMap<[u8; 32], &Reservation> {
        self.reservations
            .iter()
            .map(|r| (r.account_id, r))
            .collect()
    }

    /// The full label registered by each account in this block.
    pub fn registration_by_account(&self) -> BTreeMap<[u8; 32], &Registration> {
        self.registrations
            .iter()
            .map(|r| (r.account_id, r))
            .collect()
    }
}

#[derive(subxt::ext::scale_decode::DecodeAsType, Debug)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub(crate) struct NameReserved {
    pub candidate: subxt::utils::AccountId32,
    pub lite_label: Vec<u8>,
    pub chat_key: [u8; 65],
}

impl subxt::events::DecodeAsEvent for NameReserved {
    fn is_event(pallet: &str, event: &str) -> bool {
        pallet == PALLET && event == "NameReserved"
    }
}

/// `DotnsGateway::NameRegistered` — the only chain-native source of a
/// full-person label string.
#[derive(subxt::ext::scale_decode::DecodeAsType, Debug)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub(crate) struct NameRegistered {
    pub account: subxt::utils::AccountId32,
    pub label: Vec<u8>,
}

impl subxt::events::DecodeAsEvent for NameRegistered {
    fn is_event(pallet: &str, event: &str) -> bool {
        pallet == PALLET && event == "NameRegistered"
    }
}

pub(crate) fn observations_from_events(
    events: &subxt::events::Events<chain_types::AssetHubConfig>,
) -> Result<BlockObservations, GatewayError> {
    let mut out = BlockObservations::default();
    for event in events.find::<NameReserved>() {
        let event = event.map_err(|source| GatewayError::Decode(Box::new(source)))?;
        out.reservations.push(Reservation {
            account_id: event.candidate.0,
            lite_label: String::from_utf8(event.lite_label).map_err(|_| GatewayError::Field {
                field: "lite_label",
            })?,
            chat_key: Some(event.chat_key),
        });
    }
    for event in events.find::<NameRegistered>() {
        let event = event.map_err(|source| GatewayError::Decode(Box::new(source)))?;
        out.registrations.push(Registration {
            account_id: event.account.0,
            label: String::from_utf8(event.label)
                .map_err(|_| GatewayError::Field { field: "label" })?,
        });
    }
    Ok(out)
}

/// Gateway ingest failure.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error("decoding DotnsGateway event: {0}")]
    Decode(#[source] BoxError),
    #[error("DotnsGateway event field {field:?} is missing or has an unexpected shape")]
    Field { field: &'static str },
    #[error("reading Asset Hub storage: {0}")]
    Storage(#[source] BoxError),
    #[error(transparent)]
    Ss58(#[from] Ss58Error),
    #[error("writing username projection: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Asset Hub block number {0} exceeds the database range")]
    SnapshotNumber(u64),
}

/// The owner of one lite label at a block, used to confirm an event against
/// storage before the projection accepts it.
pub(crate) async fn lite_label_owner(
    at: &subxt::client::ClientAtBlock<
        chain_types::AssetHubConfig,
        subxt::client::OnlineClientAtBlockImpl<chain_types::AssetHubConfig>,
    >,
    label: &str,
) -> Result<Option<[u8; 32]>, GatewayError> {
    let address = subxt::dynamic::storage::<_, AccountId32>(PALLET, "LiteLabelOwner");
    let owner = at
        .storage()
        .try_fetch(
            address,
            (subxt::dynamic::Value::from_bytes(label.as_bytes()),),
        )
        .await
        .map_err(|source| GatewayError::Storage(Box::new(source)))?;
    match owner {
        Some(value) => Ok(Some(
            value
                .decode()
                .map_err(|source| GatewayError::Storage(Box::new(source)))?
                .0,
        )),
        None => Ok(None),
    }
}

pub(crate) async fn scan_lite_labels(
    chain: &AssetHubChain,
) -> Result<(Vec<Reservation>, [u8; 32], u64), GatewayError> {
    let at = chain
        .online()
        .at_current_block()
        .await
        .map_err(|source| ChainError::Query(Box::new(source)))?;
    let block_hash = at.block_hash().0;
    let block_number = at.block_number();

    let address =
        subxt::dynamic::storage::<(subxt::dynamic::Value,), AccountId32>(PALLET, "LiteLabelOwner");
    let mut entries = at
        .storage()
        .entry(address)
        .map_err(|source| GatewayError::Storage(Box::new(source)))?
        .iter(())
        .await
        .map_err(|source| GatewayError::Storage(Box::new(source)))?;

    let mut out = Vec::new();
    while let Some(entry) = futures::StreamExt::next(&mut entries).await {
        let entry = entry.map_err(|source| GatewayError::Storage(Box::new(source)))?;
        let owner = entry
            .value()
            .decode()
            .map_err(|source| GatewayError::Storage(Box::new(source)))?;
        // The map key is the label bytes; subxt hands back the raw key, and the
        // Blake2_128Concat hasher keeps the 16-byte prefix in front of them.
        let Some(label) = label_from_map_key(entry.key_bytes()) else {
            tracing::warn!("skipping DotnsGateway::LiteLabelOwner key that is not a UTF-8 label");
            continue;
        };
        out.push(Reservation {
            account_id: owner.0,
            lite_label: label,
            chat_key: None,
        });
    }
    Ok((out, block_hash, block_number))
}

/// Recover the label from a `Blake2_128Concat` map key.
fn label_from_map_key(key_bytes: &[u8]) -> Option<String> {
    // 32 bytes of twox128(pallet) ++ twox128(item), then 16 bytes of blake2_128,
    // then the SCALE-encoded BoundedVec: a compact length then the bytes.
    const PREFIX: usize = 32 + 16;
    let rest = key_bytes.get(PREFIX..)?;
    let (_, label) = decode_compact_len(rest)?;
    String::from_utf8(label.to_vec()).ok()
}

/// Split a SCALE `Compact<u32>` length prefix from the bytes that follow it.
fn decode_compact_len(input: &[u8]) -> Option<(u32, &[u8])> {
    let first = *input.first()?;
    let (len, consumed) = match first & 0b11 {
        0b00 => (u32::from(first >> 2), 1),
        0b01 => {
            let second = *input.get(1)?;
            (u32::from(u16::from_le_bytes([first, second]) >> 2), 2)
        }
        0b10 => {
            let word = u32::from_le_bytes([first, *input.get(1)?, *input.get(2)?, *input.get(3)?]);
            (word >> 2, 4)
        }
        // A label is bounded to 32 bytes, so the big-integer form never occurs.
        _ => return None,
    };
    let rest = input.get(consumed..)?;
    let rest = rest.get(..len as usize)?;
    Some((len, rest))
}

pub(crate) async fn ss58_prefix(chain: &AssetHubChain) -> Result<u16, GatewayError> {
    let at = chain
        .online()
        .at_current_block()
        .await
        .map_err(|source| ChainError::Query(Box::new(source)))?;
    let prefix: u16 = at
        .constants()
        .entry(subxt::dynamic::constant::<u16>("System", "SS58Prefix"))
        .map_err(|source| GatewayError::Storage(Box::new(source)))?;
    Ok(ss58::validate_prefix(prefix)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reservation(label: &str) -> Reservation {
        Reservation {
            account_id: [7u8; 32],
            lite_label: label.to_string(),
            chat_key: Some([0u8; 65]),
        }
    }

    #[test]
    fn a_lite_label_splits_into_base_and_digits() {
        let record =
            decode_reservation(&reservation("alice.07"), [0u8; 65], None, 0, [1u8; 32], 9).unwrap();
        assert_eq!(record.lite_base, "alice");
        // Preserved verbatim, never re-rendered from a numeric: `07` must not
        // come back as `7`.
        assert_eq!(record.lite_digits, "07");
        assert_eq!(record.display_username, "alice.07");
        assert_eq!(record.source, Source::AssetHub);
    }

    #[test]
    fn a_full_name_becomes_the_display_name() {
        let record = decode_reservation(
            &reservation("alice.07"),
            [0u8; 65],
            Some("alice".to_string()),
            0,
            [1u8; 32],
            9,
        )
        .unwrap();
        assert_eq!(record.display_username, "alice");
        assert_eq!(record.lite_username, "alice.07");
    }

    #[test]
    fn malformed_labels_are_rejected_rather_than_coerced() {
        for label in ["alice", "alice.", ".07", "alice.0a", ""] {
            assert!(
                decode_reservation(&reservation(label), [0u8; 65], None, 0, [1u8; 32], 9).is_err(),
                "{label:?} must not decode"
            );
        }
        assert_eq!(
            decode_reservation(
                &reservation("alice.07"),
                [0u8; 65],
                Some(String::new()),
                0,
                [1u8; 32],
                9
            ),
            Err(GatewayDecodeError::EmptyFull)
        );
        assert_eq!(
            decode_reservation(&reservation("al\0ice.07"), [0u8; 65], None, 0, [1u8; 32], 9),
            Err(GatewayDecodeError::NulByte)
        );
    }

    #[test]
    fn compact_lengths_split_their_payload() {
        // Single-byte mode: 5 << 2.
        assert_eq!(
            decode_compact_len(&[20, 1, 2, 3, 4, 5]),
            Some((5, &[1u8, 2, 3, 4, 5][..]))
        );
        // Two-byte mode: 64 << 2 spans a u16.
        let mut input = vec![0x01, 0x01];
        input.extend(std::iter::repeat_n(9u8, 64));
        assert_eq!(decode_compact_len(&input).map(|(len, _)| len), Some(64));
        // Truncated payload is not a length we can trust.
        assert_eq!(decode_compact_len(&[20, 1, 2]), None);
    }

    #[test]
    fn a_map_key_yields_its_label() {
        let mut key = vec![0u8; 32 + 16];
        key.push(8 << 2); // compact length 8
        key.extend_from_slice(b"alice.07");
        assert_eq!(label_from_map_key(&key).as_deref(), Some("alice.07"));
        assert_eq!(label_from_map_key(&[0u8; 10]), None);
    }

    #[test]
    fn observations_group_by_account() {
        let observations = BlockObservations {
            reservations: vec![reservation("alice.07")],
            registrations: vec![Registration {
                account_id: [7u8; 32],
                label: "alice".to_string(),
            }],
        };
        assert_eq!(observations.accounts(), vec![[7u8; 32]]);
        assert_eq!(
            observations.registration_by_account()[&[7u8; 32]].label,
            "alice"
        );
    }
}
