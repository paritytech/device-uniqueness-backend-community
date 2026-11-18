// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! The `DotnsGateway` pallet on Asset Hub, the indexer's source.
//!
//! Every lite username is issued through the gateway, which records each
//! account's labels in `AccountNames` (`account → {lite, full}`, each with the
//! chat key the contracts hold) and announces every write with `NameReserved`
//! or `NameRegistered`. The People runtime stops keeping usernames with
//! paritytech/individuality-community#129, so this is the one place they live.
//!
//! No Asset Hub API is generated: these types decode dynamically against the
//! connected runtime's metadata, naming only the fields the indexer reads.

use subxt::ext::scale_decode::DecodeAsType;
use subxt::storage::DynamicAddress;
use subxt::utils::AccountId32;

use crate::projection::{self, AssignedUsername, DecodeError};

/// The pallet this module reads.
const PALLET: &str = "DotnsGateway";

/// `DotnsGateway::AccountNames`, keyed by account.
pub(crate) fn account_names() -> DynamicAddress<(AccountId32,), AccountNameRecord> {
    subxt::dynamic::storage(PALLET, "AccountNames")
}

/// `DotnsGateway::AccountNames`'s value: the labels one account holds.
#[derive(Debug, Clone, PartialEq, Eq, DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub(crate) struct AccountNameRecord {
    /// The most recently reserved lite label, `<base>.<digits>`.
    pub lite: Option<NameEntry>,
    /// The registered full-person label.
    pub full: Option<NameEntry>,
}

/// One label and the chat key the contracts hold for it.
#[derive(Debug, Clone, PartialEq, Eq, DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub(crate) struct NameEntry {
    /// The label's bytes.
    pub label: Vec<u8>,
    /// The ECDH chat key, `None` when the pallet never saw it.
    pub chat: Option<[u8; 65]>,
}

/// The field of `NameReserved` the indexer reads.
#[derive(Debug, DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
struct NameReserved {
    candidate: AccountId32,
}

/// The field of `NameRegistered` the indexer reads.
#[derive(Debug, DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
struct NameRegistered {
    account: AccountId32,
}

/// Why an account's labels make no projection row.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Unindexable {
    /// The account holds no lite label, only a full one.
    #[error("the account holds no lite label")]
    NoLite,
    /// Neither label carries a chat key, which the row requires.
    #[error("no label carries a chat key")]
    NoChatKey,
    /// A label is malformed.
    #[error(transparent)]
    Malformed(#[from] DecodeError),
}

/// The projection row for `account`'s labels.
///
/// The lite label is the username, and the full label shadows it for display,
/// as on People. The chat key is the identifier key DUB registered with: the
/// lite label's, or the full label's when the lite one was never recorded.
pub(crate) fn assigned_username(
    account: [u8; 32],
    record: AccountNameRecord,
    ss58_prefix: u16,
    snapshot_hash: [u8; 32],
    snapshot_number: u64,
) -> Result<AssignedUsername, Unindexable> {
    let Some(lite) = record.lite else {
        return Err(Unindexable::NoLite);
    };
    let chat = lite
        .chat
        .or_else(|| record.full.as_ref().and_then(|full| full.chat))
        .ok_or(Unindexable::NoChatKey)?;
    Ok(projection::decode_username(
        account,
        chat,
        lite.label,
        record.full.map(|full| full.label),
        ss58_prefix,
        snapshot_hash,
        snapshot_number,
    )?)
}

/// The accounts a block's gateway events name, in event order.
pub(crate) fn accounts_from_events<T: subxt::Config>(
    events: &subxt::events::Events<T>,
) -> Result<Vec<[u8; 32]>, Box<subxt::error::EventsError>> {
    let mut accounts = Vec::new();
    for event in events.iter() {
        let event = event.map_err(Box::new)?;
        if event.pallet_name() != PALLET {
            continue;
        }
        match event.event_name() {
            "NameReserved" => {
                let reserved: NameReserved =
                    event.decode_fields_unchecked_as().map_err(Box::new)?;
                accounts.push(reserved.candidate.0);
            }
            "NameRegistered" => {
                let registered: NameRegistered =
                    event.decode_fields_unchecked_as().map_err(Box::new)?;
                accounts.push(registered.account.0);
            }
            _ => {}
        }
    }
    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(label: &str, chat: Option<u8>) -> NameEntry {
        NameEntry {
            label: label.as_bytes().to_vec(),
            chat: chat.map(|byte| [byte; 65]),
        }
    }

    fn row(record: AccountNameRecord) -> Result<AssignedUsername, Unindexable> {
        assigned_username([1; 32], record, 42, [3; 32], 7)
    }

    #[test]
    fn a_lite_label_is_the_username_and_its_chat_key_the_identifier() {
        let record = row(AccountNameRecord {
            lite: Some(entry("alicex.07", Some(0))),
            full: None,
        })
        .expect("a row");
        assert_eq!(record.lite_username, "alicex.07", "the lite label");
        assert_eq!(record.display_username, "alicex.07", "shown as itself");
        assert_eq!(record.identifier_key, [0; 65], "the lite label's chat key");
    }

    #[test]
    fn a_full_label_shadows_the_lite_one() {
        let record = row(AccountNameRecord {
            lite: Some(entry("alicex.07", Some(0))),
            full: Some(entry("alice", Some(9))),
        })
        .expect("a row");
        assert_eq!(record.full_username.as_deref(), Some("alice"), "kept");
        assert_eq!(record.display_username, "alice", "shown instead");
        assert_eq!(record.identifier_key, [0; 65], "still the lite label's key");
    }

    #[test]
    fn the_full_labels_chat_key_stands_in_for_a_missing_lite_one() {
        let record = row(AccountNameRecord {
            lite: Some(entry("alicex.07", None)),
            full: Some(entry("alice", Some(9))),
        })
        .expect("a row");
        assert_eq!(record.identifier_key, [9; 65], "the full label's key");
    }

    #[test]
    fn records_a_row_cannot_hold_are_unindexable() {
        assert_eq!(
            row(AccountNameRecord {
                lite: None,
                full: Some(entry("alice", Some(9))),
            }),
            Err(Unindexable::NoLite),
            "a full-only account has no lite username"
        );
        assert_eq!(
            row(AccountNameRecord {
                lite: Some(entry("alicex.07", None)),
                full: None,
            }),
            Err(Unindexable::NoChatKey),
            "the row requires an identifier key"
        );
        assert_eq!(
            row(AccountNameRecord {
                lite: Some(entry("alicex", Some(0))),
                full: None,
            }),
            Err(Unindexable::Malformed(DecodeError::LiteFormat)),
            "a lite label needs its digits"
        );
    }

    /// Reads a page of `AccountNames` and scans recent blocks for gateway
    /// events on a live Asset Hub, decoding both with these types. Either may
    /// be empty on a quiet network; anything read that does not decode fails
    /// the test.
    #[tokio::test]
    #[ignore = "requires a reachable Asset Hub RPC (ASSET_HUB_RPC_URL, or the Paseo default); \
                run with --ignored"]
    async fn live_account_names_and_events_decode() {
        let url = std::env::var("ASSET_HUB_RPC_URL")
            .unwrap_or_else(|_| "wss://paseo-asset-hub-next-rpc.polkadot.io".to_string());
        let chain = crate::chain::AssetHubChain::connect(&url, 100)
            .await
            .expect("live Asset Hub RPC");
        let at = chain.online().at_current_block().await.expect("a block");

        let mut entries = at
            .storage()
            .entry(account_names())
            .expect("the entry")
            .iter(())
            .await
            .expect("an iterator");
        let (mut rows, mut unindexable) = (0_u32, 0_u32);
        while let Some(entry) = entries.next().await {
            let entry = entry.expect("an entry");
            let (account,): (AccountId32,) =
                entry.key().and_then(|key| key.decode()).expect("a key");
            let names: AccountNameRecord = entry.value().decode().expect("a record");
            match assigned_username(account.0, names, 42, [0; 32], 0) {
                Ok(_) => rows += 1,
                Err(_) => unindexable += 1,
            }
            if rows + unindexable == 50 {
                break;
            }
        }

        let head = at.block_number();
        let mut named = 0;
        for number in head.saturating_sub(300)..=head {
            let block = chain.online().at_block(number).await.expect("a block");
            let events = block.events().fetch().await.expect("events");
            named += accounts_from_events(&events).expect("decodable").len();
        }
        println!("rows={rows} unindexable={unindexable} accounts_named_in_300_blocks={named}");
    }
}
