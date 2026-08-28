// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeSet, HashMap};

use subxt_rpcs::methods::legacy::StorageChangeSet;
use subxt_rpcs::{LegacyRpcMethods, RpcConfig};

/// A batched storage read that came back unusable.
#[derive(Debug, thiserror::Error)]
pub enum BatchReadError {
    #[error("batched storage read failed")]
    Rpc(#[source] subxt_rpcs::Error),
    #[error("expected one storage change set for one block, got {0}")]
    ChangeSetCount(usize),
    #[error("storage answered for block {got}, not the requested {want}")]
    BlockMismatch {
        want: String,
        got: String,
    },
    #[error("storage answered with a key that was not requested")]
    UnknownKey,
    #[error("storage answered twice for the same key")]
    DuplicateKey,
    #[error("storage left {0} of the requested keys unanswered")]
    MissingKeys(usize),
    #[error("storage answered with a value that is not an AccountId32")]
    UndecodableValue,
}

pub async fn fetch_many<C>(
    rpc: &LegacyRpcMethods<C>,
    keys: &[Vec<u8>],
    at: C::Hash,
) -> Result<Vec<Option<Vec<u8>>>, BatchReadError>
where
    C: RpcConfig,
    C::Hash: Copy + PartialEq + std::fmt::Debug,
{
    let changes = rpc
        .state_query_storage_at(keys.iter().map(Vec::as_slice), Some(at))
        .await
        .map_err(BatchReadError::Rpc)?;
    values_from_changes(keys, &at, changes)
}

pub async fn fetch_present<C>(
    rpc: &LegacyRpcMethods<C>,
    keys: &[Vec<u8>],
    at: C::Hash,
) -> Result<BTreeSet<usize>, BatchReadError>
where
    C: RpcConfig,
    C::Hash: Copy + PartialEq + std::fmt::Debug,
{
    Ok(present_of(fetch_many(rpc, keys, at).await?))
}

pub fn values_from_changes<H: PartialEq + std::fmt::Debug>(
    keys: &[Vec<u8>],
    want_block: &H,
    changes: Vec<StorageChangeSet<H>>,
) -> Result<Vec<Option<Vec<u8>>>, BatchReadError> {
    let [set] = <[_; 1]>::try_from(changes)
        .map_err(|changes: Vec<_>| BatchReadError::ChangeSetCount(changes.len()))?;
    if &set.block != want_block {
        return Err(BatchReadError::BlockMismatch {
            want: format!("{want_block:?}"),
            got: format!("{:?}", set.block),
        });
    }

    let index: HashMap<&[u8], usize> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| (key.as_slice(), i))
        .collect();
    let mut answered = vec![false; keys.len()];
    let mut values = vec![None; keys.len()];

    for (key, value) in set.changes {
        let i = *index
            .get(key.0.as_slice())
            .ok_or(BatchReadError::UnknownKey)?;
        if std::mem::replace(&mut answered[i], true) {
            return Err(BatchReadError::DuplicateKey);
        }
        values[i] = value.map(|bytes| bytes.0);
    }

    let unanswered = answered.iter().filter(|seen| !**seen).count();
    if unanswered > 0 {
        return Err(BatchReadError::MissingKeys(unanswered));
    }
    Ok(values)
}

pub fn present_of(values: Vec<Option<Vec<u8>>>) -> BTreeSet<usize> {
    values
        .into_iter()
        .enumerate()
        .filter_map(|(i, value)| value.is_some().then_some(i))
        .collect()
}

pub fn owners_by_name(
    names: &BTreeSet<&str>,
    values: Vec<Option<Vec<u8>>>,
) -> Result<HashMap<String, [u8; 32]>, BatchReadError> {
    let mut owners = HashMap::with_capacity(names.len());
    for (name, value) in names.iter().zip(values) {
        if let Some(bytes) = value {
            owners.insert((*name).to_string(), decode_owner(&bytes)?);
        }
    }
    Ok(owners)
}

pub fn decode_owner(bytes: &[u8]) -> Result<[u8; 32], BatchReadError> {
    use subxt::ext::codec::Decode as _;

    let mut input = bytes;
    let owner = subxt::utils::AccountId32::decode(&mut input)
        .map_err(|_| BatchReadError::UndecodableValue)?;
    if !input.is_empty() {
        return Err(BatchReadError::UndecodableValue);
    }
    Ok(owner.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Vec<Vec<u8>> {
        vec![vec![0xa0], vec![0xb0], vec![0xc0]]
    }

    fn set(block: u8, changes: &[(u8, bool)]) -> Vec<StorageChangeSet<u8>> {
        vec![StorageChangeSet {
            block,
            changes: changes
                .iter()
                .map(|(key, owned)| {
                    (
                        subxt_rpcs::methods::legacy::Bytes(vec![*key]),
                        owned.then(|| subxt_rpcs::methods::legacy::Bytes(vec![1])),
                    )
                })
                .collect(),
        }]
    }

    /// The shape the existence reads take, so the cases below read the way they
    /// did when this logic lived next to its one caller.
    fn taken_from_changes(
        keys: &[Vec<u8>],
        want_block: &u8,
        changes: Vec<StorageChangeSet<u8>>,
    ) -> Result<BTreeSet<usize>, BatchReadError> {
        Ok(present_of(values_from_changes(keys, want_block, changes)?))
    }

    #[test]
    fn resolves_owned_keys_in_any_order() {
        let taken = taken_from_changes(
            &keys(),
            &7,
            set(7, &[(0xc0, true), (0xa0, false), (0xb0, true)]),
        )
        .expect("well-formed response");
        assert_eq!(taken, BTreeSet::from([1, 2]));
    }

    #[test]
    fn absent_values_are_free() {
        let taken = taken_from_changes(
            &keys(),
            &7,
            set(7, &[(0xa0, false), (0xb0, false), (0xc0, false)]),
        )
        .expect("well-formed response");
        assert!(taken.is_empty());
    }

    #[test]
    fn missing_key_is_an_error() {
        let error = taken_from_changes(&keys(), &7, set(7, &[(0xa0, true), (0xb0, false)]))
            .expect_err("short response");
        assert!(matches!(error, BatchReadError::MissingKeys(1)), "{error:?}");
    }

    #[test]
    fn unknown_key_is_an_error() {
        let error = taken_from_changes(
            &keys(),
            &7,
            set(
                7,
                &[(0xa0, true), (0xb0, false), (0xc0, false), (0xd0, false)],
            ),
        )
        .expect_err("unrequested key");
        assert!(matches!(error, BatchReadError::UnknownKey), "{error:?}");
    }

    #[test]
    fn duplicate_key_is_an_error() {
        let error = taken_from_changes(
            &keys(),
            &7,
            set(
                7,
                &[(0xa0, true), (0xa0, false), (0xb0, false), (0xc0, false)],
            ),
        )
        .expect_err("duplicate key");
        assert!(matches!(error, BatchReadError::DuplicateKey), "{error:?}");
    }

    #[test]
    fn other_block_is_an_error() {
        let error = taken_from_changes(
            &keys(),
            &7,
            set(9, &[(0xa0, false), (0xb0, false), (0xc0, false)]),
        )
        .expect_err("wrong block");
        assert!(
            matches!(error, BatchReadError::BlockMismatch { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn multiple_change_sets_are_an_error() {
        let mut changes = set(7, &[(0xa0, false), (0xb0, false), (0xc0, false)]);
        changes.extend(set(8, &[(0xa0, true)]));
        let error = taken_from_changes(&keys(), &7, changes).expect_err("two change sets");
        assert!(
            matches!(error, BatchReadError::ChangeSetCount(2)),
            "{error:?}"
        );
    }

    #[test]
    fn empty_change_set_is_an_error() {
        let error = taken_from_changes(&keys(), &7, set(7, &[])).expect_err("empty response");
        assert!(matches!(error, BatchReadError::MissingKeys(3)), "{error:?}");
    }

    #[test]
    fn values_are_returned_positionally() {
        let changes = vec![StorageChangeSet {
            block: 7u8,
            changes: vec![
                (
                    subxt_rpcs::methods::legacy::Bytes(vec![0xc0]),
                    Some(subxt_rpcs::methods::legacy::Bytes(vec![0xcc])),
                ),
                (subxt_rpcs::methods::legacy::Bytes(vec![0xa0]), None),
                (
                    subxt_rpcs::methods::legacy::Bytes(vec![0xb0]),
                    Some(subxt_rpcs::methods::legacy::Bytes(vec![0xbb])),
                ),
            ],
        }];
        let values = values_from_changes(&keys(), &7, changes).expect("well-formed response");
        assert_eq!(values, vec![None, Some(vec![0xbb]), Some(vec![0xcc])]);
    }

    #[test]
    fn owner_values_decode_as_account_ids() {
        let account = [9u8; 32];
        assert_eq!(decode_owner(&account).expect("32 bytes"), account);

        let mut trailing = account.to_vec();
        trailing.push(0);
        assert!(matches!(
            decode_owner(&trailing),
            Err(BatchReadError::UndecodableValue)
        ));
        assert!(matches!(
            decode_owner(&account[..31]),
            Err(BatchReadError::UndecodableValue)
        ));
    }

    /// The pairing is by set order, not by the caller's argument order, and an
    /// absent key yields no entry rather than an empty one.
    #[test]
    fn names_pair_with_values_in_set_order() {
        let names = BTreeSet::from(["b.02", "a.01", "c.03"]);
        let owners = owners_by_name(
            &names,
            // Positionally: a.01, b.02, c.03 — the set's own order.
            vec![Some(vec![1u8; 32]), None, Some(vec![3u8; 32])],
        )
        .expect("well-formed values");

        assert_eq!(owners.len(), 2);
        assert_eq!(owners.get("a.01"), Some(&[1u8; 32]));
        assert_eq!(owners.get("c.03"), Some(&[3u8; 32]));
        assert!(!owners.contains_key("b.02"), "an absent key has no owner");
    }
}
