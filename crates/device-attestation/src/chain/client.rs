// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeSet;
use std::collections::HashMap;

use anyhow::Context as _;
use chain_types::people;
use chain_types::PeopleConfig;
use subxt::config::RpcConfigFor;
use subxt::OnlineClient;
use subxt_rpcs::methods::legacy::StorageChangeSet;
use subxt_rpcs::{LegacyRpcMethods, RpcClient};

const DISCRIMINATORS: u8 = 100;

const HEALTH_PROBE_USERNAME: &str = "readyz-probe.00";

#[derive(Debug, thiserror::Error)]
pub enum BatchReadError {
    #[error("expected one storage change set for one block, got {0}")]
    ChangeSetCount(usize),
    #[error("storage answered for block {got}, not the requested {want}")]
    BlockMismatch { want: String, got: String },
    #[error("storage answered with a key that was not requested")]
    UnknownKey,
    #[error("storage answered twice for the same key")]
    DuplicateKey,
    #[error("storage left {0} of the requested keys unanswered")]
    MissingKeys(usize),
    /// A stored value that is not the `AccountId32` this map is declared to
    /// hold — a runtime that changed the value's shape, not a transport fault.
    #[error("storage answered with a value that is not an AccountId32")]
    UndecodableValue,
}

fn owner_key(
    username: impl AsRef<[u8]>,
) -> people::runtime_types::bounded_collections::bounded_vec::BoundedVec<u8> {
    people::runtime_types::bounded_collections::bounded_vec::BoundedVec(username.as_ref().to_vec())
}

pub(super) fn values_from_changes<H: PartialEq + std::fmt::Debug>(
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

fn taken_from_changes<H: PartialEq + std::fmt::Debug>(
    keys: &[Vec<u8>],
    want_block: &H,
    changes: Vec<StorageChangeSet<H>>,
) -> Result<BTreeSet<u8>, BatchReadError> {
    Ok(values_from_changes(keys, want_block, changes)?
        .into_iter()
        .enumerate()
        .filter_map(|(i, value)| value.is_some().then_some(i as u8))
        .collect())
}

pub(super) fn decode_owner(bytes: &[u8]) -> Result<[u8; 32], BatchReadError> {
    use subxt::ext::codec::Decode as _;

    let mut input = bytes;
    let owner = subxt::utils::AccountId32::decode(&mut input)
        .map_err(|_| BatchReadError::UndecodableValue)?;
    if !input.is_empty() {
        return Err(BatchReadError::UndecodableValue);
    }
    Ok(owner.0)
}

#[derive(Clone)]
pub struct ChainClient {
    client: OnlineClient<PeopleConfig>,
    rpc: LegacyRpcMethods<RpcConfigFor<PeopleConfig>>,
}

impl ChainClient {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let (client, rpc) = chain_client::connect_with_rpc(url).await?;
        Ok(Self::from_parts(client, rpc))
    }

    pub fn from_parts(client: OnlineClient<PeopleConfig>, rpc: RpcClient) -> Self {
        Self {
            client,
            rpc: LegacyRpcMethods::new(rpc),
        }
    }

    pub async fn health(&self) -> anyhow::Result<()> {
        let at = self
            .client
            .at_current_block()
            .await
            .context("People Chain unreachable")?;
        let key = at
            .storage()
            .entry(people::storage().resources().username_owner_of())?
            .fetch_key((owner_key(HEALTH_PROBE_USERNAME),))?;
        self.rpc
            .state_query_storage_at([key.as_slice()], Some(at.block_hash()))
            .await
            .context("People Chain does not serve state_queryStorageAt")?;
        Ok(())
    }

    pub fn online(&self) -> &OnlineClient<PeopleConfig> {
        &self.client
    }

    pub async fn username_owner(&self, full_username: &str) -> anyhow::Result<Option<[u8; 32]>> {
        let at = self.client.at_current_block().await?;
        let address = people::storage().resources().username_owner_of();
        let owner = at
            .storage()
            .try_fetch(address, (owner_key(full_username),))
            .await?;
        match owner {
            Some(value) => Ok(Some(value.decode()?.0)),
            None => Ok(None),
        }
    }

    pub async fn free_balance(&self, account: [u8; 32]) -> anyhow::Result<u128> {
        let at = self.client.at_current_block().await?;
        let address = people::storage().system().account();
        let info = at
            .storage()
            .try_fetch(address, (subxt::utils::AccountId32(account),))
            .await?;
        match info {
            Some(value) => Ok(value.decode()?.data.free),
            None => Ok(0),
        }
    }

    pub async fn attestation_allowance(&self, account: [u8; 32]) -> anyhow::Result<u32> {
        let at = self.client.at_current_block().await?;
        let address = people::storage().people_lite().attestation_allowance();
        let allowance = at
            .storage()
            .try_fetch(address, (subxt::utils::AccountId32(account),))
            .await?;
        match allowance {
            Some(value) => Ok(value.decode()?),
            None => Ok(0),
        }
    }

    pub async fn taken_discriminators(&self, base: &str) -> anyhow::Result<BTreeSet<u8>> {
        let at = self.client.at_current_block().await?;
        self.taken_discriminators_at(base, &at).await
    }

    pub async fn taken_discriminators_at(
        &self,
        base: &str,
        at: &subxt::client::ClientAtBlock<
            PeopleConfig,
            subxt::client::OnlineClientAtBlockImpl<PeopleConfig>,
        >,
    ) -> anyhow::Result<BTreeSet<u8>> {
        let block_hash = at.block_hash();
        let entry = at
            .storage()
            .entry(people::storage().resources().username_owner_of())?;

        let keys = (0..DISCRIMINATORS)
            .map(|discriminator| {
                entry.fetch_key((owner_key(format!("{base}.{discriminator:02}")),))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let changes = self
            .rpc
            .state_query_storage_at(keys.iter().map(Vec::as_slice), Some(block_hash))
            .await
            .context("reading username owners")?;

        Ok(taken_from_changes(&keys, &block_hash, changes)?)
    }

    pub async fn username_owners(
        &self,
        names: &[&str],
    ) -> anyhow::Result<HashMap<String, [u8; 32]>> {
        if names.is_empty() {
            return Ok(HashMap::new());
        }
        let unique: BTreeSet<&str> = names.iter().copied().collect();

        let at = self.client.at_current_block().await?;
        let block_hash = at.block_hash();
        let entry = at
            .storage()
            .entry(people::storage().resources().username_owner_of())?;
        let keys = unique
            .iter()
            .map(|name| entry.fetch_key((owner_key(name),)))
            .collect::<Result<Vec<_>, _>>()?;

        let changes = self
            .rpc
            .state_query_storage_at(keys.iter().map(Vec::as_slice), Some(block_hash))
            .await
            .context("reading username owners")?;

        let values = values_from_changes(&keys, &block_hash, changes)?;
        let mut owners = HashMap::with_capacity(unique.len());
        for (name, value) in unique.iter().zip(values) {
            if let Some(bytes) = value {
                owners.insert((*name).to_string(), decode_owner(&bytes)?);
            }
        }
        Ok(owners)
    }
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
}
