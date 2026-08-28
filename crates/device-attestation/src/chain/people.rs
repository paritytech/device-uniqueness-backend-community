// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeSet, HashMap};

use anyhow::Context as _;
use chain_client::storage;
use chain_types::people;
use chain_types::PeopleConfig;
use subxt::config::RpcConfigFor;
use subxt::OnlineClient;
use subxt_rpcs::{LegacyRpcMethods, RpcClient};

const DISCRIMINATORS: u8 = 100;

const HEALTH_PROBE_USERNAME: &str = "readyz-probe.00";

fn owner_key(
    username: impl AsRef<[u8]>,
) -> people::runtime_types::bounded_collections::bounded_vec::BoundedVec<u8> {
    people::runtime_types::bounded_collections::bounded_vec::BoundedVec(username.as_ref().to_vec())
}

#[derive(Clone)]
pub struct PeopleChain {
    client: OnlineClient<PeopleConfig>,
    rpc: LegacyRpcMethods<RpcConfigFor<PeopleConfig>>,
}

impl PeopleChain {
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

        let taken = storage::fetch_present(&self.rpc, &keys, block_hash)
            .await
            .context("reading username owners")?;
        Ok(taken.into_iter().map(|i| i as u8).collect())
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

        let values = storage::fetch_many(&self.rpc, &keys, block_hash)
            .await
            .context("reading username owners")?;
        Ok(storage::owners_by_name(&unique, values)?)
    }
}
