// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Context as _;
use chain_types::AssetHubConfig;
use subxt::dynamic::{At as _, Value};
use subxt::utils::AccountId32;
use subxt::OnlineClient;

use crate::dotns;

const PALLET: &str = "DotnsGateway";

#[derive(Debug, Clone, Copy)]
pub struct ValidityWindow {
    pub max_validity_secs: u64,
    pub max_future_skew_secs: u64,
}

#[derive(Clone)]
pub struct AssetHubClient {
    client: OnlineClient<AssetHubConfig>,
}

impl AssetHubClient {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let client = chain_client::connect_asset_hub(url).await?;
        let this = Self { client };
        this.check_reserve_name_shape()
            .await
            .with_context(|| format!("Asset Hub at {url}"))?;
        Ok(this)
    }

    pub fn from_online(client: OnlineClient<AssetHubConfig>) -> Self {
        Self { client }
    }

    pub fn online(&self) -> &OnlineClient<AssetHubConfig> {
        &self.client
    }

    pub async fn health(&self) -> anyhow::Result<()> {
        self.client
            .at_current_block()
            .await
            .context("Asset Hub unreachable")?;
        Ok(())
    }

    async fn check_reserve_name_shape(&self) -> anyhow::Result<()> {
        let metadata = self.client.at_current_block().await?.metadata();
        let pallet = metadata
            .pallet_by_name(PALLET)
            .with_context(|| format!("runtime declares no {PALLET} pallet"))?;
        let call = pallet
            .call_variant_by_name("reserve_name")
            .with_context(|| format!("{PALLET} declares no reserve_name call"))?;
        let fields: Vec<&str> = call
            .fields
            .iter()
            .map(|field| field.name.as_deref().unwrap_or("<unnamed>"))
            .collect();
        dotns::check_reserve_name_shape(&fields)?;
        Ok(())
    }

    pub async fn lite_label_owner(&self, lite_label: &str) -> anyhow::Result<Option<[u8; 32]>> {
        let at = self.client.at_current_block().await?;
        let address = subxt::dynamic::storage::<_, AccountId32>(PALLET, "LiteLabelOwner");
        let owner = at
            .storage()
            .try_fetch(address, (label_key(lite_label),))
            .await?;
        match owner {
            Some(value) => Ok(Some(value.decode()?.0)),
            None => Ok(None),
        }
    }

    pub async fn attestation_allowance(&self, account: [u8; 32]) -> anyhow::Result<u32> {
        let at = self.client.at_current_block().await?;
        let address = subxt::dynamic::storage::<_, u32>(PALLET, "AttestationAllowance");
        let allowance = at
            .storage()
            .try_fetch(address, (AccountId32(account),))
            .await?;
        match allowance {
            Some(value) => Ok(value.decode()?),
            None => Ok(0),
        }
    }

    pub async fn free_balance(&self, account: [u8; 32]) -> anyhow::Result<u128> {
        let at = self.client.at_current_block().await?;
        let address = subxt::dynamic::storage::<_, Value>("System", "Account");
        let info = at
            .storage()
            .try_fetch(address, (AccountId32(account),))
            .await?;
        let Some(info) = info else { return Ok(0) };
        let value = info.decode()?;
        let free = value
            .at("data")
            .and_then(|data| data.at("free"))
            .and_then(|free| free.as_u128())
            .context("System::Account has no data.free field")?;
        Ok(free)
    }

    pub async fn validity_window(&self) -> anyhow::Result<ValidityWindow> {
        let at = self.client.at_current_block().await?;
        let constants = at.constants();
        Ok(ValidityWindow {
            max_validity_secs: constants
                .entry(subxt::dynamic::constant::<u64>(
                    PALLET,
                    "MaxValiditySeconds",
                ))
                .context("reading DotnsGateway::MaxValiditySeconds")?,
            max_future_skew_secs: constants
                .entry(subxt::dynamic::constant::<u64>(
                    PALLET,
                    "MaxFutureSkewSeconds",
                ))
                .context("reading DotnsGateway::MaxFutureSkewSeconds")?,
        })
    }
}

fn label_key(lite_label: &str) -> Value {
    Value::from_bytes(lite_label.as_bytes())
}
