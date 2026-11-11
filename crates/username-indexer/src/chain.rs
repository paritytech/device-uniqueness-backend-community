// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use chain_types::AssetHubConfig;
use subxt::{backend::LegacyBackend, client::Blocks, config::RpcConfigFor, OnlineClient};
use subxt_rpcs::client::{ReconnectingRpcClient, RpcClient};
use subxt_rpcs::LegacyRpcMethods;

/// A handle on Asset Hub at one block.
pub(crate) type AssetHubAt = subxt::client::ClientAtBlock<
    AssetHubConfig,
    subxt::client::OnlineClientAtBlockImpl<AssetHubConfig>,
>;

/// Boxed chain transport or metadata error.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Asset Hub connection or query failure.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("connecting to Asset Hub at {url}: {source}")]
    Connect {
        url: String,
        #[source]
        source: BoxError,
    },
    /// Online client metadata initialization failed.
    #[error("initializing Asset Hub client: {0}")]
    Initialize(#[source] BoxError),
    #[error("querying Asset Hub finalized snapshot: {0}")]
    Query(#[source] BoxError),
    /// `chain_getHeader` answered, but with no header at all.
    #[error("Asset Hub reported no best header")]
    NoBestHeader,
}

/// Connected Asset Hub client using a reconnecting legacy backend.
#[derive(Clone)]
pub struct AssetHubChain {
    client: OnlineClient<AssetHubConfig>,
    rpc: LegacyRpcMethods<RpcConfigFor<AssetHubConfig>>,
}

impl AssetHubChain {
    /// Connect and configure bounded legacy storage paging.
    pub async fn connect(url: &str, storage_page_size: u32) -> Result<Self, ChainError> {
        let reconnecting = ReconnectingRpcClient::builder()
            .build(url)
            .await
            .map_err(|source| ChainError::Connect {
                url: url.to_string(),
                source: Box::new(source),
            })?;
        let rpc_client = RpcClient::new(reconnecting);
        let backend = LegacyBackend::<AssetHubConfig>::builder()
            .storage_page_size(storage_page_size)
            .build(rpc_client.clone());
        let client = OnlineClient::from_backend(Arc::new(backend))
            .await
            .map_err(|source| ChainError::Initialize(Box::new(source)))?;
        Ok(Self::from_parts(client, rpc_client))
    }

    /// Wrap an already-constructed online client (offline replay tests).
    pub fn from_parts(client: OnlineClient<AssetHubConfig>, rpc: RpcClient) -> Self {
        Self {
            client,
            rpc: LegacyRpcMethods::new(rpc),
        }
    }

    pub fn online(&self) -> &OnlineClient<AssetHubConfig> {
        &self.client
    }

    pub async fn best_blocks(&self) -> Result<Blocks<AssetHubConfig>, ChainError> {
        self.client
            .stream_best_blocks()
            .await
            .map_err(|source| ChainError::Query(Box::new(source)))
    }

    pub async fn finalized_head_number(&self) -> Result<u64, ChainError> {
        Ok(self
            .client
            .at_current_block()
            .await
            .map_err(|source| ChainError::Query(Box::new(source)))?
            .block_number())
    }

    pub async fn best_head_number(&self) -> Result<u64, ChainError> {
        let header = self
            .rpc
            .chain_get_header(None)
            .await
            .map_err(|source| ChainError::Query(Box::new(source)))?
            .ok_or(ChainError::NoBestHeader)?;
        Ok(header.number)
    }

    /// Verify that a current finalized block is reachable.
    pub async fn health(&self) -> Result<(), ChainError> {
        self.client
            .at_current_block()
            .await
            .map_err(|source| ChainError::Query(Box::new(source)))?;
        Ok(())
    }
}
