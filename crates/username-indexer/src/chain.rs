// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use chain_types::PeopleConfig;
use subxt::{backend::LegacyBackend, client::Blocks, OnlineClient};
use subxt_rpcs::client::{ReconnectingRpcClient, RpcClient};

/// Boxed chain transport or metadata error.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// People Chain connection or query failure.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("connecting to People Chain at {url}: {source}")]
    Connect {
        url: String,
        #[source]
        source: BoxError,
    },
    /// Online client metadata initialization failed.
    #[error("initializing People Chain client: {0}")]
    Initialize(#[source] BoxError),
    #[error("querying People Chain finalized snapshot: {0}")]
    Query(#[source] BoxError),
}

/// Connected People Chain client using a reconnecting legacy backend.
#[derive(Clone)]
pub struct PeopleChain {
    client: OnlineClient<PeopleConfig>,
}

impl PeopleChain {
    /// Connect and configure bounded legacy storage paging.
    pub async fn connect(url: &str, storage_page_size: u32) -> Result<Self, ChainError> {
        let reconnecting = ReconnectingRpcClient::builder()
            .build(url)
            .await
            .map_err(|source| ChainError::Connect {
                url: url.to_string(),
                source: Box::new(source),
            })?;
        let backend = LegacyBackend::<PeopleConfig>::builder()
            .storage_page_size(storage_page_size)
            .build(RpcClient::new(reconnecting));
        let client = OnlineClient::from_backend(Arc::new(backend))
            .await
            .map_err(|source| ChainError::Initialize(Box::new(source)))?;
        Ok(Self { client })
    }

    /// Wrap an already-constructed online client (offline replay tests).
    pub fn from_online(client: OnlineClient<PeopleConfig>) -> Self {
        Self { client }
    }

    pub fn online(&self) -> &OnlineClient<PeopleConfig> {
        &self.client
    }

    pub async fn finalized_blocks(&self) -> Result<Blocks<PeopleConfig>, ChainError> {
        self.client
            .stream_blocks()
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

    /// Verify that a current finalized block is reachable.
    pub async fn health(&self) -> Result<(), ChainError> {
        self.client
            .at_current_block()
            .await
            .map_err(|source| ChainError::Query(Box::new(source)))?;
        Ok(())
    }
}
