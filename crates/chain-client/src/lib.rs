// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::str::FromStr as _;

use anyhow::Context as _;
use chain_types::{AssetHubConfig, PeopleConfig};
use subxt::utils::{AccountId32, MultiSignature};
use subxt::OnlineClient;
use subxt_rpcs::client::{ReconnectingRpcClient, RpcClient};

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("connecting to {chain} at {url}")]
    Transport {
        chain: &'static str,
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("building the {chain} client at {url}")]
    Client {
        chain: &'static str,
        url: String,
        #[source]
        source: subxt::error::OnlineClientError,
    },
}

pub async fn connect(url: &str) -> Result<OnlineClient<PeopleConfig>, ConnectError> {
    connect_as::<PeopleConfig>(url, "People Chain").await
}

pub async fn connect_with_rpc(
    url: &str,
) -> Result<(OnlineClient<PeopleConfig>, RpcClient), ConnectError> {
    connect_as_with_rpc::<PeopleConfig>(url, "People Chain").await
}

pub async fn connect_asset_hub(url: &str) -> Result<OnlineClient<AssetHubConfig>, ConnectError> {
    connect_as::<AssetHubConfig>(url, "Asset Hub").await
}

pub async fn connect_asset_hub_with_rpc(
    url: &str,
) -> Result<(OnlineClient<AssetHubConfig>, RpcClient), ConnectError> {
    connect_as_with_rpc::<AssetHubConfig>(url, "Asset Hub").await
}

async fn connect_as_with_rpc<T: subxt::Config + Default>(
    url: &str,
    chain: &'static str,
) -> Result<(OnlineClient<T>, RpcClient), ConnectError> {
    let rpc = reconnecting_rpc_client(url, chain).await?;
    let client = OnlineClient::<T>::from_rpc_client(rpc.clone())
        .await
        .map_err(|source| ConnectError::Client {
            chain,
            url: url.to_string(),
            source,
        })?;
    Ok((client, rpc))
}

async fn connect_as<T: subxt::Config + Default>(
    url: &str,
    chain: &'static str,
) -> Result<OnlineClient<T>, ConnectError> {
    OnlineClient::<T>::from_rpc_client(reconnecting_rpc_client(url, chain).await?)
        .await
        .map_err(|source| ConnectError::Client {
            chain,
            url: url.to_string(),
            source,
        })
}

async fn reconnecting_rpc_client(
    url: &str,
    chain: &'static str,
) -> Result<RpcClient, ConnectError> {
    let rpc_client = ReconnectingRpcClient::builder()
        .build(url)
        .await
        .map_err(|source| ConnectError::Transport {
            chain,
            url: url.to_string(),
            source: Box::new(source),
        })?;
    Ok(RpcClient::new(rpc_client))
}

pub enum WriterSigner {
    /// Keypair derived from a `SecretUri` by `subxt-signer`.
    Uri(subxt_signer::sr25519::Keypair),
    /// Keypair built directly from a raw 64-byte expanded secret.
    Raw(schnorrkel::Keypair),
}

impl WriterSigner {
    pub fn from_secret(secret: &str) -> anyhow::Result<Self> {
        let trimmed = secret.trim();
        if let Some(hex) = trimmed.strip_prefix("0x") {
            if hex.len() == 128 {
                let bytes = hex::decode(hex).context("decoding raw sr25519 secret key")?;
                let secret = schnorrkel::SecretKey::from_ed25519_bytes(&bytes)
                    .map_err(|e| anyhow::anyhow!("invalid 64-byte sr25519 secret key: {e}"))?;
                let keypair = schnorrkel::Keypair {
                    public: secret.to_public(),
                    secret,
                };
                return Ok(Self::Raw(keypair));
            }
        }
        let uri =
            subxt_signer::SecretUri::from_str(trimmed).context("parsing signer secret URI")?;
        let keypair = subxt_signer::sr25519::Keypair::from_uri(&uri)
            .context("building signer keypair from SURI")?;
        Ok(Self::Uri(keypair))
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        match self {
            Self::Uri(k) => k.public_key().0,
            Self::Raw(k) => k.public.to_bytes(),
        }
    }

    /// The account this key must proxy for, or `None` when it *is* that
    /// account.
    pub fn proxy_for(&self, primary: AccountId32) -> Option<AccountId32> {
        (primary.0 != self.public_bytes()).then_some(primary)
    }

    fn sign_bytes(&self, payload: &[u8]) -> [u8; 64] {
        match self {
            Self::Uri(k) => k.sign(payload).0,
            Self::Raw(k) => {
                let context = schnorrkel::signing_context(b"substrate");
                k.sign(context.bytes(payload)).to_bytes()
            }
        }
    }
}

impl subxt::tx::Signer<PeopleConfig> for WriterSigner {
    fn account_id(&self) -> AccountId32 {
        AccountId32(self.public_bytes())
    }

    fn sign(&self, signer_payload: &[u8]) -> MultiSignature {
        MultiSignature::Sr25519(self.sign_bytes(signer_payload))
    }
}

impl subxt::tx::Signer<AssetHubConfig> for WriterSigner {
    fn account_id(&self) -> AccountId32 {
        AccountId32(self.public_bytes())
    }

    fn sign(&self, signer_payload: &[u8]) -> MultiSignature {
        MultiSignature::Sr25519(self.sign_bytes(signer_payload))
    }
}

pub fn batch_item_results<T>(
    events: impl IntoIterator<Item = T>,
    names: impl Fn(&T) -> (&str, &str),
) -> Vec<Result<(), T>> {
    events
        .into_iter()
        .filter_map(|event| {
            // Decided before the item can move into `Err`: `names` borrows it.
            let completed = match names(&event) {
                ("Utility", "ItemCompleted") => true,
                ("Utility", "ItemFailed") => false,
                _ => return None,
            };
            Some(if completed { Ok(()) } else { Err(event) })
        })
        .collect()
}

pub fn settle_batch_size(current: u16, max: u16, succeeded: bool) -> u16 {
    if succeeded {
        current.saturating_add(1).min(max)
    } else {
        (current / 2).max(1)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;

    use jsonrpsee_core::server::RpcModule;
    use jsonrpsee_server::{ServerBuilder, ServerHandle};
    use schnorrkel::{ExpansionMode, MiniSecretKey};
    use subxt_rpcs::rpc_params;

    use super::*;

    type Event = (&'static str, &'static str);

    fn names(event: &Event) -> (&str, &str) {
        (event.0, event.1)
    }

    #[tokio::test]
    async fn reconnecting_rpc_client_recovers_after_server_restart() -> anyhow::Result<()> {
        let (server, url) = TestRpcServer::start(None).await?;
        let rpc = reconnecting_rpc_client(&url, "test RPC").await?;

        let first: String = rpc.request("ping", rpc_params![]).await?;
        assert_eq!(first, "pong");

        server.stop().await?;
        let addr = url
            .strip_prefix("ws://")
            .context("test RPC URL should be ws://")?
            .parse::<SocketAddr>()?;
        let (_server, _) = TestRpcServer::start(Some(addr)).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let second = tokio::time::timeout(
            Duration::from_secs(5),
            rpc.request::<String>("ping", rpc_params![]),
        )
        .await??;
        assert_eq!(second, "pong");

        Ok(())
    }

    struct TestRpcServer {
        handle: ServerHandle,
    }

    impl TestRpcServer {
        async fn start(addr: Option<SocketAddr>) -> anyhow::Result<(Self, String)> {
            let addr = addr.unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into());
            let server = ServerBuilder::default().build(addr).await?;
            let addr = server.local_addr()?;
            let mut module = RpcModule::new(());
            module.register_async_method("ping", |_, _, _| async { "pong" })?;
            let handle = server.start(module);

            Ok((Self { handle }, format!("ws://{addr}")))
        }

        async fn stop(self) -> anyhow::Result<()> {
            self.handle.stop()?;
            self.handle.stopped().await;
            Ok(())
        }
    }

    #[test]
    fn uri_path_derives_dev_alice() {
        let signer = WriterSigner::from_secret("//Alice").expect("valid dev uri");
        let expected =
            hex::decode("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
                .unwrap();
        assert_eq!(signer.public_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn raw_64_byte_secret_matches_seed_path() {
        let seed = [7u8; 32];
        let keypair = MiniSecretKey::from_bytes(&seed)
            .unwrap()
            .expand_to_keypair(ExpansionMode::Ed25519);
        let raw64 = keypair.secret.to_ed25519_bytes();

        let from_seed =
            WriterSigner::from_secret(&format!("0x{}", hex::encode(seed))).expect("valid seed");
        let from_raw =
            WriterSigner::from_secret(&format!("0x{}", hex::encode(raw64))).expect("valid raw");

        assert!(matches!(from_seed, WriterSigner::Uri(_)));
        assert!(matches!(from_raw, WriterSigner::Raw(_)));
        assert_eq!(from_seed.public_bytes(), keypair.public.to_bytes());
        assert_eq!(from_raw.public_bytes(), keypair.public.to_bytes());
    }

    #[test]
    fn raw_signature_verifies() {
        let seed = [9u8; 32];
        let keypair = MiniSecretKey::from_bytes(&seed)
            .unwrap()
            .expand_to_keypair(ExpansionMode::Ed25519);
        let raw64 = keypair.secret.to_ed25519_bytes();
        let signer =
            WriterSigner::from_secret(&format!("0x{}", hex::encode(raw64))).expect("valid raw");

        let message = b"dub";
        let sig = signer.sign_bytes(message);
        let public = schnorrkel::PublicKey::from_bytes(&signer.public_bytes()).unwrap();
        let signature = schnorrkel::Signature::from_bytes(&sig).unwrap();
        assert!(public
            .verify_simple(b"substrate", message, &signature)
            .is_ok());
    }

    #[test]
    fn proxy_mode_is_derived_from_the_primary() {
        let signer = WriterSigner::from_secret("//Alice").expect("valid dev uri");
        let own = AccountId32(signer.public_bytes());
        let other = AccountId32([2; 32]);

        assert_eq!(signer.proxy_for(other), Some(other));
        assert_eq!(signer.proxy_for(own), None);
    }

    #[test]
    fn batch_item_results_keep_order_and_ignore_foreign_events() {
        let events = [
            ("System", "ExtrinsicSuccess"),
            ("Utility", "ItemCompleted"),
            ("Game", "ItemCompleted"),
            ("Utility", "ItemFailed"),
            ("Utility", "BatchCompletedWithErrors"),
            ("Utility", "ItemCompleted"),
        ];
        assert_eq!(
            batch_item_results(events, names),
            vec![Ok(()), Err(("Utility", "ItemFailed")), Ok(())]
        );
        assert!(batch_item_results(Vec::<Event>::new(), names).is_empty());
    }

    #[test]
    fn only_failed_items_are_asked_for_a_reason() {
        let events = [
            ("System", "ExtrinsicSuccess"),
            ("Utility", "ItemCompleted"),
            ("Game", "ItemFailed"), // same name, wrong pallet
            ("Utility", "ItemFailed"),
            ("Utility", "ItemCompleted"),
        ];
        let mut decoded = 0;
        let reasons: Vec<Result<(), String>> = batch_item_results(events, names)
            .into_iter()
            .map(|item| {
                item.map_err(|(pallet, event)| {
                    decoded += 1;
                    format!("{pallet}::{event}")
                })
            })
            .collect();

        assert_eq!(
            reasons,
            vec![Ok(()), Err("Utility::ItemFailed".to_string()), Ok(())]
        );
        assert_eq!(decoded, 1, "a reason was decoded for a non-failed item");
    }

    #[test]
    fn batch_size_grows_by_one_and_halves_on_failure() {
        assert_eq!(settle_batch_size(50, 100, true), 51);
        assert_eq!(settle_batch_size(99, 100, true), 100);
        assert_eq!(settle_batch_size(100, 100, true), 100);

        assert_eq!(settle_batch_size(100, 100, false), 50);
        assert_eq!(settle_batch_size(3, 100, false), 1);
        assert_eq!(settle_batch_size(1, 100, false), 1);
        assert_eq!(settle_batch_size(u16::MAX, u16::MAX, true), u16::MAX);
    }
}
