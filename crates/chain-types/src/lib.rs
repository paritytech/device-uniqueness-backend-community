// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Refresh with:
//! `subxt metadata --url <people-rpc> --pallets System,Balances,Utility,Proxy,People,PeopleLite,Resources,Game,ProofOfInk,Members -f bytes -o crates/chain-types/metadata/people.scale`

#[allow(clippy::all, missing_docs, rustdoc::all)]
#[subxt::subxt(runtime_metadata_path = "metadata/people.scale")]
pub mod people {}

pub use subxt;

/// The vendored metadata [`people`] is generated from, decoded once.
static METADATA: std::sync::LazyLock<subxt::metadata::ArcMetadata> =
    std::sync::LazyLock::new(|| {
        std::sync::Arc::new(
            subxt::Metadata::decode_from(include_bytes!("../metadata/people.scale"))
                .expect("vendored People Chain metadata decodes"),
        )
    });

/// subxt's own error-decoding entry point
pub fn metadata_arc() -> subxt::metadata::ArcMetadata {
    METADATA.clone()
}

#[derive(Debug, Clone, Default)]
pub struct PeopleConfig(subxt::PolkadotConfig);

impl subxt::Config for PeopleConfig {
    type AccountId = <subxt::PolkadotConfig as subxt::Config>::AccountId;
    type Address = <subxt::PolkadotConfig as subxt::Config>::Address;
    type Signature = <subxt::PolkadotConfig as subxt::Config>::Signature;
    type Header = <subxt::PolkadotConfig as subxt::Config>::Header;
    type TransactionExtensions = PeopleTransactionExtensions<Self>;
    type AssetId = <subxt::PolkadotConfig as subxt::Config>::AssetId;
    type Hasher = <subxt::PolkadotConfig as subxt::Config>::Hasher;

    fn genesis_hash(&self) -> Option<subxt::config::HashFor<Self>> {
        self.0.genesis_hash()
    }

    fn spec_and_transaction_version_for_block_number(
        &self,
        block_number: u64,
    ) -> Option<(u32, u32)> {
        self.0
            .spec_and_transaction_version_for_block_number(block_number)
    }

    fn metadata_for_spec_version(&self, spec_version: u32) -> Option<subxt::ArcMetadata> {
        self.0.metadata_for_spec_version(spec_version)
    }

    fn set_metadata_for_spec_version(&self, spec_version: u32, metadata: subxt::ArcMetadata) {
        self.0.set_metadata_for_spec_version(spec_version, metadata);
    }
}

type PeopleTransactionExtensions<T> = (
    Noop<UnitTransactionExtension>,
    Noop<AuthorizeValueTransfer>,
    subxt::config::transaction_extensions::VerifySignature<T>,
    Noop<AsPerson>,
    Noop<AsProofOfInkParticipant>,
    Noop<ScoreAsParticipant>,
    Noop<GameAsInvited>,
    Noop<PeopleLiteAuth>,
    Noop<AsMember>,
    Noop<AsCoinage>,
    Noop<AsResources>,
    Noop<HonourAuth>,
    Noop<AuthorizeCall>,
    Noop<RestrictOrigins>,
    Noop<CheckNonZeroSender>,
    subxt::config::transaction_extensions::CheckSpecVersion,
    subxt::config::transaction_extensions::CheckTxVersion,
    subxt::config::transaction_extensions::CheckGenesis<T>,
    subxt::config::transaction_extensions::CheckMortality<T>,
    subxt::config::transaction_extensions::CheckNonce,
    Noop<CheckWeight>,
    subxt::config::transaction_extensions::ChargeAssetTxPayment<T>,
    Noop<StorageWeightReclaim>,
);

pub struct PeopleExtrinsicParamsBuilder<T: subxt::Config> {
    mortality: subxt::config::transaction_extensions::CheckMortalityParams<T>,
    nonce: Option<u64>,
    tip: u128,
}

impl<T: subxt::Config> PeopleExtrinsicParamsBuilder<T> {
    pub fn new() -> Self {
        Self {
            mortality: subxt::config::transaction_extensions::CheckMortalityParams::immortal(),
            nonce: None,
            tip: 0,
        }
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn build(
        self,
    ) -> <PeopleTransactionExtensions<T> as subxt::config::TransactionExtensions<T>>::Params {
        (
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            self.mortality,
            self.nonce.map_or_else(
                subxt::config::transaction_extensions::CheckNonceParams::from_chain,
                subxt::config::transaction_extensions::CheckNonceParams::with_nonce,
            ),
            (),
            subxt::config::transaction_extensions::ChargeAssetTxPaymentParams::tip(self.tip),
            (),
        )
    }
}

impl<T: subxt::Config> Default for PeopleExtrinsicParamsBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssetHubConfig(subxt::PolkadotConfig);

impl subxt::Config for AssetHubConfig {
    type AccountId = <subxt::PolkadotConfig as subxt::Config>::AccountId;
    type Address = <subxt::PolkadotConfig as subxt::Config>::Address;
    type Signature = <subxt::PolkadotConfig as subxt::Config>::Signature;
    type Header = <subxt::PolkadotConfig as subxt::Config>::Header;
    type TransactionExtensions = AssetHubTransactionExtensions<Self>;
    type AssetId = <subxt::PolkadotConfig as subxt::Config>::AssetId;
    type Hasher = <subxt::PolkadotConfig as subxt::Config>::Hasher;

    fn genesis_hash(&self) -> Option<subxt::config::HashFor<Self>> {
        self.0.genesis_hash()
    }

    fn spec_and_transaction_version_for_block_number(
        &self,
        block_number: u64,
    ) -> Option<(u32, u32)> {
        self.0
            .spec_and_transaction_version_for_block_number(block_number)
    }

    fn metadata_for_spec_version(&self, spec_version: u32) -> Option<subxt::ArcMetadata> {
        self.0.metadata_for_spec_version(spec_version)
    }

    fn set_metadata_for_spec_version(&self, spec_version: u32, metadata: subxt::ArcMetadata) {
        self.0.set_metadata_for_spec_version(spec_version, metadata);
    }
}

type AssetHubTransactionExtensions<T> = (
    Noop<UnitTransactionExtension>,
    Noop<AuthorizeValueTransfer>,
    Noop<AuthorizeCall>,
    Noop<AsPgas>,
    Noop<AsRingAlias>,
    Noop<AsDotnsGateway>,
    Noop<RestrictOrigins>,
    Noop<CheckNonZeroSender>,
    subxt::config::transaction_extensions::CheckSpecVersion,
    subxt::config::transaction_extensions::CheckTxVersion,
    subxt::config::transaction_extensions::CheckGenesis<T>,
    subxt::config::transaction_extensions::CheckMortality<T>,
    subxt::config::transaction_extensions::CheckNonce,
    Noop<CheckWeight>,
    subxt::config::transaction_extensions::ChargeAssetTxPayment<T>,
    // Real, not a `Noop`. Its *implicit* is `Option<[u8; 32]> = None`. A `Noop`
    // would encode that as nothing, which is a signer-payload mismatch. subxt's
    // version never provides a hash, so it encodes disabled mode.
    subxt::config::transaction_extensions::CheckMetadataHash,
    Noop<EthSetOrigin>,
    Noop<StorageWeightReclaim>,
);

pub struct AssetHubExtrinsicParamsBuilder<T: subxt::Config> {
    mortality: subxt::config::transaction_extensions::CheckMortalityParams<T>,
    nonce: Option<u64>,
    tip: u128,
}

impl<T: subxt::Config> AssetHubExtrinsicParamsBuilder<T> {
    pub fn new() -> Self {
        Self {
            mortality: subxt::config::transaction_extensions::CheckMortalityParams::immortal(),
            nonce: None,
            tip: 0,
        }
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn build(
        self,
    ) -> <AssetHubTransactionExtensions<T> as subxt::config::TransactionExtensions<T>>::Params {
        (
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            self.mortality,
            self.nonce.map_or_else(
                subxt::config::transaction_extensions::CheckNonceParams::from_chain,
                subxt::config::transaction_extensions::CheckNonceParams::with_nonce,
            ),
            (),
            subxt::config::transaction_extensions::ChargeAssetTxPaymentParams::tip(self.tip),
            (),
            (),
            (),
        )
    }
}

impl<T: subxt::Config> Default for AssetHubExtrinsicParamsBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

pub trait NoopName {
    const NAME: &'static str;
    const VALUE: &'static [u8] = &[];
}

#[derive(Debug, Clone)]
pub struct Noop<N>(core::marker::PhantomData<N>);

impl<T: subxt::Config, N: NoopName + Send + Sync + 'static> subxt::config::TransactionExtension<T>
    for Noop<N>
{
    type Decoded = ();
    type Params = ();

    fn new(
        _client: &subxt::config::ClientState<T>,
        _params: Self::Params,
    ) -> Result<Self, subxt::error::TransactionExtensionError> {
        Ok(Self(core::marker::PhantomData))
    }
}

impl<R: subxt::ext::scale_type_resolver::TypeResolver, N: NoopName>
    subxt::ext::frame_decode::extrinsics::TransactionExtension<R> for Noop<N>
{
    const NAME: &str = N::NAME;

    fn encode_value_to(
        &self,
        _type_id: R::TypeId,
        _type_resolver: &R,
        out: &mut Vec<u8>,
    ) -> Result<(), subxt::ext::frame_decode::extrinsics::TransactionExtensionError> {
        out.extend_from_slice(N::VALUE);
        Ok(())
    }

    fn encode_implicit_to(
        &self,
        _type_id: R::TypeId,
        _type_resolver: &R,
        _out: &mut Vec<u8>,
    ) -> Result<(), subxt::ext::frame_decode::extrinsics::TransactionExtensionError> {
        Ok(())
    }
}

macro_rules! noop_name {
    ($ty:ident, $name:literal) => {
        pub struct $ty;
        impl NoopName for $ty {
            const NAME: &'static str = $name;
        }
    };
    ($ty:ident, $name:literal, $value:expr) => {
        pub struct $ty;
        impl NoopName for $ty {
            const NAME: &'static str = $name;
            const VALUE: &'static [u8] = $value;
        }
    };
}

// Slot 0 differs per build, not per spec version: Paseo Next v2 declares
// `AuthorizeValueTransfer` (`Option<[u8; 64]>`, encoded `None`), PreviewNet
// declares `UnitTransactionExtension` (`()`). Both names live in the tuple;
// only the one the connected runtime declares is encoded.
noop_name!(UnitTransactionExtension, "UnitTransactionExtension");
noop_name!(AuthorizeValueTransfer, "AuthorizeValueTransfer", &[0]);
noop_name!(AsPerson, "AsPerson", &[0]);
noop_name!(AsProofOfInkParticipant, "AsProofOfInkParticipant", &[0]);
noop_name!(ScoreAsParticipant, "ScoreAsParticipant", &[0]);
noop_name!(GameAsInvited, "GameAsInvited", &[0]);
noop_name!(PeopleLiteAuth, "PeopleLiteAuth", &[0]);
noop_name!(AsMember, "AsMember", &[0]);
noop_name!(AsCoinage, "AsCoinage", &[0]);
noop_name!(AsResources, "AsResources", &[0]);
noop_name!(HonourAuth, "HonourAuth", &[0]);
noop_name!(AuthorizeCall, "AuthorizeCall");
noop_name!(RestrictOrigins, "RestrictOrigins", &[0]);
noop_name!(CheckNonZeroSender, "CheckNonZeroSender");
noop_name!(CheckWeight, "CheckWeight");
noop_name!(StorageWeightReclaim, "StorageWeightReclaim");

// Asset Hub-only origin modifiers. All three are `Option<…>`, encoded `None`.
// `EthSetOrigin` (pallet_revive's `SetOrigin`) carries no value at all.
noop_name!(AsPgas, "AsPgas", &[0]);
noop_name!(AsRingAlias, "AsRingAlias", &[0]);
noop_name!(AsDotnsGateway, "AsDotnsGateway", &[0]);
noop_name!(EthSetOrigin, "EthSetOrigin");

#[cfg(test)]
mod tests {
    use super::people;
    use super::NoopName as _;
    use subxt::storage::Address as _;

    const TUPLE_EXTENSIONS: &[&str] = &[
        "UnitTransactionExtension",
        "AuthorizeValueTransfer",
        "VerifyMultiSignature",
        "AsPerson",
        "AsProofOfInkParticipant",
        "ScoreAsParticipant",
        "GameAsInvited",
        "PeopleLiteAuth",
        "AsMember",
        "AsCoinage",
        "AsResources",
        "HonourAuth",
        "AuthorizeCall",
        "RestrictOrigins",
        "CheckNonZeroSender",
        "CheckSpecVersion",
        "CheckTxVersion",
        "CheckGenesis",
        "CheckMortality",
        "CheckNonce",
        "CheckWeight",
        "ChargeAssetTxPayment",
        "StorageWeightReclaim",
    ];

    const ASSET_HUB_TUPLE_EXTENSIONS: &[&str] = &[
        "UnitTransactionExtension",
        "AuthorizeValueTransfer",
        "AuthorizeCall",
        "AsPgas",
        "AsRingAlias",
        "AsDotnsGateway",
        "RestrictOrigins",
        "CheckNonZeroSender",
        "CheckSpecVersion",
        "CheckTxVersion",
        "CheckGenesis",
        "CheckMortality",
        "CheckNonce",
        "CheckWeight",
        "ChargeAssetTxPayment",
        "CheckMetadataHash",
        "EthSetOrigin",
        "StorageWeightReclaim",
    ];

    struct KnownRuntime {
        env: &'static str,
        spec_name: &'static str,
        spec_version: u32,
        tuple: &'static [&'static str],
        extensions: &'static [&'static str],
    }

    const KNOWN_RUNTIMES: &[KnownRuntime] = &[
        KnownRuntime {
            env: "paseo-next-v2",
            spec_name: "next-people-paseo",
            spec_version: 1_000_030,
            tuple: TUPLE_EXTENSIONS,
            extensions: &[
                "AuthorizeValueTransfer",
                "VerifyMultiSignature",
                "AsPerson",
                "AsProofOfInkParticipant",
                "ScoreAsParticipant",
                "GameAsInvited",
                "PeopleLiteAuth",
                "AsMember",
                "AsCoinage",
                "AsResources",
                "HonourAuth",
                "AuthorizeCall",
                "RestrictOrigins",
                "CheckNonZeroSender",
                "CheckSpecVersion",
                "CheckTxVersion",
                "CheckGenesis",
                "CheckMortality",
                "CheckNonce",
                "CheckWeight",
                "ChargeAssetTxPayment",
                "StorageWeightReclaim",
            ],
        },
        KnownRuntime {
            env: "previewnet",
            spec_name: "next-people-paseo",
            spec_version: 1_000_032,
            tuple: TUPLE_EXTENSIONS,
            extensions: &[
                "UnitTransactionExtension",
                "VerifyMultiSignature",
                "AsPerson",
                "AsProofOfInkParticipant",
                "ScoreAsParticipant",
                "GameAsInvited",
                "PeopleLiteAuth",
                "AsMember",
                "AsCoinage",
                "AsResources",
                "HonourAuth",
                "AuthorizeCall",
                "RestrictOrigins",
                "CheckNonZeroSender",
                "CheckSpecVersion",
                "CheckTxVersion",
                "CheckGenesis",
                "CheckMortality",
                "CheckNonce",
                "CheckWeight",
                "ChargeAssetTxPayment",
                "StorageWeightReclaim",
            ],
        },
        KnownRuntime {
            env: "paseo-next-v2 asset hub",
            spec_name: "next-asset-hub-paseo",
            spec_version: 2_000_033,
            tuple: ASSET_HUB_TUPLE_EXTENSIONS,
            extensions: &[
                "AuthorizeValueTransfer",
                "AuthorizeCall",
                "AsPgas",
                "AsRingAlias",
                "AsDotnsGateway",
                "RestrictOrigins",
                "CheckNonZeroSender",
                "CheckSpecVersion",
                "CheckTxVersion",
                "CheckGenesis",
                "CheckMortality",
                "CheckNonce",
                "CheckWeight",
                "ChargeAssetTxPayment",
                "CheckMetadataHash",
                "EthSetOrigin",
                "StorageWeightReclaim",
            ],
        },
        KnownRuntime {
            env: "previewnet asset hub",
            spec_name: "next-asset-hub-paseo",
            spec_version: 2_000_034,
            tuple: ASSET_HUB_TUPLE_EXTENSIONS,
            extensions: &[
                "UnitTransactionExtension",
                "AuthorizeCall",
                "AsPgas",
                "AsRingAlias",
                "AsDotnsGateway",
                "RestrictOrigins",
                "CheckNonZeroSender",
                "CheckSpecVersion",
                "CheckTxVersion",
                "CheckGenesis",
                "CheckMortality",
                "CheckNonce",
                "CheckWeight",
                "ChargeAssetTxPayment",
                "CheckMetadataHash",
                "EthSetOrigin",
                "StorageWeightReclaim",
            ],
        },
    ];

    #[test]
    fn covers_every_known_runtime_extension_set() {
        for runtime in KNOWN_RUNTIMES {
            for name in runtime.extensions {
                assert!(
                    runtime.tuple.contains(name),
                    "{} ({} {}) declares extension {name}, which the tuple cannot satisfy",
                    runtime.env,
                    runtime.spec_name,
                    runtime.spec_version
                );
            }
        }
    }

    #[test]
    fn slot_zero_noops_encode_their_runtime_value() {
        assert_eq!(
            super::AuthorizeValueTransfer::NAME,
            "AuthorizeValueTransfer"
        );
        assert_eq!(super::AuthorizeValueTransfer::VALUE, &[0]);
        assert_eq!(
            super::UnitTransactionExtension::NAME,
            "UnitTransactionExtension"
        );
        assert!(super::UnitTransactionExtension::VALUE.is_empty());
    }

    #[test]
    fn builds_username_owner_of_query() {
        let query = people::storage().resources().username_owner_of();
        assert_eq!(query.pallet_name(), "Resources");
        assert_eq!(query.entry_name(), "UsernameOwnerOf");
    }

    #[test]
    fn builds_attestation_allowance_query() {
        let query = people::storage().people_lite().attestation_allowance();
        assert_eq!(query.pallet_name(), "PeopleLite");
        assert_eq!(query.entry_name(), "AttestationAllowance");
    }

    #[test]
    fn builds_register_lite_person_call() {
        let username =
            people::runtime_types::bounded_collections::bounded_vec::BoundedVec(b"alice".to_vec());
        let call = people::tx()
            .resources()
            .register_lite_person([0u8; 65], username, None);
        assert_eq!(call.pallet_name(), "Resources");
        assert_eq!(call.call_name(), "register_lite_person");
    }

    #[test]
    fn builds_set_invite_ticket_calls() {
        let ticket = subxt::utils::AccountId32([0u8; 32]);
        let game = people::tx().game().set_invite_ticket(ticket);
        assert_eq!(game.pallet_name(), "Game");
        assert_eq!(game.call_name(), "set_invite_ticket");

        let poi = people::tx().proof_of_ink().set_invite_ticket(ticket);
        assert_eq!(poi.pallet_name(), "ProofOfInk");
        assert_eq!(poi.call_name(), "set_invite_ticket");
    }

    #[test]
    fn builds_available_invites_queries() {
        use subxt::storage::Address as _;

        let game = people::storage().game().available_invites();
        assert_eq!(game.pallet_name(), "Game");
        assert_eq!(game.entry_name(), "AvailableInvites");

        let poi = people::storage().proof_of_ink().available_invites();
        assert_eq!(poi.pallet_name(), "ProofOfInk");
        assert_eq!(poi.entry_name(), "AvailableInvites");
    }

    fn people_metadata() -> subxt::ArcMetadata {
        subxt::Metadata::decode_from(include_bytes!("../metadata/people.scale"))
            .expect("vendored metadata decodes")
            .arc()
    }

    fn offline_client_state() -> subxt::config::ClientState<super::PeopleConfig> {
        subxt::config::ClientState {
            genesis_hash: subxt::utils::H256::zero(),
            spec_version: 1_000_030,
            transaction_version: 4,
            metadata: people_metadata(),
        }
    }

    #[test]
    fn builder_nonce_flows_into_check_nonce_encoding() {
        use subxt::config::transaction_extensions::CheckNonce;
        use subxt::config::TransactionExtension as _;
        use subxt::ext::frame_decode::extrinsics::TransactionExtension as _;

        let state = offline_client_state();

        let (.., nonce, _, _, _) =
            super::PeopleExtrinsicParamsBuilder::<super::PeopleConfig>::new()
                .nonce(7)
                .build();
        assert_eq!(format!("{nonce:?}"), "CheckNonceParams(Some(7))");
        let mut encoded = Vec::new();
        CheckNonce::new(&state, nonce)
            .expect("CheckNonce builds offline")
            .encode_value_to(0, state.metadata.types(), &mut encoded)
            .expect("CheckNonce encodes offline");
        assert_eq!(encoded, [28], "nonce 7 must encode as Compact(7), 7 << 2");

        let (.., nonce, _, _, _) =
            super::PeopleExtrinsicParamsBuilder::<super::PeopleConfig>::new().build();
        assert_eq!(
            format!("{nonce:?}"),
            "CheckNonceParams(None)",
            "without an explicit nonce the slot must defer to the chain lookup"
        );
    }

    #[test]
    fn builder_starts_immortal_with_no_tip() {
        use subxt::config::transaction_extensions::{ChargeAssetTxPayment, CheckMortality};
        use subxt::config::TransactionExtension as _;
        use subxt::ext::frame_decode::extrinsics::TransactionExtension as _;

        let state = offline_client_state();
        let (.., mortality, _, _, tip, _) =
            super::PeopleExtrinsicParamsBuilder::<super::PeopleConfig>::new().build();

        let mut era = Vec::new();
        CheckMortality::new(&state, mortality)
            .expect("immortal params build offline")
            .encode_value_to(0, state.metadata.types(), &mut era)
            .expect("CheckMortality encodes offline");
        assert_eq!(era, [0], "immortal era is the single zero byte");

        let payment = ChargeAssetTxPayment::new(&state, tip).expect("tip params build offline");
        assert_eq!(payment.tip(), 0, "the builder must not tip by default");
        assert!(payment.asset_id().is_none(), "tip is in the native token");
    }

    #[test]
    fn default_builder_matches_new() {
        let (.., new_nonce, _, new_tip, _) =
            super::PeopleExtrinsicParamsBuilder::<super::PeopleConfig>::new().build();
        let (.., default_nonce, _, default_tip, _) =
            super::PeopleExtrinsicParamsBuilder::<super::PeopleConfig>::default().build();

        assert_eq!(format!("{default_nonce:?}"), format!("{new_nonce:?}"));
        assert_eq!(format!("{default_tip:?}"), format!("{new_tip:?}"));
    }

    #[test]
    fn noop_encoders_write_value_bytes_and_empty_implicit() {
        use subxt::config::TransactionExtension as _;
        use subxt::ext::frame_decode::extrinsics::TransactionExtension as _;

        let state = offline_client_state();
        let types = state.metadata.types();

        let authorize = super::Noop::<super::AuthorizeValueTransfer>::new(&state, ())
            .expect("noop gates build offline");
        let mut out = vec![0xAA];
        authorize
            .encode_value_to(0, types, &mut out)
            .expect("noop value encodes");
        assert_eq!(out, [0xAA, 0x00], "appends exactly the encoded-None byte");
        authorize
            .encode_implicit_to(0, types, &mut out)
            .expect("noop implicit encodes");
        assert_eq!(out, [0xAA, 0x00], "the implicit part writes nothing");

        let unit = super::Noop::<super::UnitTransactionExtension>::new(&state, ())
            .expect("noop gates build offline");
        let mut out = vec![0xAA];
        unit.encode_value_to(0, types, &mut out)
            .expect("noop value encodes");
        unit.encode_implicit_to(0, types, &mut out)
            .expect("noop implicit encodes");
        assert_eq!(out, [0xAA], "a unit-valued gate writes no bytes at all");
    }

    #[test]
    fn config_delegates_caches_to_polkadot_config() {
        use subxt::Config as _;

        let config = super::PeopleConfig::default();
        assert_eq!(config.genesis_hash(), None);
        assert_eq!(
            config.spec_and_transaction_version_for_block_number(0),
            None
        );
        assert!(config.metadata_for_spec_version(1_000_030).is_none());

        let metadata = people_metadata();
        config.set_metadata_for_spec_version(1_000_030, metadata.clone());
        let cached = config
            .metadata_for_spec_version(1_000_030)
            .expect("registered metadata is readable back");
        assert!(
            std::sync::Arc::ptr_eq(&cached, &metadata),
            "delegation must return the registered Arc"
        );
        assert!(
            config.metadata_for_spec_version(1_000_031).is_none(),
            "registration must not leak to other spec versions"
        );
    }

    #[test]
    fn builds_members_ring_root_queries() {
        let root = people::storage().members().root();
        assert_eq!(root.pallet_name(), "Members");
        assert_eq!(root.entry_name(), "Root");

        let old_roots = people::storage().members().old_roots();
        assert_eq!(old_roots.pallet_name(), "Members");
        assert_eq!(old_roots.entry_name(), "OldRoots");

        let collections = people::storage().members().collections();
        assert_eq!(collections.pallet_name(), "Members");
        assert_eq!(collections.entry_name(), "Collections");
    }
}
