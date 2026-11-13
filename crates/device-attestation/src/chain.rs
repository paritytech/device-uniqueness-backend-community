// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod asset_hub;
pub mod attest;
pub mod lease;
pub mod outbox;
pub mod people;
pub(crate) mod registry;
pub mod writer;

pub use people::PeopleChain;
