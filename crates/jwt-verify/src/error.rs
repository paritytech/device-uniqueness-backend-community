// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

#[derive(Debug, thiserror::Error, PartialEq, Clone, Copy)]
pub enum JwksError {
    #[error("malformed JWKS document")]
    Malformed,
    #[error("no usable Ed25519 key in JWKS document")]
    NoUsableKey,
}

pub type JwtError = jsonwebtoken::errors::Error;
