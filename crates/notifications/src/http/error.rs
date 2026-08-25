// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::response::{IntoResponse, Response};
pub use http_common::FieldError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Request body failed validation (400 with per-field `fields`).
    #[error("invalid request body")]
    InvalidBody(Vec<FieldError>),
    /// Request body was not parseable JSON (400).
    #[error("malformed JSON body")]
    MalformedJson,
    /// Authenticated subject exceeded the notify rate limit (429).
    #[error("rate limited")]
    RateLimited { retry_after_secs: u64 },
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::InvalidBody(errors) => http_common::error::invalid_body(&errors),
            AppError::MalformedJson => http_common::error::malformed_json(),
            AppError::RateLimited { retry_after_secs } => {
                http_common::error::rate_limited(retry_after_secs)
            }
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
