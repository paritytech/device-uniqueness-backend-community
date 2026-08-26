// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
pub use http_common::FieldError;
use serde_json::json;

use crate::search::SearchError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("invalid query parameters")]
    InvalidQuery(Vec<FieldError>),
    #[error("invalid cursor")]
    InvalidCursor,
    /// The proof-of-compute gate refused the request (400 malformed / 402 rest).
    #[error(transparent)]
    Poc(#[from] crate::poc::Rejection),
    /// Unexpected internal failure; logged, surfaced opaquely (500).
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::InvalidQuery(errors) => http_common::error::invalid_query(&errors),
            AppError::InvalidCursor => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid cursor" })),
            )
                .into_response(),
            AppError::Poc(rejection) => match rejection {
                crate::poc::Rejection::Malformed => {
                    http_common::error::bad_request(rejection.detail())
                }
                other => http_common::error::payment_required(other.detail()),
            },
            AppError::Internal(err) => http_common::error::internal(&err),
        }
    }
}

impl From<SearchError> for AppError {
    fn from(error: SearchError) -> Self {
        match error {
            SearchError::InvalidQuery(errors) => Self::InvalidQuery(errors),
            SearchError::InvalidCursor => Self::InvalidCursor,
            SearchError::Database(error) => Self::Internal(error.into()),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Internal(err.into())
    }
}

pub type AppResult<T> = Result<T, AppError>;
