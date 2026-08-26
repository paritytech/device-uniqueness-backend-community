use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};

use super::error::AppError;
use super::state::AppState;
use crate::poc::Rejection;

/// Admit a public read when the caller presents **either** a valid
/// device-attestation JWT **or** a fresh, solved proof-of-compute puzzle.
///
/// Pass-through when the gate is disabled (`state.poc` is `None`), which is the
/// shipping default. A bearer token that fails verification is treated as
/// *anonymous* rather than rejected: search must stay a public route, so this
/// middleware never emits a `401`.
pub async fn poc_gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(poc) = state.poc.clone() else {
        return next.run(req).await;
    };

    if bearer_token(&req).is_some_and(|token| poc.jwt().verify(token).is_ok()) {
        return next.run(req).await;
    }

    let Some(header) = req
        .headers()
        .get(crate::poc::solution::HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return AppError::Poc(Rejection::Missing).into_response();
    };

    let solution = match crate::poc::Solution::parse_header(header) {
        Ok(solution) => solution,
        Err(rejection) => return AppError::Poc(rejection).into_response(),
    };

    match poc
        .verify(&state.pool, &solution, crate::poc::now_millis())
        .await
    {
        Ok(Ok(())) => next.run(req).await,
        Ok(Err(rejection)) => AppError::Poc(rejection).into_response(),
        Err(error) => AppError::Internal(error.into()).into_response(),
    }
}

fn bearer_token(req: &Request) -> Option<&str> {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let mut parts = header.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("Bearer"), Some(token), None) if !token.is_empty() => Some(token),
        _ => None,
    }
}
