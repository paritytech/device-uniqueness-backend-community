// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    #[error("attestation CRL fetch failed: {0}")]
    Fetch(String),
    #[error("attestation CRL parse failed: {0}")]
    Parse(String),
}

#[derive(Deserialize)]
struct CrlResponse {
    entries: std::collections::HashMap<String, serde_json::Value>,
}

fn normalize(entries: std::collections::HashMap<String, serde_json::Value>) -> HashSet<String> {
    entries.into_keys().map(|k| k.to_lowercase()).collect()
}

pub fn parse_crl(body: &[u8]) -> Result<HashSet<String>, CrlError> {
    let response: CrlResponse =
        serde_json::from_slice(body).map_err(|e| CrlError::Parse(e.to_string()))?;
    Ok(normalize(response.entries))
}

struct Snapshot {
    fetched_at: Instant,
    serials: Arc<HashSet<String>>,
}

#[derive(Clone)]
pub struct CrlCache {
    inner: Arc<Inner>,
}

struct Inner {
    url: String,
    ttl: Duration,
    max_stale: Duration,
    http: reqwest::Client,
    cache: tokio::sync::Mutex<Option<Snapshot>>,
}

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

impl CrlCache {
    pub fn new(url: String, ttl: Duration, max_stale: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                url,
                ttl,
                max_stale,
                http: reqwest::Client::builder()
                    .timeout(FETCH_TIMEOUT)
                    .build()
                    .expect("reqwest client with a static timeout builds"),
                cache: tokio::sync::Mutex::new(None),
            }),
        }
    }

    pub async fn revoked_serials(&self) -> Result<Arc<HashSet<String>>, CrlError> {
        let mut cache = self.inner.cache.lock().await;
        if let Some(snapshot) = cache.as_ref() {
            let age = snapshot.fetched_at.elapsed();
            if age < self.inner.ttl && within_max_stale(age, self.inner.max_stale) {
                return Ok(Arc::clone(&snapshot.serials));
            }
        }

        match self.fetch().await {
            Ok(serials) => {
                let serials = Arc::new(serials);
                *cache = Some(Snapshot {
                    fetched_at: Instant::now(),
                    serials: Arc::clone(&serials),
                });
                Ok(serials)
            }
            Err(err) => match cache.as_ref() {
                Some(snapshot) => {
                    let age = snapshot.fetched_at.elapsed();
                    if within_max_stale(age, self.inner.max_stale) {
                        tracing::warn!(
                            error = %err,
                            age_secs = age.as_secs(),
                            "attestation CRL refresh failed; serving stale snapshot within max-stale bound"
                        );
                        Ok(Arc::clone(&snapshot.serials))
                    } else {
                        tracing::error!(
                            error = %err,
                            age_secs = age.as_secs(),
                            "attestation CRL snapshot exceeded max-stale bound; refusing"
                        );
                        Err(err)
                    }
                }
                None => Err(err),
            },
        }
    }

    async fn fetch(&self) -> Result<HashSet<String>, CrlError> {
        let response = self
            .inner
            .http
            .get(&self.inner.url)
            .send()
            .await
            .map_err(|e| CrlError::Fetch(e.to_string()))?
            .error_for_status()
            .map_err(|e| CrlError::Fetch(e.to_string()))?;
        let body = response
            .bytes()
            .await
            .map_err(|e| CrlError::Fetch(e.to_string()))?;
        parse_crl(&body)
    }
}

fn within_max_stale(age: Duration, max_stale: Duration) -> bool {
    age <= max_stale
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_crl_lowercases_the_google_status_shape() {
        let body = br#"{
            "entries": {
                "6681152659205225093": { "status": "REVOKED", "reason": "KEY_COMPROMISE" },
                "8350192447815228107": { "status": "SUSPENDED", "reason": "SOFTWARE_FLAW" },
                "ABCDef0123": { "status": "REVOKED" }
            }
        }"#;
        let serials = parse_crl(body).expect("parses");
        assert_eq!(serials.len(), 3);
        assert!(serials.contains("6681152659205225093"));
        assert!(serials.contains("abcdef0123"));

        assert!(parse_crl(b"not json").is_err());
        assert!(parse_crl(b"{}").is_err());
    }

    #[test]
    fn max_stale_bound_is_inclusive() {
        let max = Duration::from_secs(3_600);
        assert!(within_max_stale(Duration::from_secs(0), max));
        assert!(within_max_stale(Duration::from_secs(1_800), max));
        assert!(within_max_stale(max, max));
        assert!(!within_max_stale(Duration::from_secs(3_601), max));
    }
}
