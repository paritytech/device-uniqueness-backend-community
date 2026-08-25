// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use anyhow::{bail, Context as _};

/// How long to wait before calling the probe failed. Below compose's own
/// `timeout: 3s`, so a hung service reports as a failed check rather than a
/// killed one.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Probe `url`, or this process's own `/readyz` when it is `None`.
pub async fn run(url: Option<String>) -> anyhow::Result<()> {
    let url = match url {
        Some(url) => url,
        None => default_url()?,
    };

    let response = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .context("building the healthcheck client")?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("requesting {url}"))?;

    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        bail!("{url} answered {status}");
    }
}

/// `http://127.0.0.1:<BIND_ADDR port>/readyz`.
///
/// Only the port is taken from `BIND_ADDR`: services bind `0.0.0.0`, which is
/// not an address you can connect to on every platform, and the probe is
/// local by definition.
fn default_url() -> anyhow::Result<String> {
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    url_for(&bind)
}

/// The pure half of [`default_url`], so the parsing is testable without
/// mutating process environment shared with every other test.
fn url_for(bind: &str) -> anyhow::Result<String> {
    let port = bind
        .rsplit(':')
        .next()
        .filter(|port| !port.is_empty())
        .with_context(|| format!("BIND_ADDR ({bind}) has no port to probe"))?;
    Ok(format!("http://127.0.0.1:{port}/readyz"))
}

#[cfg(test)]
mod tests {
    use super::url_for;

    #[test]
    fn port_is_taken_from_bind_addr() {
        for (bind, expected) in [
            ("0.0.0.0:8080", "http://127.0.0.1:8080/readyz"),
            ("127.0.0.1:9999", "http://127.0.0.1:9999/readyz"),
            ("[::]:8080", "http://127.0.0.1:8080/readyz"),
        ] {
            assert_eq!(url_for(bind).unwrap(), expected, "BIND_ADDR={bind}");
        }
    }

    #[test]
    fn a_portless_bind_addr_is_an_error() {
        assert!(url_for("0.0.0.0:").is_err());
    }
}
