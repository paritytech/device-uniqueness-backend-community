// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::{Duration, Instant};

use crate::chain::asset_hub::{AssetHub, ValidityWindow};
use crate::chain::people::PeopleChain;

pub(super) trait Link {
    type Chain;
    type Ctx: Copy;

    async fn up(&mut self) -> Option<(Self::Chain, Self::Ctx)>;
}

pub(super) struct PeopleLink(pub PeopleChain);

impl Link for PeopleLink {
    type Chain = PeopleChain;
    type Ctx = ();

    async fn up(&mut self) -> Option<(PeopleChain, ())> {
        Some((self.0.clone(), ()))
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Window {
    pub window: ValidityWindow,
    pub attester: [u8; 32],
}

const DOTNS_RECONNECT_INTERVAL: Duration = Duration::from_secs(30);

pub(super) enum DotnsLink {
    Disabled,
    Enabled {
        rpc_url: String,
        attester: [u8; 32],
        connected: Option<(AssetHub, ValidityWindow)>,
        last_error: Option<String>,
        retry_at: Option<Instant>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DotnsDial {
    Ready,
    Dial,
    Skip,
}

impl DotnsLink {
    fn dial_state(&self, now: Instant) -> DotnsDial {
        match self {
            DotnsLink::Disabled => DotnsDial::Skip,
            DotnsLink::Enabled { connected, .. } if connected.is_some() => DotnsDial::Ready,
            DotnsLink::Enabled { retry_at, .. } => match retry_at {
                Some(at) if now < *at => DotnsDial::Skip,
                _ => DotnsDial::Dial,
            },
        }
    }

    fn record_dial_failure(&mut self, reason: String, now: Instant) -> bool {
        let DotnsLink::Enabled {
            last_error,
            retry_at,
            ..
        } = self
        else {
            return false;
        };
        *retry_at = Some(now + DOTNS_RECONNECT_INTERVAL);
        let is_new = last_error.as_deref() != Some(reason.as_str());
        if is_new {
            *last_error = Some(reason);
        }
        is_new
    }

    fn record_dial_success(&mut self, up: (AssetHub, ValidityWindow)) {
        if let DotnsLink::Enabled {
            connected,
            last_error,
            retry_at,
            ..
        } = self
        {
            *connected = Some(up);
            *last_error = None;
            *retry_at = None;
        }
    }
}

async fn connect_asset_hub(url: &str) -> anyhow::Result<(AssetHub, ValidityWindow)> {
    let client = AssetHub::connect(url).await?;
    let window = client.validity_window().await?;
    Ok((client, window))
}

impl DotnsLink {
    pub(super) fn new(rpc_url: Option<String>, attester: [u8; 32]) -> Self {
        match rpc_url {
            Some(rpc_url) => DotnsLink::Enabled {
                rpc_url,
                attester,
                connected: None,
                last_error: None,
                retry_at: None,
            },
            None => DotnsLink::Disabled,
        }
    }

    fn ctx(&self, up: &(AssetHub, ValidityWindow)) -> (AssetHub, Window) {
        let attester = match self {
            DotnsLink::Enabled { attester, .. } => *attester,
            DotnsLink::Disabled => [0u8; 32],
        };
        (
            up.0.clone(),
            Window {
                window: up.1,
                attester,
            },
        )
    }
}

impl Link for DotnsLink {
    type Chain = AssetHub;
    type Ctx = Window;

    async fn up(&mut self) -> Option<(AssetHub, Window)> {
        let now = Instant::now();
        match self.dial_state(now) {
            DotnsDial::Skip => return None,
            DotnsDial::Ready => {
                let DotnsLink::Enabled {
                    connected: Some(up),
                    ..
                } = &self
                else {
                    return None;
                };
                return Some(self.ctx(up));
            }
            DotnsDial::Dial => {}
        }
        let DotnsLink::Enabled { rpc_url, .. } = self else {
            return None;
        };
        let rpc_url = rpc_url.clone();
        match connect_asset_hub(&rpc_url).await {
            Ok(up) => {
                tracing::info!(
                    asset_hub_rpc = %rpc_url,
                    max_validity_secs = up.1.max_validity_secs,
                    max_future_skew_secs = up.1.max_future_skew_secs,
                    "dotns lane connected"
                );
                metrics::gauge!("dub_dotns_lane_connected").set(1.0);
                let ctx = self.ctx(&up);
                self.record_dial_success(up);
                Some(ctx)
            }
            Err(e) => {
                let reason = format!("{e:#}");
                if self.record_dial_failure(reason.clone(), now) {
                    tracing::warn!(
                        asset_hub_rpc = %rpc_url,
                        error = %reason,
                        retry_secs = DOTNS_RECONNECT_INTERVAL.as_secs(),
                        "dotns lane parked; People registration is unaffected"
                    );
                }
                metrics::gauge!("dub_dotns_lane_connected").set(0.0);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parked_dotns_lane_backs_off_and_logs_each_cause_once() {
        let t0 = Instant::now();
        let mut lane = DotnsLink::Enabled {
            rpc_url: "wss://example.invalid".to_string(),
            attester: [0u8; 32],
            connected: None,
            last_error: None,
            retry_at: None,
        };

        assert_eq!(lane.dial_state(t0), DotnsDial::Dial);

        assert!(lane.record_dial_failure("unreachable".to_string(), t0));
        assert_eq!(lane.dial_state(t0), DotnsDial::Skip);
        assert_eq!(
            lane.dial_state(t0 + DOTNS_RECONNECT_INTERVAL - Duration::from_secs(1)),
            DotnsDial::Skip
        );
        let t1 = t0 + DOTNS_RECONNECT_INTERVAL;
        assert_eq!(lane.dial_state(t1), DotnsDial::Dial);

        assert!(!lane.record_dial_failure("unreachable".to_string(), t1));
        assert_eq!(lane.dial_state(t1), DotnsDial::Skip);

        let t2 = t1 + DOTNS_RECONNECT_INTERVAL;
        assert!(lane.record_dial_failure("reserve_name shape mismatch".to_string(), t2));
        let t3 = t2 + DOTNS_RECONNECT_INTERVAL;
        assert!(lane.record_dial_failure("unreachable".to_string(), t3));

        assert_eq!(DotnsLink::Disabled.dial_state(t0), DotnsDial::Skip);
        assert!(!DotnsLink::Disabled.record_dial_failure("ignored".to_string(), t0));
    }
}
