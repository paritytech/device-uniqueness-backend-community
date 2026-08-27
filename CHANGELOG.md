# Changelog

Notable changes to the published binaries. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning:
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, a breaking change bumps the **minor**. Pin an exact `vX.Y.Z`.

## [Unreleased]

### Changed

- **`device-attestation-chain-writer` submits a whole pass as one extrinsic.** A
  claimed set now becomes one `Utility.force_batch` of `PeopleLite.attest` calls
  (wrapped as a whole in `Proxy.proxy` when the signer is a delegate) instead of
  one extrinsic per row, so N registrations cost one finalization rather than N.
  The dotNS gateway lane batches `DotnsGateway.reserve_name` the same way on
  Asset Hub. A single-row set still submits a bare call, unwrapped. Each row's
  outcome comes from its own `Utility.ItemCompleted` / `ItemFailed`
  positionally — and only when the item count matches the calls submitted;
  otherwise the positional mapping is discarded and chain state decides, so
  `ASSIGNED` can never be inferred from a mapping that does not line up.
  Failures split: a whole-batch fault (nonce, signing, transport, a proxy
  rejection of the batch) re-queues the set at an **unchanged** `attempt` on one
  shared backoff, while a per-item failure spends that row's own budget as
  before, carrying its dispatch error into `last_error` resolved to
  `Pallet::Variant`.
- **`CHAIN_WRITER_BATCH_SIZE` is now a maximum rather than a fixed claim size.**
  Each lane holds an adaptive size — halved on a whole-batch failure (floor 1),
  grown by one per successful submission, capped at the configured value — so
  the writer finds the chain's real per-batch ceiling instead of being
  configured with a guess. A lane also remembers the smallest size it has seen
  fail and stops one below it, re-probing that size only after 20 consecutive
  successful submissions: without that memory a chain that rejects *every* batch
  of two or more would make the lane alternate 1 → 2 → fail forever, paying a
  fee and a nonce on every other pass. The People and Asset Hub lanes size
  independently. The variable name and default (25) are unchanged; only its
  meaning is — a configured value that does not fit a `u16` falls back to the
  default rather than claiming the whole outbox at once.
- **The writer's owner reads are batched.** A drain pass resolves
  `Resources::UsernameOwnerOf` for its whole claimed set in one
  `state_queryStorageAt`, as does the startup `SUBMITTING` reconcile and the
  dotNS lane's `LiteLabelOwner` read — one round trip per pass instead of one
  per row. Unchanged semantics: a partial or unexpected answer is an error, never
  "unowned". Because one read now decides a whole set, a failed read is treated
  as a whole-batch fault: the set is re-queued at an **unchanged** `attempt` on
  one shared backoff, so a flapping RPC cannot walk an entire claimed set to
  `FAILED_TERMINAL`. The startup reconcile reads in chunks and keeps the rows it
  did resolve, rather than abandoning all of them on one bad response.

### Added

- **Batch observability.** `dub_chain_batch_size{lane}` (the adaptive size in
  use), `dub_chain_batch_items{lane}` (rows per submission),
  `dub_chain_batch_failed_total{lane}` (whole-batch failures),
  `dub_chain_batch_item_failed_total{lane}` (individual rejected calls),
  `dub_chain_batch_reconciled_total{lane}` (rows from a batch that submitted but
  had to be resolved from chain state — kept off the whole-batch failure counter
  so that one keeps meaning "the chain is rejecting batches"), and
  `dub_registration_latency_seconds` (end-to-end intake→on-chain, per row, and
  only for assignments the writer's own submission produced).
- **Chain failures are named the same way on both lanes.** `ProxyExecuted` and
  `Utility.ItemFailed` are now decoded through subxt's own `DispatchError`,
  against the metadata of the block the extrinsic landed in, by one
  implementation shared by People and Asset Hub. The dotNS lane previously
  recorded an undecoded value in `dotns_last_error`, having no vendored Asset Hub
  metadata to resolve names against; it now records `Pallet::Variant` like the
  People lane. People's names come from the runtime that actually executed the
  call rather than from the vendored metadata blob. The one error name the
  writer treats as success is now matched pallet-qualified
  (`PeopleLite::AlreadyRegistered`), so a gateway error that happens to be
  spelled the same way is retried rather than recorded as a reservation that
  landed.
- **`subxt` pinned to 0.50.3** (from 0.50.1), which picks up `frame-decode`
  0.18.1: V5 signer payloads now include the transaction extension version and
  call data as an immutable base implication, and unknown `Option<T>`
  transaction extensions encode as `None` instead of failing. Both are on the
  path this release's batched submission takes.

### Fixed

- **A proxied dotNS reservation rejected by the gateway is no longer recorded as
  reserved.** `Proxy.proxy` emits `ExtrinsicSuccess` even when the inner call
  fails, and the Asset Hub lane was reading that as success — the People lane has
  checked `ProxyExecuted` since the earlier silent-failure fix, but its Asset
  Hub twin never did. The check fails closed: a result field that is not a
  `Result<(), DispatchError>` is an error rather than a pass.

## [0.4.0] - 2026-08-25

Initial public release. Development up to this point happened in a private
repository, so this entry describes the state of the project at first publish
rather than a delta from a public predecessor.

The version starts at 0.4.0 rather than 0.1.0 so that it does not collide with
the internally-tagged 0.1–0.3 series, whose `docker.io/paritytech/device-uniqueness-backend`
images are public and were built from earlier source than this. A `v0.3.0`
here would name binaries that disagree with the `v0.3.0` image already
published under that name.

### Added

- **Device attestation and username registration for Polkadot's People Chain**,
  as eight services that are all `--role`s of one `dub` binary:
  `device-attestation-api` (auth handshake, username registration with free and
  paid lanes, JWKS), `device-attestation-chain-writer` (drains the reservation
  outbox onto the chain), `registration-queue` (queue advancer),
  `username-indexer` (finalized-chain username projection, prefix search, and
  the optional proof-of-compute gate), `invite-tickets-api` and
  `invite-tickets-pool`, `turn-api` (coturn REST credential issuer) and
  `notify-relay` (APNs / FCM push relay). Plus `voucher-mint`, an operator CLI.
- **A dotNS gateway lane** that claims Asset Hub labels alongside the People
  Chain username, as an independent state machine on the same row.
- **A single-URL Caddy gateway** whose route table is generated from one
  in-code ownership map (`crates/dub/src/routes/table.rs`), with a Traefik
  emitter for deployments that front the services differently.
- **A generated OpenAPI reference** under `docs/api-reference/`, kept in sync
  with the handlers by a test.
- **A Docker Compose stack** covering every service, its Postgres databases,
  the gateway, and an optional Prometheus / Loki / Grafana project.

### Changed since the 0.3.0 image

For anyone comparing against the published `v0.3.0` container image, the
source here is ahead of it. The **public HTTP surface is unchanged** — the
generated OpenAPI document is byte-identical — but the binaries are not the
same build:

- **JWT issuance and verification were consolidated into the `jwt-verify`
  crate.** `device_attestation::jwt` is gone and `Jwt` is re-exported from
  `jwt-verify`, which now carries the issuer, the verifier and the JWKS
  document. Issuing still requires the signing key that only
  `device-attestation` is given, so the sole-issuer property is unchanged.
  This pulls in `jsonwebtoken`, `sha2` and `hex` as new dependencies.
- **Both target Asset Hubs now take the `signed_at` `reserve_name` shape.** The
  boot-time shape guard remains and still refuses to return a client on a
  mismatch; it now guards against future runtime drift rather than
  distinguishing two live runtimes.

### Fixed relative to the pre-publish source

- **`cargo deny check licenses` passes.** `CC0-1.0` and `CDLA-Permissive-2.0`
  were missing from the allow list, so the audit failed on four transitive
  crates.
- **Three security advisories cleared** by updating the lockfile: `h2`
  0.4.15 → 0.4.19 (RUSTSEC-2026-0258), plus the yanked `num-bigint` and `spin`.
  Four advisories with no available fix are ignored with per-entry reasons in
  [`deny.toml`](deny.toml).
- **`jsonwebtoken` is pinned to `9`** rather than `*`. A wildcard version can
  resolve across a semver-major on any `cargo update`.
- **`.env.example` ships a working dev `TURN_SECRET`.** It previously carried
  the literal placeholder `<base64-secret>`, and `turn-api` refuses to boot on
  invalid base64 — so the documented quickstart crash-looped one service.

[Unreleased]: https://github.com/paritytech/device-uniqueness-backend-community/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/paritytech/device-uniqueness-backend-community/releases/tag/v0.4.0
