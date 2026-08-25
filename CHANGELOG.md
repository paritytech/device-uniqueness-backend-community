# Changelog

Notable changes to the published binaries. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning:
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, a breaking change bumps the **minor**. Pin an exact `vX.Y.Z`.

## [Unreleased]

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
