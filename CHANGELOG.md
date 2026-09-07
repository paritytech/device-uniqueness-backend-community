# Changelog

Notable changes to the published binaries. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning:
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, a breaking change bumps the **minor**. Pin an exact `vX.Y.Z`.

## [Unreleased]

### Changed

- **Asset Hub is now the username source of truth; the People Chain keeps only
  the consumer record.** `DotnsGateway::LiteLabelOwner` decides which usernames
  exist and who owns them. `PeopleLite.attest` still runs, because
  `Resources::Consumers` is where the chat `identifier_key` lives, but nothing
  reads its username bytes any more. This aligns the backend with the clients,
  which already resolve names against Asset Hub and treat the People username
  bytes as legacy.

  The two writer lanes swap precedence. `DotnsGateway::reserve_name` now claims a
  row as soon as intake or the queue advancer puts it in `RESERVED`, and
  `PeopleLite.attest` is claimable only once `dotns_status` reaches `RESERVED`, so
  the consumer record is never written against a name the gateway refused. The
  cross-lane abandonment reverses with it: a terminal dotNS outcome
  (`FAILED_TERMINAL`/`EXPIRED`) closes an open People half in the same guarded
  UPDATE, and `status` gains **`ABANDONED`** to say so. `DOTNS_ABANDONED` is now
  legacy — no new row can reach it. `SUBMITTING` and `ASSIGNED` are excluded from
  the sweep: one has an extrinsic in flight and is left for reconciliation, the
  other has already landed. The device record follows the lane that commits the
  claim, so Widevine consumption moves to the dotNS reservation; a People failure
  afterwards deliberately does **not** release the device, because the label is
  already claimed globally and freeing the handset would let it take a second
  name while the first stays burned.

  `device-attestation-api` now opens its own **read-only** Asset Hub connection
  and blocks on it at startup exactly as it does on the People RPC.
  `ASSET_HUB_RPC_URL` is therefore required on the API as well as the writer, and
  `verify_compose_boundaries.sh` enforces it on both. `POST
  /api/v1/usernames/available`, the registration digit selection, and the payment
  lane's confirmation-time re-selection all read
  `DotnsGateway::LiteLabelOwner` for `base.00`..`base.99` in one
  `state_queryStorageAt`, so the three can no longer disagree about what is taken.
  `EXHAUSTED` consequently means only "no free discriminator": dotNS has no
  reservation queue to be full and no bare-base ownership that closes the whole
  space, so the two extra conditions the People-chain read folded in have no
  equivalent.

  `dotns.reservedUsername` is passed through to `reserve_name` as
  `reserved_base_label` instead of into `attest`, and the backend no longer
  arbitrates it. The gateway holds the only authoritative view of the full-label
  space, so a claim on a taken full name surfaces as a deterministic dotNS
  rejection rather than a `409 FullNameUnavailable` at intake.

  **`DOTNS_GATEWAY_ENABLED` is removed.** *Breaking:* the variable is no longer
  read, and an environment still setting it is ignored rather than warned about —
  there is nothing left for either value to select. It gated a lane that was
  optional when People was the authority; now that dotNS *is* the authority there
  is no People-only mode to fall back to, and a deployment with the gateway off
  could not complete a single registration. What used to be the flag's off-state
  is now simply a missing `ASSET_HUB_RPC_URL`, which aborts the writer at startup.
  The `dotns_lane` label is gone from `dub_writer_info`, and the
  `dotNS gateway is not enabled in this environment.` 400 on `POST
  /api/v1/usernames` can no longer occur. A *parked* lane — Asset Hub configured
  but unreachable — is unchanged, and now holds the payment pass too, since
  confirmation re-selects a discriminator and must not pick one the gateway has
  not been asked about.

  Two consequences worth watching. `EXPIRED` is much more expensive: it was
  terminal for the name only, and is now terminal for the whole registration, so a
  `QUEUED` backlog deeper than the chain's `MaxValiditySeconds` will expire claims
  wholesale — see the runbook. And existing rows are untouched: there is still no
  backfill, so names written while People was the authority keep `dotns_status`
  `NULL` and stay People-only.

- **`username-indexer` projects usernames from Asset Hub, with People kept as the
  legacy half.** The search index is now built from `DotnsGateway` — the name
  authority — while the People ingest stays connected for accounts registered
  before the cutover, which are never re-registered and so can never appear on
  the gateway. Every `assigned_usernames` row carries a new `source` column
  (`people` | `asset-hub`, migration `20260908000000_assigned_usernames_source.sql`)
  and precedence is one-way: a gateway row replaces a People row for the same
  account, and the People ingest may neither overwrite nor retract a gateway row.
  The rule lives in the upsert's `ON CONFLICT` clause and the delete's `WHERE`,
  so it holds whichever pass runs first. There is still no backfill in either
  direction.

  The gateway ingest is shaped by what the pallet stores, which is less than it
  emits. `LiteLabelOwner` is keyed by label rather than account and holds only
  the owner; the chat key is never written to pallet storage at all; and
  full-person label strings are not stored either (`AliasRegistration` is
  `{ collection, account }`). The People pattern — an event points at an
  account, storage is re-read for the truth — therefore does not transfer.
  Instead `NameReserved` and `NameRegistered` carry the values, storage confirms
  only who owns the label at that block, and a census (`LiteLabelOwner` scan)
  rebuilds the lite population after a wipe. A census fills chat keys from the
  People consumer record for the same account and skips a label whose owner has
  none rather than inventing one; it cannot recover full-person names at all, so
  a census-built row shows its lite label until that account's next
  `NameRegistered`. Closing that gap needs the gateway's Lens contract
  (`nameDetail(label)`), which this workspace has no contract-call path to.

  The two ingests advance on separate cursors (`sync_state.ah_last_finalized_number`,
  `ah_last_finalized_hash`, `ah_genesis_hash`) and separate loops, because the
  chains finalize independently and driving one off the other's headers would
  stall it whenever that chain went quiet. They share only the projection lock.
  A broken Asset Hub connection degrades the projection to its legacy half
  rather than stopping it, and an Asset Hub genesis change discards only the
  `asset-hub` rows. New metrics `dub_gateway_checkpoint_block`,
  `dub_gateway_accounts_upserted_total`, `dub_gateway_observations_skipped_total`
  and `dub_gateway_pass_failures_total`.

  **`ASSET_HUB_RPC_URL` is now required on `username-indexer`** as well as the
  API and the writer, and `verify_compose_boundaries.sh` enforces it on all
  three. It is required rather than defaulted because an indexer without it
  would serve only the pre-cutover population while every health signal stayed
  green. Asset Hub events are decoded dynamically, so no second vendored
  metadata blob is introduced.

- **The registration queue now schedules against the dotNS reservation deadline.**
  Intake stamps a new `username_reservations.dotns_expires_at` (migration
  `0010_dotns_expiry.sql`) as `dotns_signed_at + DotnsGateway::MaxValiditySeconds`,
  the window read from Asset Hub rather than configured. It is advisory — the
  writer still enforces the live window before spending an extrinsic — but it is
  what lets the queue see an expiry coming instead of discovering it when the
  writer finally claims the row, which since dotNS became the name authority is
  too late: an expired reservation abandons the whole claim, and only the client
  can re-sign.

  Two behaviours follow, neither configured. The advancer **sweeps** rows already
  past their deadline before handing out slots, marking them `EXPIRED` +
  `ABANDONED`, so a doomed claim stops inflating queue depth, stops displacing a
  live claim from a slot, and never costs an extrinsic to be told what the
  deadline already said. And a row whose deadline falls inside the **current
  drain time** (`ceil(depth / 4) × interval`) is promoted ahead of the balance
  groups, out of the same four-slot budget — throughput is unchanged, the
  ordering is not. Balance priority decides who goes first among claims that will
  survive either way; it should decide nothing for a claim about to stop
  existing. The horizon is the measured depth and the advancer's own cadence, so
  it tightens by itself as a backlog grows.

  New gauges `dub_queue_depth`, `dub_queue_drain_seconds` and
  `dub_queue_safe_depth`, plus the counter `dub_queue_expired_total`. The safe
  depth is the derivation itself,
  `4 × floor((MaxValiditySeconds − 300) / QUEUE_ADVANCE_INTERVAL_SECS)` — roughly
  170,000 rows at the shipped 3-day window and 6-second cadence, which is the
  useful part of the answer: backlog depth is not what expires claims, a stalled
  advancer or writer is. Publishing it keeps that true after a cadence change or
  a runtime upgrade that shortens the window. `registration-queue` still opens no
  Asset Hub connection — the compose boundaries deny it one and it needs none:
  the deadline is on the row, and the gauge recovers the window from the most
  recently stamped row, where `dotns_expires_at − dotns_signed_at` is the
  constant that was in force.

- **`username-indexer` indexes the unfinalized window speculatively.** The sync
  loop now subscribes to **best** block headers rather than finalized ones, and
  each pass reconciles the finalized range first (unchanged, authoritative) and
  then the unfinalized window `(finalized, best]` against the best head. A new
  registration therefore reaches search about a block after it is *authored*
  instead of after it is finalized — a gap measured at 2-5 blocks on the People
  chain. New `SPECULATIVE_INDEXING_ENABLED` (default `true`) turns it off.

  Speculative rows carry `assigned_usernames.speculative_from_block` and obey one
  rule: **speculation may add rows and retract rows it added, and may never
  modify or delete finalized state.** That rule sets the scope: a *new*
  registration is admitted early, while a change to an account that already holds
  a finalized row — a full-person upgrade, an identifier key rotation — still
  becomes visible only at finality.

  The window is re-derived from the finalized head on every pass rather than
  checkpointed, so a block discarded at the tip — on PreviewNet's People chain,
  structurally about one height in eight — is retracted on the next pass instead
  of stranding a row the finalized pass would never revisit. Because
  `Resources::Consumers` is append-only on chain, that re-check is the only thing
  that ever retracts a row, so it runs on every pass: when a wake carries no
  header the best head is read over RPC instead, and when the window is too wide
  to scan the loop stops admitting but keeps re-checking what it already holds.
  Failure there is contained — the finalized pass is never failed or backed off
  by it. The checkpoint, `/readyz` freshness and the lag gauges keep their
  existing finalized-only meaning. Startup drops any speculative rows a previous
  run left behind, under the projection lock so a booting replica cannot clear
  rows a live one is serving. New metrics: `dub_chain_best_head_block`,
  `dub_chain_finality_trail_blocks`, `dub_indexer_speculative_window_blocks`,
  `dub_indexer_speculative_admitted_total`,
  `dub_indexer_speculative_retracted_total`,
  `dub_indexer_speculative_stood_down_total`,
  `dub_indexer_speculative_failed_total`.

- **`username-indexer` syncs on block headers instead of a timer.** The
  resync loop now subscribes to the People Chain's block stream and indexes on
  each header, so a newly registered username reaches
  `GET /api/v1/usernames/search` about a block after it is authored rather than
  up to `SYNC_INTERVAL_SECS` (default 30s) later. Headers are only a signal —
  every pass still re-reads the checkpoint and indexes up to the head — so a
  dropped or coalesced header costs nothing, and a burst is drained into one
  pass. `SYNC_INTERVAL_SECS` keeps its name and default but is now the fallback:
  the longest the loop sits without a header before forcing a pass anyway.
  Nothing to change in an environment. Two new metrics: `dub_indexer_subscribed`
  (1 while the best-header subscription is live) and
  `dub_indexer_resubscribes_total`.

## [0.5.0] - 2026-09-02

### Fixed

- **The invite-ticket pool mints again after People Chain 3000000.** The
  vendored metadata is refreshed from `next-people-paseo` 3000000, which
  paseo-next-v2 and previewnet both run (their metadata is identical). The
  upgrade did not touch `Game`/`ProofOfInk::set_invite_ticket` at all — what
  moved was `RuntimeCall`, which `PeopleLite` grew `register_with_fee` and
  `create_lite_people_collection` into. The pool never signs a bare
  `set_invite_ticket`; it signs the `Utility.force_batch` and `Proxy.proxy`
  wrappers around it, and those carry `RuntimeCall`, so every tick failed
  validation with `The extrinsic payload is not compatible with the live
  chain` and no ticket was minted. `/api/v1/invitation-ticket/claim` kept
  serving the pool it already had, so the first symptom an operator would
  have seen is `422 Pool exhausted` once it drained. Nothing about the wire format changed: pallet and call indices
  are identical on both sides of the upgrade, and username registration
  (`PeopleLite::attest`, `Resources::register_lite_person`) was never
  affected.
- **The dotNS lane can sign against Asset Hub 3000000.** That runtime dropped
  the `AsRingAlias` transaction extension and declares `AsScarcity` in its
  place. `AssetHubTransactionExtensions` had no member for it, and subxt
  resolves a runtime's extensions by name, so every Asset Hub submission
  would have failed to encode. The tuple now carries both gates: as with the
  People tuple, it is the union across every runtime in `KNOWN_RUNTIMES`, not
  a snapshot of the newest, so a binary pointed at a node that has not
  upgraded yet still signs.
- **An unfundable signer no longer fails registrations terminally.** A
  transaction rejected with `Inability to pay some fees`
  (`InvalidTransaction::Payment`) never enters a block, spends nothing and says
  nothing about the row, so it now **parks** the row — re-queued at an
  *unchanged* `attempt` behind a 5-minute `not_before` — instead of spending one
  of `CHAIN_WRITER_MAX_ATTEMPTS`. Previously a drained signer walked a row
  through its whole budget in about three minutes (`2^attempt` backoff, clamped
  at 6) and wrote `FAILED_TERMINAL`. On the dotNS lane that was unrecoverable:
  the client's reservation stays valid for `MaxValiditySeconds` (three days) and
  only the client holds the key that can re-sign it, so a funding gap an
  operator had not noticed yet destroyed claims that had days of validity left.
  Parked rows resume on their own once the signer is topped up; the existing
  `chain-writer signer balance below floor` warning and
  `dub_account_free_balance_planck` gauge remain how the outage is seen, now
  joined by `dub_chain_submit_total{outcome="parked"}`.
- **A rejection that cannot change is no longer retried.** A dispatch error
  named in `DETERMINISTIC_REJECTIONS` — currently
  `Resources::UsernameReservationTaken` — is terminal on the first pass. Such a
  call reached a block and paid its fee, and is byte-identical on every retry,
  so the previous behaviour paid the same fee eight times to be told the same
  thing, draining the very signer whose exhaustion then parks the lane.
  `last_error` now distinguishes the two terminal routes: `rejected
  deterministically, not retried: …` versus `max attempts reached: …`.

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

- **Metadata drift is visible at boot.** Every chain connection now logs the
  live `spec_version` and `transaction_version` once, and the People Chain
  connections compare it against the `spec_version` the vendored blob was
  generated from — read out of the blob's own `System::Version`, so the two
  cannot be edited apart. A mismatch is a `WARN` naming the file to refresh.
  Previously a runtime upgrade under a stale blob announced itself only as a
  throttled pool tick or a failed write, minutes to days later. The check is
  diagnostic and never fatal: most upgrades change nothing this workspace
  signs, and a chain that cannot be read has already failed the connect.
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

[Unreleased]: https://github.com/paritytech/device-uniqueness-backend-community/compare/v0.5.0...HEAD

[0.5.0]: https://github.com/paritytech/device-uniqueness-backend-community/rel
eases/tag/v0.5.0

[0.4.0]: https://github.com/paritytech/device-uniqueness-backend-community/releases/tag/v0.4.0
