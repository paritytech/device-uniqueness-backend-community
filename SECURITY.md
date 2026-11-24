# Security policy

## Security status

This repository contains reference code: a Rust backend that proves a device is a distinct
physical device and registers a username for it on Polkadot's People Chain, together with
the sibling services around it (username indexer, invite tickets, TURN credentials,
notification relay), the single `dub` binary that runs them, and the deployment material
(compose files, gateway, Helm chart, observability stack). It is a reference blueprint
intended to be forked and deployed by others, not a hardened production build.

Unless a specific release states otherwise, this repository has **not** received a full
security audit. Use in production or production-like deployments should only follow an
independent security review of the relevant code, configuration, and deployment
environment.

Parity does not deploy this code. It may nevertheless be used by third parties on live
networks, or reused in future production contexts. If you experience problems with a
service built on or deployed from this code, contact the party that deployed it.

## Supported versions

Security fixes are provided only on `main` and in the latest tagged release. Older releases
are not backported (exceptions might apply). Experimental, archived, deprecated, or
explicitly-unsupported code paths, examples, or branches may not be triaged unless the
issue affects maintained code, user funds, private keys, signing flows, or transaction
integrity.

## Bug bounty scope

This repository is **not** in scope for Parity's paid bug bounty programme unless
explicitly listed in the official bounty scope at the time of submission
(<https://parity.io/bug-bounty>). Reports may still be reviewed through responsible
disclosure, but bounty eligibility applies only where the affected asset or vulnerability
class is explicitly in scope.

## What to report

Report an issue only if it demonstrates realistic impact, in a deployment configured as
documented for real use, against one or more of:

- device-uniqueness guarantees — bypassing Apple App Attest or Android Play Integrity /
  key attestation verification, or registering more than one username per device, with
  attestation enforcement enabled;
- the cross-service auth contract — forging, replaying, or escalating JWTs or refresh
  tokens, or a service accepting tokens it should reject;
- private keys and signer boundaries — the JWT signing key, the attester key, the
  chain-writer signing key, or any secret reaching a process or log it should not;
- transaction construction, integrity, or signing intent — the chain writer submitting
  extrinsics other than the ones intended, or for the wrong account or network;
- user funds or assets;
- remote code execution, credential compromise, or cross-service data access in a
  realistic deployment.

## Out of scope (unless shown to cause realistic high-impact harm)

Local-development-only issues; issues that rely on the development defaults in
`.env.example` (well-known dev keys, `AUTH_ENABLED=false` / soft `ENFORCE_AUTH`, public
test networks); demo/testnet-only issues; missing security headers or rate limiting on
local setups; dependency reports without a working exploit path or that don't affect the
shipped binary; hypothetical attack paths; "this code is unaudited"; documented known
limitations (see `README.md` and `docs/architecture.md`); deployments that contradict the
documented guidance in `docs/operations.md` (e.g. publishing ports past the edge,
exposing the observability stack, scaling single-instance workers); issues requiring
access to internal Parity systems not in scope.

## Reporting a qualifying issue

Do **not** open a public issue for a qualifying vulnerability. Email
**security@parity.io** with:

- the affected repository, crate or role, commit, branch, or release;
- the network build (`testnet` or `polkadot`) and deployment topology (standard or
  `all-in-one`), if relevant;
- clear reproduction steps and realistic impact;
- whether it affects a live deployment, user funds, keys, signing, or only
  local/demo/testnet usage;
- any proof of concept or logs involved;
- assumptions required for exploitation.

## Researcher expectations

Don't access, modify, or delete data that isn't yours; don't disrupt services; don't
extract keys or secrets beyond what's needed to demonstrate impact safely; don't test
against third-party deployments without their operator's permission; no social
engineering or physical attacks; don't disclose publicly until Parity has had a reasonable
opportunity to remediate.

## Safe-use guidance

Before any production or production-like deployment, review at minimum: that every
development default in `.env.example` has been replaced, including all keys and secrets;
how the JWT signing key, attester key, and chain-writer key are generated, stored,
rotated, and destroyed, and that each reaches only its own role; that platform attestation
is enabled and enforced (`AUTH_ENABLED`, `ENFORCE_AUTH`); that the build's network
(`DUB_NETWORK`) and `PEOPLE_RPC_URL` point at the intended chain; that the deployment
topology suits your threat model (`all-in-one` holds every secret in one process);
that only the edge publishes ports and the observability stack stays loopback-only;
that the single-instance workers are not scaled; that each service's database credentials
are isolated; that dependencies are pinned and audited (`just deny`); that the container
image is one you built or verified; and that CORS, rate limits, logging, and telemetry
suit the intended environment. See `docs/operations.md` for the operator view.
