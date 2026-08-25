# Contributing

Thanks for looking. This is a reference implementation, so the most useful
contributions are usually the ones that make it easier for the next person to
run, understand, or fork — bug reports with a reproduction, documentation that
was wrong or missing, and fixes that stay inside the existing design.

Everything happens in the open: GitHub issues, pull requests and discussions.
There are no private side channels, and no preferential arrangements with any
contributor.

## Before you open a pull request

Open an issue first for anything that changes behaviour, adds a service, or
alters the HTTP surface. A design that surprises the maintainers at review time
is a design that gets rewritten, which wastes your effort more than a short
issue thread would have.

Small, self-evident fixes — a typo, a broken link, a wrong error message — can
go straight to a pull request.

## The bar

Two commands, both of which CI also runs:

```bash
just check          # rustfmt --check, clippy -D warnings, cargo test --workspace,
                    # plus the compose-boundary and role-split gates
just test-live-db   # the deterministic Postgres suites (needs docker)
```

`just check` must be green. `just test-live-db` must be green for anything
touching a database path. `cargo deny check` runs in CI as well; if you add a
dependency, make sure its licence is on the allow list in `deny.toml`.

Some things in this repo are **generated** and must be regenerated rather than
hand-edited — a test fails if they are stale:

| Artifact | Regenerate with |
| --- | --- |
| `docs/api-reference/{openapi.json,index.html}` | `just openapi` |
| the `(routes)` snippet in `gateway/Caddyfile` | `just routes` |

Commit the regenerated output in the same change.

## Conventions

- **Rust 1.95**, pinned in `rust-toolchain.toml`. `unsafe_code` is forbidden
  workspace-wide.
- **Update the docs in the same change.** If a change alters architecture,
  service boundaries, naming or a data-flow invariant, `docs/architecture.md`
  changes with it. If it alters operations, `docs/operations.md` does.
- **Commit messages** follow Conventional Commits (`feat:`, `fix:`, `docs:`,
  `chore:`). The PR title is what ends up in the history.
- **New HTTP surface** is annotated with `#[utoipa::path(...)]` and registered
  in the service's `openapi.rs`, never hand-written into the API reference.

`AGENTS.md` carries the fuller working notes — crate layout, gotchas, and the
invariants that are easy to break. It is worth reading before a first
non-trivial change, whether or not you use a coding agent.

## Licensing and sign-off

This project is GPL-3.0-only. By submitting a pull request you agree that your
contribution is licensed under the same terms.

Sign your commits off with `git commit -s`, certifying the
[Developer Certificate of Origin](https://developercertificate.org/).

## Security

Do **not** open a public issue for a suspected vulnerability. Parity's
disclosure process and bug bounty are at <https://parity.io/bug-bounty>. See the
Security section of the [README](README.md#security) for what this code is and
is not.

## Code of conduct

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
