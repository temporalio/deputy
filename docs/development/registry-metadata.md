# Registry metadata policy signals

Deputy can fetch registry-sourced metadata about the version a dependency bump
introduces and expose it to `diff_dependency_change` policies. The goal is to
surface supply-chain risk that a known-vulnerability scan cannot see: a poisoned
release has no CVE on the day it lands, but it often *looks* wrong — it was
published minutes ago, or by an account that has never published the package
before.

This metadata comes from the deps.dev Insights API that Deputy already depends
on, so the engine stays self-contained (no Python runtime, no shelling out to
other tools).

## What ships today: release freshness

`deputy diff --registry-metadata` fetches each changed package's publish date
from deps.dev and attaches it to the policy input as
`change.target_metadata` (see
[policy-inputs.md](../reference/policy-inputs.md#dependency-change-registry-metadata)).
Policies gate on `change.target_metadata.age_days` to flag bumps to versions
that are only hours or days old. See
[`policy/examples/release-freshness.yaml`](../../policy/examples/release-freshness.yaml).

Implementation:

- `internal/registry` — the deps.dev-backed `Fetcher` and the pure
  response→`Metadata` conversion.
- `internal/cli/cmd/diff.go` — `enrichChangesWithRegistryMetadata` populates
  `change.target_metadata` before policy evaluation, concurrently and
  non-fatally (a flaky upstream leaves the field unset rather than failing the
  diff).
- `api/deputy/diff/v1/service.proto` — the `RegistryMetadata` message and the
  `PackageChange.target_metadata` field.

## Deferred: maintainer / publisher change

A second high-value signal is a **maintainer change** — a brand-new or very
young account suddenly publishing an established package, the shape of an
account-takeover or infiltration (e.g. XZ-style). This is deliberately **not**
in the initial change, for a concrete reason:

> deps.dev does not expose registry publisher/maintainer account identity or
> account age. It returns publish dates and related source repositories, but not
> "who pushed this version" or "how old is that account."

So a faithful maintainer-change check cannot be built on deps.dev alone. It needs
**per-registry** lookups against each ecosystem's own API, since each models
publishers differently:

- **npm** — the packument's `maintainers` list and each version's `_npmUser`;
  account age via the npm user API.
- **PyPI** — project/role data (no per-version uploader in the JSON API; the
  newer integrity/provenance endpoints are closer).
- **RubyGems** — gem `owners`.
- **Maven / Cargo / NuGet** — varying owner/account models.

The natural shape, mirroring the release-freshness work, is a per-ecosystem
maintainer fetcher behind the same `internal/registry` package, exposing
something like `change.target_metadata.publishers` and a derived
`change.maintainer_changed` / new-account-age signal for policies. Because each
registry differs, this is best landed incrementally (npm first, where the data is
richest) rather than as one large change.

Tracking: see deputy issue #41.
