// Package pin implements dependency pinning for supply chain security.
//
// Pinning replaces mutable version references with immutable identifiers,
// preventing tag-repointing and version-substitution attacks. The package
// provides a pluggable [Strategy] interface where ecosystem-specific
// implementations handle discovery, resolution, verification, and rewriting.
//
// # Supported ecosystems
//
// GitHub Actions ([GitHubActionsStrategy]) — replaces mutable version tags
// with commit SHAs. Includes fork/imposter commit detection via the GitHub
// API. Resolution uses the git protocol (ls-remote), not the REST API.
//
//	uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
//
// Container images ([ContainerStrategy]) — appends sha256 digest pins to
// Dockerfile FROM statements, workflow container/services fields, and
// docker:// uses. Resolution uses OCI registry HEAD requests.
//
//	FROM alpine:3.19@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c
//
// # Future ecosystems
//
// The Strategy interface is designed for these ecosystems to be added without
// modifying the orchestrator. Each shares the same structural pattern: a
// mutable reference that can be replaced with an immutable one.
//
// Terraform modules — git-sourced modules (git::https://...?ref=v1.0) use
// mutable tags. Pin to commit SHA, same as GitHub Actions. HCL rewriting
// needed. Lockfile (.terraform.lock.hcl) hashes cover registry modules but
// not git-sourced ones.
//
// Helm charts — OCI-based charts use mutable tags, same as container images.
// Digest pinning via the OCI registry applies directly. Chart.yaml and
// values files need rewriting.
//
// CI script tool installs — commands like "go install pkg@latest",
// "npx tool@^2", "pip install black==24.3" in CI scripts and Dockerfiles
// use mutable versions. Pin to exact version + hash where the ecosystem
// supports it (pip --require-hashes, npm --integrity, go.sum).
//
// Git submodules — .gitmodules can reference branches. Pin to commit SHA.
// Resolution via git ls-remote (same as GitHub Actions).
package pin
