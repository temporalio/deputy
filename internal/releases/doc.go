// Package releases resolves upstream release metadata into concrete versions.
//
// It is intentionally manager-agnostic: package managers and toolchain
// integrations decide which upstream source applies, then use this package for
// network clients ([Lister] implementations) and version selection ([Newest]).
// mise is the primary consumer today, but nothing here is mise-specific.
//
// # Design
//
// Every source client embeds the shared [base] (endpoint, HTTP client, response
// bound) and is configured with the single [Option] set (e.g. [WithHTTPClient]).
// A client's List method only declares its payload shape and the mapping to
// []Release; the fetch/decode/bound plumbing lives in the generic [fetch].
//
// Sources differ in capability: most enumerate full version history (Go, Node,
// Python, HashiCorp, Temurin, mise-java), while a few expose only the current
// version ([GoogleCloudSDKClient], [OnePasswordCLIClient]) and therefore resolve
// only "latest" or a current-matching prefix.
//
// # Provenance and mise references
//
// Deputy chooses an authoritative upstream per tool. For some tools this matches
// the source mise uses; for others Deputy queries the vendor directly while mise
// routes through its aqua/asdf/vfox backends. Each client documents its own
// source and any divergence. For reference, mise's equivalents live at:
//   - HTTP client:     https://github.com/jdx/mise/blob/main/src/http.rs
//   - core runtimes:   https://github.com/jdx/mise/tree/main/src/plugins/core
//   - tool registry:   https://github.com/jdx/mise/blob/main/src/registry.rs
//   - java metadata:   https://github.com/jdx/mise-java
//
// Note that a fresh release passing through these clients is not yet filtered by
// any cooldown; mise's install-time minimum_release_age cooldown is a separate
// control (https://github.com/jdx/mise/blob/main/src/toolset/tool_version_options.rs).
package releases
