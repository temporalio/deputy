package mise

import (
	"strings"

	scalpurl "github.com/google/osv-scalibr/purl"
)

// Metadata describes a single tool entry discovered in a mise or asdf config.
// It is shared by Deputy's mise and asdf inventory extractors so both surface a
// consistent shape. The package's own PURL identity (pkg:mise or pkg:asdf) is
// set by each extractor; this metadata records the finer-grained facts.
type Metadata struct {
	// Key is the raw config key as written, e.g. "node" or "npm:prettier".
	// It is also used as the package Name / PURL name, matching the form
	// OSV-SCALIBR's upstream runtime extractors emit.
	Key string
	// Tool is the tool name without its backend prefix, e.g. "node", "prettier".
	Tool string
	// Version is the requested version string for this entry.
	Version string
	// Backend is the mise backend prefix ("npm", "cargo", …) or "" for the
	// default registry/core backend (and always "" for asdf .tool-versions).
	Backend string
	// BackendPURL is the precise underlying artifact PURL when the backend maps
	// unambiguously to a packaging ecosystem (e.g. "pkg:npm/prettier@3.0.0"),
	// otherwise "". Inventory identity stays at the manager level (pkg:mise);
	// this records what the artifact actually is for precise scan correlation.
	BackendPURL string
	// Fuzzy reports whether Version is a moving target (channel, partial
	// version, or range) rather than an exact pin.
	Fuzzy bool
	// ConfigFormat is the source syntax ("toml" or "tool-versions").
	ConfigFormat string
	// LockedVersion is the exact version recorded for this tool in a sibling
	// mise.lock, when one exists. It may differ from Version when the declared
	// request is fuzzy. Empty when there is no lockfile entry.
	LockedVersion string
	// Checksums are per-platform integrity digests ("os-arch" -> "sha256:…")
	// from the sibling mise.lock, when present.
	Checksums map[string]string
	// Platforms is the full per-platform asset metadata (checksum, size, url)
	// from the sibling mise.lock, keyed by "os-arch". Used to emit per-platform
	// integrity references in SBOMs.
	Platforms map[string]LockedPlatform
}

// ParseChecksum splits a mise.lock checksum string of the form "algo:value"
// (e.g. "sha256:abc…", "blake3:def…") into its algorithm (lowercased) and hex
// value. If there is no recognizable "algo:" prefix it returns ("", value).
func ParseChecksum(s string) (algo, value string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i > 0 {
		return strings.ToLower(s[:i]), s[i+1:]
	}
	return "", s
}

// backendPURLType maps mise backends to the canonical PURL type of the artifact
// they install, but only for backends whose tool names map unambiguously to a
// registry coordinate. Backends that install runtimes or binaries from sources
// without a flat registry coordinate (core, aqua, ubi, asdf, vfox, spm, github,
// http) — and go, whose module-path PURLs are non-trivial to derive correctly —
// are deliberately omitted so Deputy never emits an incorrect PURL.
//
// TODO(deputy): broaden vuln-scan coverage for currently inventory-only backends:
//   - go: tools (Go-module binaries, e.g. "go:github.com/x/y/cmd/z") — pinning
//     resolves module roots natively, but offline inventory cannot derive the
//     canonical pkg:golang module PURL from the package path alone. Scan/SBOM
//     coverage needs either stored resolver metadata or online scan-time
//     resolution so Deputy does not emit a wrong module root.
//   - aqua:/ubi:/github: release-binary tools — pinning resolves repo-shaped
//     specs through GitHub release/tag metadata, but there is no flat OSV
//     package ecosystem for "a binary from a GitHub release". SBOM CPE
//     attribution deliberately emits NO CPE for these rather than a fabricated
//     owner/repo one (an owner/repo string is not a valid NVD CPE
//     vendor:product); correct CPEs require an NVD CPE-dictionary lookup. See
//     the mise/asdf case in [internal/sbom] generateCPE for the deferred model.
//   - node/python runtimes — no OSV ecosystem; would likewise require an
//     NVD CPE-dictionary lookup for accurate CPE/NVD matching.
//
// Registry-backed backends below DO get accurate CPEs, derived from their
// underlying-artifact PURL (see [BackendArtifactPURL]).
var backendPURLType = map[string]string{
	"npm":    scalpurl.TypeNPM,
	"cargo":  scalpurl.TypeCargo,
	"pipx":   scalpurl.TypePyPi,
	"pip":    scalpurl.TypePyPi,
	"gem":    scalpurl.TypeGem,
	"dotnet": scalpurl.TypeNuget,
}

// BackendArtifactPURL returns the canonical underlying-artifact PackageURL for a
// tool spec at a specific version, and whether the backend has an unambiguous
// registry mapping. It handles npm scoped names (@scope/name -> namespace/name)
// and PyPI case-folding. It is the typed form of [BackendPURL]; callers that
// need the package's ecosystem identity (e.g. to derive a CPE) use this.
func BackendArtifactPURL(backend, tool, version string) (scalpurl.PackageURL, bool) {
	ptype, ok := backendPURLType[strings.ToLower(strings.TrimSpace(backend))]
	if !ok {
		return scalpurl.PackageURL{}, false
	}
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return scalpurl.PackageURL{}, false
	}
	namespace, name := "", tool
	switch {
	case ptype == scalpurl.TypeNPM && strings.HasPrefix(tool, "@"):
		if i := strings.Index(tool, "/"); i > 0 {
			namespace, name = tool[:i], tool[i+1:]
		}
	case ptype == scalpurl.TypePyPi:
		// PyPI project names are case-insensitive (PEP 503); OSV uses the
		// lowercase form. Lowercasing is unambiguously safe; we intentionally
		// don't touch -/_/. separators (their normalization is less certain).
		name = strings.ToLower(name)
	}
	return scalpurl.PackageURL{
		Type:      ptype,
		Namespace: namespace,
		Name:      name,
		Version:   strings.TrimSpace(version),
	}, true
}

// BackendPURL returns the canonical underlying-artifact PURL for a tool spec at
// a specific version, or "" when the backend has no unambiguous registry
// mapping. It handles npm scoped names (@scope/name -> namespace/name).
func BackendPURL(backend, tool, version string) string {
	pu, ok := BackendArtifactPURL(backend, tool, version)
	if !ok {
		return ""
	}
	return pu.String()
}

// ScanPURL returns the canonical underlying-artifact PURL to use when scanning a
// mise or asdf package for vulnerabilities, derived purely from the package's
// PURL type, name, and version — no metadata required. This lets scanning work
// both on live inventory and on components round-tripped through an SBOM (whose
// pkg:mise/<backend:tool>@<version> name encodes the backend).
//
// It returns "" for non-mise/asdf packages and for tools that aren't installed
// from a registry-mapped backend (language runtimes and aqua/ubi/asdf-sourced
// tools). Language runtimes that OSV does index under a dedicated coordinate
// (e.g. the Go runtime) are handled separately by [RuntimeScanCoords].
func ScanPURL(purlType, name, version string) string {
	if purlType != "mise" && purlType != "asdf" {
		return ""
	}
	backend, tool := SplitBackend(name)
	return BackendPURL(backend, tool, version)
}

// ScanCoord is an OSV query coordinate for a tool.
type ScanCoord struct {
	Ecosystem string
	Name      string
	Version   string
	PURL      string
}

// RuntimeScanCoords returns OSV query coordinates for language runtimes managed
// by mise/asdf whose vulnerabilities OSV indexes under a coordinate other than
// the tool name. The Go runtime ("go"/"golang", no backend) maps to the Go
// vulnerability database's stdlib and toolchain entries, so e.g. go = "1.25.1"
// is checked for Go stdlib/toolchain CVEs. Returns nil when there is no mapping
// (e.g. node/python runtimes, which OSV does not index by ecosystem and would
// require CPE/NVD matching instead).
func RuntimeScanCoords(purlType, name, version string) []ScanCoord {
	if purlType != "mise" && purlType != "asdf" {
		return nil
	}
	backend, tool := SplitBackend(name)
	if backend != "" {
		return nil
	}
	version = strings.TrimSpace(version)
	if version == "" || !IsExactVersion(version) {
		// OSV range matching needs a concrete version; a fuzzy runtime request
		// can't be matched precisely.
		return nil
	}
	switch tool {
	case "go", "golang":
		return []ScanCoord{
			{Ecosystem: "Go", Name: "stdlib", Version: version, PURL: "pkg:golang/stdlib@" + version},
			{Ecosystem: "Go", Name: "toolchain", Version: version, PURL: "pkg:golang/toolchain@" + version},
		}
	default:
		return nil
	}
}

// MetadataFor builds shared tool metadata for a parsed ToolSpec at a specific
// requested version, in the given config format.
func MetadataFor(spec ToolSpec, version string, format Format) *Metadata {
	return &Metadata{
		Key:          spec.Key,
		Tool:         spec.Name,
		Version:      version,
		Backend:      spec.Backend,
		BackendPURL:  BackendPURL(spec.Backend, spec.Name, version),
		Fuzzy:        !IsExactVersion(version),
		ConfigFormat: string(format),
	}
}
