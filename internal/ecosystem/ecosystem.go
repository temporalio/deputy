package ecosystem

import (
	"strings"

	pb "deps.dev/api/v3"
	"github.com/temporalio/deputy/internal/policy"
)

// Ecosystem represents a supported package ecosystem.
type Ecosystem string

// Supported ecosystems.
const (
	Go        Ecosystem = "go"
	NPM       Ecosystem = "npm"
	PyPI      Ecosystem = "pypi"
	Maven     Ecosystem = "maven"
	RubyGems  Ecosystem = "rubygems"
	Cargo     Ecosystem = "cargo"
	NuGet     Ecosystem = "nuget"
	Hex       Ecosystem = "hex"
	Pub       Ecosystem = "pub"
	CocoaPods Ecosystem = "cocoapods"
	Packagist Ecosystem = "packagist"
	Unknown   Ecosystem = "unknown"
)

// Parse normalizes a free-form ecosystem string into a canonical Ecosystem value.
// It handles common aliases and variations (e.g., "golang" -> Go, "python" -> PyPI).
func Parse(s string) Ecosystem {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "go", "golang":
		return Go
	case "npm", "javascript", "node", "nodejs":
		return NPM
	case "pypi", "python", "pip":
		return PyPI
	case "maven", "java":
		return Maven
	case "rubygems", "ruby", "gem", "gems":
		return RubyGems
	case "cargo", "rust", "crates", "crates.io":
		return Cargo
	case "nuget", "dotnet", ".net":
		return NuGet
	case "hex", "hexpm", "elixir", "erlang":
		return Hex
	case "pub", "dart", "flutter":
		return Pub
	case "cocoapods", "pod", "pods", "swift", "ios":
		return CocoaPods
	case "packagist", "composer", "php":
		return Packagist
	default:
		return Unknown
	}
}

// String returns the canonical string representation of the ecosystem.
func (e Ecosystem) String() string {
	return string(e)
}

// OSVName returns the ecosystem name as used by the OSV database.
// OSV uses title-cased names for some ecosystems.
func (e Ecosystem) OSVName() string {
	if reg := Default().Get(e); reg != nil && reg.OSVName != "" {
		return reg.OSVName
	}
	return string(e)
}

// DepsDevSystem returns the deps.dev API system enum for this ecosystem.
func (e Ecosystem) DepsDevSystem() pb.System {
	switch e {
	case Go:
		return pb.System_GO
	case NPM:
		return pb.System_NPM
	case PyPI:
		return pb.System_PYPI
	case Maven:
		return pb.System_MAVEN
	case RubyGems:
		return pb.System_RUBYGEMS
	case Cargo:
		return pb.System_CARGO
	case NuGet:
		return pb.System_NUGET
	default:
		return pb.System_SYSTEM_UNSPECIFIED
	}
}

// PackageKeyField returns the field name used in policy payloads for this ecosystem.
// Go uses "module" while other ecosystems use "package".
func (e Ecosystem) PackageKeyField() string {
	if e == Go {
		return "module"
	}
	return "package"
}

// WantsLicenseLookup returns whether this ecosystem typically benefits from
// license lookup enrichment in proxy mode.
//
// Deprecated: Use HasLicenseSupport instead.
func (e Ecosystem) WantsLicenseLookup() bool {
	return HasLicenseSupport(e)
}

// NormalizeVersion applies ecosystem-specific version normalization.
// For Go, it ensures versions have a "v" prefix.
func (e Ecosystem) NormalizeVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return ""
	}
	if e == Go && !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// NormalizeName applies ecosystem-specific name normalization.
// For PyPI, names are lowercased.
func (e Ecosystem) NormalizeName(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return ""
	}
	if e == PyPI {
		return strings.ToLower(n)
	}
	return n
}

// IsSupported returns true if this is a known, supported ecosystem.
func (e Ecosystem) IsSupported() bool {
	return e != Unknown && e != ""
}

// ProxyEntrypoint returns the CEL policy entrypoint for proxy requests
// to this ecosystem (e.g., EntrypointGoArtifactRequest, EntrypointNpmArtifactRequest).
func (e Ecosystem) ProxyEntrypoint() policy.Entrypoint {
	return policy.Entrypoint(string(e) + "_artifact_request")
}

// All returns all supported ecosystems.
func All() []Ecosystem {
	return []Ecosystem{
		Go, NPM, PyPI, Maven, RubyGems, Cargo, NuGet, Hex, Pub, CocoaPods, Packagist,
	}
}

// ScalibrPrefixes returns the OSV-SCALIBR plugin name prefixes associated with
// this ecosystem. SCALIBR plugins use names like "go/gomod", "javascript/packagejson",
// etc. This method returns the first path segment(s) that identify extractors for
// this ecosystem.
//
// Returns nil for Unknown or ecosystems without SCALIBR support.
func (e Ecosystem) ScalibrPrefixes() []string {
	if reg := Default().Get(e); reg != nil {
		return reg.ScalibrPrefixes
	}
	return nil
}

// AllScalibrPrefixes returns all SCALIBR plugin name prefixes for supported ecosystems,
// plus additional prefixes for ecosystems that Deputy supports via other mechanisms.
//
// This function is used by inventory scanning to filter OSV-SCALIBR plugins to only
// those relevant for Deputy's SCA capabilities.
func AllScalibrPrefixes() []string {
	return Default().AllScalibrPrefixes()
}

// Capabilities describes the features available for an ecosystem.
// This type is maintained for backward compatibility; prefer using
// the Registry and Capability bitmask for new code.
type Capabilities struct {
	// Scan indicates dependency scanning is supported.
	Scan bool
	// SBOM indicates SBOM generation is supported.
	SBOM bool
	// Proxy indicates download-time policy enforcement is available.
	Proxy bool
	// License indicates license lookup enrichment is available.
	License bool
	// GraphResolution indicates dependency graph edge resolution is available.
	GraphResolution bool
}

// Capabilities returns the features available for this ecosystem.
// This method delegates to the Registry for the source of truth.
func (e Ecosystem) Capabilities() Capabilities {
	reg := Default().Get(e)
	if reg == nil {
		return Capabilities{}
	}
	return Capabilities{
		Scan:            reg.HasCapability(CapInventory),
		SBOM:            reg.HasCapability(CapSBOM),
		Proxy:           reg.HasCapability(CapProxy),
		License:         reg.HasCapability(CapLicense),
		GraphResolution: reg.HasCapability(CapGraph),
	}
}

// WithProxy returns all ecosystems that have proxy capability.
func WithProxy() []Ecosystem {
	return ProxyCapableEcosystems()
}

// WithGraphResolution returns all ecosystems that support dependency graph resolution.
func WithGraphResolution() []Ecosystem {
	return GraphSupportedEcosystems()
}
