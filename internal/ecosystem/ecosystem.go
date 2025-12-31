// Package ecosystem provides a single authoritative source for ecosystem
// identification and normalization across the deputy codebase.
//
// Deputy supports 15 ecosystems for dependency scanning:
//
// Core ecosystems with full support (scan, SBOM, policies):
//   - Go, npm, PyPI, Maven, RubyGems, Cargo, NuGet, Hex, Pub, CocoaPods, Packagist
//
// Ecosystems supported via OSV-SCALIBR extractors:
//   - Haskell (cabal, stack)
//   - R (renv)
//   - C++ (conan)
//
// Ecosystems supported via Deputy's custom extractors:
//   - GitHub Actions (.github/workflows/*.yml)
//
// Proxy support (download-time policy enforcement) is available for:
//   - Go, npm, PyPI, RubyGems
//
// The [All] function returns core ecosystems. For filtering OSV-SCALIBR plugins,
// use [AllScalibrPrefixes] which includes both core and extra ecosystem prefixes.
package ecosystem

import (
	"strings"

	pb "deps.dev/api/v3"
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
	switch e {
	case Go:
		return "Go"
	case NPM:
		return "npm"
	case PyPI:
		return "PyPI"
	case Maven:
		return "Maven"
	case RubyGems:
		return "RubyGems"
	case Cargo:
		return "crates.io"
	case NuGet:
		return "NuGet"
	case Hex:
		return "Hex"
	case Pub:
		return "Pub"
	case CocoaPods:
		return "CocoaPods"
	case Packagist:
		return "Packagist"
	default:
		return string(e)
	}
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
func (e Ecosystem) WantsLicenseLookup() bool {
	return e == Go
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

// ProxyEntrypoint returns the CEL policy entrypoint name for proxy requests
// to this ecosystem (e.g., "go_artifact_request", "npm_artifact_request").
func (e Ecosystem) ProxyEntrypoint() string {
	return string(e) + "_artifact_request"
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
	switch e {
	case Go:
		return []string{"go"}
	case NPM:
		return []string{"javascript"}
	case PyPI:
		return []string{"python"}
	case Maven:
		return []string{"java"}
	case RubyGems:
		return []string{"ruby"}
	case Cargo:
		return []string{"rust"}
	case NuGet:
		return []string{"dotnet"}
	case Hex:
		return []string{"elixir", "erlang"}
	case Pub:
		return []string{"dart"}
	case CocoaPods:
		return []string{"swift"}
	case Packagist:
		return []string{"php"}
	default:
		return nil
	}
}

// AllScalibrPrefixes returns all SCALIBR plugin name prefixes for supported ecosystems,
// plus additional prefixes for ecosystems that Deputy supports via other mechanisms.
//
// This function is used by inventory scanning to filter OSV-SCALIBR plugins to only
// those relevant for Deputy's SCA capabilities.
//
// Returns prefixes for:
//   - Core ecosystems via [All] and their [Ecosystem.ScalibrPrefixes]
//   - github: GitHub Actions (Deputy's custom extractor)
//   - haskell: Cabal, Stack (OSV-SCALIBR)
//   - r: renv (OSV-SCALIBR)
//   - cpp: Conan (OSV-SCALIBR)
func AllScalibrPrefixes() []string {
	seen := make(map[string]struct{})
	var prefixes []string

	// Collect prefixes from all supported ecosystems
	for _, eco := range All() {
		for _, prefix := range eco.ScalibrPrefixes() {
			if _, ok := seen[prefix]; !ok {
				seen[prefix] = struct{}{}
				prefixes = append(prefixes, prefix)
			}
		}
	}

	// Additional prefixes for ecosystems Deputy supports via other mechanisms:
	// - github: GitHub Actions (Deputy's custom plugin at internal/inventory/plugins/github/actionsx)
	// - haskell, r, cpp: Ecosystems supported by OSV-SCALIBR but without dedicated Ecosystem constants
	extras := []string{"github", "haskell", "r", "cpp"}
	for _, prefix := range extras {
		if _, ok := seen[prefix]; !ok {
			seen[prefix] = struct{}{}
			prefixes = append(prefixes, prefix)
		}
	}

	return prefixes
}
