package ecosystem

import (
	"strings"

	pb "deps.dev/api/v3"
	"golang.org/x/mod/semver"
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
	Mise      Ecosystem = "mise"
	Asdf      Ecosystem = "asdf"
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
	case "cargo", "rust", "crates", "crates.io", "cargo (crates.io)":
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
	case "mise", "mise-en-place", "rtx":
		return Mise
	case "asdf", "tool-versions":
		return Asdf
	default:
		return Unknown
	}
}

// String returns the canonical string representation of the ecosystem.
func (e Ecosystem) String() string {
	return string(e)
}

// OSVName returns the ecosystem name as used by the OSV database.
// OSV uses title-cased names for some ecosystems. When the ecosystem has no
// registered OSV name it falls back to the ecosystem string; use OSVQueryable
// to distinguish real OSV coverage from that fallback.
func (e Ecosystem) OSVName() string {
	if reg := Default().Get(e); reg != nil && reg.OSVName != "" {
		return reg.OSVName
	}
	return string(e)
}

// OSVQueryable reports whether the OSV vulnerability database covers this
// ecosystem, i.e. the registry defines a real OSV name for it. This is the
// authoritative signal for whether a package can be sent to OSV's querybatch
// API: ecosystems without OSV coverage (e.g. tool managers like mise/asdf, or
// Dockerfile base images) are inventory-only and must not be queried, since OSV
// rejects an entire batch that names an ecosystem it does not recognize.
func (e Ecosystem) OSVQueryable() bool {
	reg := Default().Get(e)
	return reg != nil && reg.OSVName != ""
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
//
// The prefix is only added to a string that is a Go version once prefixed.
// Scanners report unversioned builds with non-version sentinels, SCALIBR's
// gobinary extractor emitting the literal "(devel)" for an unstamped main
// module, and "v(devel)" is neither a version nor the sentinel a policy or a
// comparison matches on.
func (e Ecosystem) NormalizeVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return ""
	}
	if e == Go && !strings.HasPrefix(v, "v") && semver.IsValid("v"+v) {
		return "v" + v
	}
	return v
}

// NormalizeName folds a package name into the single spelling this ecosystem
// considers one package, so two records of the same dependency compare equal no
// matter which manifest, registry, or advisory they came from. It is the one
// implementation of that rule: the comparison pipeline and the policy boundary
// both call it, which is what keeps an exact-match policy from missing a
// package that inventory already treats as the same one.
//
// Ecosystems whose names are case-sensitive and separator-significant (npm, Go,
// Maven, and everything Deputy has no rule for) get the name back unchanged
// apart from surrounding whitespace, because folding there would merge distinct
// packages.
func (e Ecosystem) NormalizeName(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return ""
	}
	switch e {
	case PyPI:
		return normalizePyPIName(n)
	case Cargo:
		return normalizeCargoName(n)
	default:
		return n
	}
}

// normalizePyPIName applies PEP 503: a distribution name is lowercase, and any
// run of "-", "_", or "." is a single "-". That is the form PyPI itself
// compares and the form OSV indexes, so "Flask_SQLAlchemy", "flask.sqlalchemy",
// and "Flask-SQLAlchemy" all collapse to "flask-sqlalchemy".
func normalizePyPIName(name string) string {
	lowered := strings.ToLower(name)
	var out strings.Builder
	out.Grow(len(lowered))
	inSeparator := false
	for _, r := range lowered {
		if r == '-' || r == '_' || r == '.' {
			if !inSeparator {
				out.WriteByte('-')
				inSeparator = true
			}
			continue
		}
		out.WriteRune(r)
		inSeparator = false
	}
	return out.String()
}

// normalizeCargoName folds a crate name the way crates.io does: names are
// case-insensitive and "-" and "_" are interchangeable, so a crate cannot be
// registered under both spellings. Deputy normalizes to the underscore form
// because that is how a crate is named in Rust source.
func normalizeCargoName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "-", "_")
}

// IsSupported returns true if this is a known, supported ecosystem.
func (e Ecosystem) IsSupported() bool {
	return e != Unknown && e != ""
}

// All returns all supported ecosystems.
func All() []Ecosystem {
	return []Ecosystem{
		Go, NPM, PyPI, Maven, RubyGems, Cargo, NuGet, Hex, Pub, CocoaPods, Packagist,
		Mise, Asdf,
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
