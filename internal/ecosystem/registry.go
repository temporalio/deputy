// Package ecosystem provides a single authoritative source for ecosystem
// identification and normalization across the deputy codebase.
//
// Deputy supports 16 ecosystems for dependency scanning:
//
// Core ecosystems with full support (scan, SBOM, policies):
//   - Go, npm, PyPI, Maven, RubyGems, Cargo, NuGet, Hex, Pub, CocoaPods, Packagist
//
// Ecosystems supported via OSV-SCALIBR extractors:
//   - Haskell (cabal, stack)
//   - R (renv)
//   - C++ (conan)
//   - Nix (flake.lock, /nix/store)
//
// Ecosystems supported via Deputy's custom extractors:
//   - GitHub Actions (.github/workflows/*.yml)
//
// Proxy support (download-time policy enforcement) is available for:
//   - Go, npm, PyPI, RubyGems
//
// The Registry is the single source of truth for ecosystem capabilities.
// Use [Default] to access the global registry, or [NewRegistry] for testing.

package ecosystem

import (
	"cmp"
	"slices"
	"sync"
)

// Capability represents a feature an ecosystem may support.
// Capabilities are combined using bitwise OR operations.
type Capability uint8

const (
	// CapInventory indicates the ecosystem can extract package inventory.
	CapInventory Capability = 1 << iota

	// CapGraph indicates the ecosystem can resolve dependency graph edges.
	CapGraph

	// CapProxy indicates the ecosystem has proxy support for download-time policies.
	CapProxy

	// CapLicense indicates the ecosystem supports license lookup.
	CapLicense

	// CapFix indicates the ecosystem supports automated fix suggestions.
	CapFix

	// CapSBOM indicates SBOM generation is supported.
	CapSBOM
)

// String returns a human-readable name for the capability.
func (c Capability) String() string {
	switch c {
	case CapInventory:
		return "Inventory"
	case CapGraph:
		return "Graph"
	case CapProxy:
		return "Proxy"
	case CapLicense:
		return "License"
	case CapFix:
		return "Fix"
	case CapSBOM:
		return "SBOM"
	default:
		return "Unknown"
	}
}

// AllCapabilities returns all defined capabilities for iteration.
func AllCapabilities() []Capability {
	return []Capability{CapInventory, CapGraph, CapProxy, CapLicense, CapFix, CapSBOM}
}

// Registration describes an ecosystem's capabilities and metadata.
// This is the single source of truth for ecosystem information.
type Registration struct {
	// Ecosystem is the canonical ecosystem identifier.
	Ecosystem Ecosystem

	// DisplayName is the human-readable name (e.g., "Go", "npm", "PyPI").
	DisplayName string

	// Description provides a brief summary of the ecosystem.
	Description string

	// Capabilities is a bitmask of supported features.
	Capabilities Capability

	// Aliases are alternative names that map to this ecosystem
	// (e.g., "golang" -> Go, "python" -> PyPI).
	Aliases []string

	// ScalibrPrefixes are the OSV-SCALIBR plugin name prefixes for inventory.
	// SCALIBR plugins use names like "go/gomod", "javascript/packagejson".
	ScalibrPrefixes []string

	// Lockfiles lists the lockfile patterns this ecosystem recognizes.
	Lockfiles []string

	// UpstreamURL is the primary package registry URL.
	UpstreamURL string

	// OSVName is the ecosystem name as used by the OSV database.
	OSVName string
}

// HasCapability returns true if the registration includes the given capability.
func (r Registration) HasCapability(cap Capability) bool {
	return r.Capabilities&cap != 0
}

// CapabilityList returns a slice of capabilities this registration supports.
func (r Registration) CapabilityList() []Capability {
	var caps []Capability
	for _, c := range AllCapabilities() {
		if r.HasCapability(c) {
			caps = append(caps, c)
		}
	}
	return caps
}

// Registry holds ecosystem registrations and provides lookup methods.
// The registry is thread-safe for concurrent reads and writes.
type Registry struct {
	mu          sync.RWMutex
	byEcosystem map[Ecosystem]*Registration
	byAlias     map[string]*Registration
}

// NewRegistry creates a Registry populated with default ecosystem registrations.
func NewRegistry() *Registry {
	r := &Registry{
		byEcosystem: make(map[Ecosystem]*Registration),
		byAlias:     make(map[string]*Registration),
	}
	r.registerDefaults()
	return r
}

// Register adds an ecosystem registration to the registry.
func (r *Registry) Register(reg Registration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.byEcosystem[reg.Ecosystem] = &reg
	for _, alias := range reg.Aliases {
		r.byAlias[alias] = &reg
	}
}

// Lookup returns the registration for an ecosystem (by name or alias).
// Returns nil if not found.
func (r *Registry) Lookup(name string) *Registration {
	eco := Parse(name)

	r.mu.RLock()
	defer r.mu.RUnlock()

	if reg, ok := r.byEcosystem[eco]; ok {
		return reg
	}
	if reg, ok := r.byAlias[name]; ok {
		return reg
	}
	return nil
}

// Get returns the registration for an ecosystem constant.
// Returns nil if not found.
func (r *Registry) Get(eco Ecosystem) *Registration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byEcosystem[eco]
}

// WithCapability returns all registrations that have the given capability.
func (r *Registry) WithCapability(cap Capability) []Registration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Registration
	for _, reg := range r.byEcosystem {
		if reg.HasCapability(cap) {
			result = append(result, *reg)
		}
	}
	return result
}

// All returns all registered ecosystems, sorted by display name.
func (r *Registry) All() []Registration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Registration, 0, len(r.byEcosystem))
	for _, reg := range r.byEcosystem {
		result = append(result, *reg)
	}
	slices.SortFunc(result, func(a, b Registration) int {
		return cmp.Compare(a.DisplayName, b.DisplayName)
	})
	return result
}

// Ecosystems returns all registered ecosystem constants, sorted alphabetically.
func (r *Registry) Ecosystems() []Ecosystem {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Ecosystem, 0, len(r.byEcosystem))
	for eco := range r.byEcosystem {
		result = append(result, eco)
	}
	slices.SortFunc(result, func(a, b Ecosystem) int {
		return cmp.Compare(string(a), string(b))
	})
	return result
}

// AllScalibrPrefixes returns all SCALIBR plugin name prefixes for all registered
// ecosystems, plus additional prefixes for ecosystems Deputy supports via other
// mechanisms (GitHub Actions, Haskell, R, C++, OS packages).
func (r *Registry) AllScalibrPrefixes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]struct{})
	var prefixes []string

	for _, reg := range r.byEcosystem {
		for _, prefix := range reg.ScalibrPrefixes {
			if _, ok := seen[prefix]; !ok {
				seen[prefix] = struct{}{}
				prefixes = append(prefixes, prefix)
			}
		}
	}

	// Additional prefixes for ecosystems Deputy supports via other mechanisms:
	// - github: GitHub Actions (Deputy's custom plugin)
	// - haskell, r, cpp: Ecosystems supported by OSV-SCALIBR
	// - os: OS-level package managers for container image scanning
	extras := []string{"github", "haskell", "r", "cpp", "os"}
	for _, extra := range extras {
		if _, ok := seen[extra]; !ok {
			seen[extra] = struct{}{}
			prefixes = append(prefixes, extra)
		}
	}

	return prefixes
}

// registerDefaults populates the registry with built-in ecosystem definitions.
func (r *Registry) registerDefaults() {
	r.Register(Registration{
		Ecosystem:       Go,
		DisplayName:     "Go",
		Description:     "Go modules (golang.org)",
		Capabilities:    CapInventory | CapGraph | CapProxy | CapLicense | CapFix | CapSBOM,
		Aliases:         []string{"golang"},
		ScalibrPrefixes: []string{"go"},
		Lockfiles:       []string{"go.mod", "go.sum"},
		UpstreamURL:     "https://proxy.golang.org",
		OSVName:         "Go",
	})

	r.Register(Registration{
		Ecosystem:       NPM,
		DisplayName:     "npm",
		Description:     "Node.js packages (npmjs.com)",
		Capabilities:    CapInventory | CapGraph | CapProxy | CapLicense | CapSBOM,
		Aliases:         []string{"javascript", "node", "nodejs"},
		ScalibrPrefixes: []string{"javascript"},
		Lockfiles:       []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
		UpstreamURL:     "https://registry.npmjs.org",
		OSVName:         "npm",
	})

	r.Register(Registration{
		Ecosystem:       PyPI,
		DisplayName:     "PyPI",
		Description:     "Python packages (pypi.org)",
		Capabilities:    CapInventory | CapGraph | CapProxy | CapSBOM,
		Aliases:         []string{"python", "pip"},
		ScalibrPrefixes: []string{"python"},
		Lockfiles:       []string{"requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock"},
		UpstreamURL:     "https://pypi.org",
		OSVName:         "PyPI",
	})

	r.Register(Registration{
		Ecosystem:       RubyGems,
		DisplayName:     "RubyGems",
		Description:     "Ruby gems (rubygems.org)",
		Capabilities:    CapInventory | CapGraph | CapProxy | CapSBOM,
		Aliases:         []string{"ruby", "gem", "gems"},
		ScalibrPrefixes: []string{"ruby"},
		Lockfiles:       []string{"Gemfile.lock", "*.gemspec"},
		UpstreamURL:     "https://rubygems.org",
		OSVName:         "RubyGems",
	})

	r.Register(Registration{
		Ecosystem:       Cargo,
		DisplayName:     "Cargo",
		Description:     "Rust crates (crates.io)",
		Capabilities:    CapInventory | CapGraph | CapLicense | CapSBOM,
		Aliases:         []string{"rust", "crates", "crates.io"},
		ScalibrPrefixes: []string{"rust"},
		Lockfiles:       []string{"Cargo.lock"},
		UpstreamURL:     "https://crates.io",
		OSVName:         "crates.io",
	})

	r.Register(Registration{
		Ecosystem:       Maven,
		DisplayName:     "Maven",
		Description:     "Java/JVM packages (Maven Central)",
		Capabilities:    CapInventory | CapGraph | CapSBOM,
		Aliases:         []string{"java"},
		ScalibrPrefixes: []string{"java"},
		Lockfiles:       []string{"pom.xml", "build.gradle", "build.gradle.kts"},
		UpstreamURL:     "https://repo1.maven.org/maven2",
		OSVName:         "Maven",
	})

	r.Register(Registration{
		Ecosystem:       NuGet,
		DisplayName:     "NuGet",
		Description:     ".NET packages (nuget.org)",
		Capabilities:    CapInventory | CapGraph | CapSBOM,
		Aliases:         []string{"dotnet", ".net"},
		ScalibrPrefixes: []string{"dotnet"},
		Lockfiles:       []string{"packages.lock.json", "*.csproj", "*.fsproj"},
		UpstreamURL:     "https://api.nuget.org/v3/index.json",
		OSVName:         "NuGet",
	})

	r.Register(Registration{
		Ecosystem:       Hex,
		DisplayName:     "Hex",
		Description:     "Elixir/Erlang packages (hex.pm)",
		Capabilities:    CapInventory | CapGraph | CapSBOM,
		Aliases:         []string{"hexpm", "elixir", "erlang"},
		ScalibrPrefixes: []string{"elixir", "erlang"},
		Lockfiles:       []string{"mix.lock"},
		UpstreamURL:     "https://hex.pm",
		OSVName:         "Hex",
	})

	r.Register(Registration{
		Ecosystem:       Pub,
		DisplayName:     "Pub",
		Description:     "Dart/Flutter packages (pub.dev)",
		Capabilities:    CapInventory | CapGraph | CapSBOM,
		Aliases:         []string{"dart", "flutter"},
		ScalibrPrefixes: []string{"dart"},
		Lockfiles:       []string{"pubspec.lock"},
		UpstreamURL:     "https://pub.dev",
		OSVName:         "Pub",
	})

	r.Register(Registration{
		Ecosystem:       CocoaPods,
		DisplayName:     "CocoaPods",
		Description:     "Swift/iOS packages (cocoapods.org)",
		Capabilities:    CapInventory | CapSBOM,
		Aliases:         []string{"pod", "pods", "swift", "ios"},
		ScalibrPrefixes: []string{"swift"},
		Lockfiles:       []string{"Podfile.lock"},
		UpstreamURL:     "https://cocoapods.org",
		OSVName:         "CocoaPods",
	})

	r.Register(Registration{
		Ecosystem:       Packagist,
		DisplayName:     "Packagist",
		Description:     "PHP packages (packagist.org)",
		Capabilities:    CapInventory | CapSBOM,
		Aliases:         []string{"composer", "php"},
		ScalibrPrefixes: []string{"php"},
		Lockfiles:       []string{"composer.lock"},
		UpstreamURL:     "https://packagist.org",
		OSVName:         "Packagist",
	})

	r.Register(Registration{
		Ecosystem:       Nix,
		DisplayName:     "Nix",
		Description:     "NixOS/Nixpkgs packages (nixos.org)",
		Capabilities:    CapInventory | CapSBOM | CapLicense | CapGraph,
		Aliases:         []string{"nixos", "nixpkgs", "flakes"},
		ScalibrPrefixes: []string{"os/nix", "nix"},
		Lockfiles:       []string{"flake.lock"},
		UpstreamURL:     "https://nixos.org",
		OSVName:         "NixOS",
	})
}

// DefaultRegistry is the global registry instance.
// It's initialized lazily to allow for testing with custom registries.
var (
	defaultRegistry     *Registry
	defaultRegistryOnce sync.Once
)

// Default returns the default global registry.
func Default() *Registry {
	defaultRegistryOnce.Do(func() {
		defaultRegistry = NewRegistry()
	})
	return defaultRegistry
}

// HasGraphSupport returns true if the ecosystem supports graph resolution.
func HasGraphSupport(eco Ecosystem) bool {
	reg := Default().Get(eco)
	return reg != nil && reg.HasCapability(CapGraph)
}

// HasProxySupportFor returns true if the ecosystem has proxy support.
func HasProxySupportFor(eco Ecosystem) bool {
	reg := Default().Get(eco)
	return reg != nil && reg.HasCapability(CapProxy)
}

// HasLicenseSupport returns true if the ecosystem supports license lookup.
func HasLicenseSupport(eco Ecosystem) bool {
	reg := Default().Get(eco)
	return reg != nil && reg.HasCapability(CapLicense)
}

// HasFixSupport returns true if the ecosystem supports automated fixes.
func HasFixSupport(eco Ecosystem) bool {
	reg := Default().Get(eco)
	return reg != nil && reg.HasCapability(CapFix)
}

// GraphSupportedEcosystems returns all ecosystems with graph resolution support.
func GraphSupportedEcosystems() []Ecosystem {
	regs := Default().WithCapability(CapGraph)
	result := make([]Ecosystem, len(regs))
	for i, reg := range regs {
		result[i] = reg.Ecosystem
	}
	return result
}

// ProxyCapableEcosystems returns all ecosystems that have proxy capability declared.
// This returns ecosystems that could support proxy mode, not necessarily those with
// active proxy handlers. Use [ProxySupportedEcosystems] to get ecosystems with
// registered proxy handlers.
func ProxyCapableEcosystems() []Ecosystem {
	regs := Default().WithCapability(CapProxy)
	result := make([]Ecosystem, len(regs))
	for i, reg := range regs {
		result[i] = reg.Ecosystem
	}
	return result
}
