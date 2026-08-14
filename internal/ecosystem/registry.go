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
// The Registry is the single source of truth for ecosystem capabilities.
// Use [Default] to access the global registry, or [NewRegistry] for testing.

package ecosystem

import (
	"cmp"
	"slices"
	"sync"

	// Both PURL packages appear here on purpose, and which one a registration's
	// PURLType comes from is the statement that the type is registered upstream
	// or is not.
	//
	// packageurl-go carries the types the package-url spec has adopted, and it
	// validates against that set. purlx carries the ones it has not: mise, asdf,
	// and GitHub Actions are emerging types that neither packageurl-go nor
	// OSV-SCALIBR's allowlist recognizes yet, so Deputy defines them and parses
	// them loosely (see [purlx] for the upstream issue).
	//
	// Re-exporting the upstream types through purlx would collapse the imports
	// at the cost of that distinction: every PURLType below would read the same
	// whether the spec blesses it or Deputy invented it, and purlx would own a
	// hand-maintained mirror of an upstream list, which is the drift this
	// package exists to avoid elsewhere. The two imports are the cheaper signal.
	packageurl "github.com/package-url/packageurl-go"

	"github.com/temporalio/deputy/internal/purlx"
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

// Projection names a value the registry promises to carry for every
// ecosystem. Every registration must supply each projection unless it declares
// the projection absent, so a missing value is always a bug rather than an
// ambiguous blank. See [Registration.Absent] and [Registration.Lacks].
type Projection string

const (
	// ProjectionDisplayName is the human-readable name (see [Display]).
	ProjectionDisplayName Projection = "display_name"

	// ProjectionDescription is the one-line summary of the ecosystem.
	ProjectionDescription Projection = "description"

	// ProjectionCapabilities is the capability bitmask.
	ProjectionCapabilities Projection = "capabilities"

	// ProjectionScalibrPrefixes are the OSV-SCALIBR plugin name prefixes.
	ProjectionScalibrPrefixes Projection = "scalibr_prefixes"

	// ProjectionManifests are the manifest file patterns.
	ProjectionManifests Projection = "manifests"

	// ProjectionUpstreamURL is the primary registry URL.
	ProjectionUpstreamURL Projection = "upstream_url"

	// ProjectionOSVName is the ecosystem name OSV uses. Ecosystems OSV does not
	// index (tool managers such as mise and asdf) declare it absent, which is
	// also what makes [Ecosystem.OSVQueryable] false for them.
	ProjectionOSVName Projection = "osv_name"

	// ProjectionPURLType is the package-url type for the ecosystem (see
	// [PURLType]).
	ProjectionPURLType Projection = "purl_type"
)

// RequiredProjections returns every projection a registration must supply
// unless it declares the projection absent.
func RequiredProjections() []Projection {
	return []Projection{
		ProjectionDisplayName,
		ProjectionDescription,
		ProjectionCapabilities,
		ProjectionScalibrPrefixes,
		ProjectionManifests,
		ProjectionUpstreamURL,
		ProjectionOSVName,
		ProjectionPURLType,
	}
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

	// Manifests lists the human-edited manifest/declaration file patterns this
	// ecosystem recognizes (e.g. go.mod, package.json, mise.toml).
	Manifests []string

	// Lockfiles lists generated lockfile patterns this ecosystem recognizes
	// (e.g. package-lock.json, Cargo.lock, mise.lock).
	Lockfiles []string

	// UpstreamURL is the primary package registry URL.
	UpstreamURL string

	// OSVName is the ecosystem name as used by the OSV database.
	OSVName string

	// PURLType is the package-url type that identifies this ecosystem in a
	// PURL. It is frequently not the canonical token ("go" is pkg:golang,
	// "rubygems" is pkg:gem, "conancenter" is pkg:conan), which is why every
	// registration states it instead of letting callers guess from the token.
	PURLType string

	// Absent declares the projections this ecosystem intentionally does not
	// have, so a blank value is a deliberate statement instead of an oversight.
	// Declaring a projection absent while still supplying it is a bug, and the
	// registry completeness test rejects both halves of that.
	Absent []Projection
}

// Spellings returns every string that names this ecosystem: its canonical
// token, its display name, and each alias. It is the one definition of that set,
// used both by [Registry.Register] and by the alias index for the canonical
// tokens that carry no registration, so the two answer the same spellings. The
// strings are returned as declared; callers fold them.
func (r Registration) Spellings() []string {
	out := make([]string, 0, len(r.Aliases)+2)
	out = append(out, string(r.Ecosystem), r.DisplayName)
	return append(out, r.Aliases...)
}

// Lacks reports whether this registration declares the projection absent.
func (r Registration) Lacks(p Projection) bool {
	return slices.Contains(r.Absent, p)
}

// Projection returns the registration's value for p, and ok=false when p is not
// a projection this type carries. Values are returned as the empty-checkable
// any so callers (notably the completeness test) can treat them uniformly.
func (r Registration) Projection(p Projection) (value any, ok bool) {
	switch p {
	case ProjectionDisplayName:
		return r.DisplayName, true
	case ProjectionDescription:
		return r.Description, true
	case ProjectionCapabilities:
		return r.Capabilities, true
	case ProjectionScalibrPrefixes:
		return r.ScalibrPrefixes, true
	case ProjectionManifests:
		return r.Manifests, true
	case ProjectionUpstreamURL:
		return r.UpstreamURL, true
	case ProjectionOSVName:
		return r.OSVName, true
	case ProjectionPURLType:
		return r.PURLType, true
	default:
		return nil, false
	}
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

// Register adds an ecosystem registration to the registry, indexing every
// spelling that names it (see [Registration.Spellings]) under the fold
// [normalizeToken] applies.
//
// The fold is what makes the index and the resolver agree. [Canonical]
// normalizes before it asks, and a verbatim index answers only the one spelling
// the registration happened to use, so a plugin that declared the alias
// "Acme Registry" could not be resolved from it, from "acme-registry", or from
// any other casing, while [Canonical] documents the opposite. Registration is
// the half that folds because every reader then gets it without knowing to.
func (r *Registry) Register(reg Registration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.byEcosystem[reg.Ecosystem] = &reg
	for _, spelling := range reg.Spellings() {
		if key := normalizeToken(spelling); key != "" {
			r.byAlias[key] = &reg
		}
	}
}

// Lookup returns the registration for an ecosystem named by any of its
// spellings: its canonical token, its display name, or an alias, in any casing
// and with spaces or underscores where the token has hyphens. Returns nil if no
// registration claims the name.
//
// The name is folded with the same [normalizeToken] that built the index, so the
// two cannot disagree about what a spelling is. [Parse] still sees the raw
// string first, because some of its aliases carry separators of their own
// ("cargo (crates.io)") that the fold does not produce.
func (r *Registry) Lookup(name string) *Registration {
	eco := Parse(name)

	r.mu.RLock()
	defer r.mu.RUnlock()

	if reg, ok := r.byEcosystem[eco]; ok {
		return reg
	}
	if reg, ok := r.byAlias[normalizeToken(name)]; ok {
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

	// The canonical tokens with no capability registration declare their SCALIBR
	// group the same way a registered ecosystem does, so Hackage, CRAN, and
	// ConanCenter contribute haskell, r, and cpp from their own registration
	// rather than from a copy of them kept here.
	for _, reg := range extraCanonicalEcosystems {
		for _, prefix := range reg.ScalibrPrefixes {
			if _, ok := seen[prefix]; !ok {
				seen[prefix] = struct{}{}
				prefixes = append(prefixes, prefix)
			}
		}
	}

	// Prefixes that belong to no single ecosystem:
	// - github: GitHub Actions (Deputy's custom plugin, whose group name is not
	//   the ecosystem's purl type)
	// - os: OS-level package managers for container image scanning
	extras := []string{"github", "os"}
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
		Manifests:       []string{"go.mod"},
		UpstreamURL:     "https://proxy.golang.org",
		OSVName:         "Go",
		PURLType:        packageurl.TypeGolang,
	})

	r.Register(Registration{
		Ecosystem:       NPM,
		DisplayName:     "npm",
		Description:     "Node.js packages (npmjs.com)",
		Capabilities:    CapInventory | CapGraph | CapProxy | CapLicense | CapSBOM,
		Aliases:         []string{"javascript", "node", "nodejs"},
		ScalibrPrefixes: []string{"javascript"},
		Manifests:       []string{"package.json"},
		Lockfiles:       []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"},
		UpstreamURL:     "https://registry.npmjs.org",
		OSVName:         "npm",
		PURLType:        packageurl.TypeNPM,
	})

	r.Register(Registration{
		Ecosystem:       PyPI,
		DisplayName:     "PyPI",
		Description:     "Python packages (pypi.org)",
		Capabilities:    CapInventory | CapGraph | CapProxy | CapSBOM,
		Aliases:         []string{"python", "pip"},
		ScalibrPrefixes: []string{"python"},
		Manifests:       []string{"pyproject.toml", "setup.py", "setup.cfg"},
		Lockfiles:       []string{"requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock"},
		UpstreamURL:     "https://pypi.org",
		OSVName:         "PyPI",
		PURLType:        packageurl.TypePyPi,
	})

	r.Register(Registration{
		Ecosystem:       RubyGems,
		DisplayName:     "RubyGems",
		Description:     "Ruby gems (rubygems.org)",
		Capabilities:    CapInventory | CapGraph | CapProxy | CapSBOM,
		Aliases:         []string{"ruby", "gem", "gems"},
		ScalibrPrefixes: []string{"ruby"},
		Manifests:       []string{"Gemfile", "*.gemspec"},
		Lockfiles:       []string{"Gemfile.lock"},
		UpstreamURL:     "https://rubygems.org",
		OSVName:         "RubyGems",
		PURLType:        packageurl.TypeGem,
	})

	r.Register(Registration{
		Ecosystem:       Cargo,
		DisplayName:     "Cargo",
		Description:     "Rust crates (crates.io)",
		Capabilities:    CapInventory | CapGraph | CapLicense | CapSBOM,
		Aliases:         []string{"rust", "crates", "crates.io"},
		ScalibrPrefixes: []string{"rust"},
		Manifests:       []string{"Cargo.toml"},
		Lockfiles:       []string{"Cargo.lock"},
		UpstreamURL:     "https://crates.io",
		OSVName:         "crates.io",
		PURLType:        packageurl.TypeCargo,
	})

	r.Register(Registration{
		Ecosystem:       Maven,
		DisplayName:     "Maven",
		Description:     "Java/JVM packages (Maven Central)",
		Capabilities:    CapInventory | CapGraph | CapSBOM,
		Aliases:         []string{"java"},
		ScalibrPrefixes: []string{"java"},
		Manifests:       []string{"pom.xml", "build.gradle", "build.gradle.kts"},
		Lockfiles:       []string{"gradle/verification-metadata.xml"},
		UpstreamURL:     "https://repo1.maven.org/maven2",
		OSVName:         "Maven",
		PURLType:        packageurl.TypeMaven,
	})

	r.Register(Registration{
		Ecosystem:       NuGet,
		DisplayName:     "NuGet",
		Description:     ".NET packages (nuget.org)",
		Capabilities:    CapInventory | CapGraph | CapSBOM,
		Aliases:         []string{"dotnet", ".net"},
		ScalibrPrefixes: []string{"dotnet"},
		Manifests:       []string{"*.csproj", "*.fsproj"},
		Lockfiles:       []string{"packages.lock.json"},
		UpstreamURL:     "https://api.nuget.org/v3/index.json",
		OSVName:         "NuGet",
		PURLType:        packageurl.TypeNuget,
	})

	r.Register(Registration{
		Ecosystem:       Hex,
		DisplayName:     "Hex",
		Description:     "Elixir/Erlang packages (hex.pm)",
		Capabilities:    CapInventory | CapGraph | CapSBOM,
		Aliases:         []string{"hexpm", "elixir", "erlang"},
		ScalibrPrefixes: []string{"elixir", "erlang"},
		Manifests:       []string{"mix.exs"},
		Lockfiles:       []string{"mix.lock"},
		UpstreamURL:     "https://hex.pm",
		OSVName:         "Hex",
		PURLType:        packageurl.TypeHex,
	})

	r.Register(Registration{
		Ecosystem:       Pub,
		DisplayName:     "Pub",
		Description:     "Dart/Flutter packages (pub.dev)",
		Capabilities:    CapInventory | CapGraph | CapSBOM,
		Aliases:         []string{"dart", "flutter"},
		ScalibrPrefixes: []string{"dart"},
		Manifests:       []string{"pubspec.yaml"},
		Lockfiles:       []string{"pubspec.lock"},
		UpstreamURL:     "https://pub.dev",
		OSVName:         "Pub",
		PURLType:        packageurl.TypePub,
	})

	r.Register(Registration{
		Ecosystem:       CocoaPods,
		DisplayName:     "CocoaPods",
		Description:     "Swift/iOS packages (cocoapods.org)",
		Capabilities:    CapInventory | CapSBOM,
		Aliases:         []string{"pod", "pods", "swift", "ios"},
		ScalibrPrefixes: []string{"swift"},
		Manifests:       []string{"Podfile", "*.podspec"},
		Lockfiles:       []string{"Podfile.lock"},
		UpstreamURL:     "https://cocoapods.org",
		OSVName:         "CocoaPods",
		PURLType:        packageurl.TypeCocoapods,
	})

	r.Register(Registration{
		Ecosystem:       Packagist,
		DisplayName:     "Packagist",
		Description:     "PHP packages (packagist.org)",
		Capabilities:    CapInventory | CapSBOM,
		Aliases:         []string{"composer", "php"},
		ScalibrPrefixes: []string{"php"},
		Manifests:       []string{"composer.json"},
		Lockfiles:       []string{"composer.lock"},
		UpstreamURL:     "https://packagist.org",
		OSVName:         "Packagist",
		PURLType:        packageurl.TypeComposer,
	})

	r.Register(Registration{
		Ecosystem:       Mise,
		DisplayName:     "mise",
		Description:     "mise-en-place dev toolchains (mise.toml)",
		Capabilities:    CapInventory | CapSBOM,
		Aliases:         []string{"mise-en-place", "rtx"},
		ScalibrPrefixes: []string{"mise"},
		Manifests:       []string{"mise.toml", ".mise.toml", "mise.local.toml", ".config/mise/config.toml"},
		Lockfiles:       []string{"mise.lock"},
		UpstreamURL:     "https://mise.jdx.dev",
		OSVName:         "",
		Absent:          []Projection{ProjectionOSVName},
		PURLType:        purlx.TypeMise,
	})

	r.Register(Registration{
		Ecosystem:       Asdf,
		DisplayName:     "asdf",
		Description:     "asdf dev toolchains (.tool-versions)",
		Capabilities:    CapInventory | CapSBOM,
		Aliases:         []string{"tool-versions"},
		ScalibrPrefixes: []string{"asdf"},
		Manifests:       []string{".tool-versions"},
		Lockfiles:       nil,
		UpstreamURL:     "https://asdf-vm.com",
		OSVName:         "",
		Absent:          []Projection{ProjectionOSVName},
		PURLType:        purlx.TypeAsdf,
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
