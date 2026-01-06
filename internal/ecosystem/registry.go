// Package ecosystem registry provides a unified view of ecosystem capabilities.
//
// This file introduces a Registry that ties together the various ecosystem
// capabilities (inventory, graph resolution, proxy) into a single queryable
// structure. This is designed to evolve toward a plugin-based architecture
// where ecosystems can be registered dynamically.

package ecosystem

import (
	"sync"
)

// Capability represents a feature an ecosystem may support.
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
)

// Registration describes an ecosystem's capabilities.
type Registration struct {
	// Ecosystem is the canonical ecosystem identifier.
	Ecosystem Ecosystem

	// Capabilities is a bitmask of supported features.
	Capabilities Capability

	// Aliases are alternative names that map to this ecosystem.
	Aliases []string

	// ScalibrPrefixes are the OSV-SCALIBR plugin name prefixes for inventory.
	ScalibrPrefixes []string
}

// HasCapability returns true if the registration includes the given capability.
func (r Registration) HasCapability(cap Capability) bool {
	return r.Capabilities&cap != 0
}

// Registry holds ecosystem registrations and provides lookup methods.
type Registry struct {
	mu            sync.RWMutex
	byEcosystem   map[Ecosystem]*Registration
	byAlias       map[string]*Registration
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

// All returns all registered ecosystems.
func (r *Registry) All() []Registration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Registration, 0, len(r.byEcosystem))
	for _, reg := range r.byEcosystem {
		result = append(result, *reg)
	}
	return result
}

// registerDefaults populates the registry with built-in ecosystem definitions.
func (r *Registry) registerDefaults() {
	// Go: Full support
	r.Register(Registration{
		Ecosystem:       Go,
		Capabilities:    CapInventory | CapGraph | CapProxy | CapLicense | CapFix,
		Aliases:         []string{"golang"},
		ScalibrPrefixes: []string{"go"},
	})

	// npm: Full support
	r.Register(Registration{
		Ecosystem:       NPM,
		Capabilities:    CapInventory | CapGraph | CapProxy | CapLicense,
		Aliases:         []string{"javascript", "node", "nodejs"},
		ScalibrPrefixes: []string{"javascript"},
	})

	// PyPI: Graph and proxy support
	r.Register(Registration{
		Ecosystem:       PyPI,
		Capabilities:    CapInventory | CapGraph | CapProxy,
		Aliases:         []string{"python", "pip"},
		ScalibrPrefixes: []string{"python"},
	})

	// RubyGems: Graph and proxy support
	r.Register(Registration{
		Ecosystem:       RubyGems,
		Capabilities:    CapInventory | CapGraph | CapProxy,
		Aliases:         []string{"ruby", "gem", "gems"},
		ScalibrPrefixes: []string{"ruby"},
	})

	// Cargo: Graph support
	r.Register(Registration{
		Ecosystem:       Cargo,
		Capabilities:    CapInventory | CapGraph,
		Aliases:         []string{"rust", "crates", "crates.io"},
		ScalibrPrefixes: []string{"rust"},
	})

	// Maven: Inventory only (graph resolution in progress)
	r.Register(Registration{
		Ecosystem:       Maven,
		Capabilities:    CapInventory | CapGraph,
		Aliases:         []string{"java"},
		ScalibrPrefixes: []string{"java"},
	})

	// NuGet: Inventory and graph support
	r.Register(Registration{
		Ecosystem:       NuGet,
		Capabilities:    CapInventory | CapGraph,
		Aliases:         []string{"dotnet", ".net"},
		ScalibrPrefixes: []string{"dotnet"},
	})

	// Hex: Inventory and graph support
	r.Register(Registration{
		Ecosystem:       Hex,
		Capabilities:    CapInventory | CapGraph,
		Aliases:         []string{"hexpm", "elixir", "erlang"},
		ScalibrPrefixes: []string{"elixir", "erlang"},
	})

	// Pub: Inventory and graph support
	r.Register(Registration{
		Ecosystem:       Pub,
		Capabilities:    CapInventory | CapGraph,
		Aliases:         []string{"dart", "flutter"},
		ScalibrPrefixes: []string{"dart"},
	})

	// CocoaPods: Inventory only
	r.Register(Registration{
		Ecosystem:       CocoaPods,
		Capabilities:    CapInventory,
		Aliases:         []string{"pod", "pods", "swift", "ios"},
		ScalibrPrefixes: []string{"swift"},
	})

	// Packagist: Inventory only
	r.Register(Registration{
		Ecosystem:       Packagist,
		Capabilities:    CapInventory,
		Aliases:         []string{"composer", "php"},
		ScalibrPrefixes: []string{"php"},
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
	reg := Default().Lookup(string(eco))
	return reg != nil && reg.HasCapability(CapGraph)
}

// HasProxySupport returns true if the ecosystem has proxy support.
// This is a convenience wrapper around the registry lookup.
func HasProxySupportFor(eco Ecosystem) bool {
	reg := Default().Lookup(string(eco))
	return reg != nil && reg.HasCapability(CapProxy)
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
