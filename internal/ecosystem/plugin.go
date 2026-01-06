// Package ecosystem plugin support is built on OSV-SCALIBR.
//
// Deputy uses OSV-SCALIBR (https://github.com/google/osv-scalibr) for inventory
// extraction. To add support for a new ecosystem, implement a SCALIBR filesystem
// extractor rather than a custom plugin interface.
//
// # SCALIBR Extractor Interface
//
// SCALIBR extractors implement [github.com/google/osv-scalibr/extractor/filesystem.Extractor]:
//
//	type Extractor interface {
//	    plugin.Plugin
//	    FileRequired(api FileAPI) bool
//	    Extract(ctx context.Context, input *ScanInput) (inventory.Inventory, error)
//	}
//
// The base [github.com/google/osv-scalibr/plugin.Plugin] interface requires:
//
//	type Plugin interface {
//	    Name() string
//	    Version() int
//	    Requirements() *Capabilities
//	}
//
// # Adding a New Ecosystem Extractor
//
// 1. Create a package under internal/inventory/plugins/<ecosystem>/
// 2. Implement filesystem.Extractor
// 3. Register in internal/inventory/inventory.go's resolvePlugins()
//
// See existing implementations:
//   - internal/inventory/plugins/github/actionsx/actions.go (GitHub Actions)
//   - internal/inventory/plugins/docker/dockerfilex/dockerfile.go (Dockerfile)
//   - internal/inventory/plugins/ruby/gemspecx/gemspec.go (Ruby gemspec)
//
// # Proxy Support
//
// Proxy handlers are separate from inventory extraction. To add proxy support
// for an ecosystem, implement a handler in internal/proxy/ following the
// pattern of gomod.go, npm.go, pypi.go, and rubygems.go.
//
// # This Package
//
// This file provides optional higher-level abstractions for ecosystems that
// want additional Deputy-specific capabilities beyond what SCALIBR provides.
// These are purely optional - SCALIBR extractors work without them.
package ecosystem

import (
	"context"
	"net/http"

	"github.com/google/osv-scalibr/extractor/filesystem"
)

// ExtractorPlugin extends a SCALIBR extractor with Deputy-specific capabilities.
// This is optional - SCALIBR extractors work without implementing this interface.
// Use this when you need proxy support or other Deputy-specific features.
type ExtractorPlugin interface {
	filesystem.Extractor

	// Ecosystem returns the canonical ecosystem identifier (e.g., "go", "npm").
	Ecosystem() Ecosystem

	// OSVEcosystem returns the ecosystem name as used by OSV (e.g., "Go", "npm", "PyPI").
	OSVEcosystem() string
}

// ProxyHandler defines proxy support for an ecosystem.
// Implement this interface to enable download-time policy enforcement.
// This is separate from inventory extraction (SCALIBR extractors).
type ProxyHandler interface {
	// Ecosystem returns the canonical ecosystem identifier.
	Ecosystem() Ecosystem

	// DefaultUpstream returns the default upstream registry URL.
	DefaultUpstream() string

	// ParseRequest extracts package information from an HTTP request.
	ParseRequest(r *http.Request) (ProxyRequestInfo, error)

	// ServeProxy handles the proxy request after policy evaluation passes.
	ServeProxy(w http.ResponseWriter, r *http.Request, upstream string) error
}

// ProxyRequestInfo contains parsed information from a proxy request.
type ProxyRequestInfo struct {
	// Name is the package name being requested.
	Name string

	// Version is the requested version, if specified.
	Version string

	// HasVersion indicates whether a specific version was requested.
	HasVersion bool

	// Operation describes what kind of request this is (e.g., "download", "metadata").
	Operation string
}

// LicenseLookup provides license information for packages.
// Implement this for ecosystems where deps.dev or other sources provide license data.
type LicenseLookup interface {
	// Ecosystem returns the canonical ecosystem identifier.
	Ecosystem() Ecosystem

	// LookupLicense retrieves license information for a package.
	// Returns a list of SPDX license identifiers.
	LookupLicense(ctx context.Context, name, version string) ([]string, error)
}

// proxyRegistry holds registered proxy handlers.
var proxyRegistry = make(map[Ecosystem]ProxyHandler)

// RegisterProxyHandler registers a proxy handler for an ecosystem.
// Panics if a handler for the ecosystem is already registered.
func RegisterProxyHandler(h ProxyHandler) {
	eco := h.Ecosystem()
	if _, exists := proxyRegistry[eco]; exists {
		panic("ecosystem: duplicate proxy handler: " + string(eco))
	}
	proxyRegistry[eco] = h
}

// GetProxyHandler returns the proxy handler for an ecosystem, or nil if none.
func GetProxyHandler(eco Ecosystem) ProxyHandler {
	return proxyRegistry[eco]
}

// HasProxySupport returns true if the ecosystem has proxy support registered.
func HasProxySupport(eco Ecosystem) bool {
	return proxyRegistry[eco] != nil
}

// AllProxyHandlers returns all registered proxy handlers.
func AllProxyHandlers() []ProxyHandler {
	handlers := make([]ProxyHandler, 0, len(proxyRegistry))
	for _, h := range proxyRegistry {
		handlers = append(handlers, h)
	}
	return handlers
}

// ProxySupportedEcosystems returns ecosystems with proxy support.
func ProxySupportedEcosystems() []Ecosystem {
	ecosystems := make([]Ecosystem, 0, len(proxyRegistry))
	for eco := range proxyRegistry {
		ecosystems = append(ecosystems, eco)
	}
	return ecosystems
}
