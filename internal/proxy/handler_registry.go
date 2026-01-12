package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/picatz/deputy/internal/ecosystem"
)

// PathParseResult holds the parsed components from an ecosystem-specific URL path.
type PathParseResult struct {
	Name      string
	Version   string
	Operation string
	FileType  string // optional, used by Go proxy
	Filename  string // optional, used by PyPI
	Error     error  // optional, for paths that fail validation
}

// PathParser is a function that parses an ecosystem-specific URL path
// into its component parts (name, version, operation, etc.).
type PathParser func(path string) PathParseResult

// EcosystemConfig defines the configuration for a proxy handler of a specific ecosystem.
// Ecosystem metadata (entrypoint names, license lookup preferences) is derived from
// the Ecosystem type itself, keeping this config focused on handler-specific concerns.
type EcosystemConfig struct {
	// Ecosystem is the canonical ecosystem identifier.
	Ecosystem ecosystem.Ecosystem

	// PathParser extracts request information from URL paths.
	PathParser PathParser
}

// ecosystemRegistry holds the configurations for all supported ecosystems.
var ecosystemRegistry = map[ecosystem.Ecosystem]EcosystemConfig{
	ecosystem.NPM: {
		Ecosystem:  ecosystem.NPM,
		PathParser: wrapNPMParser,
	},
	ecosystem.PyPI: {
		Ecosystem:  ecosystem.PyPI,
		PathParser: wrapPyPIParser,
	},
	ecosystem.Go: {
		Ecosystem:  ecosystem.Go,
		PathParser: wrapGoParser,
	},
	ecosystem.RubyGems: {
		Ecosystem:  ecosystem.RubyGems,
		PathParser: wrapRubyGemsParser,
	},
}

// Wrapper functions adapt existing parsers to the PathParser signature.

func wrapNPMParser(path string) PathParseResult {
	pkg, version, operation := parseNPMPath(path)
	return PathParseResult{
		Name:      pkg,
		Version:   version,
		Operation: operation,
	}
}

func wrapPyPIParser(path string) PathParseResult {
	pkg, version, filename, operation := parsePyPIPath(path)
	return PathParseResult{
		Name:      pkg,
		Version:   version,
		Operation: operation,
		Filename:  filename,
	}
}

func wrapGoParser(path string) PathParseResult {
	module, version, fileType, operation, err := parseGoProxyPath(path)
	return PathParseResult{
		Name:      module,
		Version:   version,
		Operation: operation,
		FileType:  fileType,
		Error:     err,
	}
}

func wrapRubyGemsParser(path string) PathParseResult {
	name, version, operation := parseRubyGemsPath(path)
	return PathParseResult{
		Name:      name,
		Version:   version,
		Operation: operation,
	}
}

// genericHandler is an ecosystem-agnostic proxy handler that uses configuration
// to determine behavior.
type genericHandler struct {
	*baseHandler
	config EcosystemConfig
}

// ServeHTTP handles incoming requests by parsing the path using the configured
// parser and delegating to the base handler for policy evaluation and proxying.
func (h *genericHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parsed := h.config.PathParser(r.URL.Path)

	// Handle parse errors (currently only Go proxy has validation)
	if parsed.Error != nil {
		http.Error(w, "bad request: "+parsed.Error.Error(), http.StatusBadRequest)
		return
	}

	info := requestInfo{
		Name:       parsed.Name,
		Version:    parsed.Version,
		HasVersion: strings.TrimSpace(parsed.Version) != "",
		Operation:  parsed.Operation,
		Ecosystem:  string(h.config.Ecosystem),
		FileType:   parsed.FileType,
		Filename:   parsed.Filename,
	}

	payload := h.buildPayload(r.Context(), info, r.URL.Path)
	h.serve(w, r, h.config.Ecosystem.ProxyEntrypoint(), info, payload)
}

// HandlerFactory creates ecosystem-specific proxy handlers using the registry.
type HandlerFactory struct {
	mu       sync.RWMutex
	registry map[ecosystem.Ecosystem]EcosystemConfig
}

// NewHandlerFactory creates a factory with the default ecosystem registry.
func NewHandlerFactory() *HandlerFactory {
	return &HandlerFactory{
		registry: ecosystemRegistry,
	}
}

// Register adds or updates an ecosystem configuration in the factory.
// This allows extending the factory with custom ecosystems.
func (f *HandlerFactory) Register(config EcosystemConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.registry == nil {
		f.registry = make(map[ecosystem.Ecosystem]EcosystemConfig)
	}
	f.registry[config.Ecosystem] = config
}

// CreateHandler creates a proxy handler for the specified ecosystem.
func (f *HandlerFactory) CreateHandler(eco ecosystem.Ecosystem, upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return f.CreateHandlerWithOptions(eco, upstream, policies, nil)
}

// HandlerOptions provides optional configuration for handler creation.
type HandlerOptions struct {
	// OSVCache overrides the default OSV vulnerability cache.
	OSVCache OSVCache
	// LicenseCache overrides the default license cache.
	LicenseCache LicenseCache
	// ListenerName is the name of the listener, used for cache scoping.
	ListenerName string
	// PolicyPaths are the policy files, used to compute a hash for cache scoping.
	PolicyPaths []string
}

// CreateHandlerWithOptions creates a proxy handler with custom options.
//
// When ListenerName or PolicyPaths are provided, caches will be scoped to prevent
// cross-tenant cache poisoning. Per-request tenant isolation is handled by
// wrapping caches with request-scoped keys based on JWT claims.
func (f *HandlerFactory) CreateHandlerWithOptions(eco ecosystem.Ecosystem, upstream string, policies PolicyEvaluator, opts *HandlerOptions) (http.Handler, error) {
	f.mu.RLock()
	config, ok := f.registry[eco]
	f.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unsupported ecosystem: %s", eco)
	}

	baseCfg := handlerConfig{
		ecosystem:    string(config.Ecosystem),
		osvEcosystem: config.Ecosystem.OSVName(),
		upstream:     upstream,
		policies:     policies,
		wantLicenses: ecosystem.HasLicenseSupport(config.Ecosystem),
	}

	if opts != nil {
		// Build base scope from listener/policy configuration.
		// Tenant ID is added dynamically per-request by the handler.
		baseScope := CacheScope{
			ListenerName: opts.ListenerName,
			PolicyHash:   HashPolicyPaths(opts.PolicyPaths),
		}

		// Apply scoping to provided caches, or create scoped defaults
		// Use RequestScoped*Cache for per-request tenant isolation (via JWT claims)
		if opts.OSVCache != nil {
			baseCfg.osvCache = NewRequestScopedOSVCache(baseScope, opts.OSVCache)
		} else if !baseScope.IsEmpty() {
			baseCfg.osvCache = NewRequestScopedOSVCache(baseScope, defaultOSVCache)
		}

		if opts.LicenseCache != nil {
			baseCfg.licenseCache = NewRequestScopedLicenseCache(baseScope, opts.LicenseCache)
		} else if !baseScope.IsEmpty() {
			baseCfg.licenseCache = NewRequestScopedLicenseCache(baseScope, defaultLicenseCache)
		}
	}

	base, err := newBaseHandler(baseCfg)
	if err != nil {
		return nil, err
	}

	return &genericHandler{
		baseHandler: base,
		config:      config,
	}, nil
}

// SupportedEcosystems returns a list of all ecosystems supported by the factory.
func (f *HandlerFactory) SupportedEcosystems() []ecosystem.Ecosystem {
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]ecosystem.Ecosystem, 0, len(f.registry))
	for eco := range f.registry {
		result = append(result, eco)
	}
	return result
}

// DefaultFactory is the default handler factory instance.
var DefaultFactory = NewHandlerFactory()

// NewHandler creates a proxy handler using the default factory.
// This is a convenience function for simple use cases.
func NewHandler(eco ecosystem.Ecosystem, upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return DefaultFactory.CreateHandler(eco, upstream, policies)
}

// NewHandlerFromString creates a proxy handler by parsing the ecosystem string.
func NewHandlerFromString(ecoString, upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return NewHandlerFromStringWithOptions(ecoString, upstream, policies, nil)
}

// NewHandlerFromStringWithOptions creates a proxy handler with options for cache scoping.
// This is the preferred constructor for production use as it enables cache isolation.
func NewHandlerFromStringWithOptions(ecoString, upstream string, policies PolicyEvaluator, opts *HandlerOptions) (http.Handler, error) {
	if strings.EqualFold(strings.TrimSpace(ecoString), "oci") {
		if opts != nil {
			return NewOCIHandlerWithOptions(upstream, policies, &OCIHandlerOptions{
				ListenerName: opts.ListenerName,
				PolicyPaths:  opts.PolicyPaths,
			})
		}
		return NewOCIHandler(upstream, policies)
	}
	eco := ecosystem.Parse(ecoString)
	if !eco.IsSupported() {
		return nil, fmt.Errorf("unknown ecosystem: %s", ecoString)
	}
	return DefaultFactory.CreateHandlerWithOptions(eco, upstream, policies, opts)
}
