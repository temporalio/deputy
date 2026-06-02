package mise

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/BurntSushi/toml"

	"github.com/temporalio/deputy/internal/httputil"
)

const (
	// defaultMiseRegistryBaseURL is mise's canonical GitHub-hosted registry
	// source. The registry is embedded into mise at build time from this tree.
	defaultMiseRegistryBaseURL = "https://raw.githubusercontent.com/jdx/mise/main/registry"
	// defaultMiseRegistryTimeout bounds registry metadata requests.
	defaultMiseRegistryTimeout = 10 * time.Second
	// defaultMiseRegistryMaxBytes bounds a single registry tool TOML file.
	defaultMiseRegistryMaxBytes = 64 << 10
)

var (
	// errMiseRegistryToolNotFound marks a valid registry lookup for a tool that
	// does not exist in mise's registry source.
	errMiseRegistryToolNotFound = errors.New("mise registry tool not found")
	// errMiseRegistryNoNativeBackend marks a registry entry that Deputy can read
	// but cannot resolve through its native metadata sources.
	errMiseRegistryNoNativeBackend = errors.New("mise registry entry has no native backend")
)

// miseRegistryClient is the narrow registry lookup surface needed by the native
// resolver.
type miseRegistryClient interface {
	// Backends returns the full backend specs from a mise registry entry.
	Backends(ctx context.Context, name string) ([]string, error)
}

// miseRegistryHTTPClient fetches per-tool registry TOML files from mise's
// GitHub-hosted registry source.
type miseRegistryHTTPClient struct {
	baseURL    string
	httpClient *http.Client
	maxBytes   int64
	mu         sync.RWMutex
	cache      map[string][]string
}

// newMiseRegistryClient returns Deputy's default mise registry metadata client.
func newMiseRegistryClient() *miseRegistryHTTPClient {
	return &miseRegistryHTTPClient{
		baseURL:    defaultMiseRegistryBaseURL,
		httpClient: httputil.NewSafeRetryableClient(defaultMiseRegistryTimeout),
		maxBytes:   defaultMiseRegistryMaxBytes,
	}
}

// miseRegistryTool is the subset of a registry/<tool>.toml file that Deputy
// needs for native resolution.
type miseRegistryTool struct {
	Backends miseRegistryBackends `toml:"backends"`
}

// miseRegistryBackends decodes mise registry backend entries. The registry uses
// both plain strings and inline tables with a full field.
type miseRegistryBackends []string

// UnmarshalTOML decodes mise registry backend strings from TOML.
func (b *miseRegistryBackends) UnmarshalTOML(data any) error {
	backends, err := registryBackendStrings(data)
	if err != nil {
		return err
	}
	*b = backends
	return nil
}

// Backends returns full backend specs for name from the mise registry.
func (c *miseRegistryHTTPClient) Backends(ctx context.Context, name string) ([]string, error) {
	file, ok := miseRegistryToolFile(name)
	if !ok {
		return nil, fmt.Errorf("%w: %s", errMiseRegistryToolNotFound, name)
	}

	c.mu.RLock()
	if backends, ok := c.cache[file]; ok {
		c.mu.RUnlock()
		return append([]string(nil), backends...), nil
	}
	c.mu.RUnlock()

	baseURL := cmp.Or(strings.TrimSpace(c.baseURL), defaultMiseRegistryBaseURL)
	endpoint, err := url.JoinPath(baseURL, file)
	if err != nil {
		return nil, fmt.Errorf("building mise registry URL: %w", err)
	}
	httpClient := cmp.Or(c.httpClient, httputil.NewSafeRetryableClient(defaultMiseRegistryTimeout))
	maxBytes := cmp.Or(c.maxBytes, int64(defaultMiseRegistryMaxBytes))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating mise registry request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching mise registry entry %q: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", errMiseRegistryToolNotFound, name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching mise registry entry %q: status %d", name, resp.StatusCode)
	}

	var tool miseRegistryTool
	if _, err := toml.NewDecoder(io.LimitReader(resp.Body, maxBytes)).Decode(&tool); err != nil {
		return nil, fmt.Errorf("decoding mise registry entry %q: %w", name, err)
	}
	backends := cleanRegistryBackends(tool.Backends)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[string][]string{}
	}
	// Re-check under the write lock: a racing caller may have populated this
	// entry while we were fetching. Concurrent first-fetches can both hit the
	// network (serializing the fetch would be worse than a rare duplicate
	// request), but the cache write stays idempotent and callers get a copy.
	if existing, ok := c.cache[file]; ok {
		return append([]string(nil), existing...), nil
	}
	c.cache[file] = append([]string(nil), backends...)
	return backends, nil
}

// cleanRegistryBackends trims empty backend entries while preserving registry
// order, which is mise's backend preference order.
func cleanRegistryBackends(backends []string) []string {
	cleaned := make([]string, 0, len(backends))
	for _, backend := range backends {
		if backend = strings.TrimSpace(backend); backend != "" {
			cleaned = append(cleaned, backend)
		}
	}
	return cleaned
}

// registryBackendStrings normalizes a mise registry backends value to full
// backend strings.
func registryBackendStrings(data any) ([]string, error) {
	switch data := data.(type) {
	case []any:
		backends := make([]string, 0, len(data))
		for _, item := range data {
			backend, ok, err := registryBackendString(item)
			if err != nil {
				return nil, err
			}
			if ok {
				backends = append(backends, backend)
			}
		}
		return backends, nil
	case []map[string]any:
		backends := make([]string, 0, len(data))
		for _, item := range data {
			backend, ok, err := registryBackendString(item)
			if err != nil {
				return nil, err
			}
			if ok {
				backends = append(backends, backend)
			}
		}
		return backends, nil
	case []string:
		return append([]string(nil), data...), nil
	case string:
		return []string{data}, nil
	default:
		return nil, fmt.Errorf("unsupported mise registry backends type %T", data)
	}
}

// registryBackendString extracts one full backend string from a registry
// backend entry.
func registryBackendString(data any) (string, bool, error) {
	switch data := data.(type) {
	case string:
		return data, true, nil
	case map[string]any:
		full, ok := data["full"]
		if !ok {
			return "", false, nil
		}
		value, ok := full.(string)
		if !ok {
			return "", false, fmt.Errorf("unsupported mise registry backend full type %T", full)
		}
		return value, true, nil
	default:
		return "", false, fmt.Errorf("unsupported mise registry backend entry type %T", data)
	}
}

// miseRegistryToolFile returns the registry filename for a bare mise tool name.
func miseRegistryToolFile(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, "/\\:") {
		return "", false
	}
	for _, r := range name {
		if unicode.IsLower(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", false
	}
	if alias := miseRegistryAliases[name]; alias != "" {
		name = alias
	}
	return name + ".toml", true
}

// miseRegistryAliases maps common mise tool aliases to their canonical registry
// filenames.
var miseRegistryAliases = map[string]string{
	"1password-cli": "1password",
	"aws":           "aws-cli",
	"awscli":        "aws-cli",
	"azure-cli":     "azure",
	"op":            "1password",
}
