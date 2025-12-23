package proxy

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/picatz/jose/pkg/jwk"
)

const (
	defaultJWKSRefreshInterval = 1 * time.Hour
	defaultJWKSCacheDuration   = 24 * time.Hour
	defaultJWKSHTTPTimeout     = 10 * time.Second
	minJWKSRefreshInterval     = 5 * time.Minute
)

// JWKSCache manages JWKS key sets with background refresh.
type JWKSCache struct {
	url             string
	oidcDiscovery   bool
	refreshInterval time.Duration

	mu          sync.RWMutex
	keySet      *jwk.Set
	lastRefresh time.Time
	lastError   error

	httpClient *http.Client
	stopCh     chan struct{}
	wg         sync.WaitGroup
	closeOnce  sync.Once
}

// NewJWKSCache creates a new JWKS cache with the given configuration.
func NewJWKSCache(cfg *JWKSConfig) (*JWKSCache, error) {
	if cfg == nil || cfg.URL == "" {
		return nil, fmt.Errorf("JWKS URL is required")
	}

	refreshInterval := cfg.RefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = defaultJWKSRefreshInterval
	}
	if refreshInterval < minJWKSRefreshInterval {
		refreshInterval = minJWKSRefreshInterval
	}

	cache := &JWKSCache{
		url:             cfg.URL,
		oidcDiscovery:   cfg.OIDCDiscovery,
		refreshInterval: refreshInterval,
		httpClient: &http.Client{
			Timeout: defaultJWKSHTTPTimeout,
		},
		stopCh: make(chan struct{}),
	}

	// Resolve JWKS URL from OIDC discovery if needed
	if cfg.OIDCDiscovery {
		jwksURL, err := cache.discoverJWKSURL(context.Background())
		if err != nil {
			return nil, fmt.Errorf("OIDC discovery failed: %w", err)
		}
		cache.url = jwksURL
	}

	// Initial fetch (blocking)
	ctx, cancel := context.WithTimeout(context.Background(), defaultJWKSHTTPTimeout)
	defer cancel()
	if err := cache.refresh(ctx); err != nil {
		return nil, fmt.Errorf("initial JWKS fetch failed: %w", err)
	}

	// Start background refresh
	cache.wg.Add(1)
	go cache.refreshLoop()

	return cache, nil
}

// GetKey returns the public key for the given key ID.
func (c *JWKSCache) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.keySet == nil {
		authMetrics.RecordJWKSKeyLookup(false)
		return nil, fmt.Errorf("no JWKS loaded")
	}

	keyValue, err := c.keySet.Get(kid)
	if err != nil {
		authMetrics.RecordJWKSKeyLookup(false)
		return nil, fmt.Errorf("key %q not found in JWKS: %w", kid, err)
	}

	authMetrics.RecordJWKSKeyLookup(true)
	return extractPublicKey(keyValue)
}

// ForceRefresh triggers an immediate refresh if min interval has passed.
func (c *JWKSCache) ForceRefresh(ctx context.Context) error {
	c.mu.RLock()
	elapsed := time.Since(c.lastRefresh)
	c.mu.RUnlock()

	if elapsed < minJWKSRefreshInterval {
		return nil // Too soon
	}

	return c.refresh(ctx)
}

// Close stops background refresh and releases resources.
// It is safe to call Close multiple times.
func (c *JWKSCache) Close() error {
	c.closeOnce.Do(func() {
		close(c.stopCh)
		c.wg.Wait()
	})
	return nil
}

// discoverJWKSURL fetches the JWKS URL from the OIDC discovery endpoint.
func (c *JWKSCache) discoverJWKSURL(ctx context.Context) (string, error) {
	discoveryURL := c.url
	if discoveryURL == "" {
		return "", fmt.Errorf("discovery URL is empty")
	}
	if discoveryURL[len(discoveryURL)-1] != '/' {
		discoveryURL += "/"
	}
	discoveryURL += ".well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", fmt.Errorf("decode OIDC config: %w", err)
	}

	if config.JWKSURI == "" {
		return "", fmt.Errorf("jwks_uri not found in OIDC configuration")
	}

	return config.JWKSURI, nil
}

// refresh fetches the JWKS from the remote endpoint.
func (c *JWKSCache) refresh(ctx context.Context) error {
	keySet, err := jwk.FetchSet(ctx, c.url, c.httpClient)
	if err != nil {
		authMetrics.RecordJWKSRefresh(false)
		c.mu.Lock()
		c.lastError = err
		c.mu.Unlock()
		return fmt.Errorf("fetch JWKS: %w", err)
	}

	authMetrics.RecordJWKSRefresh(true)
	c.mu.Lock()
	c.keySet = keySet
	c.lastRefresh = time.Now()
	c.lastError = nil
	c.mu.Unlock()

	slog.Debug("JWKS refreshed", "url", c.url, "keys", len(keySet.Keys))
	return nil
}

// refreshLoop runs background JWKS refresh.
func (c *JWKSCache) refreshLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), defaultJWKSHTTPTimeout)
			if err := c.refresh(ctx); err != nil {
				slog.WarnContext(ctx, "JWKS refresh failed", "url", c.url, "error", err)
			}
			cancel()
		}
	}
}

// extractPublicKey extracts a crypto.PublicKey from a JWK value.
func extractPublicKey(v jwk.Value) (crypto.PublicKey, error) {
	kty, ok := v[jwk.KeyType].(string)
	if !ok {
		return nil, fmt.Errorf("missing key type")
	}

	switch kty {
	case "RSA":
		pub, _, err := jwk.RSAPublicKey(v)
		return pub, err
	case "EC":
		pub, _, err := jwk.ECDSAPublicKey(v)
		return pub, err
	case "OKP":
		pub, err := jwk.Ed25519PublicKey(v)
		return pub, err
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}
