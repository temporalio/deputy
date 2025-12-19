package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

// Store is the central credential store for Deputy.
// It provides a unified interface for credential lookup with host-aware
// security to prevent credential leakage.
type Store struct {
	mu       sync.RWMutex
	provider Provider
	logger   *slog.Logger

	// requireHTTPS prevents sending credentials over non-HTTPS connections.
	// Defaults to true.
	requireHTTPS bool

	// strictAuthErrors controls whether auth application errors are returned
	// from HTTP configuration helpers (e.g., RoundTripper). When false (default),
	// auth errors are logged (debug) and the request proceeds without auth.
	strictAuthErrors bool
}

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithProvider sets the credential provider chain.
func WithProvider(p Provider) StoreOption {
	return func(s *Store) {
		s.provider = p
	}
}

// WithoutHTTPSRequirement disables the HTTPS requirement for credentials.
// Use with caution - only for testing or known-safe local networks.
func WithoutHTTPSRequirement() StoreOption {
	return func(s *Store) {
		s.requireHTTPS = false
	}
}

// WithStrictAuthErrors causes HTTP auth application failures to be returned
// to the caller (e.g., RoundTripper.RoundTrip). By default, errors are logged
// at debug level and the request continues without credentials.
func WithStrictAuthErrors() StoreOption {
	return func(s *Store) {
		s.strictAuthErrors = true
	}
}

// WithLogger sets a structured logger for observability.
// If not set, a no-op logger is used.
func WithLogger(logger *slog.Logger) StoreOption {
	return func(s *Store) {
		s.logger = logger
	}
}

// NewStore creates a credential store with the given options.
func NewStore(opts ...StoreOption) *Store {
	s := &Store{
		provider:     NullProvider{},
		requireHTTPS: true,
		logger:       slog.New(discardHandler{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// discardHandler is a slog.Handler that discards all records.
// It is used as a no-op logger when no logger is configured.
type discardHandler struct{}

// Enabled implements [slog.Handler]. Always returns false.
func (discardHandler) Enabled(context.Context, slog.Level) bool { return false }

// Handle implements [slog.Handler]. Discards the record.
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }

// WithAttrs implements [slog.Handler]. Returns itself unchanged.
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler { return d }

// WithGroup implements [slog.Handler]. Returns itself unchanged.
func (d discardHandler) WithGroup(string) slog.Handler { return d }

// DefaultStore creates a Store with sensible defaults:
// - Environment variables (standard conventions)
// - Docker config for container registries (if available)
func DefaultStore() *Store {
	chain := NewChainProvider(
		NewEnvProvider(),
	)
	return NewStore(WithProvider(chain))
}

// GitAuthForURL is a convenience function that creates a default store and
// returns a go-git transport.AuthMethod for the given URL. It uses environment
// variables to find credentials.
//
// This is a shorthand for:
//
//	store := auth.DefaultStore()
//	gitAuth, err := store.GitAuth(ctx, rawURL)
//
// If no credentials are found or an error occurs, it returns nil, nil (safe
// to pass directly to go-git). This makes it ideal for best-effort auth where
// public repos should still work without credentials.
func GitAuthForURL(ctx context.Context, rawURL string) (transport.AuthMethod, error) {
	return DefaultStore().GitAuth(ctx, rawURL)
}

// Logger returns the store's configured logger.
func (s *Store) Logger() *slog.Logger {
	return s.logger
}

// Lookup retrieves a credential for the given scope.
// Returns nil, nil if no credential is found.
func (s *Store) Lookup(ctx context.Context, scope Scope) (Credential, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	provider := s.provider
	s.mu.RUnlock()

	cred, err := provider.Lookup(ctx, scope)
	if err != nil {
		s.logger.DebugContext(ctx, "credential lookup failed",
			slog.String("host", scope.Host),
			slog.String("hint", scope.Hint),
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("lookup credential for %s: %w", scope.Host, err)
	}

	// Validate the credential is actually valid for this host
	if cred != nil && !cred.ValidForHost(scope.Host) {
		s.logger.WarnContext(ctx, "credential host mismatch",
			slog.String("host", scope.Host),
			slog.String("credential", cred.Redacted()),
		)
		return nil, fmt.Errorf("%w: %s", ErrHostMismatch, scope.Host)
	}

	if cred != nil {
		s.logger.DebugContext(ctx, "credential found",
			slog.String("host", scope.Host),
			slog.String("hint", scope.Hint),
			slog.String("type", string(cred.Type())),
		)
	}

	return cred, nil
}

// GitAuth returns a go-git transport.AuthMethod for the given URL.
// This is the primary method for Git operations (clone, fetch, push).
//
// The URL is parsed to extract the host and determine the appropriate
// authentication method. Returns nil if no credentials are available.
func (s *Store) GitAuth(ctx context.Context, rawURL string) (transport.AuthMethod, error) {
	host := extractHost(rawURL)
	if host == "" {
		return nil, fmt.Errorf("cannot extract host from URL: %s", rawURL)
	}

	scope := Scope{
		Host: host,
		Hint: "git",
	}

	cred, err := s.Lookup(ctx, scope)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, nil
	}

	return credentialToGitAuth(cred, host)
}

// HTTPBearerToken returns a bearer token for HTTP Authorization headers.
// Returns empty string if no token is available for the host.
func (s *Store) HTTPBearerToken(ctx context.Context, host string) (string, error) {
	scope := Scope{
		Host: host,
		Hint: "api",
	}

	cred, err := s.Lookup(ctx, scope)
	if err != nil {
		return "", err
	}
	if cred == nil {
		return "", nil
	}

	if bp, ok := cred.(BearerTokenProvider); ok {
		return bp.BearerToken(), nil
	}
	return "", fmt.Errorf("%w: %T cannot provide bearer token", ErrUnsupportedCredentialType, cred)
}

// HTTPBasicAuth returns username/password for HTTP Basic Authentication.
func (s *Store) HTTPBasicAuth(ctx context.Context, host string) (username, password string, err error) {
	scope := Scope{
		Host: host,
		Hint: "api",
	}

	cred, err := s.Lookup(ctx, scope)
	if err != nil {
		return "", "", err
	}
	if cred == nil {
		return "", "", nil
	}

	if ba, ok := cred.(BasicAuthProvider); ok {
		u, p := ba.BasicAuth()
		return u, p, nil
	}
	return "", "", fmt.Errorf("%w: %T cannot provide basic auth", ErrUnsupportedCredentialType, cred)
}

// ConfigureHTTPRequest adds authentication to an HTTP request.
// The host is extracted from the request URL and credentials are applied
// only if valid for that specific host.
func (s *Store) ConfigureHTTPRequest(ctx context.Context, req *http.Request) error {
	if req.URL == nil {
		return fmt.Errorf("request has no URL")
	}

	host := req.URL.Host
	if host == "" {
		return fmt.Errorf("request URL has no host")
	}

	// Enforce HTTPS requirement
	if s.requireHTTPS && req.URL.Scheme != "https" {
		return nil // Don't add credentials to non-HTTPS requests
	}

	scope := Scope{
		Host: host,
		Hint: "api",
	}

	cred, err := s.Lookup(ctx, scope)
	if err != nil {
		return err
	}
	if cred == nil {
		return nil
	}

	// Prefer bearer token if available, otherwise try basic auth.
	if bp, ok := cred.(BearerTokenProvider); ok {
		req.Header.Set("Authorization", "Bearer "+bp.BearerToken())
		return nil
	}
	if ba, ok := cred.(BasicAuthProvider); ok {
		u, p := ba.BasicAuth()
		req.SetBasicAuth(u, p)
		return nil
	}

	return fmt.Errorf("%w: %T cannot be used for HTTP request", ErrUnsupportedCredentialType, cred)
}

// ContainerAuth returns credentials for a container registry.
func (s *Store) ContainerAuth(ctx context.Context, registry string) (*DockerCredential, error) {
	host := extractHost(registry)
	if host == "" {
		return nil, fmt.Errorf("cannot extract host from registry: %s", registry)
	}

	scope := Scope{
		Host: host,
		Hint: "container",
	}

	cred, err := s.Lookup(ctx, scope)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, nil
	}

	switch c := cred.(type) {
	case *DockerCredential:
		return c, nil
	case *BasicCredential:
		return &DockerCredential{
			Username:      c.Username,
			Password:      c.Password,
			ServerAddress: registry,
			Source:        c.Source,
		}, nil
	case *TokenCredential:
		return &DockerCredential{
			Username:      "oauth2",
			Password:      c.Token,
			ServerAddress: registry,
			Source:        c.Source,
		}, nil
	default:
		return nil, fmt.Errorf("%w: %T cannot be used for container registry", ErrUnsupportedCredentialType, cred)
	}
}

// LLMAPIKey returns an API key for an LLM provider.
func (s *Store) LLMAPIKey(ctx context.Context, host string) (string, error) {
	scope := Scope{Host: host, Hint: "llm"}
	cred, err := s.Lookup(ctx, scope)
	if err != nil {
		return "", err
	}
	if cred == nil {
		return "", nil
	}
	if bp, ok := cred.(BearerTokenProvider); ok {
		return bp.BearerToken(), nil
	}
	return "", fmt.Errorf("%w: %T cannot provide bearer token", ErrUnsupportedCredentialType, cred)
}

// credentialToGitAuth converts a Credential to a go-git AuthMethod.
func credentialToGitAuth(cred Credential, host string) (transport.AuthMethod, error) {
	// SSH credentials need special handling.
	if c, ok := cred.(*SSHCredential); ok {
		return sshCredentialToGitAuth(c)
	}

	// For HTTP-based auth, prefer BasicAuthProvider.
	if ba, ok := cred.(BasicAuthProvider); ok {
		u, p := ba.BasicAuth()
		// If username is generic "oauth2", try to use host-specific convention.
		if u == "oauth2" {
			u = tokenUsernameForHost(host)
		}
		return &githttp.BasicAuth{
			Username: u,
			Password: p,
		}, nil
	}

	return nil, fmt.Errorf("%w: %T cannot be used for Git auth", ErrUnsupportedCredentialType, cred)
}

// sshCredentialToGitAuth converts an SSHCredential to a go-git AuthMethod.
func sshCredentialToGitAuth(c *SSHCredential) (transport.AuthMethod, error) {
	if c.PrivateKeyPath != "" {
		auth, err := gitssh.NewPublicKeysFromFile(c.User, c.PrivateKeyPath, c.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("load SSH key from %s: %w", c.PrivateKeyPath, err)
		}
		return auth, nil
	}
	if len(c.PrivateKey) > 0 {
		auth, err := gitssh.NewPublicKeys(c.User, c.PrivateKey, c.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("parse SSH key: %w", err)
		}
		return auth, nil
	}
	return nil, fmt.Errorf("SSH credential has no key")
}

// tokenUsernameForHost returns the appropriate username for token auth.
// Different services expect different "dummy" usernames for token auth.
func tokenUsernameForHost(host string) string {
	host = normalizeHost(host)

	switch {
	case host == "github.com" || host == "api.github.com":
		return "oauth2" // GitHub convention
	case host == "gitlab.com" || matchHost(host, "*.gitlab.com"):
		return "oauth2" // GitLab convention
	case host == "bitbucket.org":
		return "x-token-auth" // Bitbucket convention
	default:
		return "x-access-token" // Common fallback
	}
}
