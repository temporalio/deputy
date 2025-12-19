package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"golang.org/x/oauth2"
)

// This file provides adapters to integrate the auth package with common
// Go authentication interfaces:
//
//   - oauth2.TokenSource for HTTP clients (GitHub API, etc.)
//   - transport.AuthMethod for go-git operations
//   - http.RoundTripper for custom HTTP clients

// =============================================================================
// oauth2.TokenSource Adapter
// =============================================================================

// TokenSource returns an oauth2.TokenSource for the given host.
// This is useful for creating authenticated HTTP clients using oauth2.NewClient.
//
//	client := oauth2.NewClient(ctx, ts)
//	// Use client for GitHub API calls
func (s *Store) TokenSource(ctx context.Context, host string) (oauth2.TokenSource, error) {
	scope := Scope{Host: host, Hint: "api"}
	cred, err := s.Lookup(ctx, scope)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, nil
	}

	return &storeTokenSource{
		store: s,
		host:  host,
		ctx:   ctx,
	}, nil
}

// storeTokenSource implements oauth2.TokenSource backed by a Store.
type storeTokenSource struct {
	store *Store
	host  string
	ctx   context.Context
}

// Token implements oauth2.TokenSource.
func (s *storeTokenSource) Token() (*oauth2.Token, error) {
	scope := Scope{Host: s.host, Hint: "api"}
	cred, err := s.store.Lookup(s.ctx, scope)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("%w for %s", ErrNoCredential, s.host)
	}

	// If the credential is expiring/expired, attempt refresh when supported.
	if expired(cred) {
		if rc, ok := cred.(RefreshableCredential); ok {
			newCred, rerr := rc.Refresh(s.ctx)
			if rerr != nil {
				return nil, fmt.Errorf("refresh credential: %w", rerr)
			}
			if newCred != nil {
				if !newCred.ValidForHost(s.host) {
					return nil, fmt.Errorf("%w: %s", ErrHostMismatch, s.host)
				}
				cred = newCred
			}
		} else {
			return nil, ErrCredentialExpired
		}
	}

	// Extract bearer token via interface.
	bp, ok := cred.(BearerTokenProvider)
	if !ok {
		return nil, fmt.Errorf("%w: %T cannot be converted to oauth2.Token", ErrUnsupportedCredentialType, cred)
	}

	// Extract expiry via Expirable interface if available.
	var expiry time.Time
	if e, ok := cred.(Expirable); ok {
		if t := e.ExpiresAt(); t != nil {
			expiry = *t
		}
	}

	return &oauth2.Token{
		AccessToken: bp.BearerToken(),
		TokenType:   "Bearer",
		Expiry:      expiry,
	}, nil
}

// =============================================================================
// http.RoundTripper Adapter
// =============================================================================

// RoundTripper returns an http.RoundTripper that adds authentication
// headers to requests. It wraps the given base transport (or http.DefaultTransport
// if nil) and adds credentials based on the request host.
//
// This is more flexible than oauth2.Transport because it:
//   - Supports per-host credential resolution
//   - Works with any credential type (token, basic auth, etc.)
//   - Enforces host matching to prevent credential leakage
//
// Example:
//
//	rt := store.RoundTripper(http.DefaultTransport)
//	client := &http.Client{Transport: rt}
func (s *Store) RoundTripper(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &authRoundTripper{
		store: s,
		base:  base,
	}
}

// authRoundTripper is an http.RoundTripper that adds authentication headers
// to outgoing requests based on the request host.
type authRoundTripper struct {
	store *Store
	base  http.RoundTripper
}

// RoundTrip implements [http.RoundTripper]. It clones the request,
// attempts to add authentication headers via [Store.ConfigureHTTPRequest],
// and then delegates to the base transport.
func (rt *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	// Clone request to avoid modifying the original
	req2 := req.Clone(ctx)

	// Try to add auth
	if err := rt.store.ConfigureHTTPRequest(ctx, req2); err != nil {
		if rt.store.strictAuthErrors {
			return nil, err
		}
		// Best-effort: log and continue without auth
		rt.store.logger.DebugContext(ctx, "auth configuration failed, continuing without auth",
			"host", req.URL.Host,
			"error", err.Error(),
		)
	}

	return rt.base.RoundTrip(req2)
}

// HTTPClient returns an *http.Client with authentication configured.
// The client will automatically add credentials based on request host.
func (s *Store) HTTPClient(base http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: s.RoundTripper(base),
	}
}

// =============================================================================
// go-git transport.AuthMethod Adapter
// =============================================================================

// GitAuthMethod implements transport.AuthMethod backed by a credential.
// This is what Store.GitAuth returns internally, but exposed for direct use.
type GitAuthMethod struct {
	cred Credential
	host string
}

// Name implements transport.AuthMethod.
func (g *GitAuthMethod) Name() string {
	switch {
	case isSSHCredential(g.cred):
		return "ssh-public-key"
	case implementsBasicAuth(g.cred):
		return "http-basic-auth"
	default:
		return "unknown"
	}
}

// isSSHCredential returns true if the credential is an SSH credential.
func isSSHCredential(c Credential) bool {
	_, ok := c.(*SSHCredential)
	return ok
}

// implementsBasicAuth returns true if the credential supports basic auth.
func implementsBasicAuth(c Credential) bool {
	_, ok := c.(BasicAuthProvider)
	return ok
}

// String implements transport.AuthMethod (via fmt.Stringer).
func (g *GitAuthMethod) String() string {
	return fmt.Sprintf("%s (host: %s)", g.Name(), g.host)
}

// ToTransportAuth converts to go-git's native auth types.
// This is called internally when the auth is actually used.
func (g *GitAuthMethod) ToTransportAuth() (transport.AuthMethod, error) {
	return credentialToGitAuth(g.cred, g.host)
}
