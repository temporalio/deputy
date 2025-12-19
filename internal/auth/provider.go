package auth

import (
	"context"
	"errors"
	"fmt"
)

// Provider is a source of credentials.
// Implementations should be safe for concurrent use.
type Provider interface {
	// Name returns a human-readable name for this provider.
	Name() string

	// Lookup attempts to find a credential for the given scope.
	// Returns nil, nil if no credential is available (not an error).
	// Returns nil, error if there was a problem looking up credentials.
	Lookup(ctx context.Context, scope Scope) (Credential, error)
}

// Scope describes what kind of credential is needed and for what purpose.
type Scope struct {
	// Host is the target hostname (required).
	Host string

	// Hint provides additional context for credential lookup.
	// For example, "git" for Git operations, "llm" for LLM providers,
	// "container" for container registries, etc.
	Hint string
}

// Compile-time interface assertion.
var _ fmt.Stringer = Scope{}

// NewScope creates a new Scope for the given host.
// This is the preferred constructor for building scopes.
//
// Example:
//
//	scope := auth.NewScope("github.com")
//	scope := auth.NewScope("api.anthropic.com").WithHint("llm")
func NewScope(host string) Scope {
	return Scope{Host: host}
}

// Validate checks if the scope has the minimum required fields.
func (s Scope) Validate() error {
	if s.Host == "" {
		return fmt.Errorf("scope requires a host")
	}
	return nil
}

// String implements [fmt.Stringer] for debugging and logging.
func (s Scope) String() string {
	if s.Hint != "" {
		return fmt.Sprintf("%s (%s)", s.Host, s.Hint)
	}
	return s.Host
}

// IsZero reports whether the scope is empty/unset.
func (s Scope) IsZero() bool {
	return s.Host == "" && s.Hint == ""
}

// WithHint returns a copy of the scope with the given hint.
func (s Scope) WithHint(hint string) Scope {
	s.Hint = hint
	return s
}

// ChainProvider chains multiple providers, returning the first successful match.
// Hard errors (non-ErrNoCredential) are propagated immediately; providers
// returning nil or ErrNoCredential are skipped.
type ChainProvider struct {
	providers []Provider
}

// Compile-time interface assertion.
var _ Provider = (*ChainProvider)(nil)

// NewChainProvider creates a provider that tries each provider in order.
func NewChainProvider(providers ...Provider) *ChainProvider {
	return &ChainProvider{providers: providers}
}

// Name implements [Provider].
func (c *ChainProvider) Name() string {
	return "chain"
}

// Lookup implements [Provider]. It tries each provider in order,
// returning the first successful match. Hard errors are propagated;
// ErrNoCredential is treated as "continue to next provider".
func (c *ChainProvider) Lookup(ctx context.Context, scope Scope) (Credential, error) {
	for _, p := range c.providers {
		cred, err := p.Lookup(ctx, scope)
		if err != nil {
			// ErrNoCredential means "not found, try next"
			if errors.Is(err, ErrNoCredential) {
				continue
			}
			// Propagate hard errors (unauthorized, rate limited, etc.)
			return nil, fmt.Errorf("%s: %w", p.Name(), err)
		}
		if cred != nil {
			return cred, nil
		}
	}
	return nil, nil
}

// Add appends providers to the chain.
func (c *ChainProvider) Add(providers ...Provider) {
	c.providers = append(c.providers, providers...)
}

// Providers returns a copy of the provider list for introspection.
func (c *ChainProvider) Providers() []Provider {
	result := make([]Provider, len(c.providers))
	copy(result, c.providers)
	return result
}

// Len returns the number of providers in the chain.
func (c *ChainProvider) Len() int {
	return len(c.providers)
}

// StaticProvider returns a fixed credential for matching hosts.
type StaticProvider struct {
	cred Credential
}

// Compile-time interface assertion.
var _ Provider = (*StaticProvider)(nil)

// NewStaticProvider creates a provider that always returns the same credential.
func NewStaticProvider(cred Credential) *StaticProvider {
	return &StaticProvider{cred: cred}
}

// Name implements [Provider].
func (s *StaticProvider) Name() string {
	return "static"
}

// Lookup implements [Provider]. It returns the static credential if it
// is valid for the requested host.
func (s *StaticProvider) Lookup(ctx context.Context, scope Scope) (Credential, error) {
	if s.cred == nil {
		return nil, nil
	}
	if !s.cred.ValidForHost(scope.Host) {
		return nil, nil
	}
	return s.cred, nil
}

// NullProvider never returns credentials. It is used as a default/sentinel.
type NullProvider struct{}

// Compile-time interface assertion.
var _ Provider = NullProvider{}

// Name implements [Provider].
func (NullProvider) Name() string { return "null" }

// Lookup implements [Provider]. It always returns nil, nil.
func (NullProvider) Lookup(ctx context.Context, scope Scope) (Credential, error) { return nil, nil }
