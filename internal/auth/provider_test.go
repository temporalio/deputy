package auth

import (
	"context"
	"errors"
	"testing"
)

func TestNewScope(t *testing.T) {
	scope := NewScope("github.com")

	if scope.Host != "github.com" {
		t.Errorf("expected host github.com, got %s", scope.Host)
	}
}

func TestScope_String(t *testing.T) {
	tests := []struct {
		name  string
		scope Scope
		want  string
	}{
		{
			name:  "basic scope",
			scope: Scope{Host: "github.com"},
			want:  "github.com",
		},
		{
			name:  "scope with hint",
			scope: Scope{Host: "registry.npmjs.org", Hint: "publish"},
			want:  "registry.npmjs.org (publish)",
		},
		{
			name:  "empty scope",
			scope: Scope{},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.scope.String()
			if got != tt.want {
				t.Errorf("Scope.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScope_IsZero(t *testing.T) {
	tests := []struct {
		name  string
		scope Scope
		want  bool
	}{
		{
			name:  "zero scope",
			scope: Scope{},
			want:  true,
		},
		{
			name:  "non-zero with host",
			scope: Scope{Host: "github.com"},
			want:  false,
		},
		{
			name:  "non-zero with hint",
			scope: Scope{Hint: "test"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.scope.IsZero()
			if got != tt.want {
				t.Errorf("Scope.IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScope_WithHint(t *testing.T) {
	scope := Scope{Host: "github.com"}
	newScope := scope.WithHint("push")

	if newScope.Hint != "push" {
		t.Errorf("expected hint push, got %s", newScope.Hint)
	}
	// Original should be unchanged
	if scope.Hint != "" {
		t.Errorf("original scope should not be modified")
	}
}

func TestScope_Fluent(t *testing.T) {
	scope := NewScope("registry.npmjs.org").WithHint("publish")

	if scope.Host != "registry.npmjs.org" {
		t.Errorf("expected host registry.npmjs.org, got %s", scope.Host)
	}
	if scope.Hint != "publish" {
		t.Errorf("expected hint publish, got %s", scope.Hint)
	}
}

func TestChainProvider_Add(t *testing.T) {
	chain := NewChainProvider()
	if chain.Len() != 0 {
		t.Fatalf("expected empty chain, got %d", chain.Len())
	}

	chain.Add(NullProvider{})
	if chain.Len() != 1 {
		t.Fatalf("expected 1 provider, got %d", chain.Len())
	}

	chain.Add(NullProvider{}, NullProvider{})
	if chain.Len() != 3 {
		t.Fatalf("expected 3 providers, got %d", chain.Len())
	}
}

func TestChainProvider_Providers(t *testing.T) {
	p1 := NullProvider{}
	p2 := NewStaticProvider(nil)

	chain := NewChainProvider(p1, p2)
	providers := chain.Providers()

	if len(providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(providers))
	}

	// Verify it returns a copy (modifying returned slice doesn't affect chain)
	providers[0] = nil
	if chain.Len() != 2 {
		t.Error("modifying returned slice should not affect chain")
	}
}

func TestChainProvider_Name(t *testing.T) {
	chain := NewChainProvider()
	if chain.Name() != "chain" {
		t.Errorf("expected name 'chain', got %s", chain.Name())
	}
}

func TestStaticProvider_Name(t *testing.T) {
	p := NewStaticProvider(nil)
	if p.Name() != "static" {
		t.Errorf("expected name 'static', got %s", p.Name())
	}
}

func TestNullProvider_Name(t *testing.T) {
	p := NullProvider{}
	if p.Name() != "null" {
		t.Errorf("expected name 'null', got %s", p.Name())
	}
}

// errorProvider is a test provider that always returns an error.
type errorProvider struct {
	err error
}

func (e errorProvider) Name() string { return "error" }
func (e errorProvider) Lookup(ctx context.Context, scope Scope) (Credential, error) {
	return nil, e.err
}

func TestChainProvider_Lookup_Error(t *testing.T) {
	testErr := errors.New("lookup failed")
	chain := NewChainProvider(
		NullProvider{},
		errorProvider{err: testErr},
	)

	ctx := t.Context()
	_, err := chain.Lookup(ctx, Scope{Host: "github.com"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, testErr) {
		t.Errorf("expected wrapped error, got %v", err)
	}
}

func TestChainProvider_Lookup_SkipsErrNoCredential(t *testing.T) {
	// Provider that returns ErrNoCredential should be skipped
	noCredProvider := errorProvider{err: ErrNoCredential}
	staticCred := &TokenCredential{Token: "test", AllowedHosts: []string{"github.com"}}
	staticProvider := NewStaticProvider(staticCred)

	chain := NewChainProvider(noCredProvider, staticProvider)

	ctx := t.Context()
	cred, err := chain.Lookup(ctx, Scope{Host: "github.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Error("expected credential from second provider")
	}
}

func TestStaticProvider_NilCredential(t *testing.T) {
	p := NewStaticProvider(nil)

	ctx := t.Context()
	cred, err := p.Lookup(ctx, Scope{Host: "github.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred != nil {
		t.Error("expected nil credential")
	}
}
