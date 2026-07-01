package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/temporalio/deputy/internal/mcp"
)

func TestMCPHTTPConfigFromFlags(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		cfg, err := mcpHTTPConfigFromFlags(mcpServeFlags{})
		if err != nil {
			t.Fatalf("mcpHTTPConfigFromFlags() error = %v", err)
		}
		if cfg.Auth != nil {
			t.Fatalf("Auth = %#v, want nil", cfg.Auth)
		}
	})

	t.Run("required jwt auth", func(t *testing.T) {
		cfg, err := mcpHTTPConfigFromFlags(mcpServeFlags{
			authMode:           " required ",
			authJWKSURL:        " https://issuer.example.com/.well-known/jwks.json ",
			authOIDCDiscovery:  true,
			authIssuers:        []string{" https://issuer.example.com ", ""},
			authAudiences:      []string{" deputy-mcp "},
			authRequiredClaims: []string{" sub "},
			authClockSkew:      30 * time.Second,
		})
		if err != nil {
			t.Fatalf("mcpHTTPConfigFromFlags() error = %v", err)
		}
		if cfg.Auth == nil {
			t.Fatal("Auth is nil")
		}
		if got, want := cfg.Auth.Mode, "required"; got != want {
			t.Fatalf("Auth.Mode = %q, want %q", got, want)
		}
		if cfg.Auth.JWKS == nil {
			t.Fatal("Auth.JWKS is nil")
		}
		if got, want := cfg.Auth.JWKS.URL, "https://issuer.example.com/.well-known/jwks.json"; got != want {
			t.Fatalf("JWKS.URL = %q, want %q", got, want)
		}
		if !cfg.Auth.JWKS.OIDCDiscovery {
			t.Fatal("JWKS.OIDCDiscovery = false, want true")
		}
		if got, want := strings.Join(cfg.Auth.Issuers, ","), "https://issuer.example.com"; got != want {
			t.Fatalf("Issuers = %q, want %q", got, want)
		}
		if got, want := strings.Join(cfg.Auth.Audiences, ","), "deputy-mcp"; got != want {
			t.Fatalf("Audiences = %q, want %q", got, want)
		}
		if got, want := strings.Join(cfg.Auth.RequiredClaims, ","), "sub"; got != want {
			t.Fatalf("RequiredClaims = %q, want %q", got, want)
		}
		if got, want := cfg.Auth.ClockSkew, 30*time.Second; got != want {
			t.Fatalf("ClockSkew = %v, want %v", got, want)
		}
	})

	t.Run("rejects auth details when disabled", func(t *testing.T) {
		_, err := mcpHTTPConfigFromFlags(mcpServeFlags{
			authMode:    "disabled",
			authJWKSURL: "https://issuer.example.com/.well-known/jwks.json",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "--auth-mode optional") {
			t.Fatalf("error = %q, want auth-mode guidance", err)
		}
	})

	t.Run("rejects enabled auth without jwks", func(t *testing.T) {
		_, err := mcpHTTPConfigFromFlags(mcpServeFlags{authMode: "required"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "--auth-jwks-url") {
			t.Fatalf("error = %q, want jwks guidance", err)
		}
	})

	t.Run("rejects unknown mode", func(t *testing.T) {
		_, err := mcpHTTPConfigFromFlags(mcpServeFlags{authMode: "strict"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "disabled, optional, or required") {
			t.Fatalf("error = %q, want supported mode guidance", err)
		}
	})

	t.Run("rejects negative clock skew", func(t *testing.T) {
		_, err := mcpHTTPConfigFromFlags(mcpServeFlags{
			authMode:      "required",
			authJWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
			authClockSkew: -time.Second,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "non-negative") {
			t.Fatalf("error = %q, want non-negative guidance", err)
		}
	})

	t.Run("rejects excessive clock skew", func(t *testing.T) {
		_, err := mcpHTTPConfigFromFlags(mcpServeFlags{
			authMode:      "required",
			authJWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
			authClockSkew: 5*time.Minute + time.Second,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "clock skew") || !strings.Contains(err.Error(), "5m") {
			t.Fatalf("error = %q, want clock skew maximum guidance", err)
		}
	})
}

func TestValidateMCPHTTPExposure(t *testing.T) {
	disabled, err := mcpHTTPConfigFromFlags(mcpServeFlags{})
	if err != nil {
		t.Fatalf("disabled config: %v", err)
	}
	required, err := mcpHTTPConfigFromFlags(mcpServeFlags{
		authMode:    "required",
		authJWKSURL: "https://issuer.example.com/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("required config: %v", err)
	}
	optional, err := mcpHTTPConfigFromFlags(mcpServeFlags{
		authMode:    "optional",
		authJWKSURL: "https://issuer.example.com/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("optional config: %v", err)
	}

	tests := []struct {
		name          string
		address       string
		cfg           mcp.HTTPConfig
		allowInsecure bool
		wantErr       string
	}{
		{name: "loopback host disabled auth", address: "127.0.0.1:8080", cfg: disabled},
		{name: "localhost disabled auth", address: "localhost:8080", cfg: disabled},
		{name: "ipv6 loopback disabled auth", address: "[::1]:8080", cfg: disabled},
		{name: "public bind required auth", address: "0.0.0.0:8080", cfg: required},
		{name: "public bind disabled auth rejected", address: "0.0.0.0:8080", cfg: disabled, wantErr: "--auth-mode required"},
		{name: "empty host bind disabled auth rejected", address: ":8080", cfg: disabled, wantErr: "--auth-mode required"},
		{name: "public bind optional auth rejected", address: "0.0.0.0:8080", cfg: optional, wantErr: "--auth-mode required"},
		{name: "public bind explicit insecure allowed", address: "0.0.0.0:8080", cfg: disabled, allowInsecure: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMCPHTTPExposure(tt.address, tt.cfg, tt.allowInsecure)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateMCPHTTPExposure() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestMCPServeCommandExposesHTTPAuthFlags(t *testing.T) {
	root := &cobra.Command{Use: "deputy"}
	AddMCPCommand(root)

	mcpCmd := findTestCommand(t, root, "mcp")
	serveCmd := findTestCommand(t, mcpCmd, "serve")

	for _, name := range []string{
		"allow-insecure",
		"auth-mode",
		"auth-jwks-url",
		"auth-oidc-discovery",
		"auth-issuers",
		"auth-audiences",
		"auth-required-claims",
		"auth-clock-skew",
	} {
		if serveCmd.Flags().Lookup(name) == nil {
			t.Fatalf("mcp serve is missing --%s", name)
		}
	}
	if got, want := serveCmd.Flags().Lookup("address").DefValue, "127.0.0.1:8080"; got != want {
		t.Fatalf("--address default = %q, want %q", got, want)
	}
}

func findTestCommand(t *testing.T, parent *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, cmd := range parent.Commands() {
		if cmd.Name() == name {
			return cmd
		}
	}
	t.Fatalf("command %q not found", name)
	return nil
}
