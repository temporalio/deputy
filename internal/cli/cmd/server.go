package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/temporalio/deputy/internal/config"
	"github.com/temporalio/deputy/internal/logs"
	"github.com/temporalio/deputy/internal/server"
)

// serverFlags holds flags for the server command.
type serverFlags struct {
	// Address and timeouts
	addr         string
	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration

	// TLS configuration
	tlsCertFile   string
	tlsKeyFile    string
	tlsMinVersion string
	tlsClientCA   string
	tlsClientAuth string

	// CORS configuration
	corsOrigins     []string
	corsMethods     []string
	corsHeaders     []string
	corsCredentials bool
	corsMaxAge      int

	// Auth configuration
	authMode           string
	authJWKSURL        string
	authOIDCDiscovery  bool
	authIssuers        []string
	authAudiences      []string
	authRequiredClaims []string
	authClockSkew      time.Duration

	// Rate limiting
	rateLimitEnabled bool
	rateLimitRPS     float64
	rateLimitBurst   int

	// Policies
	policies []string

	// Other
	maxRequestBodyMB int64

	// Security
	allowPublic   bool
	allowInsecure bool

	// Egress allowlists
	egressAllowHosts     []string
	egressAllowCIDRs     []string
	egressAllowSSH       bool
	egressAllowLoopback  bool
	egressAllowLinkLocal bool
}

// AddServerCommand adds the server command to the root command.
func AddServerCommand(root *cobra.Command) {
	flags := &serverFlags{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the Deputy gRPC/Connect server",
		Long: `Start the Deputy server which exposes all Deputy capabilities via gRPC and HTTP.

The server supports both gRPC and HTTP/JSON protocols via ConnectRPC, making it
accessible from various clients including:
  - gRPC clients (Go, Python, Java, etc.)
  - HTTP clients using JSON (curl, web browsers, etc.)
  - gRPC-Web clients (browser-based applications)

SERVICES:
  ScanService        - Vulnerability scanning (CVEs, advisories in dependencies)
  SecretsService     - Secret detection (leaked credentials, API keys)
  ListService        - Package and ecosystem enumeration
  SBOMService        - Software Bill of Materials generation and diff
  RemediationService - Fix planning and AI-assisted remediation

Examples:
  # Start server on default port (127.0.0.1:8090)
  deputy server

  # Start server on custom port
  deputy server --addr :9000

  # Start server with custom timeouts
  deputy server --write-timeout 10m

  # Bind publicly with TLS + auth (production)
  deputy server --public --addr 0.0.0.0:8090 \
    --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem \
    --auth-mode required --auth-jwks-url https://issuer/.well-known/jwks.json

  # Allow internal registries/SCM
  deputy server --egress-allow-host .corp.local --egress-allow-cidr 10.0.0.0/8

ENDPOINTS:
  Vulnerability Scanning (ScanService):
    POST /deputy.scan.v1.ScanService/Scan           - Find CVEs in dependencies
    POST /deputy.scan.v1.ScanService/StreamScan     - Scan with streaming progress

  Secret Detection (SecretsService):
    POST /deputy.secrets.v1.SecretsService/Scan          - Find leaked credentials
    POST /deputy.secrets.v1.SecretsService/StreamScan    - Scan with streaming progress
    POST /deputy.secrets.v1.SecretsService/ScanHistory   - Scan git history for secrets
    POST /deputy.secrets.v1.SecretsService/ScanDiff      - Scan git diff for secrets
    POST /deputy.secrets.v1.SecretsService/Verify        - Verify if secrets are active
    POST /deputy.secrets.v1.SecretsService/ListDetectors - List available detectors

  Package Enumeration (ListService):
    POST /deputy.list.v1.ListService/ListPackages   - List project dependencies
    POST /deputy.list.v1.ListService/ListEcosystems - List supported ecosystems

  SBOM Generation (SBOMService):
    POST /deputy.sbom.v1.SBOMService/Generate       - Generate SBOM
    POST /deputy.sbom.v1.SBOMService/Diff           - Compare two SBOMs

  Remediation (RemediationService):
    POST /deputy.remediation.v1.RemediationService/GeneratePlan     - Create fix plan
    POST /deputy.remediation.v1.RemediationService/ExecutePlan      - Apply fixes
    POST /deputy.remediation.v1.RemediationService/ExecuteWithAgent - AI-assisted remediation

  Health:
    GET  /health  - Health check
    GET  /ready   - Readiness check
    GET  /version - API version

Examples (curl):
  # Scan for VULNERABILITIES (CVEs in dependencies)
  curl -X POST http://localhost:8090/deputy.scan.v1.ScanService/Scan \
    -H "Content-Type: application/json" \
    -d '{"target": "github.com/example/repo"}'

  # Scan for SECRETS (leaked credentials, API keys)
  curl -X POST http://localhost:8090/deputy.secrets.v1.SecretsService/Scan \
    -H "Content-Type: application/json" \
    -d '{"target": "github.com/example/repo"}'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(cmd.Context(), flags, cmd)
		},
	}

	// Address and timeout flags
	cmd.Flags().StringVar(&flags.addr, "addr", "127.0.0.1:8090", "Address to listen on")
	cmd.Flags().DurationVar(&flags.readTimeout, "read-timeout", 30*time.Second, "Maximum duration for reading request")
	cmd.Flags().DurationVar(&flags.writeTimeout, "write-timeout", 5*time.Minute, "Maximum duration for writing response")
	cmd.Flags().DurationVar(&flags.idleTimeout, "idle-timeout", 2*time.Minute, "Maximum time to wait for next request")

	// TLS flags
	cmd.Flags().StringVar(&flags.tlsCertFile, "tls-cert", "", "Path to TLS certificate file")
	cmd.Flags().StringVar(&flags.tlsKeyFile, "tls-key", "", "Path to TLS private key file")
	cmd.Flags().StringVar(&flags.tlsMinVersion, "tls-min-version", "1.2", "Minimum TLS version (1.2 or 1.3)")
	cmd.Flags().StringVar(&flags.tlsClientCA, "tls-client-ca", "", "Path to CA certificate for client verification (enables mTLS)")
	cmd.Flags().StringVar(&flags.tlsClientAuth, "tls-client-auth", "", "Client auth policy: require, request, verify, none")

	// CORS flags
	cmd.Flags().StringSliceVar(&flags.corsOrigins, "cors-origins", nil, "Allowed CORS origins (comma-separated, or * for all)")
	cmd.Flags().StringSliceVar(&flags.corsMethods, "cors-methods", nil, "Allowed CORS methods (uses ConnectRPC defaults if empty)")
	cmd.Flags().StringSliceVar(&flags.corsHeaders, "cors-headers", nil, "Allowed CORS headers (uses ConnectRPC defaults if empty)")
	cmd.Flags().BoolVar(&flags.corsCredentials, "cors-credentials", false, "Allow credentials in CORS requests")
	cmd.Flags().IntVar(&flags.corsMaxAge, "cors-max-age", 0, "Max age for CORS preflight cache (seconds)")

	// Auth flags
	cmd.Flags().StringVar(&flags.authMode, "auth-mode", "disabled", "Authentication mode: disabled, required")
	cmd.Flags().StringVar(&flags.authJWKSURL, "auth-jwks-url", "", "JWKS endpoint URL for JWT validation")
	cmd.Flags().BoolVar(&flags.authOIDCDiscovery, "auth-oidc-discovery", false, "Use OIDC discovery to find JWKS endpoint")
	cmd.Flags().StringSliceVar(&flags.authIssuers, "auth-issuers", nil, "Trusted token issuers (comma-separated)")
	cmd.Flags().StringSliceVar(&flags.authAudiences, "auth-audiences", nil, "Expected token audiences (comma-separated)")
	cmd.Flags().StringSliceVar(&flags.authRequiredClaims, "auth-required-claims", nil, "Required JWT claims (comma-separated)")
	cmd.Flags().DurationVar(&flags.authClockSkew, "auth-clock-skew", 0, "Clock skew tolerance for token validation (max 5m)")

	// Rate limiting flags
	cmd.Flags().BoolVar(&flags.rateLimitEnabled, "rate-limit", false, "Enable per-client rate limiting")
	cmd.Flags().Float64Var(&flags.rateLimitRPS, "rate-limit-rps", 10, "Maximum requests per second per client")
	cmd.Flags().IntVar(&flags.rateLimitBurst, "rate-limit-burst", 20, "Rate limit burst size")

	// Policy flags
	cmd.Flags().StringSliceVar(&flags.policies, "policy", nil, "Policy files for service-level authorization (can be repeated)")

	// Other flags
	cmd.Flags().Int64Var(&flags.maxRequestBodyMB, "max-request-body-mb", 10, "Maximum request body size in MB")

	// Security flags
	cmd.Flags().BoolVar(&flags.allowPublic, "public", false, "Allow binding to non-loopback addresses (explicit opt-in)")
	cmd.Flags().BoolVar(&flags.allowInsecure, "insecure", false, "Allow insecure server modes (no TLS/auth, policy errors)")

	// Egress allowlists
	cmd.Flags().StringSliceVar(&flags.egressAllowHosts, "egress-allow-host", nil, "Allowlisted egress hostnames (repeatable)")
	cmd.Flags().StringSliceVar(&flags.egressAllowCIDRs, "egress-allow-cidr", nil, "Allowlisted egress CIDR ranges (repeatable)")
	cmd.Flags().BoolVar(&flags.egressAllowSSH, "egress-allow-ssh", false, "Allow non-HTTPS git targets (ssh://, git@host, git://)")
	cmd.Flags().BoolVar(&flags.egressAllowLoopback, "egress-allow-loopback", false, "Allow loopback targets in remote server mode")
	cmd.Flags().BoolVar(&flags.egressAllowLinkLocal, "egress-allow-link-local", false, "Allow link-local targets in remote server mode")

	root.AddCommand(cmd)
}

// parseTLSVersion converts a version string to a tls.Version constant.
func parseTLSVersion(version string) uint16 {
	switch strings.TrimPrefix(strings.ToLower(version), "tls") {
	case "1.3", "13":
		return tls.VersionTLS13
	case "1.2", "12":
		return tls.VersionTLS12
	case "1.1", "11":
		return tls.VersionTLS11
	case "1.0", "10":
		return tls.VersionTLS10
	default:
		return tls.VersionTLS12 // Default to TLS 1.2
	}
}

// parseTLSClientAuth converts a client auth string to a tls.ClientAuthType.
func parseTLSClientAuth(auth string) tls.ClientAuthType {
	switch strings.ToLower(auth) {
	case "require", "required":
		return tls.RequireAndVerifyClientCert
	case "request":
		return tls.RequestClientCert
	case "verify":
		return tls.VerifyClientCertIfGiven
	case "none", "":
		return tls.NoClientCert
	default:
		return tls.NoClientCert
	}
}

// loadServerConfig builds a server.Config with proper precedence:
// CLI flags > environment variables > config file > defaults.
// A config file that cannot be loaded is an error rather than a fall back to
// defaults: silently ignoring it would start the server on a different address,
// without the configured TLS settings, and with different egress allowlists
// than the operator asked for. The CLI already refuses to run any command in
// this state (see internal/cli.loadRuntimeConfig), so this is a second line of
// defense for callers that construct the command directly.
func loadServerConfig(flags *serverFlags, cmd *cobra.Command) (server.Config, error) {
	// Load config file + env vars (config.Loader handles file + env precedence)
	configPath := config.FindConfigFile()
	loader := config.NewLoader(configPath)
	fileCfg, err := loader.Load()
	if err != nil {
		if configPath != "" {
			return server.Config{}, fmt.Errorf("failed to load config from %s: %w", configPath, err)
		}
		return server.Config{}, fmt.Errorf("failed to load config: %w", err)
	}

	// Start with defaults, then apply config file values
	cfg := server.Config{
		Addr:                "127.0.0.1:8090",
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        5 * time.Minute,
		IdleTimeout:         2 * time.Minute,
		MaxRequestBodyBytes: 10 * 1024 * 1024, // 10MB default
	}

	// Apply config file values (already merged with env vars by loader)
	serverCfg := fileCfg.Server
	if serverCfg.Addr != "" {
		cfg.Addr = serverCfg.Addr
	}
	if serverCfg.ReadTimeout > 0 {
		cfg.ReadTimeout = serverCfg.ReadTimeout
	}
	if serverCfg.WriteTimeout > 0 {
		cfg.WriteTimeout = serverCfg.WriteTimeout
	}
	if serverCfg.IdleTimeout > 0 {
		cfg.IdleTimeout = serverCfg.IdleTimeout
	}
	if serverCfg.MaxRequestBodyBytes > 0 {
		cfg.MaxRequestBodyBytes = serverCfg.MaxRequestBodyBytes
	}

	// Apply TLS from config file
	if serverCfg.TLS != nil && serverCfg.TLS.CertFile != "" && serverCfg.TLS.KeyFile != "" {
		cfg.TLS = &server.TLSConfig{
			CertFile:     serverCfg.TLS.CertFile,
			KeyFile:      serverCfg.TLS.KeyFile,
			ClientCAFile: serverCfg.TLS.ClientCAFile,
			MinVersion:   tls.VersionTLS12, // Default
		}
	}

	// Apply CORS from config file
	if serverCfg.CORS != nil && len(serverCfg.CORS.AllowedOrigins) > 0 {
		cfg.CORS = &server.CORSConfig{
			AllowedOrigins:   serverCfg.CORS.AllowedOrigins,
			AllowedMethods:   serverCfg.CORS.AllowedMethods,
			AllowedHeaders:   serverCfg.CORS.AllowedHeaders,
			AllowCredentials: serverCfg.CORS.AllowCredentials,
			MaxAge:           serverCfg.CORS.MaxAge,
		}
	}

	// Apply Auth from config file
	if serverCfg.Auth != nil {
		mode := strings.TrimSpace(serverCfg.Auth.Mode)
		if mode == "" && serverCfg.Auth.Enabled {
			mode = "required"
		}
		if mode != "" || serverCfg.Auth.Enabled || serverCfg.Auth.JWKSURL != "" {
			cfg.Auth = &server.AuthConfig{
				Mode:           mode,
				Issuers:        serverCfg.Auth.Issuers,
				Audiences:      serverCfg.Auth.Audiences,
				RequiredClaims: serverCfg.Auth.RequiredClaims,
				ClockSkew:      serverCfg.Auth.ClockSkew,
			}
			if serverCfg.Auth.JWKSURL != "" {
				cfg.Auth.JWKS = &server.JWKSConfig{
					URL:           serverCfg.Auth.JWKSURL,
					OIDCDiscovery: serverCfg.Auth.OIDCDiscovery,
				}
			}
		}
	}

	// Apply RateLimit from config file
	if serverCfg.RateLimit != nil && serverCfg.RateLimit.Enabled {
		cfg.RateLimit = &server.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: serverCfg.RateLimit.RequestsPerSecond,
			Burst:             serverCfg.RateLimit.Burst,
		}
	}

	// Apply Security from config file
	if serverCfg.Security != nil {
		cfg.Security = &server.SecurityConfig{
			AllowPublic:   serverCfg.Security.AllowPublic,
			AllowInsecure: serverCfg.Security.AllowInsecure,
		}
	}

	// Apply Egress from config file
	if serverCfg.Egress != nil {
		cfg.Egress = &server.EgressConfig{
			AllowedHosts:   serverCfg.Egress.AllowedHosts,
			AllowedCIDRs:   serverCfg.Egress.AllowedCIDRs,
			AllowSSH:       serverCfg.Egress.AllowSSH,
			AllowLoopback:  serverCfg.Egress.AllowLoopback,
			AllowLinkLocal: serverCfg.Egress.AllowLinkLocal,
		}
	}

	// Apply policy paths from config file
	if len(fileCfg.Policy.Paths) > 0 {
		cfg.Policies = fileCfg.Policy.Paths
	}

	// Now apply CLI flags (highest precedence) - only if explicitly set
	if cmd.Flags().Changed("addr") {
		cfg.Addr = flags.addr
	}
	if cmd.Flags().Changed("read-timeout") {
		cfg.ReadTimeout = flags.readTimeout
	}
	if cmd.Flags().Changed("write-timeout") {
		cfg.WriteTimeout = flags.writeTimeout
	}
	if cmd.Flags().Changed("idle-timeout") {
		cfg.IdleTimeout = flags.idleTimeout
	}
	if cmd.Flags().Changed("max-request-body-mb") {
		cfg.MaxRequestBodyBytes = flags.maxRequestBodyMB * 1024 * 1024
	}
	if cmd.Flags().Changed("policy") {
		cfg.Policies = flags.policies
	}

	// TLS flags override config file
	if cmd.Flags().Changed("tls-cert") || cmd.Flags().Changed("tls-key") {
		if flags.tlsCertFile != "" && flags.tlsKeyFile != "" {
			cfg.TLS = &server.TLSConfig{
				CertFile:     flags.tlsCertFile,
				KeyFile:      flags.tlsKeyFile,
				MinVersion:   parseTLSVersion(flags.tlsMinVersion),
				ClientCAFile: flags.tlsClientCA,
				ClientAuth:   parseTLSClientAuth(flags.tlsClientAuth),
			}
		}
	} else if cfg.TLS != nil {
		// Apply TLS sub-flags to existing config
		if cmd.Flags().Changed("tls-min-version") {
			cfg.TLS.MinVersion = parseTLSVersion(flags.tlsMinVersion)
		}
		if cmd.Flags().Changed("tls-client-ca") {
			cfg.TLS.ClientCAFile = flags.tlsClientCA
		}
		if cmd.Flags().Changed("tls-client-auth") {
			cfg.TLS.ClientAuth = parseTLSClientAuth(flags.tlsClientAuth)
		}
	}

	// CORS flags override config file
	if cmd.Flags().Changed("cors-origins") {
		if len(flags.corsOrigins) > 0 {
			if cfg.CORS == nil {
				cfg.CORS = &server.CORSConfig{}
			}
			cfg.CORS.AllowedOrigins = flags.corsOrigins
		}
	}
	if cmd.Flags().Changed("cors-methods") {
		if cfg.CORS == nil {
			cfg.CORS = &server.CORSConfig{}
		}
		cfg.CORS.AllowedMethods = flags.corsMethods
	}
	if cmd.Flags().Changed("cors-headers") {
		if cfg.CORS == nil {
			cfg.CORS = &server.CORSConfig{}
		}
		cfg.CORS.AllowedHeaders = flags.corsHeaders
	}
	if cmd.Flags().Changed("cors-credentials") {
		if cfg.CORS == nil {
			cfg.CORS = &server.CORSConfig{}
		}
		cfg.CORS.AllowCredentials = flags.corsCredentials
	}
	if cmd.Flags().Changed("cors-max-age") {
		if cfg.CORS == nil {
			cfg.CORS = &server.CORSConfig{}
		}
		cfg.CORS.MaxAge = flags.corsMaxAge
	}

	// Auth flags override config file
	if cmd.Flags().Changed("auth-mode") {
		if flags.authMode != "disabled" && flags.authMode != "" {
			if cfg.Auth == nil {
				cfg.Auth = &server.AuthConfig{}
			}
			cfg.Auth.Mode = flags.authMode
		} else {
			cfg.Auth = nil // Explicitly disabled
		}
	}
	if cfg.Auth != nil {
		if cmd.Flags().Changed("auth-jwks-url") {
			if cfg.Auth.JWKS == nil {
				cfg.Auth.JWKS = &server.JWKSConfig{}
			}
			cfg.Auth.JWKS.URL = flags.authJWKSURL
		}
		if cmd.Flags().Changed("auth-oidc-discovery") {
			if cfg.Auth.JWKS == nil {
				cfg.Auth.JWKS = &server.JWKSConfig{}
			}
			cfg.Auth.JWKS.OIDCDiscovery = flags.authOIDCDiscovery
		}
		if cmd.Flags().Changed("auth-issuers") {
			cfg.Auth.Issuers = flags.authIssuers
		}
		if cmd.Flags().Changed("auth-audiences") {
			cfg.Auth.Audiences = flags.authAudiences
		}
		if cmd.Flags().Changed("auth-required-claims") {
			cfg.Auth.RequiredClaims = flags.authRequiredClaims
		}
		if cmd.Flags().Changed("auth-clock-skew") {
			cfg.Auth.ClockSkew = flags.authClockSkew
		}
	}

	// Rate limit flags override config file
	if cmd.Flags().Changed("rate-limit") {
		if flags.rateLimitEnabled {
			if cfg.RateLimit == nil {
				cfg.RateLimit = &server.RateLimitConfig{}
			}
			cfg.RateLimit.Enabled = true
		} else {
			cfg.RateLimit = nil // Explicitly disabled
		}
	}
	if cfg.RateLimit != nil {
		if cmd.Flags().Changed("rate-limit-rps") {
			cfg.RateLimit.RequestsPerSecond = flags.rateLimitRPS
		}
		if cmd.Flags().Changed("rate-limit-burst") {
			cfg.RateLimit.Burst = flags.rateLimitBurst
		}
	}

	// Security flags override config file
	if cmd.Flags().Changed("public") || cmd.Flags().Changed("insecure") {
		if cfg.Security == nil {
			cfg.Security = &server.SecurityConfig{}
		}
		if cmd.Flags().Changed("public") {
			cfg.Security.AllowPublic = flags.allowPublic
		}
		if cmd.Flags().Changed("insecure") {
			cfg.Security.AllowInsecure = flags.allowInsecure
		}
	}

	// Egress flags override config file
	if cmd.Flags().Changed("egress-allow-host") ||
		cmd.Flags().Changed("egress-allow-cidr") ||
		cmd.Flags().Changed("egress-allow-ssh") ||
		cmd.Flags().Changed("egress-allow-loopback") ||
		cmd.Flags().Changed("egress-allow-link-local") {
		if cfg.Egress == nil {
			cfg.Egress = &server.EgressConfig{}
		}
		if cmd.Flags().Changed("egress-allow-host") {
			cfg.Egress.AllowedHosts = flags.egressAllowHosts
		}
		if cmd.Flags().Changed("egress-allow-cidr") {
			cfg.Egress.AllowedCIDRs = flags.egressAllowCIDRs
		}
		if cmd.Flags().Changed("egress-allow-ssh") {
			cfg.Egress.AllowSSH = flags.egressAllowSSH
		}
		if cmd.Flags().Changed("egress-allow-loopback") {
			cfg.Egress.AllowLoopback = flags.egressAllowLoopback
		}
		if cmd.Flags().Changed("egress-allow-link-local") {
			cfg.Egress.AllowLinkLocal = flags.egressAllowLinkLocal
		}
	}

	return cfg, nil
}

func runServer(ctx context.Context, flags *serverFlags, cmd *cobra.Command) error {
	// Load configuration with proper precedence: flags > env > config file > defaults
	cfg, err := loadServerConfig(flags, cmd)
	if err != nil {
		return err
	}

	srv, err := server.New(cfg)
	if err != nil {
		return err
	}

	// Handle graceful shutdown
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	fmt.Fprintf(os.Stderr, "Deputy server listening on %s\n", cfg.Addr)
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop\n")

	// Wait for shutdown signal or error
	select {
	case <-shutdownCh:
		logs.Info(ctx, "received shutdown signal")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
