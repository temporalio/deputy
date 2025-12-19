package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Sentinel errors for common authentication failure cases.
var (
	// ErrNoCredential is returned when no credential is available for a host.
	ErrNoCredential = errors.New("no credential available")

	// ErrCredentialExpired is returned when a credential has expired and cannot be refreshed.
	ErrCredentialExpired = errors.New("credential expired")

	// ErrHostMismatch is returned when a credential is not valid for the requested host.
	ErrHostMismatch = errors.New("credential not valid for host")

	// ErrUnsupportedCredentialType is returned when a credential type cannot be used
	// for the requested operation (e.g., SSH credential for HTTP bearer auth).
	ErrUnsupportedCredentialType = errors.New("unsupported credential type")
)

// Credential represents an authentication credential.
// It is designed to be type-safe and prevent accidental credential leakage.
type Credential interface {
	// Type returns the credential type identifier.
	Type() CredentialType

	// Hosts returns the list of hosts this credential is valid for.
	// An empty slice means the credential cannot be used; use InsecureAllowAnyHosts
	// to explicitly opt into insecure wildcard host allowance.
	Hosts() []string

	// ValidForHost reports whether this credential can be used for the given host.
	ValidForHost(host string) bool

	// Redacted returns a safe-to-log representation of the credential.
	Redacted() string
}

// CredentialType identifies the kind of credential.
type CredentialType string

// String implements [fmt.Stringer].
func (t CredentialType) String() string { return string(t) }

const (
	// TypeToken represents bearer/API token credentials.
	TypeToken CredentialType = "token"

	// TypeBasic represents username/password credentials.
	TypeBasic CredentialType = "basic"

	// TypeSSH represents SSH key credentials.
	TypeSSH CredentialType = "ssh"

	// TypeDocker represents Docker/OCI registry credentials.
	TypeDocker CredentialType = "docker"
)

// InsecureAllowAnyHost is a sentinel that disables host scoping. Using this
// expands a credential to all hosts and should be avoided in production.
const InsecureAllowAnyHost = "*"

// InsecureAllowAnyHosts returns the sentinel slice that opts a credential into
// insecure wildcard host allowance. Prefer host-specific lists whenever
// possible.
func InsecureAllowAnyHosts() []string {
	return []string{InsecureAllowAnyHost}
}

// NewInsecureTokenForAnyHost creates a TokenCredential that matches any host.
// This is dangerous and should only be used in controlled environments like
// local development or testing. The name is intentionally verbose to make
// the security implications clear.
//
// WARNING: Credentials created with this function will be sent to ANY host.
// Use host-specific credentials in production.
func NewInsecureTokenForAnyHost(token, source string) *TokenCredential {
	return &TokenCredential{
		Token:        token,
		AllowedHosts: InsecureAllowAnyHosts(),
		Source:       source,
	}
}

// TokenCredential holds a bearer or API token.
type TokenCredential struct {
	// Token is the secret token value.
	Token string

	// Expiry optionally indicates when the token expires. If nil, the token is treated as non-expiring.
	Expiry *time.Time

	// AllowedHosts restricts which hosts can receive this token.
	// If empty, the credential is not used; use InsecureAllowAnyHosts to opt into
	// insecure wildcard matching.
	AllowedHosts []string

	// Source indicates where the credential came from (for debugging).
	Source string
}

// Compile-time interface assertions.
var (
	_ Credential          = (*TokenCredential)(nil)
	_ Expirable           = (*TokenCredential)(nil)
	_ BearerTokenProvider = (*TokenCredential)(nil)
	_ BasicAuthProvider   = (*TokenCredential)(nil)
	_ Sourced             = (*TokenCredential)(nil)
	_ fmt.Stringer        = (*TokenCredential)(nil)
)

// Type implements [Credential].
func (c *TokenCredential) Type() CredentialType { return TypeToken }

// Hosts implements [Credential].
func (c *TokenCredential) Hosts() []string {
	return c.AllowedHosts
}

// ValidForHost implements [Credential].
func (c *TokenCredential) ValidForHost(host string) bool {
	return validForHost(host, c.AllowedHosts)
}

// Redacted implements [Credential].
func (c *TokenCredential) Redacted() string {
	if c.Token == "" {
		return "TokenCredential{empty}"
	}
	redacted := redactToken(c.Token)
	if c.Source != "" {
		return fmt.Sprintf("TokenCredential{%s, source=%s}", redacted, c.Source)
	}
	return fmt.Sprintf("TokenCredential{%s}", redacted)
}

// ExpiresAt implements [Expirable].
func (c *TokenCredential) ExpiresAt() *time.Time { return c.Expiry }

// BearerToken implements [BearerTokenProvider].
func (c *TokenCredential) BearerToken() string { return c.Token }

// BasicAuth implements [BasicAuthProvider]. Many services accept token as password.
func (c *TokenCredential) BasicAuth() (username, password string) { return "oauth2", c.Token }

// CredentialSource implements [Sourced].
func (c *TokenCredential) CredentialSource() string { return c.Source }

// String implements [fmt.Stringer] using the redacted representation.
func (c *TokenCredential) String() string { return c.Redacted() }

// BasicCredential holds username/password authentication.
type BasicCredential struct {
	// Username is the authentication username.
	Username string

	// Password is the authentication password or token.
	Password string

	// Expiry optionally indicates when the credential expires. If nil, treated as non-expiring.
	Expiry *time.Time

	// AllowedHosts restricts which hosts can receive this credential.
	// If empty, the credential is not used; use InsecureAllowAnyHosts to opt into
	// insecure wildcard matching.
	AllowedHosts []string

	// Source indicates where the credential came from.
	Source string
}

// Compile-time interface assertions.
var (
	_ Credential          = (*BasicCredential)(nil)
	_ Expirable           = (*BasicCredential)(nil)
	_ BearerTokenProvider = (*BasicCredential)(nil)
	_ BasicAuthProvider   = (*BasicCredential)(nil)
	_ Sourced             = (*BasicCredential)(nil)
	_ fmt.Stringer        = (*BasicCredential)(nil)
)

// Type implements [Credential].
func (c *BasicCredential) Type() CredentialType { return TypeBasic }

// Hosts implements [Credential].
func (c *BasicCredential) Hosts() []string {
	return c.AllowedHosts
}

// ValidForHost implements [Credential].
func (c *BasicCredential) ValidForHost(host string) bool {
	return validForHost(host, c.AllowedHosts)
}

// Redacted implements [Credential].
func (c *BasicCredential) Redacted() string {
	redacted := redactToken(c.Password)
	if c.Source != "" {
		return fmt.Sprintf("BasicCredential{user=%s, pass=%s, source=%s}", c.Username, redacted, c.Source)
	}
	return fmt.Sprintf("BasicCredential{user=%s, pass=%s}", c.Username, redacted)
}

// ExpiresAt implements [Expirable].
func (c *BasicCredential) ExpiresAt() *time.Time { return c.Expiry }

// BearerToken implements [BearerTokenProvider]. Some APIs accept password as bearer token.
func (c *BasicCredential) BearerToken() string { return c.Password }

// BasicAuth implements [BasicAuthProvider].
func (c *BasicCredential) BasicAuth() (username, password string) { return c.Username, c.Password }

// CredentialSource implements [Sourced].
func (c *BasicCredential) CredentialSource() string { return c.Source }

// String implements [fmt.Stringer] using the redacted representation.
func (c *BasicCredential) String() string { return c.Redacted() }

// SSHCredential holds SSH key-based authentication.
type SSHCredential struct {
	// User is the SSH username (typically "git").
	User string

	// Expiry optionally indicates when the credential expires.
	Expiry *time.Time

	// PrivateKey is the PEM-encoded private key.
	PrivateKey []byte

	// PrivateKeyPath is the path to the private key file (alternative to PrivateKey).
	PrivateKeyPath string

	// Passphrase is the optional key passphrase.
	Passphrase string

	// AllowedHosts restricts which hosts can use this key.
	// If empty, the credential is not used; use InsecureAllowAnyHosts to opt into
	// insecure wildcard matching.
	AllowedHosts []string

	// Source indicates where the credential came from.
	Source string
}

// Compile-time interface assertions.
var (
	_ Credential   = (*SSHCredential)(nil)
	_ Expirable    = (*SSHCredential)(nil)
	_ Sourced      = (*SSHCredential)(nil)
	_ fmt.Stringer = (*SSHCredential)(nil)
)

// Type implements [Credential].
func (c *SSHCredential) Type() CredentialType { return TypeSSH }

// Hosts implements [Credential].
func (c *SSHCredential) Hosts() []string {
	return c.AllowedHosts
}

// ValidForHost implements [Credential].
func (c *SSHCredential) ValidForHost(host string) bool {
	return validForHost(host, c.AllowedHosts)
}

// Redacted implements [Credential].
func (c *SSHCredential) Redacted() string {
	if c.Source != "" {
		return fmt.Sprintf("SSHCredential{user=%s, source=%s}", c.User, c.Source)
	}
	return fmt.Sprintf("SSHCredential{user=%s}", c.User)
}

// ExpiresAt implements [Expirable].
func (c *SSHCredential) ExpiresAt() *time.Time { return c.Expiry }

// CredentialSource implements [Sourced].
func (c *SSHCredential) CredentialSource() string { return c.Source }

// String implements [fmt.Stringer] using the redacted representation.
func (c *SSHCredential) String() string { return c.Redacted() }

// DockerCredential holds container registry authentication.
type DockerCredential struct {
	// Username is the registry username.
	Username string

	// Password is the registry password or token.
	Password string

	// IdentityToken is an alternative to password (for OAuth).
	IdentityToken string

	// RegistryToken is used by some registries.
	RegistryToken string

	// ServerAddress is the registry server (e.g., "https://index.docker.io/v1/").
	ServerAddress string

	// Source indicates where the credential came from.
	Source string
}

// Compile-time interface assertions.
var (
	_ Credential        = (*DockerCredential)(nil)
	_ BasicAuthProvider = (*DockerCredential)(nil)
	_ Sourced           = (*DockerCredential)(nil)
	_ fmt.Stringer      = (*DockerCredential)(nil)
)

// Type implements [Credential].
func (c *DockerCredential) Type() CredentialType { return TypeDocker }

// Hosts implements [Credential].
func (c *DockerCredential) Hosts() []string {
	if c.ServerAddress == "" {
		return nil
	}
	host := extractHost(c.ServerAddress)
	if host == "" {
		return nil
	}
	return []string{host}
}

// ValidForHost implements [Credential].
func (c *DockerCredential) ValidForHost(host string) bool {
	if c.ServerAddress == "" {
		return false // Docker credentials require explicit server address
	}
	credHost := extractHost(c.ServerAddress)
	return matchHost(normalizeHost(host), credHost)
}

// Redacted implements [Credential].
func (c *DockerCredential) Redacted() string {
	if c.Source != "" {
		return fmt.Sprintf("DockerCredential{server=%s, source=%s}", c.ServerAddress, c.Source)
	}
	return fmt.Sprintf("DockerCredential{server=%s}", c.ServerAddress)
}

// BasicAuth implements [BasicAuthProvider].
func (c *DockerCredential) BasicAuth() (username, password string) { return c.Username, c.Password }

// CredentialSource implements [Sourced].
func (c *DockerCredential) CredentialSource() string { return c.Source }

// String implements [fmt.Stringer] using the redacted representation.
func (c *DockerCredential) String() string { return c.Redacted() }

// RefreshableCredential can produce a fresh credential (e.g., token refresh).
// Implementations should preserve host scoping and avoid leaking secrets.
type RefreshableCredential interface {
	Refresh(ctx context.Context) (Credential, error)
}

// Expirable is implemented by credentials that have an expiry time.
type Expirable interface {
	// ExpiresAt returns the expiry timestamp, or nil if the credential does not expire.
	ExpiresAt() *time.Time
}

// BearerTokenProvider is implemented by credentials that can provide a bearer token
// for HTTP Authorization headers.
type BearerTokenProvider interface {
	// BearerToken returns the token string for use in "Authorization: Bearer <token>".
	BearerToken() string
}

// BasicAuthProvider is implemented by credentials that can provide username/password
// for HTTP Basic Authentication.
type BasicAuthProvider interface {
	// BasicAuth returns the username and password for HTTP Basic Auth.
	BasicAuth() (username, password string)
}

// Sourced is implemented by credentials that track their origin.
// This is useful for debugging and audit logging.
type Sourced interface {
	// CredentialSource returns a description of where the credential came from.
	CredentialSource() string
}

// expiresAt returns the expiry timestamp if the credential implements Expirable.
func expiresAt(cred Credential) *time.Time {
	if e, ok := cred.(Expirable); ok {
		return e.ExpiresAt()
	}
	return nil
}

// expired reports whether a credential is past its expiry (if defined).
func expired(cred Credential) bool {
	if t := expiresAt(cred); t != nil {
		return time.Now().After(*t)
	}
	return false
}

func validForHost(host string, allowedHosts []string) bool {
	if len(allowedHosts) == 0 {
		return false
	}

	if hasInsecureAllowAnyHost(allowedHosts) {
		return true
	}

	host = normalizeHost(host)
	if host == "" {
		return false
	}

	for _, allowed := range allowedHosts {
		if matchHost(host, allowed) {
			return true
		}
	}

	return false
}

// hasInsecureAllowAnyHost returns true if the allowed hosts list contains
// the InsecureAllowAnyHost sentinel value, indicating the credential
// should match any host.
func hasInsecureAllowAnyHost(allowedHosts []string) bool {
	for _, allowed := range allowedHosts {
		if normalizeHost(allowed) == InsecureAllowAnyHost {
			return true
		}
	}
	return false
}

// normalizeHost converts a host string to a consistent lowercase form
// for comparison. This ensures host matching is case-insensitive.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.ToLower(host)

	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Check if this looks like a port (after last colon)
		port := host[idx+1:]
		if _, err := url.Parse("http://localhost:" + port); err == nil {
			host = host[:idx]
		}
	}

	return host
}

// extractHost extracts the host from a URL string.
func extractHost(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}

	// Handle URLs without scheme
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	return normalizeHost(u.Host)
}

// matchHost checks if a host matches an allowed pattern.
// Supports exact match and wildcard suffix matching (*.example.com).
func matchHost(host, pattern string) bool {
	host = normalizeHost(host)
	pattern = normalizeHost(pattern)

	if pattern == InsecureAllowAnyHost {
		return true
	}

	if host == pattern {
		return true
	}

	// Wildcard suffix matching: *.example.com matches sub.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	return false
}

// redactToken returns a redacted version of a token for safe logging.
// Short tokens (≤8 chars) are fully redacted as "***", while longer
// tokens show only the first 4 characters followed by "...".
func redactToken(token string) string {
	if len(token) == 0 {
		return "[empty]"
	}
	if len(token) <= 8 {
		return "[redacted]"
	}
	return token[:4] + "..." + token[len(token)-4:]
}
