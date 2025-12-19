package auth

import (
	"errors"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	// Verify sentinel errors are properly defined and can be used with errors.Is
	tests := []struct {
		name string
		err  error
	}{
		{"ErrNoCredential", ErrNoCredential},
		{"ErrCredentialExpired", ErrCredentialExpired},
		{"ErrHostMismatch", ErrHostMismatch},
		{"ErrUnsupportedCredentialType", ErrUnsupportedCredentialType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Error("sentinel error is nil")
			}
			if tt.err.Error() == "" {
				t.Error("sentinel error has empty message")
			}
			// Verify it can be wrapped and unwrapped
			wrapped := errors.Join(tt.err, errors.New("context"))
			if !errors.Is(wrapped, tt.err) {
				t.Error("wrapped error does not match original")
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"github.com", "github.com"},
		{"GITHUB.COM", "github.com"},
		{"  github.com  ", "github.com"},
		{"github.com:443", "github.com"},
		{"api.github.com:8080", "api.github.com"},
		{"localhost:3000", "localhost"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeHost(tt.input)
			if got != tt.want {
				t.Errorf("normalizeHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://github.com/user/repo", "github.com"},
		{"https://github.com:443/user/repo", "github.com"},
		{"http://localhost:3000/api", "localhost"},
		{"github.com/user/repo", "github.com"},
		{"api.github.com", "api.github.com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractHost(tt.input)
			if got != tt.want {
				t.Errorf("extractHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMatchHost(t *testing.T) {
	tests := []struct {
		host    string
		pattern string
		want    bool
	}{
		{"github.com", "github.com", true},
		{"GITHUB.COM", "github.com", true},
		{"api.github.com", "github.com", false},
		{"api.github.com", "*.github.com", true},
		{"sub.api.github.com", "*.github.com", true},
		{"gitlab.com", "*.github.com", false},
		{"anything.com", "*", true},
		{"", "github.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host+"_"+tt.pattern, func(t *testing.T) {
			got := matchHost(tt.host, tt.pattern)
			if got != tt.want {
				t.Errorf("matchHost(%q, %q) = %v, want %v", tt.host, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestRedactToken(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "[empty]"},
		{"abc", "[redacted]"},
		{"12345678", "[redacted]"},
		{"ghp_xxxxxxxxxxxxxxxxxxxxxxxxx", "ghp_...xxxx"},
		{"sk-1234567890abcdef", "sk-1...cdef"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := redactToken(tt.input)
			if got != tt.want {
				t.Errorf("redactToken(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTokenCredential_ValidForHost(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		host    string
		want    bool
	}{
		{
			name:    "empty disallowed",
			allowed: nil,
			host:    "anything.com",
			want:    false,
		},
		{
			name:    "explicit insecure any host",
			allowed: InsecureAllowAnyHosts(),
			host:    "anything.com",
			want:    true,
		},
		{
			name:    "exact match",
			allowed: []string{"github.com"},
			host:    "github.com",
			want:    true,
		},
		{
			name:    "exact match case insensitive",
			allowed: []string{"github.com"},
			host:    "GITHUB.COM",
			want:    true,
		},
		{
			name:    "no match",
			allowed: []string{"github.com"},
			host:    "gitlab.com",
			want:    false,
		},
		{
			name:    "wildcard match",
			allowed: []string{"*.github.com"},
			host:    "api.github.com",
			want:    true,
		},
		{
			name:    "wildcard no match for exact",
			allowed: []string{"*.github.com"},
			host:    "github.com",
			want:    false,
		},
		{
			name:    "multiple allowed",
			allowed: []string{"github.com", "api.github.com"},
			host:    "api.github.com",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &TokenCredential{
				Token:        "secret",
				AllowedHosts: tt.allowed,
			}
			got := cred.ValidForHost(tt.host)
			if got != tt.want {
				t.Errorf("ValidForHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestTokenCredential_Redacted(t *testing.T) {
	cred := &TokenCredential{
		Token:        "ghp_verylongsecrettoken",
		AllowedHosts: []string{"github.com"},
		Source:       "GITHUB_TOKEN",
	}
	got := cred.Redacted()
	if got == "" {
		t.Error("Redacted() returned empty string")
	}
	if containsSubstring(got, "verylongsecrettoken") {
		t.Error("Redacted() contains secret token")
	}
	if !containsSubstring(got, "ghp_") {
		t.Error("Redacted() should show prefix")
	}
	if !containsSubstring(got, "GITHUB_TOKEN") {
		t.Error("Redacted() should show source")
	}
}

func TestBasicCredential_ValidForHost(t *testing.T) {
	cred := &BasicCredential{
		Username:     "user",
		Password:     "pass",
		AllowedHosts: []string{"registry.npmjs.org"},
	}

	if !cred.ValidForHost("registry.npmjs.org") {
		t.Error("should be valid for allowed host")
	}
	if cred.ValidForHost("evil.com") {
		t.Error("should not be valid for other hosts")
	}
}

func TestDockerCredential_ValidForHost(t *testing.T) {
	cred := &DockerCredential{
		Username:      "user",
		Password:      "pass",
		ServerAddress: "https://index.docker.io/v1/",
	}

	if !cred.ValidForHost("index.docker.io") {
		t.Error("should be valid for server address host")
	}
	if cred.ValidForHost("gcr.io") {
		t.Error("should not be valid for other hosts")
	}
}

func TestDockerCredential_NoServerAddress(t *testing.T) {
	cred := &DockerCredential{
		Username: "user",
		Password: "pass",
	}

	if cred.ValidForHost("any.host") {
		t.Error("should not be valid without server address")
	}
	if len(cred.Hosts()) != 0 {
		t.Error("Hosts() should return empty slice without server address")
	}
}

func TestCredentialType_String(t *testing.T) {
	tests := []struct {
		ct   CredentialType
		want string
	}{
		{TypeToken, "token"},
		{TypeBasic, "basic"},
		{TypeSSH, "ssh"},
		{TypeDocker, "docker"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.ct.String(); got != tt.want {
				t.Errorf("CredentialType.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTokenCredential_String(t *testing.T) {
	cred := &TokenCredential{
		Token:        "ghp_verylongsecrettoken",
		AllowedHosts: []string{"github.com"},
		Source:       "GITHUB_TOKEN",
	}
	s := cred.String()
	if s == "" {
		t.Error("String() returned empty")
	}
	if containsSubstring(s, "verylongsecrettoken") {
		t.Error("String() should not contain full secret")
	}
}

func TestTokenCredential_Hosts(t *testing.T) {
	cred := &TokenCredential{
		Token:        "token",
		AllowedHosts: []string{"github.com", "api.github.com"},
	}
	hosts := cred.Hosts()
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
}

func TestTokenCredential_CredentialSource(t *testing.T) {
	cred := &TokenCredential{
		Token:        "token",
		AllowedHosts: []string{"github.com"},
		Source:       "GITHUB_TOKEN",
	}
	if cred.CredentialSource() != "GITHUB_TOKEN" {
		t.Errorf("expected source GITHUB_TOKEN, got %s", cred.CredentialSource())
	}
}

func TestBasicCredential_String(t *testing.T) {
	cred := &BasicCredential{
		Username:     "user",
		Password:     "secretpassword123",
		AllowedHosts: []string{"registry.npmjs.org"},
		Source:       "NPM_AUTH",
	}
	s := cred.String()
	if containsSubstring(s, "secretpassword") {
		t.Error("String() should not contain password")
	}
}

func TestBasicCredential_Hosts(t *testing.T) {
	cred := &BasicCredential{
		Username:     "user",
		Password:     "pass",
		AllowedHosts: []string{"registry.npmjs.org"},
	}
	hosts := cred.Hosts()
	if len(hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(hosts))
	}
}

func TestBasicCredential_CredentialSource(t *testing.T) {
	cred := &BasicCredential{
		Username:     "user",
		Password:     "pass",
		AllowedHosts: []string{"npmjs.org"},
		Source:       "NPM_AUTH",
	}
	if cred.CredentialSource() != "NPM_AUTH" {
		t.Errorf("expected source NPM_AUTH, got %s", cred.CredentialSource())
	}
}

func TestBasicCredential_Redacted(t *testing.T) {
	cred := &BasicCredential{
		Username:     "user",
		Password:     "secretpassword123",
		AllowedHosts: []string{"registry.npmjs.org"},
	}
	r := cred.Redacted()
	if containsSubstring(r, "secretpassword") {
		t.Error("Redacted() should not contain password")
	}
	if !containsSubstring(r, "user") {
		t.Error("Redacted() should show username")
	}
}

func TestSSHCredential_Hosts(t *testing.T) {
	cred := &SSHCredential{
		User:         "git",
		PrivateKey:   []byte("fake-key"),
		AllowedHosts: []string{"github.com", "gitlab.com"},
	}
	hosts := cred.Hosts()
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
}

func TestSSHCredential_Redacted(t *testing.T) {
	cred := &SSHCredential{
		User:         "git",
		PrivateKey:   []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"),
		AllowedHosts: []string{"github.com"},
	}
	r := cred.Redacted()
	if containsSubstring(r, "secret") {
		t.Error("Redacted() should not contain key content")
	}
}

func TestSSHCredential_CredentialSource(t *testing.T) {
	cred := &SSHCredential{
		User:         "git",
		PrivateKey:   []byte("key"),
		AllowedHosts: []string{"github.com"},
		Source:       "~/.ssh/id_rsa",
	}
	if cred.CredentialSource() != "~/.ssh/id_rsa" {
		t.Errorf("expected source ~/.ssh/id_rsa, got %s", cred.CredentialSource())
	}
}

func TestSSHCredential_String(t *testing.T) {
	cred := &SSHCredential{
		User:         "git",
		PrivateKey:   []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"),
		AllowedHosts: []string{"github.com"},
	}
	s := cred.String()
	if containsSubstring(s, "secret") {
		t.Error("String() should not contain key content")
	}
}

func TestDockerCredential_Redacted(t *testing.T) {
	cred := &DockerCredential{
		Username:      "user",
		Password:      "secretdockerpass",
		ServerAddress: "https://index.docker.io/v1/",
	}
	r := cred.Redacted()
	if containsSubstring(r, "secretdockerpass") {
		t.Error("Redacted() should not contain password")
	}
	if !containsSubstring(r, "index.docker.io") {
		t.Error("Redacted() should show server address")
	}
}

func TestDockerCredential_BasicAuth(t *testing.T) {
	cred := &DockerCredential{
		Username:      "user",
		Password:      "pass",
		ServerAddress: "https://index.docker.io/v1/",
	}
	u, p := cred.BasicAuth()
	if u != "user" || p != "pass" {
		t.Errorf("BasicAuth() = (%q, %q), want (user, pass)", u, p)
	}
}

func TestDockerCredential_CredentialSource(t *testing.T) {
	cred := &DockerCredential{
		Username:      "user",
		Password:      "pass",
		ServerAddress: "https://index.docker.io/v1/",
		Source:        "~/.docker/config.json",
	}
	if cred.CredentialSource() != "~/.docker/config.json" {
		t.Errorf("expected source ~/.docker/config.json, got %s", cred.CredentialSource())
	}
}

func TestDockerCredential_String(t *testing.T) {
	cred := &DockerCredential{
		Username:      "user",
		Password:      "secretdockerpass",
		ServerAddress: "https://index.docker.io/v1/",
	}
	s := cred.String()
	if containsSubstring(s, "secretdockerpass") {
		t.Error("String() should not contain password")
	}
}

func TestNewInsecureTokenForAnyHost(t *testing.T) {
	cred := NewInsecureTokenForAnyHost("secret-token", "test-source")

	if cred.Token != "secret-token" {
		t.Errorf("expected token 'secret-token', got %q", cred.Token)
	}
	if cred.Source != "test-source" {
		t.Errorf("expected source 'test-source', got %q", cred.Source)
	}
	if !cred.ValidForHost("any.host.com") {
		t.Error("should be valid for any host")
	}
	if !cred.ValidForHost("another.host.io") {
		t.Error("should be valid for any host")
	}
	if len(cred.AllowedHosts) != 1 || cred.AllowedHosts[0] != InsecureAllowAnyHost {
		t.Errorf("expected InsecureAllowAnyHost, got %v", cred.AllowedHosts)
	}
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
