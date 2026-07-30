package secrets

import (
	"context"
	"testing"
)

func TestEngine_Scan_GitHubToken(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	content := []byte(`
config:
  token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789
  name: test
`)

	findings, err := engine.Scan(t.Context(), content)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to find GitHub token, got no findings")
	}

	found := false
	for _, f := range findings {
		if f.Type == TypeGitHubToken {
			found = true
			if f.Line != 3 {
				t.Errorf("expected line 3, got %d", f.Line)
			}
			if f.Confidence < 0.9 {
				t.Errorf("expected high confidence, got %f", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected TypeGitHubToken in findings")
	}
}

func TestEngine_Scan_AWSAccessKey(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	content := []byte(`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`)

	findings, err := engine.Scan(t.Context(), content)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == TypeAWSAccessKey {
			found = true
		}
	}
	if !found {
		t.Error("expected to find AWS access key")
	}
}

func TestEngine_Scan_PrivateKey(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	content := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`)

	findings, err := engine.Scan(t.Context(), content)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == TypePrivateKey {
			found = true
		}
	}
	if !found {
		t.Error("expected to find private key")
	}
}

func TestEngine_Scan_JWT(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	// Example JWT (not a real secret)
	content := []byte(`token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`)

	findings, err := engine.Scan(t.Context(), content)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == TypeJWT {
			found = true
		}
	}
	if !found {
		t.Error("expected to find JWT")
	}
}

func TestEngine_Scan_SlackToken(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	content := []byte(`SLACK_TOKEN=xoxb-1234567890-1234567890123-abcdefghijklmnop`)

	findings, err := engine.Scan(t.Context(), content)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == TypeSlackToken {
			found = true
		}
	}
	if !found {
		t.Error("expected to find Slack token")
	}
}

func TestEngine_Scan_StripeKey(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	content := []byte(`stripe_key: sk_live_abcdefghijklmnopqrstuvwxyz`)

	findings, err := engine.Scan(t.Context(), content)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == TypeStripeKey {
			found = true
		}
	}
	if !found {
		t.Error("expected to find Stripe key")
	}
}

func TestEngine_Scan_NoSecrets(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	content := []byte(`
# This is a normal config file
name: myapp
version: 1.0.0
description: A normal application
`)

	findings, err := engine.Scan(t.Context(), content)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d: %+v", len(findings), findings)
	}
}

func TestEngine_Scan_SendGridKey(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	// SendGrid key format: SG.<22 chars>.<43 chars>
	content := []byte(`SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.wxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ012`)

	findings, err := engine.Scan(t.Context(), content)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == TypeSendGridKey {
			found = true
		}
	}
	if !found {
		t.Error("expected to find SendGrid key")
	}
}

func TestEngine_Scan_NpmToken(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	content := []byte(`//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789`)

	findings, err := engine.Scan(t.Context(), content)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == TypeNpmToken {
			found = true
		}
	}
	if !found {
		t.Error("expected to find npm token")
	}
}

func TestEngine_ScanFile(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	content := []byte(`token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789`)

	findings, err := engine.ScanFile(t.Context(), "config.yaml", content)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings")
	}

	if findings[0].File != "config.yaml" {
		t.Errorf("expected file config.yaml, got %s", findings[0].File)
	}
}

func TestIsSensitiveEnvName(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		expected bool
	}{
		{"password", "DATABASE_PASSWORD", true},
		{"token", "AUTH_TOKEN", true},
		{"api key", "STRIPE_API_KEY", true},
		{"secret", "MY_SECRET", true},
		{"normal", "DATABASE_HOST", false},
		{"normal port", "SERVER_PORT", false},
		{"mixed case", "github_token", true},
		{"apikey no underscore", "MYAPIKEY", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSensitiveEnvName(tt.envName)
			if got != tt.expected {
				t.Errorf("IsSensitiveEnvName(%q) = %v, want %v", tt.envName, got, tt.expected)
			}
		})
	}
}

func TestEngineConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  EngineConfig
		wantErr bool
	}{
		{
			name:    "default config is valid",
			config:  DefaultEngineConfig(),
			wantErr: false,
		},
		{
			name: "valid config with entropy",
			config: EngineConfig{
				EnableEntropy:    true,
				EntropyThreshold: 4.5,
				EntropyMinLength: 20,
			},
			wantErr: false,
		},
		{
			name: "entropy threshold too high",
			config: EngineConfig{
				EnableEntropy:    true,
				EntropyThreshold: 10.0,
				EntropyMinLength: 20,
			},
			wantErr: true,
		},
		{
			name: "entropy threshold negative",
			config: EngineConfig{
				EnableEntropy:    true,
				EntropyThreshold: -1.0,
				EntropyMinLength: 20,
			},
			wantErr: true,
		},
		{
			name: "entropy min length too small",
			config: EngineConfig{
				EnableEntropy:    true,
				EntropyThreshold: 4.5,
				EntropyMinLength: 5,
			},
			wantErr: true,
		},
		{
			name: "entropy min length too large",
			config: EngineConfig{
				EnableEntropy:    true,
				EntropyThreshold: 4.5,
				EntropyMinLength: 2000,
			},
			wantErr: true,
		},
		{
			name: "custom pattern with nil regex",
			config: EngineConfig{
				CustomPatterns: []PatternDetector{
					{Type: "test", Pattern: nil, Confidence: 0.9},
				},
			},
			wantErr: true,
		},
		{
			name: "custom pattern with empty type",
			config: EngineConfig{
				CustomPatterns: []PatternDetector{
					{Type: "", Pattern: nil, Confidence: 0.9},
				},
			},
			wantErr: true,
		},
		{
			name: "custom pattern with invalid confidence",
			config: EngineConfig{
				CustomPatterns: []PatternDetector{
					{Type: "test", Pattern: nil, Confidence: 1.5},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMultiScanner(t *testing.T) {
	engine1, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	engine2, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	multi := NewMultiScanner(engine1, engine2)

	content := []byte(`token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789`)

	findings, err := multi.Scan(t.Context(), content)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Should deduplicate findings from both engines
	githubTokenCount := 0
	for _, f := range findings {
		if f.Type == TypeGitHubToken {
			githubTokenCount++
		}
	}

	if githubTokenCount != 1 {
		t.Errorf("expected 1 deduplicated GitHub token, got %d", githubTokenCount)
	}
}

func TestFilteringScanner(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	content := []byte(`
token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789
stripe: sk_live_abcdefghijklmnopqrstuvwxyz
`)

	t.Run("allow types", func(t *testing.T) {
		filtered := NewFilteringScanner(engine, WithAllowedTypes(TypeGitHubToken))
		findings, err := filtered.Scan(t.Context(), content)
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}

		for _, f := range findings {
			if f.Type != TypeGitHubToken {
				t.Errorf("unexpected type %s, only TypeGitHubToken should pass", f.Type)
			}
		}
	})

	t.Run("deny types", func(t *testing.T) {
		filtered := NewFilteringScanner(engine, WithDeniedTypes(TypeGitHubToken))
		findings, err := filtered.Scan(t.Context(), content)
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}

		for _, f := range findings {
			if f.Type == TypeGitHubToken {
				t.Error("TypeGitHubToken should be filtered out")
			}
		}
	})

	t.Run("min confidence", func(t *testing.T) {
		filtered := NewFilteringScanner(engine, WithMinConfidence(0.98))
		findings, err := filtered.Scan(t.Context(), content)
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}

		for _, f := range findings {
			if f.Confidence < 0.98 {
				t.Errorf("finding %s has confidence %f, expected >= 0.98", f.Type, f.Confidence)
			}
		}
	})
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input  string
		minExp float64
		maxExp float64
	}{
		{"", 0, 0},
		{"aaaaaaaaaa", 0, 0.1},
		{"abcdefghij", 3.0, 4.0},
		{"aB3$xY9!zW", 3.0, 4.0},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 5.5, 6.5},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			if got < tt.minExp || got > tt.maxExp {
				t.Errorf("shannonEntropy(%q) = %f, expected between %f and %f", tt.input, got, tt.minExp, tt.maxExp)
			}
		})
	}
}

func TestIsLikelyFalsePositive(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		// UUIDs
		{"550e8400-e29b-41d4-a716-446655440000", true},
		// Hex hashes
		{"0123456789abcdef0123456789abcdef", true},
		{"0123456789abcdef0123456789abcdef01234567", true},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		// Excessive base64 padding
		{"abc===defghi===jklmno", true},
		// Version strings
		{"version_12345_build", true},
		// Repeated chars
		{"aaaaaaaaaaaaaaaaaaaa", true},
		// Random looking (not false positive)
		{"ghp_ABCDEFghijklmnopqrst", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isLikelyFalsePositive(tt.input)
			if got != tt.expected {
				t.Errorf("isLikelyFalsePositive(%q) = %v, expected %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestBatchScanner_ScanBatch(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	batch := NewBatchScanner(engine, 2)

	items := map[string][]byte{
		"config1.yaml": []byte(`token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789`),
		"config2.yaml": []byte(`key: sk_live_abcdefghijklmnopqrstuvwxyz`),
		"clean.yaml":   []byte(`name: test`),
	}

	results := batch.ScanBatch(t.Context(), items)

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	// Check results by ID
	resultMap := make(map[string]BatchResult)
	for _, r := range results {
		resultMap[r.ID] = r
	}

	// config1 should have GitHub token
	if r, ok := resultMap["config1.yaml"]; ok {
		if r.Error != nil {
			t.Errorf("config1.yaml error: %v", r.Error)
		}
		hasGitHub := false
		for _, f := range r.Findings {
			if f.Type == TypeGitHubToken {
				hasGitHub = true
			}
		}
		if !hasGitHub {
			t.Error("expected GitHub token in config1.yaml")
		}
	} else {
		t.Error("missing result for config1.yaml")
	}

	// config2 should have Stripe key
	if r, ok := resultMap["config2.yaml"]; ok {
		if r.Error != nil {
			t.Errorf("config2.yaml error: %v", r.Error)
		}
		hasStripe := false
		for _, f := range r.Findings {
			if f.Type == TypeStripeKey {
				hasStripe = true
			}
		}
		if !hasStripe {
			t.Error("expected Stripe key in config2.yaml")
		}
	} else {
		t.Error("missing result for config2.yaml")
	}

	// clean should have no findings
	if r, ok := resultMap["clean.yaml"]; ok {
		if r.Error != nil {
			t.Errorf("clean.yaml error: %v", r.Error)
		}
		if len(r.Findings) != 0 {
			t.Errorf("expected no findings in clean.yaml, got %d", len(r.Findings))
		}
	} else {
		t.Error("missing result for clean.yaml")
	}
}

func TestBatchScanner_ContextCancellation(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	batch := NewBatchScanner(engine, 1)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	items := map[string][]byte{
		"file1.yaml": []byte(`token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789`),
		"file2.yaml": []byte(`key: sk_live_abcdefghijklmnopqrstuvwxyz`),
	}

	results := batch.ScanBatch(ctx, items)

	// Should have results for all items (some may have context errors)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}
