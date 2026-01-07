package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpapikey"
	"github.com/google/osv-scalibr/veles/secrets/gcpsak"
	"github.com/google/osv-scalibr/veles/secrets/rubygemsapikey"
)

// SecretType identifies the kind of secret detected.
type SecretType string

const (
	// Veles-detected types
	TypeGCPAPIKey            SecretType = "gcp_api_key"
	TypeGCPServiceAccountKey SecretType = "gcp_service_account_key"
	TypeRubyGemsAPIKey       SecretType = "rubygems_api_key"

	// Pattern-detected types
	TypeAWSAccessKey     SecretType = "aws_access_key"
	TypeAWSSecretKey     SecretType = "aws_secret_key"
	TypeGitHubToken      SecretType = "github_token"
	TypeGitHubFineGrain  SecretType = "github_fine_grained_token"
	TypeGenericAPIKey    SecretType = "generic_api_key"
	TypePrivateKey       SecretType = "private_key"
	TypeJWT              SecretType = "jwt"
	TypeSlackToken       SecretType = "slack_token"
	TypeStripeKey        SecretType = "stripe_key"
	TypeSendGridKey      SecretType = "sendgrid_key"
	TypeNpmToken         SecretType = "npm_token"
	TypePyPIToken        SecretType = "pypi_token"
	TypeDiscordToken     SecretType = "discord_token"
	TypeTelegramToken    SecretType = "telegram_token"
	TypeHerokuAPIKey     SecretType = "heroku_api_key"
	TypeMailgunKey       SecretType = "mailgun_key"
	TypeTwilioKey        SecretType = "twilio_key"
	TypeHighEntropy      SecretType = "high_entropy_string"
	TypeSensitiveEnvVar  SecretType = "sensitive_env_var"

	// Additional patterns
	TypeSlackWebhook      SecretType = "slack_webhook"
	TypeTerraformToken    SecretType = "terraform_token"
	TypeCloudflareAPIKey  SecretType = "cloudflare_api_key"
	TypeDatadogAPIKey     SecretType = "datadog_api_key"
	TypeLinearAPIKey      SecretType = "linear_api_key"
	TypeOpenAIKey         SecretType = "openai_api_key"
	TypeAnthropicKey      SecretType = "anthropic_api_key"
	TypeAzureSASToken     SecretType = "azure_sas_token"
	TypeGitLabToken       SecretType = "gitlab_token"
	TypeBitbucketToken    SecretType = "bitbucket_token"
	TypeDigitalOceanToken SecretType = "digitalocean_token"
)

// Finding represents a detected secret.
type Finding struct {
	// Type identifies what kind of secret was found.
	Type SecretType `json:"type"`

	// Description provides human-readable context.
	Description string `json:"description"`

	// File is the source file where the secret was found (if applicable).
	File string `json:"file,omitempty"`

	// Line number where the secret was found (1-indexed, 0 if unknown).
	Line int `json:"line,omitempty"`

	// Column where the secret starts (1-indexed, 0 if unknown).
	Column int `json:"column,omitempty"`

	// Value is the actual secret value (for masking purposes).
	// This should NOT be logged or exposed in reports.
	Value string `json:"-"`

	// Redacted is a safe representation for display.
	Redacted string `json:"redacted"`

	// Confidence indicates detection certainty (0.0-1.0).
	Confidence float64 `json:"confidence"`

	// Validated indicates if the secret was verified as active.
	Validated bool `json:"validated,omitempty"`
}

// EngineConfig configures the secret detection engine.
type EngineConfig struct {
	// EnableEntropy enables entropy-based detection for unknown secret formats.
	EnableEntropy bool
	// EntropyThreshold is the minimum Shannon entropy to flag (0-8 for bytes).
	// Default is 4.5, which catches most random strings while avoiding false positives.
	EntropyThreshold float64
	// EntropyMinLength is the minimum string length for entropy detection.
	EntropyMinLength int
	// DisabledPatterns allows disabling specific pattern detectors.
	DisabledPatterns map[SecretType]bool
	// CustomPatterns allows adding custom pattern detectors.
	CustomPatterns []PatternDetector
}

// DefaultEngineConfig returns sensible defaults for secret detection.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		EnableEntropy:    false, // Disabled by default to reduce false positives
		EntropyThreshold: 4.5,   // High entropy threshold
		EntropyMinLength: 20,    // Minimum 20 chars for entropy detection
		DisabledPatterns: make(map[SecretType]bool),
	}
}

// Validate checks the configuration for errors.
func (c EngineConfig) Validate() error {
	var errs []error

	if c.EnableEntropy {
		// Shannon entropy for printable ASCII is roughly 0-6.5
		if c.EntropyThreshold < 0 || c.EntropyThreshold > 8 {
			errs = append(errs, fmt.Errorf("entropy threshold must be between 0 and 8, got %f", c.EntropyThreshold))
		}
		if c.EntropyMinLength < 8 {
			errs = append(errs, fmt.Errorf("entropy min length must be at least 8, got %d", c.EntropyMinLength))
		}
		if c.EntropyMinLength > 1000 {
			errs = append(errs, fmt.Errorf("entropy min length must be at most 1000, got %d", c.EntropyMinLength))
		}
	}

	for _, cp := range c.CustomPatterns {
		if cp.Pattern == nil {
			errs = append(errs, fmt.Errorf("custom pattern for type %q has nil regex", cp.Type))
		}
		if cp.Type == "" {
			errs = append(errs, errors.New("custom pattern has empty type"))
		}
		if cp.Confidence < 0 || cp.Confidence > 1 {
			errs = append(errs, fmt.Errorf("custom pattern %q confidence must be between 0 and 1, got %f", cp.Type, cp.Confidence))
		}
	}

	return errors.Join(errs...)
}

// PatternDetector defines a regex-based secret detector (exported for extensibility).
type PatternDetector struct {
	Type        SecretType
	Pattern     *regexp.Regexp
	Description string
	Confidence  float64
}

// Engine provides secret detection capabilities.
type Engine struct {
	velesEngine *veles.DetectionEngine
	patterns    []patternDetector
	config      EngineConfig
}

// patternDetector defines a regex-based secret detector.
type patternDetector struct {
	Type        SecretType
	Pattern     *regexp.Regexp
	Description string
	Confidence  float64
}

// NewEngine creates a new secret detection engine with default configuration.
func NewEngine() (*Engine, error) {
	return NewEngineWithConfig(DefaultEngineConfig())
}

// NewEngineWithConfig creates a new secret detection engine with custom configuration.
func NewEngineWithConfig(config EngineConfig) (*Engine, error) {
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid engine config: %w", err)
	}

	// Initialize Veles detectors
	detectors := []veles.Detector{
		gcpapikey.NewDetector(),
		gcpsak.NewDetector(),
		rubygemsapikey.NewDetector(),
	}

	velesEngine, err := veles.NewDetectionEngine(detectors)
	if err != nil {
		return nil, err
	}

	// Initialize pattern-based detectors
	patterns := []patternDetector{
		// AWS
		{
			Type:        TypeAWSAccessKey,
			Pattern:     regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
			Description: "AWS Access Key ID",
			Confidence:  0.95,
		},
		{
			Type: TypeAWSSecretKey,
			// Fixed: AWS secret keys are base64, typically 40 chars but can vary 32-64
			Pattern:     regexp.MustCompile(`(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{32,64})["']?`),
			Description: "AWS Secret Access Key",
			Confidence:  0.9,
		},

		// GitHub
		{
			Type:        TypeGitHubToken,
			Pattern:     regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
			Description: "GitHub Personal Access Token (classic)",
			Confidence:  0.99,
		},
		{
			Type:        TypeGitHubFineGrain,
			Pattern:     regexp.MustCompile(`github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`),
			Description: "GitHub Fine-Grained Personal Access Token",
			Confidence:  0.99,
		},

		// GitLab
		{
			Type:        TypeGitLabToken,
			Pattern:     regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`),
			Description: "GitLab Personal Access Token",
			Confidence:  0.98,
		},

		// Slack
		{
			Type:        TypeSlackToken,
			Pattern:     regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
			Description: "Slack Token",
			Confidence:  0.95,
		},
		{
			Type:        TypeSlackWebhook,
			Pattern:     regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}`),
			Description: "Slack Webhook URL",
			Confidence:  0.98,
		},

		// Stripe
		{
			Type:        TypeStripeKey,
			Pattern:     regexp.MustCompile(`(?:sk|pk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}`),
			Description: "Stripe API Key",
			Confidence:  0.95,
		},

		// SendGrid
		{
			Type:        TypeSendGridKey,
			Pattern:     regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
			Description: "SendGrid API Key",
			Confidence:  0.98,
		},

		// npm
		{
			Type:        TypeNpmToken,
			Pattern:     regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
			Description: "npm Access Token",
			Confidence:  0.98,
		},

		// PyPI
		{
			Type:        TypePyPIToken,
			Pattern:     regexp.MustCompile(`pypi-[A-Za-z0-9_-]{50,}`),
			Description: "PyPI API Token",
			Confidence:  0.98,
		},

		// Discord - updated pattern for current token format
		{
			Type:        TypeDiscordToken,
			Pattern:     regexp.MustCompile(`[A-Za-z0-9]{24,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}`),
			Description: "Discord Token",
			Confidence:  0.9,
		},

		// Telegram
		{
			Type:        TypeTelegramToken,
			Pattern:     regexp.MustCompile(`[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}`),
			Description: "Telegram Bot Token",
			Confidence:  0.9,
		},

		// Heroku
		{
			Type:        TypeHerokuAPIKey,
			Pattern:     regexp.MustCompile(`[hH]eroku.*[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`),
			Description: "Heroku API Key",
			Confidence:  0.85,
		},

		// Mailgun
		{
			Type:        TypeMailgunKey,
			Pattern:     regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
			Description: "Mailgun API Key",
			Confidence:  0.85,
		},

		// Twilio
		{
			Type:        TypeTwilioKey,
			Pattern:     regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
			Description: "Twilio API Key",
			Confidence:  0.85,
		},

		// Terraform Cloud
		{
			Type:        TypeTerraformToken,
			Pattern:     regexp.MustCompile(`(?i)(?:TFE|atlasv1)\.[A-Za-z0-9]{14,}\.[A-Za-z0-9]{67,}`),
			Description: "Terraform Cloud/Enterprise Token",
			Confidence:  0.95,
		},

		// Cloudflare
		{
			Type:        TypeCloudflareAPIKey,
			Pattern:     regexp.MustCompile(`(?i)(?:cloudflare|cf).*[0-9a-f]{37}`),
			Description: "Cloudflare API Key",
			Confidence:  0.85,
		},

		// Datadog
		{
			Type:        TypeDatadogAPIKey,
			Pattern:     regexp.MustCompile(`(?i)(?:datadog|dd).*[0-9a-f]{32}`),
			Description: "Datadog API Key",
			Confidence:  0.85,
		},

		// OpenAI
		{
			Type:        TypeOpenAIKey,
			Pattern:     regexp.MustCompile(`sk-[A-Za-z0-9]{48}`),
			Description: "OpenAI API Key",
			Confidence:  0.95,
		},

		// Anthropic
		{
			Type:        TypeAnthropicKey,
			Pattern:     regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{95,}`),
			Description: "Anthropic API Key",
			Confidence:  0.98,
		},

		// Linear
		{
			Type:        TypeLinearAPIKey,
			Pattern:     regexp.MustCompile(`lin_api_[A-Za-z0-9]{40}`),
			Description: "Linear API Key",
			Confidence:  0.95,
		},

		// Azure SAS
		{
			Type:        TypeAzureSASToken,
			Pattern:     regexp.MustCompile(`(?i)(?:sv|sig|se|sp)=[^&\s]{10,}`),
			Description: "Azure SAS Token",
			Confidence:  0.75,
		},

		// Bitbucket
		{
			Type:        TypeBitbucketToken,
			Pattern:     regexp.MustCompile(`ATBB[A-Za-z0-9]{32}`),
			Description: "Bitbucket App Password",
			Confidence:  0.95,
		},

		// DigitalOcean
		{
			Type:        TypeDigitalOceanToken,
			Pattern:     regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
			Description: "DigitalOcean Personal Access Token",
			Confidence:  0.98,
		},

		// Private keys
		{
			Type:        TypePrivateKey,
			Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?:\s+BLOCK)?-----`),
			Description: "Private Key",
			Confidence:  0.99,
		},

		// JWT
		{
			Type:        TypeJWT,
			Pattern:     regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			Description: "JSON Web Token",
			Confidence:  0.95,
		},

		// Generic API Key - increased min length and confidence
		{
			Type:        TypeGenericAPIKey,
			Pattern:     regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api_secret|auth[_-]?token|access[_-]?token)["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{24,})["']?`),
			Description: "Generic API Key pattern",
			Confidence:  0.75,
		},
	}

	// Add custom patterns from config
	for _, cp := range config.CustomPatterns {
		patterns = append(patterns, patternDetector{
			Type:        cp.Type,
			Pattern:     cp.Pattern,
			Description: cp.Description,
			Confidence:  cp.Confidence,
		})
	}

	return &Engine{
		velesEngine: velesEngine,
		patterns:    patterns,
		config:      config,
	}, nil
}

// Scan detects secrets in the given content.
func (e *Engine) Scan(ctx context.Context, content []byte) ([]Finding, error) {
	var findings []Finding

	// Run Veles detection
	velesFindings, err := e.velesEngine.Detect(ctx, bytes.NewReader(content))
	if err != nil {
		// Log but don't fail - continue with pattern detection
		// Veles errors shouldn't block pattern-based detection
	}
	for _, vf := range velesFindings {
		secretType := velesSecretType(vf)
		// Skip disabled patterns
		if e.config.DisabledPatterns[secretType] {
			continue
		}
		finding := Finding{
			Type:       secretType,
			Confidence: 0.95, // Veles has high confidence
			Redacted:   redact(vf),
		}
		// Try to extract actual value for masking
		if s, ok := vf.(interface{ String() string }); ok {
			finding.Value = s.String()
		}
		findings = append(findings, finding)
	}

	// Track matched positions to avoid duplicates with entropy detection
	matchedPositions := make(map[int]bool)

	// Run pattern-based detection
	lines := bytes.Split(content, []byte("\n"))
	for lineNum, line := range lines {
		for _, pd := range e.patterns {
			// Skip disabled patterns
			if e.config.DisabledPatterns[pd.Type] {
				continue
			}
			matches := pd.Pattern.FindAllIndex(line, -1)
			for _, match := range matches {
				value := string(line[match[0]:match[1]])
				findings = append(findings, Finding{
					Type:        pd.Type,
					Description: pd.Description,
					Line:        lineNum + 1,
					Column:      match[0] + 1,
					Value:       value,
					Redacted:    redactValue(value, pd.Type),
					Confidence:  pd.Confidence,
				})
				// Mark this region as matched
				for i := match[0]; i < match[1]; i++ {
					matchedPositions[lineNum*10000+i] = true
				}
			}
		}
	}

	// Run entropy-based detection if enabled
	if e.config.EnableEntropy {
		entropyFindings := e.detectHighEntropyStrings(lines, matchedPositions)
		findings = append(findings, entropyFindings...)
	}

	return findings, nil
}

// detectHighEntropyStrings finds high-entropy strings that weren't matched by patterns.
func (e *Engine) detectHighEntropyStrings(lines [][]byte, matchedPositions map[int]bool) []Finding {
	var findings []Finding

	// Regex to find potential secret-like strings (alphanumeric with some special chars)
	secretLikePattern := regexp.MustCompile(`[A-Za-z0-9_\-+/=]{` + string(rune('0'+e.config.EntropyMinLength/10)) + string(rune('0'+e.config.EntropyMinLength%10)) + `,}`)

	for lineNum, line := range lines {
		matches := secretLikePattern.FindAllIndex(line, -1)
		for _, match := range matches {
			// Skip if already matched by a pattern
			alreadyMatched := false
			for i := match[0]; i < match[1]; i++ {
				if matchedPositions[lineNum*10000+i] {
					alreadyMatched = true
					break
				}
			}
			if alreadyMatched {
				continue
			}

			value := string(line[match[0]:match[1]])

			// Skip if too short
			if len(value) < e.config.EntropyMinLength {
				continue
			}

			// Calculate Shannon entropy
			entropy := shannonEntropy(value)
			if entropy >= e.config.EntropyThreshold {
				// Skip common false positives
				if isLikelyFalsePositive(value) {
					continue
				}

				findings = append(findings, Finding{
					Type:        TypeHighEntropy,
					Description: "High-entropy string (possible secret)",
					Line:        lineNum + 1,
					Column:      match[0] + 1,
					Value:       value,
					Redacted:    redactValue(value, TypeHighEntropy),
					Confidence:  0.6 + (entropy-e.config.EntropyThreshold)*0.1, // Scale confidence by entropy
				})
			}
		}
	}

	return findings
}

// shannonEntropy calculates the Shannon entropy of a string.
// Returns a value between 0 (no randomness) and log2(alphabet_size) (max randomness).
// For printable ASCII, max is about 6.5-7.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// isLikelyFalsePositive checks if a high-entropy string is likely a false positive.
func isLikelyFalsePositive(s string) bool {
	lower := strings.ToLower(s)

	// Skip UUIDs (common in code)
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}

	// Skip hex strings that look like hashes
	if isAllHex(s) && (len(s) == 32 || len(s) == 40 || len(s) == 64) {
		return true
	}

	// Skip base64 padding-heavy strings (likely encoded data, not secrets)
	if strings.Count(s, "=") > 2 {
		return true
	}

	// Skip strings that look like version numbers or build IDs
	if strings.Contains(lower, "version") || strings.Contains(lower, "build") {
		return true
	}

	// Skip strings that are all the same character repeated
	if len(s) > 0 {
		allSame := true
		first := s[0]
		for i := 1; i < len(s); i++ {
			if s[i] != first {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	return false
}

// isAllHex returns true if the string contains only hex characters.
func isAllHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ScanFile detects secrets in the given file content.
func (e *Engine) ScanFile(ctx context.Context, filename string, content []byte) ([]Finding, error) {
	findings, err := e.Scan(ctx, content)
	if err != nil {
		return nil, err
	}

	// Annotate with filename
	for i := range findings {
		findings[i].File = filename
	}

	return findings, nil
}

// velesSecretType maps Veles secret types to our SecretType.
func velesSecretType(secret veles.Secret) SecretType {
	switch secret.(type) {
	case *gcpapikey.GCPAPIKey:
		return TypeGCPAPIKey
	case *gcpsak.GCPSAK:
		return TypeGCPServiceAccountKey
	case *rubygemsapikey.RubyGemsAPIKey:
		return TypeRubyGemsAPIKey
	default:
		return SecretType("unknown")
	}
}

// redact creates a safe redacted representation of a Veles secret.
func redact(secret veles.Secret) string {
	switch s := secret.(type) {
	case *gcpapikey.GCPAPIKey:
		if len(s.Key) >= 8 {
			return "[REDACTED:GCP_API_KEY:" + s.Key[:8] + "...]"
		}
		return "[REDACTED:GCP_API_KEY]"
	case *gcpsak.GCPSAK:
		return "[REDACTED:GCP_SERVICE_ACCOUNT_KEY]"
	case *rubygemsapikey.RubyGemsAPIKey:
		return "[REDACTED:RUBYGEMS_API_KEY]"
	default:
		return "[REDACTED:SECRET]"
	}
}

// redactValue creates a safe redacted representation for pattern matches.
func redactValue(value string, secretType SecretType) string {
	if len(value) <= 8 {
		return "[REDACTED:" + string(secretType) + "]"
	}
	// Show first 4 chars for context
	return "[REDACTED:" + string(secretType) + ":" + value[:4] + "...]"
}

// SensitiveEnvPatterns returns patterns for detecting sensitive environment variable names.
// This is used for env var name detection (not value detection).
var SensitiveEnvPatterns = []string{
	"PASSWORD", "PASSWD", "PWD",
	"SECRET", "KEY", "TOKEN",
	"API_KEY", "APIKEY",
	"PRIVATE", "CREDENTIAL",
	"AUTH", "ACCESS_KEY",
	"AWS_SECRET", "GITHUB_TOKEN",
	"DATABASE_URL", "CONNECTION_STRING",
}

// IsSensitiveEnvName returns true if the environment variable name
// matches sensitive patterns.
func IsSensitiveEnvName(name string) bool {
	nameUpper := strings.ToUpper(name)
	for _, pattern := range SensitiveEnvPatterns {
		if strings.Contains(nameUpper, pattern) {
			return true
		}
	}
	return false
}

// Scanner defines the interface for secret scanning.
// This allows for composable, pluggable scanner implementations.
type Scanner interface {
	// Scan analyzes content and returns any detected secrets.
	Scan(ctx context.Context, content []byte) ([]Finding, error)

	// ScanFile analyzes file content with filename context.
	ScanFile(ctx context.Context, filename string, content []byte) ([]Finding, error)
}

// Ensure Engine implements Scanner.
var _ Scanner = (*Engine)(nil)

// MultiScanner composes multiple scanners, deduplicating results.
type MultiScanner struct {
	scanners []Scanner
}

// NewMultiScanner creates a scanner that runs multiple scanners and combines results.
func NewMultiScanner(scanners ...Scanner) *MultiScanner {
	return &MultiScanner{scanners: scanners}
}

// Scan runs all scanners and returns combined, deduplicated findings.
func (m *MultiScanner) Scan(ctx context.Context, content []byte) ([]Finding, error) {
	var allFindings []Finding
	seen := make(map[string]bool)

	for _, scanner := range m.scanners {
		findings, err := scanner.Scan(ctx, content)
		if err != nil {
			// Continue with other scanners on error
			continue
		}
		for _, f := range findings {
			// Deduplicate by type+line+column+value hash
			key := dedupKey(f)
			if !seen[key] {
				seen[key] = true
				allFindings = append(allFindings, f)
			}
		}
	}

	return allFindings, nil
}

// ScanFile runs all scanners with filename context.
func (m *MultiScanner) ScanFile(ctx context.Context, filename string, content []byte) ([]Finding, error) {
	findings, err := m.Scan(ctx, content)
	if err != nil {
		return nil, err
	}

	// Annotate with filename
	for i := range findings {
		findings[i].File = filename
	}

	return findings, nil
}

// Ensure MultiScanner implements Scanner.
var _ Scanner = (*MultiScanner)(nil)

// dedupKey generates a unique key for deduplication.
func dedupKey(f Finding) string {
	return string(f.Type) + ":" + f.File + ":" + string(rune(f.Line)) + ":" + string(rune(f.Column)) + ":" + f.Value
}

// FilteringScanner wraps a scanner with filtering capabilities.
type FilteringScanner struct {
	scanner    Scanner
	allowTypes map[SecretType]bool // If set, only allow these types
	denyTypes  map[SecretType]bool // If set, block these types
	minConf    float64             // Minimum confidence threshold
}

// FilteringScannerOption configures a FilteringScanner.
type FilteringScannerOption func(*FilteringScanner)

// WithAllowedTypes only reports findings of specified types.
func WithAllowedTypes(types ...SecretType) FilteringScannerOption {
	return func(fs *FilteringScanner) {
		if fs.allowTypes == nil {
			fs.allowTypes = make(map[SecretType]bool)
		}
		for _, t := range types {
			fs.allowTypes[t] = true
		}
	}
}

// WithDeniedTypes excludes findings of specified types.
func WithDeniedTypes(types ...SecretType) FilteringScannerOption {
	return func(fs *FilteringScanner) {
		if fs.denyTypes == nil {
			fs.denyTypes = make(map[SecretType]bool)
		}
		for _, t := range types {
			fs.denyTypes[t] = true
		}
	}
}

// WithMinConfidence only reports findings above the threshold.
func WithMinConfidence(conf float64) FilteringScannerOption {
	return func(fs *FilteringScanner) {
		fs.minConf = conf
	}
}

// NewFilteringScanner wraps a scanner with filtering options.
func NewFilteringScanner(scanner Scanner, opts ...FilteringScannerOption) *FilteringScanner {
	fs := &FilteringScanner{scanner: scanner}
	for _, opt := range opts {
		opt(fs)
	}
	return fs
}

// Scan runs the underlying scanner and filters results.
func (fs *FilteringScanner) Scan(ctx context.Context, content []byte) ([]Finding, error) {
	findings, err := fs.scanner.Scan(ctx, content)
	if err != nil {
		return nil, err
	}
	return fs.filter(findings), nil
}

// ScanFile runs the underlying scanner and filters results.
func (fs *FilteringScanner) ScanFile(ctx context.Context, filename string, content []byte) ([]Finding, error) {
	findings, err := fs.scanner.ScanFile(ctx, filename, content)
	if err != nil {
		return nil, err
	}
	return fs.filter(findings), nil
}

func (fs *FilteringScanner) filter(findings []Finding) []Finding {
	var filtered []Finding
	for _, f := range findings {
		// Check confidence threshold
		if fs.minConf > 0 && f.Confidence < fs.minConf {
			continue
		}
		// Check allow list
		if fs.allowTypes != nil && !fs.allowTypes[f.Type] {
			continue
		}
		// Check deny list
		if fs.denyTypes != nil && fs.denyTypes[f.Type] {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// Ensure FilteringScanner implements Scanner.
var _ Scanner = (*FilteringScanner)(nil)

// BatchResult represents the result of scanning a single item in a batch.
type BatchResult struct {
	// ID is the identifier for the scanned item (e.g., filename, path).
	ID string `json:"id"`
	// Findings are the secrets found in this item.
	Findings []Finding `json:"findings"`
	// Error is any error encountered during scanning (nil if successful).
	Error error `json:"error,omitempty"`
}

// BatchScanner provides concurrent batch scanning capabilities.
type BatchScanner struct {
	scanner     Scanner
	concurrency int
}

// NewBatchScanner creates a scanner for concurrent batch operations.
// Concurrency controls max parallel scans (defaults to runtime.NumCPU if <= 0).
func NewBatchScanner(scanner Scanner, concurrency int) *BatchScanner {
	if concurrency <= 0 {
		concurrency = 4 // Sensible default
	}
	return &BatchScanner{
		scanner:     scanner,
		concurrency: concurrency,
	}
}

// ScanBatch scans multiple content items concurrently and returns results.
// Items is a map of ID to content bytes.
func (b *BatchScanner) ScanBatch(ctx context.Context, items map[string][]byte) []BatchResult {
	results := make([]BatchResult, 0, len(items))
	resultCh := make(chan BatchResult, len(items))

	// Semaphore for concurrency control
	sem := make(chan struct{}, b.concurrency)

	// Launch goroutines
	for id, content := range items {
		select {
		case <-ctx.Done():
			// Context cancelled, stop launching new scans
			resultCh <- BatchResult{ID: id, Error: ctx.Err()}
			continue
		case sem <- struct{}{}: // Acquire semaphore
		}

		go func(id string, content []byte) {
			defer func() { <-sem }() // Release semaphore

			findings, err := b.scanner.ScanFile(ctx, id, content)
			resultCh <- BatchResult{
				ID:       id,
				Findings: findings,
				Error:    err,
			}
		}(id, content)
	}

	// Collect results
	for i := 0; i < len(items); i++ {
		results = append(results, <-resultCh)
	}

	return results
}

// ScanFiles scans multiple files concurrently.
// Returns a channel of results for streaming processing.
func (b *BatchScanner) ScanFiles(ctx context.Context, files []string) <-chan BatchResult {
	resultCh := make(chan BatchResult)

	go func() {
		defer close(resultCh)

		sem := make(chan struct{}, b.concurrency)

		var wg struct {
			count int
			done  chan struct{}
		}
		wg.done = make(chan struct{})
		wg.count = len(files)

		for _, file := range files {
			select {
			case <-ctx.Done():
				resultCh <- BatchResult{ID: file, Error: ctx.Err()}
				wg.count--
				continue
			case sem <- struct{}{}:
			}

			go func(file string) {
				defer func() {
					<-sem
					wg.count--
					if wg.count == 0 {
						close(wg.done)
					}
				}()

				// Read file
				content, err := readFile(file)
				if err != nil {
					resultCh <- BatchResult{ID: file, Error: err}
					return
				}

				findings, err := b.scanner.ScanFile(ctx, file, content)
				resultCh <- BatchResult{
					ID:       file,
					Findings: findings,
					Error:    err,
				}
			}(file)
		}

		// Wait for all goroutines
		<-wg.done
	}()

	return resultCh
}

// readFile reads a file and returns its contents.
func readFile(path string) ([]byte, error) {
	// Use os.ReadFile with size limit for safety
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > 100*1024*1024 { // 100MB limit
		return nil, fmt.Errorf("file too large: %s (%d bytes)", path, info.Size())
	}
	return os.ReadFile(path)
}

// BatchScannerOption configures a BatchScanner.
type BatchScannerOption func(*BatchScanner)

// WithConcurrency sets the concurrency level.
func WithConcurrency(n int) BatchScannerOption {
	return func(b *BatchScanner) {
		if n > 0 {
			b.concurrency = n
		}
	}
}
