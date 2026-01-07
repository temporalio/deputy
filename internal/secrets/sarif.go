// Package secrets provides secret detection capabilities.
package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/picatz/deputy/internal/sarif"
)

// SARIFReportOptions configures SARIF report generation for secrets.
type SARIFReportOptions struct {
	// ToolVersion is the version of the tool.
	ToolVersion string
	// BaseURI is the base URI for relative file paths.
	BaseURI string
	// Repo is the repository URL or path that was scanned.
	Repo string
	// Ref is the git reference (branch/tag) that was scanned.
	Ref string
	// Commit is the git commit hash.
	Commit string
	// Category is a unique identifier for this analysis run.
	Category string
	// WorkingDirectory is the base path for artifact URIs.
	WorkingDirectory string
	// StartTime is when the scan started.
	StartTime time.Time
	// EndTime is when the scan completed.
	EndTime time.Time
}

// DefaultSARIFOptions returns sensible defaults for SARIF generation.
func DefaultSARIFOptions() SARIFReportOptions {
	return SARIFReportOptions{
		ToolVersion: "1.0.0",
		Category:    "deputy-secrets",
	}
}

// SARIFReport generates a SARIF report from secret findings.
type SARIFReport struct {
	options SARIFReportOptions
}

// NewSARIFReport creates a new SARIF report generator.
func NewSARIFReport(opts SARIFReportOptions) *SARIFReport {
	return &SARIFReport{options: opts}
}

// secretRuleDefinitions maps secret types to SARIF rule metadata.
var secretRuleDefinitions = map[SecretType]struct {
	Name        string
	Description string
	CWE         string
	Severity    float64 // CVSS-like 0-10 score
}{
	TypeAWSAccessKey:         {"AWS Access Key", "AWS Access Key ID exposed in source code", "798", 8.5},
	TypeAWSSecretKey:         {"AWS Secret Key", "AWS Secret Access Key exposed in source code", "798", 9.5},
	TypeGitHubToken:          {"GitHub Token", "GitHub Personal Access Token exposed in source code", "798", 8.0},
	TypeGitHubFineGrain:      {"GitHub Fine-Grained Token", "GitHub Fine-Grained Personal Access Token exposed", "798", 8.0},
	TypeGitLabToken:          {"GitLab Token", "GitLab Personal Access Token exposed in source code", "798", 8.0},
	TypeSlackToken:           {"Slack Token", "Slack API Token exposed in source code", "798", 7.5},
	TypeSlackWebhook:         {"Slack Webhook", "Slack Webhook URL exposed in source code", "798", 6.5},
	TypeStripeKey:            {"Stripe Key", "Stripe API Key exposed in source code", "798", 9.0},
	TypeSendGridKey:          {"SendGrid Key", "SendGrid API Key exposed in source code", "798", 7.5},
	TypeNpmToken:             {"npm Token", "npm Access Token exposed in source code", "798", 8.5},
	TypePyPIToken:            {"PyPI Token", "PyPI API Token exposed in source code", "798", 8.5},
	TypeDiscordToken:         {"Discord Token", "Discord Bot Token exposed in source code", "798", 7.0},
	TypeTelegramToken:        {"Telegram Token", "Telegram Bot Token exposed in source code", "798", 7.0},
	TypeHerokuAPIKey:         {"Heroku API Key", "Heroku API Key exposed in source code", "798", 8.0},
	TypeMailgunKey:           {"Mailgun Key", "Mailgun API Key exposed in source code", "798", 7.5},
	TypeTwilioKey:            {"Twilio Key", "Twilio API Key exposed in source code", "798", 8.0},
	TypeTerraformToken:       {"Terraform Token", "Terraform Cloud/Enterprise Token exposed", "798", 8.5},
	TypeCloudflareAPIKey:     {"Cloudflare API Key", "Cloudflare API Key exposed in source code", "798", 8.0},
	TypeDatadogAPIKey:        {"Datadog API Key", "Datadog API Key exposed in source code", "798", 7.0},
	TypeOpenAIKey:            {"OpenAI API Key", "OpenAI API Key exposed in source code", "798", 8.0},
	TypeAnthropicKey:         {"Anthropic API Key", "Anthropic API Key exposed in source code", "798", 8.0},
	TypeLinearAPIKey:         {"Linear API Key", "Linear API Key exposed in source code", "798", 7.0},
	TypeAzureSASToken:        {"Azure SAS Token", "Azure SAS Token exposed in source code", "798", 8.5},
	TypeBitbucketToken:       {"Bitbucket Token", "Bitbucket App Password exposed in source code", "798", 8.0},
	TypeDigitalOceanToken:    {"DigitalOcean Token", "DigitalOcean Personal Access Token exposed", "798", 8.0},
	TypePrivateKey:           {"Private Key", "Private key file content exposed in source code", "321", 9.5},
	TypeJWT:                  {"JSON Web Token", "JWT token exposed in source code", "798", 7.0},
	TypeGenericAPIKey:        {"Generic API Key", "Generic API key pattern detected", "798", 6.0},
	TypeHighEntropy:          {"High Entropy String", "High-entropy string that may be a secret", "798", 5.0},
	TypeGCPAPIKey:            {"GCP API Key", "Google Cloud Platform API Key exposed", "798", 8.5},
	TypeGCPServiceAccountKey: {"GCP Service Account Key", "GCP Service Account JSON key exposed", "798", 9.5},
	TypeRubyGemsAPIKey:       {"RubyGems API Key", "RubyGems API Key exposed in source code", "798", 8.0},
}

// Generate creates a SARIF document from findings using the shared sarif package.
func (r *SARIFReport) Generate(findings []Finding) *sarif.Log {
	// Collect unique rules used
	usedRules := make(map[SecretType]bool)
	for _, f := range findings {
		usedRules[f.Type] = true
	}

	// Build rules array
	rules := make([]sarif.ReportingDesc, 0, len(usedRules))
	ruleIndex := make(map[SecretType]int)
	idx := 0
	for secretType := range usedRules {
		rule := r.buildRule(secretType)
		rules = append(rules, rule)
		ruleIndex[secretType] = idx
		idx++
	}

	// Convert findings to results
	results := make([]sarif.Result, 0, len(findings))
	for _, f := range findings {
		result := r.findingToResult(f, ruleIndex)
		results = append(results, result)
	}

	// Build driver with secrets-specific rules
	driver := sarif.ToolComponent{
		Name:           "Deputy",
		FullName:       fmt.Sprintf("Deputy %s (secrets)", r.options.ToolVersion),
		Version:        r.options.ToolVersion,
		InformationURI: "https://github.com/picatz/deputy",
		Organization:   "picatz",
		Rules:          rules,
		ShortDesc: &sarif.Message{
			Text: "Secret detection scanner",
		},
		FullDesc: &sarif.Message{
			Text: "Deputy secrets scanner detects hardcoded credentials, API keys, and other sensitive data in source code.",
		},
	}

	// Build invocation
	invocations := []sarif.Invocation{
		{
			ExecutionSuccessful: true,
		},
	}
	if r.options.WorkingDirectory != "" {
		invocations[0].WorkingDirectory = &sarif.URI{URI: r.options.WorkingDirectory}
	}
	if !r.options.StartTime.IsZero() {
		invocations[0].StartTimeUTC = r.options.StartTime.UTC().Format(time.RFC3339)
	}
	if !r.options.EndTime.IsZero() {
		invocations[0].EndTimeUTC = r.options.EndTime.UTC().Format(time.RFC3339)
	}

	// Build version control provenance
	var vcs []sarif.VersionControl
	var originalURIBases map[string]sarif.URI
	if r.options.Repo != "" || r.options.Commit != "" {
		vc := sarif.VersionControl{
			RepositoryURI: r.options.Repo,
			RevisionID:    r.options.Commit,
			Branch:        r.options.Ref,
			MappedTo: &sarif.ArtifactLocation{
				URIBaseID: "%SRCROOT%",
			},
		}
		vcs = append(vcs, vc)
		originalURIBases = map[string]sarif.URI{
			"%SRCROOT%": {URI: ""},
		}
	}

	// Build automation details
	automationID := r.options.Category
	if automationID == "" {
		automationID = "deputy-secrets"
	}

	// Build CWE taxonomy
	taxonomies := []sarif.ToolComponent{
		{
			Name:           "CWE",
			Version:        "4.13",
			InformationURI: "https://cwe.mitre.org/",
			ShortDesc: &sarif.Message{
				Text: "Common Weakness Enumeration",
			},
			Taxa: []sarif.ReportingDesc{
				{
					ID:   "CWE-798",
					Name: "UseOfHardcodedCredentials",
					ShortDescription: &sarif.Message{
						Text: "The software contains hard-coded credentials, such as a password or cryptographic key.",
					},
				},
				{
					ID:   "CWE-321",
					Name: "UseOfHardcodedCryptographicKey",
					ShortDescription: &sarif.Message{
						Text: "The use of a hard-coded cryptographic key significantly increases the possibility of compromising confidential data.",
					},
				},
			},
		},
	}

	run := sarif.Run{
		Tool: sarif.Tool{
			Driver: driver,
		},
		Results:         results,
		Invocations:     invocations,
		VersionControl:  vcs,
		AutomationID:    &sarif.RunAutomation{ID: automationID},
		OriginalURIBase: originalURIBases,
		Taxonomies:      taxonomies,
	}

	return &sarif.Log{
		Schema:  sarif.DefaultSchema,
		Version: sarif.DefaultVersion,
		Runs:    []sarif.Run{run},
	}
}

// buildRule creates a SARIF rule definition for a secret type.
func (r *SARIFReport) buildRule(secretType SecretType) sarif.ReportingDesc {
	def, ok := secretRuleDefinitions[secretType]
	if !ok {
		// Fallback for unknown types
		def = struct {
			Name        string
			Description string
			CWE         string
			Severity    float64
		}{
			Name:        string(secretType),
			Description: fmt.Sprintf("%s detected in source code", secretType),
			CWE:         "798",
			Severity:    7.0,
		}
	}

	ruleID := fmt.Sprintf("secret/%s", secretType)

	return sarif.ReportingDesc{
		ID:   ruleID,
		Name: toPascalCase(def.Name),
		ShortDescription: &sarif.Message{
			Text: def.Description,
		},
		FullDescription: &sarif.Message{
			Text:     def.Description + ". Secrets in source code can be extracted by attackers with access to the repository.",
			Markdown: fmt.Sprintf("**%s**\n\n%s. Secrets in source code can be extracted by attackers with access to the repository.", def.Name, def.Description),
		},
		HelpURI: "https://github.com/picatz/deputy/blob/main/docs/secrets.md",
		Help: &sarif.Message{
			Text:     "Remove the secret from source code and rotate it immediately. Use environment variables or a secret management solution instead.",
			Markdown: "## Remediation\n\n1. **Remove** the secret from source code\n2. **Rotate** the compromised credential immediately\n3. **Use** environment variables or a secret management solution\n4. **Review** git history for exposed secrets",
		},
		DefaultConfig: &sarif.RuleConfig{
			Level: "error",
		},
		Relationships: []sarif.ReportingDescRelationship{
			{
				Target: sarif.ReportingDescRef{
					ID: "CWE-" + def.CWE,
					ToolComponent: &sarif.ToolComponentRef{
						Name:  "CWE",
						Index: 0,
					},
				},
				Kinds: []string{"superset"},
			},
		},
		Properties: &sarif.PropertyBag{
			SecuritySeverity: def.Severity,
			Tags:             []string{"security", "secrets", "credentials"},
		},
	}
}

// findingToResult converts a Finding to a SARIF Result.
func (r *SARIFReport) findingToResult(f Finding, ruleIndex map[SecretType]int) sarif.Result {
	// Determine level based on confidence and validation
	level := "warning"
	if f.Confidence >= 0.9 {
		level = "error"
	} else if f.Confidence < 0.7 {
		level = "note"
	}
	if f.Validated {
		level = "error" // Verified secrets are always errors
	}

	// Build message
	message := f.Description
	if message == "" {
		message = fmt.Sprintf("Detected %s", f.Type)
	}
	if f.Validated {
		message += " (verified active)"
	}

	result := sarif.Result{
		RuleID:  fmt.Sprintf("secret/%s", f.Type),
		Level:   level,
		Message: sarif.Message{Text: message},
		Properties: &sarif.PropertyBag{
			Precision: confidenceToPrecision(f.Confidence),
		},
	}

	// Add rule index if available
	if idx, ok := ruleIndex[f.Type]; ok {
		result.RuleIndex = idx
	}

	// Add location if file is specified
	if f.File != "" {
		// Normalize file path for SARIF (use forward slashes)
		uri := filepath.ToSlash(f.File)
		// Make relative if possible
		if r.options.BaseURI != "" {
			uri = strings.TrimPrefix(uri, filepath.ToSlash(r.options.BaseURI))
			uri = strings.TrimPrefix(uri, "/")
		}

		location := sarif.Location{
			PhysicalLocation: &sarif.PhysicalLocation{
				ArtifactLocation: sarif.ArtifactLocation{
					URI:       uri,
					URIBaseID: "%SRCROOT%",
				},
			},
		}

		// Add region if line info is available
		if f.Line > 0 {
			location.PhysicalLocation.Region = &sarif.Region{
				StartLine:   f.Line,
				StartColumn: f.Column,
			}
			// Estimate end column based on typical secret length
			if f.Column > 0 {
				location.PhysicalLocation.Region.EndColumn = f.Column + 40
			}
		}

		result.Locations = []sarif.Location{location}
	}

	// Add partial fingerprints for deduplication
	result.PartialFingerprints = map[string]string{
		"secretType/v1": string(f.Type),
	}
	if f.File != "" {
		result.PartialFingerprints["primaryLocationLineHash"] = sarif.HashFingerprint(string(f.Type), f.File, fmt.Sprintf("%d", f.Line))
	}

	return result
}

// Write writes the SARIF report to a writer.
func (r *SARIFReport) Write(w io.Writer, findings []Finding) error {
	log := r.Generate(findings)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

// ToJSON returns the SARIF report as a JSON string.
func (r *SARIFReport) ToJSON(findings []Finding) (string, error) {
	log := r.Generate(findings)
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FindingsToSARIF is a convenience function to convert findings to SARIF JSON.
func FindingsToSARIF(findings []Finding, opts ...func(*SARIFReportOptions)) (string, error) {
	options := DefaultSARIFOptions()
	for _, opt := range opts {
		opt(&options)
	}
	report := NewSARIFReport(options)
	return report.ToJSON(findings)
}

// WithToolVersion sets the tool version in SARIF options.
func WithToolVersion(version string) func(*SARIFReportOptions) {
	return func(opts *SARIFReportOptions) {
		opts.ToolVersion = version
	}
}

// WithBaseURI sets the base URI for relative paths.
func WithBaseURI(baseURI string) func(*SARIFReportOptions) {
	return func(opts *SARIFReportOptions) {
		opts.BaseURI = baseURI
	}
}

// Helper functions

// toPascalCase converts a string to PascalCase for SARIF rule names.
func toPascalCase(s string) string {
	var result strings.Builder
	capitalizeNext := true
	for _, r := range s {
		if r == ' ' || r == '-' || r == '_' {
			capitalizeNext = true
			continue
		}
		if capitalizeNext {
			result.WriteRune(toUpper(r))
			capitalizeNext = false
		} else {
			result.WriteRune(toLower(r))
		}
	}
	return result.String()
}

func toUpper(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}

func toLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}

// confidenceToPrecision converts confidence score to SARIF precision.
func confidenceToPrecision(confidence float64) string {
	switch {
	case confidence >= 0.95:
		return "very-high"
	case confidence >= 0.85:
		return "high"
	case confidence >= 0.7:
		return "medium"
	default:
		return "low"
	}
}
