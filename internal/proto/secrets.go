package proto

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	secretsv1 "github.com/picatz/deputy/gen/deputy/secrets/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	"github.com/picatz/deputy/internal/scan"
	"github.com/picatz/deputy/internal/secrets"
)

// SecretTypeToProto converts internal SecretType to proto SecretType.
func SecretTypeToProto(t secrets.SecretType) secretsv1.SecretType {
	switch t {
	case secrets.TypeGCPAPIKey:
		return secretsv1.SecretType_SECRET_TYPE_GCP_API_KEY
	case secrets.TypeGCPServiceAccountKey:
		return secretsv1.SecretType_SECRET_TYPE_GCP_SERVICE_ACCOUNT_KEY
	case secrets.TypeAWSAccessKey:
		return secretsv1.SecretType_SECRET_TYPE_AWS_ACCESS_KEY
	case secrets.TypeAWSSecretKey:
		return secretsv1.SecretType_SECRET_TYPE_AWS_SECRET_KEY
	case secrets.TypeAzureSASToken:
		return secretsv1.SecretType_SECRET_TYPE_AZURE_SAS_TOKEN
	case secrets.TypeDigitalOceanToken:
		return secretsv1.SecretType_SECRET_TYPE_DIGITALOCEAN_TOKEN
	case secrets.TypeGitHubToken:
		return secretsv1.SecretType_SECRET_TYPE_GITHUB_TOKEN
	case secrets.TypeGitHubFineGrain:
		return secretsv1.SecretType_SECRET_TYPE_GITHUB_FINE_GRAINED_TOKEN
	case secrets.TypeGitLabToken:
		return secretsv1.SecretType_SECRET_TYPE_GITLAB_TOKEN
	case secrets.TypeBitbucketToken:
		return secretsv1.SecretType_SECRET_TYPE_BITBUCKET_TOKEN
	case secrets.TypeTerraformToken:
		return secretsv1.SecretType_SECRET_TYPE_TERRAFORM_TOKEN
	case secrets.TypeSlackToken:
		return secretsv1.SecretType_SECRET_TYPE_SLACK_TOKEN
	case secrets.TypeSlackWebhook:
		return secretsv1.SecretType_SECRET_TYPE_SLACK_WEBHOOK
	case secrets.TypeDiscordToken:
		return secretsv1.SecretType_SECRET_TYPE_DISCORD_TOKEN
	case secrets.TypeTelegramToken:
		return secretsv1.SecretType_SECRET_TYPE_TELEGRAM_TOKEN
	case secrets.TypeStripeKey:
		return secretsv1.SecretType_SECRET_TYPE_STRIPE_KEY
	case secrets.TypeSendGridKey:
		return secretsv1.SecretType_SECRET_TYPE_SENDGRID_KEY
	case secrets.TypeMailgunKey:
		return secretsv1.SecretType_SECRET_TYPE_MAILGUN_KEY
	case secrets.TypeTwilioKey:
		return secretsv1.SecretType_SECRET_TYPE_TWILIO_KEY
	case secrets.TypeHerokuAPIKey:
		return secretsv1.SecretType_SECRET_TYPE_HEROKU_API_KEY
	case secrets.TypeNpmToken:
		return secretsv1.SecretType_SECRET_TYPE_NPM_TOKEN
	case secrets.TypePyPIToken:
		return secretsv1.SecretType_SECRET_TYPE_PYPI_TOKEN
	case secrets.TypeRubyGemsAPIKey:
		return secretsv1.SecretType_SECRET_TYPE_RUBYGEMS_API_KEY
	case secrets.TypeOpenAIKey:
		return secretsv1.SecretType_SECRET_TYPE_OPENAI_KEY
	case secrets.TypeAnthropicKey:
		return secretsv1.SecretType_SECRET_TYPE_ANTHROPIC_KEY
	case secrets.TypeCloudflareAPIKey:
		return secretsv1.SecretType_SECRET_TYPE_CLOUDFLARE_API_KEY
	case secrets.TypeDatadogAPIKey:
		return secretsv1.SecretType_SECRET_TYPE_DATADOG_API_KEY
	case secrets.TypeLinearAPIKey:
		return secretsv1.SecretType_SECRET_TYPE_LINEAR_API_KEY
	case secrets.TypePrivateKey:
		return secretsv1.SecretType_SECRET_TYPE_PRIVATE_KEY
	case secrets.TypeJWT:
		return secretsv1.SecretType_SECRET_TYPE_JWT
	case secrets.TypeGenericAPIKey:
		return secretsv1.SecretType_SECRET_TYPE_GENERIC_API_KEY
	case secrets.TypeHighEntropy:
		return secretsv1.SecretType_SECRET_TYPE_HIGH_ENTROPY_STRING
	case secrets.TypeSensitiveEnvVar:
		return secretsv1.SecretType_SECRET_TYPE_SENSITIVE_ENV_VAR
	default:
		return secretsv1.SecretType_SECRET_TYPE_UNSPECIFIED
	}
}

// SecretTypeFromProto converts proto SecretType to internal SecretType.
func SecretTypeFromProto(t secretsv1.SecretType) secrets.SecretType {
	switch t {
	case secretsv1.SecretType_SECRET_TYPE_GCP_API_KEY:
		return secrets.TypeGCPAPIKey
	case secretsv1.SecretType_SECRET_TYPE_GCP_SERVICE_ACCOUNT_KEY:
		return secrets.TypeGCPServiceAccountKey
	case secretsv1.SecretType_SECRET_TYPE_AWS_ACCESS_KEY:
		return secrets.TypeAWSAccessKey
	case secretsv1.SecretType_SECRET_TYPE_AWS_SECRET_KEY:
		return secrets.TypeAWSSecretKey
	case secretsv1.SecretType_SECRET_TYPE_AZURE_SAS_TOKEN:
		return secrets.TypeAzureSASToken
	case secretsv1.SecretType_SECRET_TYPE_DIGITALOCEAN_TOKEN:
		return secrets.TypeDigitalOceanToken
	case secretsv1.SecretType_SECRET_TYPE_GITHUB_TOKEN:
		return secrets.TypeGitHubToken
	case secretsv1.SecretType_SECRET_TYPE_GITHUB_FINE_GRAINED_TOKEN:
		return secrets.TypeGitHubFineGrain
	case secretsv1.SecretType_SECRET_TYPE_GITLAB_TOKEN:
		return secrets.TypeGitLabToken
	case secretsv1.SecretType_SECRET_TYPE_BITBUCKET_TOKEN:
		return secrets.TypeBitbucketToken
	case secretsv1.SecretType_SECRET_TYPE_TERRAFORM_TOKEN:
		return secrets.TypeTerraformToken
	case secretsv1.SecretType_SECRET_TYPE_SLACK_TOKEN:
		return secrets.TypeSlackToken
	case secretsv1.SecretType_SECRET_TYPE_SLACK_WEBHOOK:
		return secrets.TypeSlackWebhook
	case secretsv1.SecretType_SECRET_TYPE_DISCORD_TOKEN:
		return secrets.TypeDiscordToken
	case secretsv1.SecretType_SECRET_TYPE_TELEGRAM_TOKEN:
		return secrets.TypeTelegramToken
	case secretsv1.SecretType_SECRET_TYPE_STRIPE_KEY:
		return secrets.TypeStripeKey
	case secretsv1.SecretType_SECRET_TYPE_SENDGRID_KEY:
		return secrets.TypeSendGridKey
	case secretsv1.SecretType_SECRET_TYPE_MAILGUN_KEY:
		return secrets.TypeMailgunKey
	case secretsv1.SecretType_SECRET_TYPE_TWILIO_KEY:
		return secrets.TypeTwilioKey
	case secretsv1.SecretType_SECRET_TYPE_HEROKU_API_KEY:
		return secrets.TypeHerokuAPIKey
	case secretsv1.SecretType_SECRET_TYPE_NPM_TOKEN:
		return secrets.TypeNpmToken
	case secretsv1.SecretType_SECRET_TYPE_PYPI_TOKEN:
		return secrets.TypePyPIToken
	case secretsv1.SecretType_SECRET_TYPE_RUBYGEMS_API_KEY:
		return secrets.TypeRubyGemsAPIKey
	case secretsv1.SecretType_SECRET_TYPE_OPENAI_KEY:
		return secrets.TypeOpenAIKey
	case secretsv1.SecretType_SECRET_TYPE_ANTHROPIC_KEY:
		return secrets.TypeAnthropicKey
	case secretsv1.SecretType_SECRET_TYPE_CLOUDFLARE_API_KEY:
		return secrets.TypeCloudflareAPIKey
	case secretsv1.SecretType_SECRET_TYPE_DATADOG_API_KEY:
		return secrets.TypeDatadogAPIKey
	case secretsv1.SecretType_SECRET_TYPE_LINEAR_API_KEY:
		return secrets.TypeLinearAPIKey
	case secretsv1.SecretType_SECRET_TYPE_PRIVATE_KEY:
		return secrets.TypePrivateKey
	case secretsv1.SecretType_SECRET_TYPE_JWT:
		return secrets.TypeJWT
	case secretsv1.SecretType_SECRET_TYPE_GENERIC_API_KEY:
		return secrets.TypeGenericAPIKey
	case secretsv1.SecretType_SECRET_TYPE_HIGH_ENTROPY_STRING:
		return secrets.TypeHighEntropy
	case secretsv1.SecretType_SECRET_TYPE_SENSITIVE_ENV_VAR:
		return secrets.TypeSensitiveEnvVar
	default:
		return secrets.SecretType("")
	}
}

// SecretsFindingToProto converts internal secrets.Finding to proto Finding.
func SecretsFindingToProto(f secrets.Finding) *secretsv1.Finding {
	return &secretsv1.Finding{
		Type:        SecretTypeToProto(f.Type),
		Description: f.Description,
		Location: &secretsv1.Location{
			File:   f.File,
			Line:   int32(f.Line),
			Column: int32(f.Column),
			Source: secretsv1.SecretSource_SECRET_SOURCE_FILE,
		},
		Redacted:   f.Redacted,
		Confidence: float32(f.Confidence),
		Verification: &secretsv1.VerificationStatus{
			Status: secretsVerificationResult(f.Validated),
		},
	}
}

// secretsVerificationResult maps validated bool to proto VerificationResult.
func secretsVerificationResult(validated bool) secretsv1.VerificationResult {
	if validated {
		return secretsv1.VerificationResult_VERIFICATION_RESULT_VALID
	}
	return secretsv1.VerificationResult_VERIFICATION_RESULT_SKIPPED
}

// SecretsFindingFromProto converts proto Finding to internal secrets.Finding.
func SecretsFindingFromProto(f *secretsv1.Finding) secrets.Finding {
	if f == nil {
		return secrets.Finding{}
	}

	finding := secrets.Finding{
		Type:        SecretTypeFromProto(f.Type),
		Description: f.Description,
		Redacted:    f.Redacted,
		Confidence:  float64(f.Confidence),
	}

	if f.Location != nil {
		finding.File = f.Location.File
		finding.Line = int(f.Location.Line)
		finding.Column = int(f.Location.Column)
	}

	if f.Verification != nil {
		finding.Validated = f.Verification.Status == secretsv1.VerificationResult_VERIFICATION_RESULT_VALID
	}

	return finding
}

// SecretsFindingsToProto converts a slice of internal Findings to proto.
func SecretsFindingsToProto(findings []secrets.Finding) []*secretsv1.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]*secretsv1.Finding, len(findings))
	for i, f := range findings {
		out[i] = SecretsFindingToProto(f)
	}
	return out
}

// SecretsFindingsFromProto converts a slice of proto Finding to internal.
func SecretsFindingsFromProto(findings []*secretsv1.Finding) []secrets.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]secrets.Finding, len(findings))
	for i, f := range findings {
		out[i] = SecretsFindingFromProto(f)
	}
	return out
}

// SecretsStatsToProto converts secret findings to proto Stats.
func SecretsStatsToProto(findings []secrets.Finding) *secretsv1.Stats {
	if len(findings) == 0 {
		return &secretsv1.Stats{}
	}

	stats := &secretsv1.Stats{
		Total:       int32(len(findings)),
		CountByType: make(map[string]int32),
	}

	for _, f := range findings {
		typeKey := string(f.Type)
		stats.CountByType[typeKey]++

		if f.Confidence >= 0.9 {
			stats.HighConfidenceCount++
		}
		if f.Validated {
			stats.VerifiedCount++
		}
	}

	return stats
}

// SecretsStatsFromProto converts proto Stats to a simple stats struct.
// Note: internal secrets doesn't have a Stats type, so this returns a map.
func SecretsStatsFromProto(s *secretsv1.Stats) map[string]int32 {
	if s == nil {
		return nil
	}
	return s.CountByType
}

// SecretsScanOptionsFromProto converts proto ScanOptions to internal engine config.
func SecretsScanOptionsFromProto(o *secretsv1.ScanOptions) secrets.EngineConfig {
	if o == nil {
		return secrets.DefaultEngineConfig()
	}

	config := secrets.DefaultEngineConfig()
	config.EnableEntropy = o.EntropyDetection
	if o.EntropyThreshold > 0 {
		config.EntropyThreshold = float64(o.EntropyThreshold)
	}

	// Map disabled detector IDs to disabled patterns
	// Note: detector IDs map to SecretType strings
	if len(o.DetectorIds) > 0 {
		// If specific detectors are requested, disable all others
		// This inverts the logic: enable only specified detectors
		// For now, we'll just use the options as-is
	}

	return config
}

// SecretsScanOptionsToProto converts internal engine config to proto ScanOptions.
func SecretsScanOptionsToProto(c secrets.EngineConfig) *secretsv1.ScanOptions {
	return &secretsv1.ScanOptions{
		EntropyDetection: c.EnableEntropy,
		EntropyThreshold: float32(c.EntropyThreshold),
	}
}

// SecretsScanResultToProto converts internal scan results to proto ScanResponse.
func SecretsScanResultToProto(target scan.Target, findings []secrets.Finding, policyActions []policyv1.Action, warnings []string) *secretsv1.ScanResponse {
	return &secretsv1.ScanResponse{
		Target: &targetv1.Target{
			Kind:        target.Kind,
			DisplayPath: target.DisplayPath,
			LocalPath:   target.LocalPath,
		},
		GeneratedAt:   timestamppb.New(time.Now()),
		Findings:      SecretsFindingsToProto(findings),
		Stats:         SecretsStatsToProto(findings),
		PolicyActions: policyActionsToProtoPointers(policyActions),
		Warnings:      warnings,
	}
}

// policyActionsToProtoPointers converts value slice to pointer slice.
func policyActionsToProtoPointers(actions []policyv1.Action) []*policyv1.Action {
	if len(actions) == 0 {
		return nil
	}
	out := make([]*policyv1.Action, len(actions))
	for i := range actions {
		out[i] = &policyv1.Action{
			Type:        actions[i].Type,
			PolicyName:  actions[i].PolicyName,
			RuleName:    actions[i].RuleName,
			Reason:      actions[i].Reason,
			Remediation: actions[i].Remediation,
		}
	}
	return out
}

// SecretsTargetHintFromProto converts proto TargetHint to internal scan.TargetHint.
func SecretsTargetHintFromProto(h *secretsv1.TargetHint) scan.TargetHint {
	if h == nil {
		return scan.TargetHint{}
	}
	return scan.TargetHint{
		Kind:           h.Kind,
		ImageTransport: h.ImageTransport,
	}
}
