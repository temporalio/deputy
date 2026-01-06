package ai

import (
	"fmt"
	"os"
	"strings"
)

// Config represents AI configuration from .deputy.yaml.
type Config struct {
	// DefaultProvider is used when no provider is explicitly specified.
	DefaultProvider string `yaml:"default_provider" json:"default_provider"`

	// Providers contains per-provider configuration.
	Providers map[string]ProviderConfig `yaml:"providers" json:"providers"`

	// Approval configures when user approval is required.
	Approval ApprovalConfig `yaml:"approval" json:"approval"`

	// Disabled completely disables AI features.
	Disabled bool `yaml:"disabled" json:"disabled"`
}

// ProviderConfig contains settings for a specific AI provider.
type ProviderConfig struct {
	// Model specifies the model to use.
	Model string `yaml:"model" json:"model"`

	// APIKey for API-based providers.
	// Supports ${ENV_VAR} syntax for environment variable expansion.
	APIKey string `yaml:"api_key" json:"api_key"`

	// BaseURL overrides the default API endpoint.
	BaseURL string `yaml:"base_url" json:"base_url"`

	// Sandbox sets the default sandbox mode for agentic providers.
	Sandbox string `yaml:"sandbox" json:"sandbox"`

	// MaxTokens sets the default max tokens for completions.
	MaxTokens int `yaml:"max_tokens" json:"max_tokens"`

	// Temperature sets the default temperature.
	Temperature *float64 `yaml:"temperature" json:"temperature"`

	// Timeout for API requests (Go duration string).
	Timeout string `yaml:"timeout" json:"timeout"`

	// Extra contains provider-specific additional configuration.
	Extra map[string]any `yaml:"extra" json:"extra"`
}

// ApprovalConfig controls when user approval is required.
// This is the YAML-serializable configuration, which can be converted to
// an [ApprovalPolicy] for use in sessions via [ApprovalConfig.ToPolicy].
type ApprovalConfig struct {
	// Required makes all AI operations require approval.
	Required bool `yaml:"required" json:"required"`

	// Commands requires approval before shell command execution.
	Commands bool `yaml:"commands" json:"commands"`

	// FileWrites requires approval before file modifications.
	FileWrites bool `yaml:"file_writes" json:"file_writes"`

	// HighRisk requires approval for operations flagged as high-risk.
	// This is true by default and should rarely be disabled.
	HighRisk bool `yaml:"high_risk" json:"high_risk"`
}

// ToPolicy converts the configuration to a runtime [ApprovalPolicy].
// The returned policy has no Approver set; callers must provide one
// if approval is required.
//
// Configuration mapping:
//   - Required=true: all operations require approval (overrides other settings)
//   - Commands=true: command execution requires approval
//   - FileWrites=true: file modifications require approval
//   - HighRisk=true: high-risk operations always require approval
func (ac ApprovalConfig) ToPolicy() *ApprovalPolicy {
	policy := &ApprovalPolicy{
		HighRiskAlways: ac.HighRisk,
		Approver:       nil, // Caller must provide
	}

	// If Required is set, everything needs approval
	if ac.Required {
		policy.Commands = ApprovalRequired
		policy.FileWrites = ApprovalRequired
		return policy
	}

	// Map individual settings
	if ac.Commands {
		policy.Commands = ApprovalRequired
	} else {
		policy.Commands = ApprovalNotRequired
	}

	if ac.FileWrites {
		policy.FileWrites = ApprovalRequired
	} else {
		policy.FileWrites = ApprovalNotRequired
	}

	return policy
}

// DefaultConfig returns the default AI configuration.
func DefaultConfig() Config {
	return Config{
		DefaultProvider: "", // No default - must be explicitly chosen
		Providers:       make(map[string]ProviderConfig),
		Approval: ApprovalConfig{
			Required:   false,
			Commands:   true,  // Approve commands by default
			FileWrites: false, // Allow file writes in workspace
			HighRisk:   true,  // Approve dangerous operations
		},
		Disabled: false,
	}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.Disabled {
		return nil // Nothing to validate if disabled
	}

	// Validate default provider exists if specified
	if c.DefaultProvider != "" {
		if _, ok := c.Providers[c.DefaultProvider]; !ok {
			// Check if it's a built-in provider
			if _, err := GetProvider(c.DefaultProvider); err != nil {
				return fmt.Errorf("default_provider %q is not configured or registered", c.DefaultProvider)
			}
		}
	}

	// Validate each provider config
	for name, pcfg := range c.Providers {
		if err := pcfg.Validate(name); err != nil {
			return err
		}
	}

	return nil
}

// Validate checks a provider configuration for errors.
func (pc *ProviderConfig) Validate(name string) error {
	// Validate sandbox if specified
	if pc.Sandbox != "" {
		switch Sandbox(strings.ToLower(pc.Sandbox)) {
		case SandboxReadOnly, SandboxWorkspaceWrite, SandboxFullAccess:
			// Valid
		default:
			return fmt.Errorf("ai.providers.%s.sandbox: invalid value %q (must be read-only, workspace-write, or full-access)", name, pc.Sandbox)
		}
	}

	// Validate temperature if specified
	if pc.Temperature != nil {
		if *pc.Temperature < 0 || *pc.Temperature > 2 {
			return fmt.Errorf("ai.providers.%s.temperature: must be between 0 and 2", name)
		}
	}

	return nil
}

// ExpandedAPIKey returns the API key with environment variable expansion.
func (pc *ProviderConfig) ExpandedAPIKey() string {
	return expandEnvVars(pc.APIKey)
}

// GetSandbox returns the sandbox mode, defaulting to workspace-write.
func (pc *ProviderConfig) GetSandbox() Sandbox {
	if pc.Sandbox == "" {
		return SandboxWorkspaceWrite
	}
	return Sandbox(strings.ToLower(pc.Sandbox))
}

// expandEnvVars replaces ${VAR} patterns with environment variable values.
func expandEnvVars(s string) string {
	if s == "" {
		return s
	}
	return os.Expand(s, func(key string) string {
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
		return "${" + key + "}" // Keep unexpanded if not set
	})
}

// GetProviderConfig returns the configuration for a specific provider.
// Returns default config if the provider isn't explicitly configured.
func (c *Config) GetProviderConfig(name string) ProviderConfig {
	if cfg, ok := c.Providers[name]; ok {
		return cfg
	}
	return ProviderConfig{} // Empty defaults
}

// ResolveProvider determines which provider to use.
// Priority: explicit > default > first available
func (c *Config) ResolveProvider(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if c.DefaultProvider != "" {
		return c.DefaultProvider, nil
	}
	// Fall back to first registered provider
	providers := ListProviders()
	if len(providers) > 0 {
		return providers[0], nil
	}
	return "", fmt.Errorf("no AI provider available; configure one in .deputy.yaml or install codex/claude")
}
