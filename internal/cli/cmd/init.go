package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/spf13/cobra"
)

// AddInitCommand adds the init command to the root command.
func AddInitCommand(root *cobra.Command) {
	var (
		force      bool
		configOnly bool
		policyOnly bool
	)

	initCmd := &cobra.Command{
		Use:   "init [directory]",
		Short: "Initialize Deputy in a project",
		Long: `Initialize Deputy configuration and policies in a project directory.

Creates starter files to help you get started with Deputy:
  - .deputy.yaml: Configuration file with documented options
  - policy/deputy.yaml: Starter policy with common rules

Use flags to generate only specific files.`,
		Example: `  # Initialize in current directory
  deputy init

  # Initialize in a specific directory
  deputy init ./my-project

  # Only generate config file
  deputy init --config-only

  # Only generate policy file
  deputy init --policy-only

  # Overwrite existing files
  deputy init --force`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}

			// Ensure directory exists
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}

			var created []string

			// Generate config file
			if !policyOnly {
				configPath := filepath.Join(dir, ".deputy.yaml")
				if err := writeIfNotExists(configPath, configTemplate, force); err != nil {
					if !os.IsExist(err) {
						return err
					}
					fmt.Fprintf(out, "Skipped: %s (already exists, use --force to overwrite)\n", configPath)
				} else {
					created = append(created, configPath)
				}
			}

			// Generate policy file
			if !configOnly {
				policyDir := filepath.Join(dir, "policy")
				if err := os.MkdirAll(policyDir, 0755); err != nil {
					return fmt.Errorf("failed to create policy directory: %w", err)
				}

				policyPath := filepath.Join(policyDir, "deputy.yaml")
				if err := writeIfNotExists(policyPath, policyTemplate, force); err != nil {
					if !os.IsExist(err) {
						return err
					}
					fmt.Fprintf(out, "Skipped: %s (already exists, use --force to overwrite)\n", policyPath)
				} else {
					created = append(created, policyPath)
				}
			}

			if len(created) == 0 {
				fmt.Fprintln(out, "No files created. Use --force to overwrite existing files.")
				return nil
			}

			fmt.Fprintln(out, "Created:")
			for _, path := range created {
				fmt.Fprintf(out, "  %s\n", path)
			}

			// Detect ecosystems in the directory
			ecosystems := detectEcosystems(dir)
			if len(ecosystems) > 0 {
				fmt.Fprintln(out, "")
				fmt.Fprintf(out, "Detected ecosystems: %s\n", strings.Join(ecosystems, ", "))
			}

			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "Next steps:")
			fmt.Fprintln(out, "  1. Run 'deputy scan' to find vulnerabilities")
			fmt.Fprintln(out, "  2. Edit policy/deputy.yaml to customize rules")
			fmt.Fprintln(out, "  3. Run 'deputy scan --policy policy/' to enforce policies")

			// Add ecosystem-specific tips
			for _, eco := range ecosystems {
				if tip := ecosystemTip(eco); tip != "" {
					fmt.Fprintf(out, "\n%s tip: %s\n", eco, tip)
				}
			}

			return nil
		},
	}

	initCmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing files")
	initCmd.Flags().BoolVar(&configOnly, "config-only", false, "Only generate config file")
	initCmd.Flags().BoolVar(&policyOnly, "policy-only", false, "Only generate policy file")

	root.AddCommand(initCmd)
}

func writeIfNotExists(path, content string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return os.ErrExist
		}
	}

	return os.WriteFile(path, []byte(strings.TrimPrefix(content, "\n")), 0644)
}

const configTemplate = `
# Deputy Configuration
# https://github.com/temporalio/deputy
#
# This file configures Deputy's behavior. All settings have sensible defaults,
# so you only need to specify values you want to change.
#
# Configuration precedence: CLI flags > Environment variables > This file > Defaults

# Logging configuration
logging:
  # Log level: debug, info, warn, error
  level: info
  # Output format: text, json
  format: text

# Scanning configuration
scan:
  # Limit scanning to specific ecosystems (empty = all)
  # ecosystems:
  #   - go
  #   - npm

# Policy configuration
policy:
  # Default policy evaluation mode: enforce (exit 1 on violations) or advisory (warn only)
  mode: enforce
  # Default policy file paths
  # paths:
  #   - policy/

# Performance tuning (usually not needed)
# performance:
#   osv_concurrency: 10
#   graph_concurrency: 5
#   cache:
#     ttl: 1h
#     disabled: false

# Local CLI egress allowlists (optional, for in-process mode)
# egress:
#   allowed_hosts:
#     - ".corp.local"
#   allowed_cidrs:
#     - "10.0.0.0/8"
#   allow_loopback: false
#   allow_link_local: false
`

const policyTemplate = `
# Deputy Security Policy
# https://github.com/temporalio/deputy/tree/main/policy/examples
#
# This policy defines rules for vulnerability management and dependency governance.
# Customize these rules to match your organization's security requirements.

policies:
  # Block critical and high severity vulnerabilities
  - name: block-critical-high
    description: Prevent critical and high severity vulnerabilities from shipping
    entrypoints:
      - scan_vulnerability
    rules:
      - action: deny
        when: vulnerability.severity in ["CRITICAL", "HIGH"]
        reason: "Critical/High severity vulnerability must be remediated"
        remediation: "Upgrade to a fixed version or apply a patch"

  # Warn on medium severity vulnerabilities
  - name: warn-medium
    description: Flag medium severity vulnerabilities for review
    entrypoints:
      - scan_vulnerability
    rules:
      - action: warn
        when: vulnerability.severity == "MEDIUM"
        reason: "Medium severity vulnerability should be reviewed"

  # Block vulnerabilities in CISA KEV (Known Exploited Vulnerabilities)
  # Requires --enrich flag during scanning
  - name: block-kev
    description: Block vulnerabilities known to be actively exploited
    entrypoints:
      - scan_vulnerability
    rules:
      - action: deny
        when: vulnerability.inKEV == true
        reason: "Vulnerability is in CISA Known Exploited Vulnerabilities catalog"
        remediation: "This vulnerability is actively exploited - prioritize immediate remediation"

  # Block vulnerabilities with high EPSS scores
  # Requires --enrich flag during scanning
  - name: block-high-epss
    description: Block vulnerabilities with high exploitation probability
    entrypoints:
      - scan_vulnerability
    rules:
      - action: deny
        when: vulnerability.?epss.orValue(0.0) > 0.7
        reason: "Vulnerability has >70% probability of exploitation in next 30 days"

  # Example: Require approved licenses (uncomment to enable)
  # - name: license-allowlist
  #   description: Only allow packages with approved licenses
  #   entrypoints:
  #     - scan_vulnerability
  #   vars:
  #     approved: ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"]
  #   rules:
  #     - action: deny
  #       when: |
  #         pkg.licenses.size() > 0 &&
  #         pkg.licenses.all(l, !(l in approved))
  #       reason: "Package license not in approved list"

  # Example: Block specific packages (uncomment to enable)
  # - name: package-blocklist
  #   description: Block known problematic packages
  #   entrypoints:
  #     - scan_vulnerability
  #   vars:
  #     blocked:
  #       - "event-stream"      # Supply chain attack
  #       - "ua-parser-js"      # Compromised versions
  #       - "coa"               # Compromised versions
  #   rules:
  #     - action: deny
  #       when: pkg.name in blocked
  #       reason: "Package is on the blocklist due to past security incidents"
`

// detectEcosystems scans a directory for manifest files and returns detected ecosystems.
func detectEcosystems(dir string) []string {
	// Map of manifest file patterns to ecosystems
	manifestPatterns := map[string]string{
		"go.mod":              "Go",
		"go.sum":              "Go",
		"package.json":        "npm",
		"package-lock.json":   "npm",
		"yarn.lock":           "npm",
		"pnpm-lock.yaml":      "npm",
		"requirements.txt":    "Python",
		"Pipfile":             "Python",
		"pyproject.toml":      "Python",
		"poetry.lock":         "Python",
		"Gemfile":             "Ruby",
		"Gemfile.lock":        "Ruby",
		"Cargo.toml":          "Rust",
		"Cargo.lock":          "Rust",
		"composer.json":       "PHP",
		"composer.lock":       "PHP",
		"pom.xml":             "Maven",
		"build.gradle":        "Gradle",
		"build.gradle.kts":    "Gradle",
		"Dockerfile":          "Docker",
		"docker-compose.yml":  "Docker",
		"docker-compose.yaml": "Docker",
	}

	seen := make(map[string]bool)
	var ecosystems []string

	// Check for manifest files in the directory (non-recursive for speed)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if eco, ok := manifestPatterns[name]; ok {
			if !seen[eco] {
				seen[eco] = true
				ecosystems = append(ecosystems, eco)
			}
		}
	}

	// Sort for consistent output
	slices.Sort(ecosystems)
	return ecosystems
}

// ecosystemTip returns ecosystem-specific advice for using Deputy.
func ecosystemTip(eco string) string {
	switch ecosystem.Parse(eco) {
	case ecosystem.Go:
		return "Use 'deputy graph why <pkg>' to trace why a dependency is included"
	case ecosystem.NPM:
		return "Run 'deputy proxy npm -- npm install' to enforce policies during install"
	case ecosystem.PyPI:
		return "Run 'deputy proxy pypi -- pip install -r requirements.txt' for policy enforcement"
	case ecosystem.RubyGems:
		return "Run 'deputy proxy rubygems -- bundle install' for policy enforcement"
	default:
		return ""
	}
}
