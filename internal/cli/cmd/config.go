package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/picatz/deputy/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// AddConfigCommand adds the config command and its subcommands to the root command.
func AddConfigCommand(root *cobra.Command) {
	configCmd := &cobra.Command{
		Use:   "config [command]",
		Short: "Manage Deputy configuration",
		Long: `Manage Deputy configuration files and settings.

The config command helps you work with Deputy configuration:
  - validate: Check a config file for errors
  - show: Display the effective configuration
  - path: Show where Deputy looks for config files

CONFIGURATION PRECEDENCE:
  CLI flags > Environment variables > Config file > Defaults

CONFIG FILE LOCATIONS (searched in order):
  1. $DEPUTY_CONFIG environment variable
  2. .deputy.yaml or .deputy.yml in current directory
  3. deputy.yaml or deputy.yml in current directory
  4. .deputy.yaml in home directory`,
		Example: `  # Validate a config file
  deputy config validate .deputy.yaml

  # Show effective configuration
  deputy config show

  # Show config as JSON
  deputy config show --format json

  # Find config file location
  deputy config path`,
	}

	configCmd.AddCommand(newConfigValidateCommand())
	configCmd.AddCommand(newConfigShowCommand())
	configCmd.AddCommand(newConfigPathCommand())

	root.AddCommand(configCmd)
}

func newConfigValidateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate [config-file]",
		Short: "Validate a configuration file",
		Long: `Validate a Deputy configuration file for syntax and semantic errors.

If no file is specified, validates the auto-discovered config file
(if one exists) or reports that no config file was found.

CHECKS PERFORMED:
  - YAML syntax validation
  - Field type validation
  - Value range validation (e.g., positive timeouts)
  - Known field validation (warns on unknown fields)`,
		Example: `  # Validate explicit config file
  deputy config validate .deputy.yaml

  # Validate auto-discovered config
  deputy config validate`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			var configPath string
			if len(args) > 0 {
				configPath = args[0]
			} else {
				configPath = config.FindConfigFile()
				if configPath == "" {
					fmt.Fprintln(out, "No configuration file found.")
					fmt.Fprintln(out, "")
					fmt.Fprintln(out, "Deputy looks for config files in these locations:")
					fmt.Fprintln(out, "  1. $DEPUTY_CONFIG environment variable")
					fmt.Fprintln(out, "  2. .deputy.yaml in current directory")
					fmt.Fprintln(out, "  3. deputy.yaml in current directory")
					fmt.Fprintln(out, "  4. .deputy.yaml in home directory")
					return nil
				}
			}

			// Check file exists
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				return fmt.Errorf("config file not found: %s", configPath)
			}

			// Load and validate
			loader := config.NewLoader(configPath)
			cfg, err := loader.Load()
			if err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}

			// Additional validation
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}

			absPath, _ := filepath.Abs(configPath)
			fmt.Fprintf(out, "Configuration valid: %s\n", absPath)
			return nil
		},
	}

	return cmd
}

func newConfigShowCommand() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show effective configuration",
		Long: `Display the effective configuration after merging all sources.

Shows the final configuration after applying:
  1. Built-in defaults
  2. Config file values (if found)
  3. Environment variable overrides

This helps debug configuration issues by showing exactly
what values Deputy will use.`,
		Example: `  # Show as YAML (default)
  deputy config show

  # Show as JSON
  deputy config show --format json

  # Check a specific value
  deputy config show --format json | jq '.logging.level'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			configPath := config.FindConfigFile()
			loader := config.NewLoader(configPath)
			cfg, err := loader.Load()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			return renderConfig(out, cfg, format, configPath)
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "yaml", "Output format: yaml, json")

	return cmd
}

func newConfigPathCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Show configuration file path",
		Long: `Show which configuration file Deputy will use.

If no config file is found, shows where Deputy searched.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// Check explicit env var
			if envPath := os.Getenv("DEPUTY_CONFIG"); envPath != "" {
				if _, err := os.Stat(envPath); err == nil {
					absPath, _ := filepath.Abs(envPath)
					fmt.Fprintf(out, "%s (from $DEPUTY_CONFIG)\n", absPath)
					return nil
				}
				fmt.Fprintf(out, "$DEPUTY_CONFIG set to %s but file not found\n", envPath)
			}

			// Check auto-discovered path
			if path := config.FindConfigFile(); path != "" {
				absPath, _ := filepath.Abs(path)
				fmt.Fprintln(out, absPath)
				return nil
			}

			fmt.Fprintln(out, "No configuration file found.")
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "Searched locations:")

			cwd, _ := os.Getwd()
			candidates := []string{".deputy.yaml", ".deputy.yml", "deputy.yaml", "deputy.yml"}
			for _, name := range candidates {
				fmt.Fprintf(out, "  %s\n", filepath.Join(cwd, name))
			}

			if home, err := os.UserHomeDir(); err == nil {
				for _, name := range candidates {
					fmt.Fprintf(out, "  %s\n", filepath.Join(home, name))
				}
			}

			return nil
		},
	}

	return cmd
}

func renderConfig(w io.Writer, cfg *config.Config, format, sourcePath string) error {
	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(cfg)

	case "yaml", "":
		if sourcePath != "" {
			fmt.Fprintf(w, "# Source: %s\n", sourcePath)
		} else {
			fmt.Fprintln(w, "# Source: defaults (no config file found)")
		}
		fmt.Fprintln(w, "# Effective configuration after merging all sources")
		fmt.Fprintln(w, "")

		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		return enc.Encode(cfg)

	default:
		return fmt.Errorf("unsupported format %q (use yaml or json)", format)
	}
}
