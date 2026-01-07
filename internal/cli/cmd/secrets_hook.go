package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/picatz/deputy/internal/secrets"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
)

// AddSecretsHookCommand adds the 'secrets hook' subcommand.
func AddSecretsHookCommand(secretsCmd *cobra.Command) {
	var (
		hookType    string
		warn        bool
		verify      bool
		format      string
		exclude     string
		include     string
		allowlist   string
		deputyPath  string
		repoPath    string
	)

	hookCmd := &cobra.Command{
		Use:   "hook",
		Short: "Manage git hooks for secret detection",
		Long: `Install, configure, and manage git hooks for automatic secret detection.

Deputy can install pre-commit and pre-push hooks that automatically scan for
secrets before code is committed or pushed to remote repositories.

HOOK TYPES:
• pre-commit: Scans staged files before each commit
• pre-push: Scans commits before pushing to remote

These hooks help prevent secrets from being accidentally committed to version
control, which is critical for security since git history is permanent.

The hooks integrate seamlessly with your git workflow and can be configured
to either block (fail) or warn when secrets are detected.`,
		Example: `INSTALLATION:
  # Install pre-commit hook (default)
  deputy secrets hook install

  # Install pre-push hook
  deputy secrets hook install --type pre-push

  # Install both hooks
  deputy secrets hook install --type pre-commit
  deputy secrets hook install --type pre-push

  # Install with custom configuration
  deputy secrets hook install --verify --exclude "*.test.js,__fixtures__/*"

  # Warn only (don't block commits)
  deputy secrets hook install --warn

MANAGEMENT:
  # Show hook status
  deputy secrets hook status

  # Uninstall a hook
  deputy secrets hook uninstall --type pre-commit

  # Generate hook script without installing
  deputy secrets hook generate --type pre-commit > my-hook.sh

USING INSTALLED HOOKS:
  # Hooks run automatically on git commit/push
  git commit -m "my changes"  # Pre-commit hook runs

  # Skip hooks if needed (use sparingly!)
  git commit --no-verify -m "emergency fix"`,
	}

	// Install subcommand
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install git hooks for secret detection",
		Long: `Install pre-commit and/or pre-push hooks that scan for secrets.

The hooks are installed in .git/hooks/ and run automatically when you commit
or push. If an existing hook is present, it will be backed up.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			errW := cmd.ErrOrStderr()

			// Determine repository path
			repo := repoPath
			if repo == "" {
				var err error
				repo, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("getting current directory: %w", err)
				}
			}

			// Parse hook type
			var ht secrets.HookType
			switch strings.ToLower(hookType) {
			case "pre-commit", "precommit":
				ht = secrets.HookPreCommit
			case "pre-push", "prepush":
				ht = secrets.HookPrePush
			default:
				return fmt.Errorf("invalid hook type: %s (use pre-commit or pre-push)", hookType)
			}

			// Build config
			config := secrets.DefaultHookConfig(ht)
			config.FailOnSecrets = !warn
			config.VerifySecrets = verify
			config.Format = format
			if exclude != "" {
				config.ExcludePatterns = strings.Split(exclude, ",")
			}
			if include != "" {
				config.IncludePatterns = strings.Split(include, ",")
			}
			if allowlist != "" {
				config.AllowList = allowlist
			}
			if deputyPath != "" {
				config.DeputyPath = deputyPath
			}

			fmt.Fprintf(errW, "%s\n", ui.StyleMeta.Render(fmt.Sprintf("Installing %s hook...", ht)))

			if err := secrets.InstallHook(repo, config); err != nil {
				return fmt.Errorf("installing hook: %w", err)
			}

			fmt.Fprintln(out)
			fmt.Fprintf(out, "%s %s hook installed successfully\n",
				ui.StyleAdded.Render("✓"),
				ui.StyleBold.Render(string(ht)))

			hookPath := filepath.Join(repo, ".git", "hooks", string(ht))
			fmt.Fprintf(out, "  Location: %s\n", ui.StylePath.Render(hookPath))

			if warn {
				fmt.Fprintf(out, "  Mode: %s\n", ui.StyleDowngraded.Render("warn only (will not block commits)"))
			} else {
				fmt.Fprintf(out, "  Mode: %s\n", ui.StyleRemoved.Render("strict (will block commits with secrets)"))
			}

			fmt.Fprintln(out)
			fmt.Fprintln(out, ui.StyleMeta.Render("The hook will run automatically on git "+strings.TrimPrefix(string(ht), "pre-")+"."))
			fmt.Fprintln(out, ui.StyleMeta.Render("To skip: git "+strings.TrimPrefix(string(ht), "pre-")+" --no-verify"))

			return nil
		},
	}

	// Uninstall subcommand
	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall git hooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			repo := repoPath
			if repo == "" {
				var err error
				repo, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("getting current directory: %w", err)
				}
			}

			var ht secrets.HookType
			switch strings.ToLower(hookType) {
			case "pre-commit", "precommit":
				ht = secrets.HookPreCommit
			case "pre-push", "prepush":
				ht = secrets.HookPrePush
			default:
				return fmt.Errorf("invalid hook type: %s", hookType)
			}

			if err := secrets.UninstallHook(repo, ht); err != nil {
				return err
			}

			fmt.Fprintf(out, "%s %s hook uninstalled\n",
				ui.StyleAdded.Render("✓"),
				string(ht))

			return nil
		},
	}

	// Status subcommand
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show status of installed hooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			repo := repoPath
			if repo == "" {
				var err error
				repo, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("getting current directory: %w", err)
				}
			}

			statuses, err := secrets.GetHookStatus(repo)
			if err != nil {
				return err
			}

			fmt.Fprintln(out)
			fmt.Fprintln(out, ui.StyleHeader.Render("Git Hook Status:"))
			fmt.Fprintf(out, "  Repository: %s\n", ui.StylePackageName.Render(repo))
			fmt.Fprintln(out)

			for _, status := range statuses {
				var statusLabel string
				if !status.Installed {
					statusLabel = ui.StyleMeta.Render("not installed")
				} else if status.IsDeputy {
					statusLabel = ui.StyleAdded.Render("installed (deputy)")
				} else {
					statusLabel = ui.StyleDowngraded.Render("installed (other)")
				}

				fmt.Fprintf(out, "  %s: %s\n",
					ui.StyleBold.Render(string(status.Type)),
					statusLabel)

				if status.HasBackup {
					fmt.Fprintf(out, "    %s\n", ui.StyleMeta.Render("(backup available)"))
				}
			}

			return nil
		},
	}

	// Generate subcommand
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate hook script to stdout",
		Long: `Generate a hook script without installing it.

This is useful for:
- Reviewing the hook before installation
- Customizing the hook manually
- Using with other hook management tools`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			var ht secrets.HookType
			switch strings.ToLower(hookType) {
			case "pre-commit", "precommit":
				ht = secrets.HookPreCommit
			case "pre-push", "prepush":
				ht = secrets.HookPrePush
			default:
				return fmt.Errorf("invalid hook type: %s", hookType)
			}

			config := secrets.DefaultHookConfig(ht)
			config.FailOnSecrets = !warn
			config.VerifySecrets = verify
			config.Format = format
			if exclude != "" {
				config.ExcludePatterns = strings.Split(exclude, ",")
			}
			if include != "" {
				config.IncludePatterns = strings.Split(include, ",")
			}
			if allowlist != "" {
				config.AllowList = allowlist
			}
			if deputyPath != "" {
				config.DeputyPath = deputyPath
			}

			return secrets.GenerateHook(out, config)
		},
	}

	// Shared flags
	for _, c := range []*cobra.Command{installCmd, generateCmd} {
		c.Flags().StringVar(&hookType, "type", "pre-commit", "Hook type: pre-commit, pre-push")
		c.Flags().BoolVar(&warn, "warn", false, "Warn on secrets instead of failing")
		c.Flags().BoolVar(&verify, "verify", false, "Verify detected secrets are active")
		c.Flags().StringVar(&format, "format", "text", "Output format: text, json, sarif")
		c.Flags().StringVar(&exclude, "exclude", "", "Comma-separated file patterns to exclude")
		c.Flags().StringVar(&include, "include", "", "Comma-separated file patterns to include")
		c.Flags().StringVar(&allowlist, "allowlist", "", "Path to allowlist file")
		c.Flags().StringVar(&deputyPath, "deputy-path", "", "Path to deputy binary")
	}

	uninstallCmd.Flags().StringVar(&hookType, "type", "pre-commit", "Hook type to uninstall")

	// Repo path flag for all subcommands
	for _, c := range []*cobra.Command{installCmd, uninstallCmd, statusCmd} {
		c.Flags().StringVar(&repoPath, "repo", "", "Repository path (default: current directory)")
	}

	hookCmd.AddCommand(installCmd, uninstallCmd, statusCmd, generateCmd)
	secretsCmd.AddCommand(hookCmd)
}

// renderHookHelp renders help about hooks with examples.
func renderHookHelp(out io.Writer) {
	fmt.Fprintln(out, ui.StyleHeader.Render("Git Hooks for Secret Detection"))
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Deputy can install git hooks to automatically scan for secrets before")
	fmt.Fprintln(out, "commits or pushes reach your repository.")
	fmt.Fprintln(out)

	fmt.Fprintln(out, ui.StyleBold.Render("Quick Start:"))
	fmt.Fprintln(out, "  deputy secrets hook install          # Install pre-commit hook")
	fmt.Fprintln(out, "  deputy secrets hook install --type pre-push")
	fmt.Fprintln(out)

	fmt.Fprintln(out, ui.StyleBold.Render("Available Hook Types:"))
	fmt.Fprintln(out, "  pre-commit  Scans staged files before each commit")
	fmt.Fprintln(out, "  pre-push    Scans commits before pushing to remote")
	fmt.Fprintln(out)

	fmt.Fprintln(out, ui.StyleBold.Render("Why Use Git Hooks?"))
	fmt.Fprintln(out, "  - Prevent secrets from entering git history")
	fmt.Fprintln(out, "  - Catch mistakes before they become incidents")
	fmt.Fprintln(out, "  - Defense in depth alongside CI/CD scanning")
}

// preCommitHookPreview returns a preview of the pre-commit hook.
func preCommitHookPreview() string {
	var buf bytes.Buffer
	config := secrets.DefaultHookConfig(secrets.HookPreCommit)
	secrets.GenerateHook(&buf, config)
	return buf.String()
}
