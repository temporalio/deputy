package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/picatz/deputy/internal/version"
	"github.com/spf13/cobra"
)

// AddVersionCommand adds the version command to the root.
func AddVersionCommand(root *cobra.Command) {
	var showFull bool

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: `Print Deputy version information.

By default, prints just the version number. Use --full for detailed
build information including Go version and module dependencies.`,
		Example: `  # Print version
  deputy version

  # Print full build info
  deputy version --full`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showFull {
				return printFullVersion(cmd)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deputy version %s\n", version.Value)
			return nil
		},
	}

	versionCmd.Flags().BoolVar(&showFull, "full", false, "Show full build information")

	root.AddCommand(versionCmd)
}

func printFullVersion(cmd *cobra.Command) error {
	w := cmd.OutOrStdout()

	fmt.Fprintf(w, "deputy version %s\n", version.Value)
	fmt.Fprintf(w, "go version:    %s\n", runtime.Version())
	fmt.Fprintf(w, "platform:      %s/%s\n", runtime.GOOS, runtime.GOARCH)

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}

	// Show main module
	if info.Main.Path != "" {
		fmt.Fprintf(w, "module:        %s\n", info.Main.Path)
	}

	// Extract VCS info from build settings
	var vcsRevision, vcsTime, vcsModified string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			vcsRevision = setting.Value
		case "vcs.time":
			vcsTime = setting.Value
		case "vcs.modified":
			vcsModified = setting.Value
		}
	}

	if vcsRevision != "" {
		commit := vcsRevision
		if len(commit) > 12 {
			commit = commit[:12]
		}
		if vcsModified == "true" {
			commit += " (modified)"
		}
		fmt.Fprintf(w, "commit:        %s\n", commit)
	}
	if vcsTime != "" {
		fmt.Fprintf(w, "built:         %s\n", vcsTime)
	}

	// Show key dependencies
	keyDeps := []string{
		"github.com/google/osv-scalibr",
		"github.com/google/cel-go",
		"github.com/spf13/cobra",
		"github.com/go-git/go-git",
	}

	var deps []string
	for _, dep := range info.Deps {
		for _, key := range keyDeps {
			if strings.HasPrefix(dep.Path, key) {
				deps = append(deps, fmt.Sprintf("  %s %s", dep.Path, dep.Version))
				break
			}
		}
	}

	if len(deps) > 0 {
		fmt.Fprintf(w, "\nkey dependencies:\n")
		for _, d := range deps {
			fmt.Fprintln(w, d)
		}
	}

	return nil
}
