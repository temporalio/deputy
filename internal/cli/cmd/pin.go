package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v63/github"
	deperrors "github.com/temporalio/deputy/internal/errors"
	"github.com/temporalio/deputy/internal/otel"
	"github.com/temporalio/deputy/internal/pin"
	"github.com/temporalio/deputy/internal/pin/container"
	"github.com/temporalio/deputy/internal/pin/githubactions"
	ui "github.com/temporalio/deputy/internal/ui"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// AddPinCommand registers the pin subcommand and its children with the root command.
func AddPinCommand(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:           "pin [directory]",
		Short:         "Pin dependencies to immutable references for supply chain security",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Pin dependencies to immutable references for supply chain security.

Scans for mutable dependency references and replaces them with immutable
pins. By default, pins both GitHub Actions and container images.

GITHUB ACTIONS:
Replaces mutable version tags like @v4 with commit SHA pins:

    uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

The version comment enables Dependabot and Renovate to propose update PRs.
Each resolved SHA is verified against the GitHub API to detect fork/imposter
commits unless --skip-verification is set.

CONTAINER IMAGES:
Appends sha256 digest pins to Dockerfile FROM statements, workflow
container/services fields, and docker:// action uses:

    FROM alpine:3.19@sha256:a8560b36e8b8...
    container: postgres:16@sha256:1234abcd...
    uses: docker://redis:7@sha256:5678ef01...

The original tag is preserved for readability and automated update tooling.

AUTHENTICATION:
  GitHub Actions: Set GITHUB_TOKEN or GH_TOKEN for API verification.
  Container images: Uses Docker credential keychain (~/.docker/config.json).
  Public dependencies work without any credentials.

SUBCOMMANDS:
  check    Check that all dependencies are pinned (CI gate)
  verify   Verify existing SHA pins for provenance (fork/imposter detection)
  update   Update existing pins to the latest version`,
		Example: `  # Pin everything (actions + container images)
  deputy pin

  # Preview changes without modifying files
  deputy pin --dry-run

  # Pin a specific directory
  deputy pin /path/to/repo

  # Pin only GitHub Actions
  deputy pin --ecosystems github-actions

  # Pin only container images (Dockerfiles, workflow containers)
  deputy pin --ecosystems container-image

  # Skip specific dependencies
  deputy pin --exclude actions/checkout --exclude 'myorg/*'

  # Skip verification (faster, no GitHub API calls)
  deputy pin --skip-verification

  # JSON output for CI integration
  deputy pin --dry-run --format json`,
		RunE: runPin,
	}

	// Persistent flags inherited by subcommands.
	cmd.PersistentFlags().StringSliceP("ecosystems", "e", []string{"all"}, "Ecosystems to pin (github-actions, container-image, all)")
	cmd.PersistentFlags().StringSliceP("exclude", "x", nil, "Skip dependencies matching glob patterns (e.g., 'actions/*', 'alpine')")
	cmd.PersistentFlags().StringP("format", "f", "text", "Output format: text, json")
	cmd.PersistentFlags().StringP("output", "o", "", "Output file (default: stdout)")

	// Flags specific to the pin command.
	cmd.Flags().BoolP("dry-run", "n", false, "Show what would change without modifying files")
	cmd.Flags().Bool("skip-verification", false, "Skip fork/imposter commit verification")
	cmd.Flags().Int("concurrency", 4, "Max parallel network requests")

	addPinCheckCommand(cmd)
	addPinVerifyCommand(cmd)
	addPinUpdateCommand(cmd)

	root.AddCommand(cmd)
}

// addPinCheckCommand registers the "pin check" subcommand.
func addPinCheckCommand(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:           "check [directory]",
		Short:         "Check that all dependencies are pinned (CI gate)",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Check that all pinnable dependency references are pinned to immutable
references. Exits with code 1 if any unpinned references are found.

This command makes no network calls and writes no files — it only scans
local files. Use it in CI to enforce that all dependencies are pinned.`,
		Example: `  # Check that all dependencies are pinned
  deputy pin check

  # Check a specific directory
  deputy pin check /path/to/repo

  # Check only GitHub Actions
  deputy pin check --ecosystems github-actions

  # JSON output for CI parsing
  deputy pin check --format json`,
		RunE: runPinCheck,
	}

	parent.AddCommand(cmd)
}

// addPinVerifyCommand registers the "pin verify" subcommand.
func addPinVerifyCommand(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:           "verify [directory]",
		Short:         "Verify existing SHA pins for provenance (fork/imposter detection)",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Verify that existing pinned dependency references are trustworthy.

For GitHub Actions, checks each commit SHA against the GitHub API to detect
fork/imposter commits — commits fetchable from the shared object store but
not belonging to any branch in the action's repository.

Container image digest verification (cosign/sigstore) is not yet supported;
pinned container images are reported as present but not provenance-checked.

Unpinned references are skipped. Use 'deputy pin' first to pin them.`,
		Example: `  # Verify all pinned dependencies
  deputy pin verify

  # Verify in a specific directory
  deputy pin verify /path/to/repo

  # JSON output
  deputy pin verify --format json`,
		RunE: runPinVerify,
	}

	cmd.Flags().Int("concurrency", 4, "Max parallel network requests")

	parent.AddCommand(cmd)
}

// addPinUpdateCommand registers the "pin update" subcommand.
func addPinUpdateCommand(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:           "update [directory]",
		Short:         "Update existing pins to the latest version",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Update already-pinned dependency references to the latest version.

For GitHub Actions, re-resolves the major version tag (e.g., v4) to get the
latest SHA. For container images, re-resolves the tag to get the current
digest (detects when an image tag has been re-pushed with security patches).

Unpinned references are skipped — use 'deputy pin' first to pin them.`,
		Example: `  # Update all pinned dependencies to latest
  deputy pin update

  # Preview updates without modifying files
  deputy pin update --dry-run

  # Update in a specific directory
  deputy pin update /path/to/repo

  # Skip verification for faster updates
  deputy pin update --skip-verification`,
		RunE: runPinUpdate,
	}

	cmd.Flags().BoolP("dry-run", "n", false, "Show what would change without modifying files")
	cmd.Flags().Bool("skip-verification", false, "Skip fork/imposter commit verification")
	cmd.Flags().Int("concurrency", 4, "Max parallel network requests")

	parent.AddCommand(cmd)
}

func runPin(cmd *cobra.Command, args []string) error {
	ctx, span := otel.StartSpan(cmd.Context(), "deputy.pin",
		trace.WithAttributes(
			attribute.String("deputy.command", "pin"),
		))
	defer span.End()

	absDir, err := resolveDir(args)
	if err != nil {
		return err
	}

	root, err := os.OpenRoot(absDir)
	if err != nil {
		return fmt.Errorf("opening directory: %w", err)
	}
	defer root.Close()

	ecosystems, _ := cmd.Flags().GetStringSlice("ecosystems")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipVerification, _ := cmd.Flags().GetBool("skip-verification")
	format, _ := cmd.Flags().GetString("format")
	outPath, _ := cmd.Flags().GetString("output")
	concurrency, _ := cmd.Flags().GetInt("concurrency")

	span.SetAttributes(
		attribute.String("deputy.pin.dir", absDir),
		attribute.Bool("deputy.pin.dry_run", dryRun),
		attribute.Bool("deputy.pin.skip_verification", skipVerification),
		attribute.Int("deputy.pin.concurrency", concurrency),
	)

	opts := pin.Options{
		DryRun:           dryRun,
		SkipVerification: skipVerification,
		Concurrency:      concurrency,
		Exclude:          exclude,
	}

	strategies, err := buildPinStrategies(ctx, ecosystems, !skipVerification)
	if err != nil {
		return err
	}

	report, err := pin.Pin(ctx, root, opts, strategies...)
	if err != nil {
		return err
	}

	if err := outputPinReport(cmd, report, format, outPath, dryRun); err != nil {
		return err
	}

	return pinExitCode(report)
}

func runPinCheck(cmd *cobra.Command, args []string) error {
	ctx, span := otel.StartSpan(cmd.Context(), "deputy.pin.check",
		trace.WithAttributes(
			attribute.String("deputy.command", "pin.check"),
		))
	defer span.End()

	absDir, err := resolveDir(args)
	if err != nil {
		return err
	}

	root, err := os.OpenRoot(absDir)
	if err != nil {
		return fmt.Errorf("opening directory: %w", err)
	}
	defer root.Close()

	ecosystems, _ := cmd.Flags().GetStringSlice("ecosystems")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	format, _ := cmd.Flags().GetString("format")
	outPath, _ := cmd.Flags().GetString("output")

	opts := pin.Options{
		Exclude: exclude,
	}

	strategies, err := buildPinStrategies(ctx, ecosystems, false)
	if err != nil {
		return err
	}

	report, err := pin.Check(ctx, root, opts, strategies...)
	if err != nil {
		return err
	}

	if err := outputPinReport(cmd, report, format, outPath, false); err != nil {
		return err
	}

	if report.Stats.Unpinned > 0 {
		return deperrors.WithExitCode(
			fmt.Errorf("%d unpinned dependency reference(s)", report.Stats.Unpinned), 1)
	}
	return nil
}

func runPinVerify(cmd *cobra.Command, args []string) error {
	ctx, span := otel.StartSpan(cmd.Context(), "deputy.pin.verify",
		trace.WithAttributes(
			attribute.String("deputy.command", "pin.verify"),
		))
	defer span.End()

	absDir, err := resolveDir(args)
	if err != nil {
		return err
	}

	root, err := os.OpenRoot(absDir)
	if err != nil {
		return fmt.Errorf("opening directory: %w", err)
	}
	defer root.Close()

	ecosystems, _ := cmd.Flags().GetStringSlice("ecosystems")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	format, _ := cmd.Flags().GetString("format")
	outPath, _ := cmd.Flags().GetString("output")
	concurrency, _ := cmd.Flags().GetInt("concurrency")

	opts := pin.Options{
		Concurrency: concurrency,
		Exclude:     exclude,
	}

	strategies, err := buildPinStrategies(ctx, ecosystems, true)
	if err != nil {
		return err
	}

	report, err := pin.Verify(ctx, root, opts, strategies...)
	if err != nil {
		return err
	}

	if err := outputPinReport(cmd, report, format, outPath, false); err != nil {
		return err
	}

	return pinExitCode(report)
}

func runPinUpdate(cmd *cobra.Command, args []string) error {
	ctx, span := otel.StartSpan(cmd.Context(), "deputy.pin.update",
		trace.WithAttributes(
			attribute.String("deputy.command", "pin.update"),
		))
	defer span.End()

	absDir, err := resolveDir(args)
	if err != nil {
		return err
	}

	root, err := os.OpenRoot(absDir)
	if err != nil {
		return fmt.Errorf("opening directory: %w", err)
	}
	defer root.Close()

	ecosystems, _ := cmd.Flags().GetStringSlice("ecosystems")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipVerification, _ := cmd.Flags().GetBool("skip-verification")
	format, _ := cmd.Flags().GetString("format")
	outPath, _ := cmd.Flags().GetString("output")
	concurrency, _ := cmd.Flags().GetInt("concurrency")

	opts := pin.Options{
		DryRun:           dryRun,
		SkipVerification: skipVerification,
		Concurrency:      concurrency,
		Exclude:          exclude,
	}

	strategies, err := buildPinStrategies(ctx, ecosystems, !skipVerification)
	if err != nil {
		return err
	}

	report, err := pin.PinUpdate(ctx, root, opts, strategies...)
	if err != nil {
		return err
	}

	if err := outputPinReport(cmd, report, format, outPath, dryRun); err != nil {
		return err
	}

	return pinExitCode(report)
}

// resolveDir returns an absolute path for the target directory.
func resolveDir(args []string) (string, error) {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolving directory: %w", err)
	}
	return absDir, nil
}

// outputPinReport writes the report in the requested format. dryRun adjusts the
// human-readable wording so a preview never claims files were modified.
func outputPinReport(_ *cobra.Command, report *pin.Report, format, outPath string, dryRun bool) error {
	var w io.Writer = os.Stdout
	if outPath != "" && outPath != "-" {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
	default:
		renderPinReport(w, report, dryRun)
	}
	return nil
}

// pinExitCode returns an error with the appropriate exit code based on results.
func pinExitCode(report *pin.Report) error {
	if report.Stats.Suspicious > 0 {
		return deperrors.WithExitCode(
			fmt.Errorf("%d suspicious pin(s) detected", report.Stats.Suspicious), 2)
	}
	if report.Stats.Errors > 0 {
		return deperrors.WithExitCode(
			fmt.Errorf("%d pinning error(s)", report.Stats.Errors), 1)
	}
	return nil
}

// renderPinReport writes a human-readable summary of pin results to w,
// grouped by file. When dryRun is true, wording reflects a preview so the
// output never implies files were modified.
func renderPinReport(w io.Writer, report *pin.Report, dryRun bool) {
	if len(report.Results) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.StyleAdded.Render("✓ No pinnable dependencies found"))
		return
	}

	// Determine section heading based on what happened.
	heading := "Pin Results:"
	s := report.Stats
	switch {
	case s.Suspicious > 0:
		heading = "Suspicious Pins Detected:"
	case s.Unpinned > 0:
		heading = "Unpinned Dependencies Found:"
	case s.Updated > 0:
		heading = "Dependencies to Update:"
		if !dryRun {
			heading = "Dependencies Updated:"
		}
	case s.Pinned > 0:
		heading = "Dependencies to Pin:"
		if !dryRun {
			heading = "Dependencies Pinned:"
		}
	case s.Verified > 0:
		heading = "Verification Results:"
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleDowngraded.Render("∴ ")+ui.StyleHeader.Render(heading))

	// Group results by file, preserving discovery order
	var fileOrder []string
	byFile := map[string][]pin.Result{}
	for _, r := range report.Results {
		f := r.Ref.FilePath
		if _, ok := byFile[f]; !ok {
			fileOrder = append(fileOrder, f)
		}
		byFile[f] = append(byFile[f], r)
	}

	arrow := ui.StyleUpdateArrow.Render("->")

	for _, file := range fileOrder {
		results := byFile[file]
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", ui.StylePath.Render(relPath(file)))

		for _, r := range results {
			renderPinResult(w, r, arrow)
		}
	}

	fmt.Fprintln(w)
	renderPinSummary(w, report.Stats, dryRun)

	if dryRun && (report.Stats.Pinned > 0 || report.Stats.Updated > 0) {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.StyleDim.Render("  Dry run — no files were modified. Re-run without --dry-run to apply."))
	}
}

func renderPinResult(w io.Writer, r pin.Result, arrow string) {
	name := r.Ref.DisplayName()

	// Build parts list and join with spaces — avoids %-Ns on ANSI-styled
	// strings where invisible escape codes break visual alignment.
	prefix := "    " + ui.StyleVersion.Render("• ")
	styledName := ui.StylePackageName.Render(name)

	switch r.Status {
	case pin.StatusPinned:
		fmt.Fprintln(w, prefix+strings.Join([]string{
			styledName,
			ui.StyleVersion.Render(r.PreviousRef),
			arrow,
			ui.StyleAdded.Render(r.PinnedValue + " # " + r.VersionTag),
		}, " "))

	case pin.StatusUpdated:
		fmt.Fprintln(w, prefix+strings.Join([]string{
			styledName,
			ui.StyleVersion.Render(shortenSHA(r.PreviousRef)),
			arrow,
			ui.StyleAdded.Render(r.PinnedValue + " # " + r.VersionTag),
		}, " "))

	case pin.StatusAlreadyPinned:
		detail := "already pinned"
		if r.PinnedValue != "" {
			detail += " " + shortenSHA(r.PinnedValue)
		}
		if r.VersionTag != "" {
			detail += " (" + r.VersionTag + ")"
		}
		fmt.Fprintln(w, prefix+styledName+" "+ui.StyleDim.Render(detail))

	case pin.StatusUnpinned:
		fmt.Fprintln(w, prefix+styledName+" "+
			ui.StyleRemoved.Render("UNPINNED")+" "+
			ui.StyleDim.Render(r.Ref.Version))

	case pin.StatusVerified:
		detail := "verified"
		var caveats []string
		if r.Verification != nil {
			var parts []string
			if r.Verification.SignatureValid {
				parts = append(parts, "signed")
			}
			if r.Verification.OnBranch {
				parts = append(parts, "on "+r.Verification.BranchName)
			}
			if len(parts) > 0 {
				detail = strings.Join(parts, ", ")
			}
			caveats = r.Verification.Warnings
		}
		line := prefix + styledName + " " + ui.StyleAdded.Render(detail)
		// Surface non-fatal caveats (unsigned, ahead of branch, unverifiable
		// reachability) that don't rise to "suspicious" but are worth seeing.
		if len(caveats) > 0 {
			line += " " + ui.StyleDim.Render("("+strings.Join(caveats, "; ")+")")
		}
		fmt.Fprintln(w, line)

	case pin.StatusSuspicious:
		fmt.Fprintln(w, prefix+styledName+" "+
			ui.StyleRemoved.Render("SUSPICIOUS")+" "+
			ui.StyleDim.Render(r.Reason))

	case pin.StatusSkipped:
		fmt.Fprintln(w, prefix+styledName+" "+
			ui.StyleDim.Render("skipped ("+r.Reason+")"))

	case pin.StatusError:
		fmt.Fprintln(w, prefix+styledName+" "+
			ui.StyleRemoved.Render("error")+" "+
			ui.StyleDim.Render(r.Error))
	}
}

func renderPinSummary(w io.Writer, s pin.Stats, dryRun bool) {
	fmt.Fprintln(w, ui.StyleHeader.Render("Summary:"))
	if s.Pinned > 0 {
		msg := fmt.Sprintf("%d pinned to immutable SHA", s.Pinned)
		if dryRun {
			msg = fmt.Sprintf("%d would be pinned to immutable SHA", s.Pinned)
		}
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render(ui.StyleAdded.Render("↑")),
			ui.StyleSymbol.Render(msg))
	}
	if s.Updated > 0 {
		msg := fmt.Sprintf("%d updated to latest version", s.Updated)
		if dryRun {
			msg = fmt.Sprintf("%d would be updated to latest version", s.Updated)
		}
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render(ui.StyleUpgraded.Render("↑")),
			ui.StyleSymbol.Render(msg))
	}
	if s.AlreadyPinned > 0 {
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render(ui.StyleAdded.Render("✓")),
			ui.StyleDim.Render(fmt.Sprintf("%d already pinned", s.AlreadyPinned)))
	}
	if s.Verified > 0 {
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render(ui.StyleAdded.Render("✓")),
			ui.StyleSymbol.Render(fmt.Sprintf("%d verified", s.Verified)))
	}
	if s.Unpinned > 0 {
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render(ui.StyleRemoved.Render("!")),
			ui.StyleSymbol.Render(fmt.Sprintf("%d unpinned ", s.Unpinned))+ui.StyleRemoved.Render("(run deputy pin to fix)"))
	}
	if s.Suspicious > 0 {
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render(ui.StyleRemoved.Render("!")),
			ui.StyleSymbol.Render(fmt.Sprintf("%d suspicious ", s.Suspicious))+ui.StyleRemoved.Render("(possible supply chain risk)"))
	}
	if s.Errors > 0 {
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render(ui.StyleRemoved.Render("-")),
			ui.StyleSymbol.Render(fmt.Sprintf("%d errors", s.Errors)))
	}
	if s.Skipped > 0 {
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render("-"),
			ui.StyleDim.Render(fmt.Sprintf("%d skipped", s.Skipped)))
	}
}

// relPath returns a relative path from the current working directory, or
// the original path if relativization fails.
func relPath(abs string) string {
	if cwd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(cwd, abs); err == nil {
			return rel
		}
	}
	return abs
}

// shortenSHA returns the first 12 characters of a SHA with "..." suffix,
// or the full string if shorter.
func shortenSHA(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

// supportedPinEcosystems lists ecosystems that have pinning support.
var supportedPinEcosystems = []string{githubactions.Ecosystem, container.Ecosystem}

// buildPinStrategies creates Strategy instances for the requested ecosystems.
// "all" expands to all supported ecosystems. When needsVerification is true,
// a GitHub API client is created for commit provenance checks; otherwise
// only the git protocol is used (no API token required).
func buildPinStrategies(ctx context.Context, ecosystems []string, needsVerification bool) ([]pin.Strategy, error) {
	// Expand "all" to every supported ecosystem.
	if len(ecosystems) == 1 && ecosystems[0] == "all" {
		ecosystems = supportedPinEcosystems
	}

	seen := make(map[string]bool)
	var strategies []pin.Strategy
	for _, eco := range ecosystems {
		if seen[eco] {
			continue
		}
		seen[eco] = true
		switch eco {
		case githubactions.Ecosystem:
			var ghClient *github.Client
			if needsVerification {
				ghClient = githubactions.NewGitHubClient(ctx)
			}
			strategies = append(strategies, githubactions.NewStrategy(ghClient))
		case container.Ecosystem:
			strategies = append(strategies, container.NewStrategy())
		default:
			return nil, fmt.Errorf("unsupported ecosystem for pinning: %q (supported: %s)",
				eco, strings.Join(supportedPinEcosystems, ", "))
		}
	}
	if len(strategies) == 0 {
		return nil, fmt.Errorf("no ecosystems selected for pinning")
	}
	return strategies, nil
}
