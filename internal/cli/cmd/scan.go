package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	git "github.com/go-git/go-git/v5"
	"github.com/google/osv-scalibr/extractor"
	cliflags "github.com/picatz/deputy/internal/cli/flags"
	"github.com/picatz/deputy/internal/collections"
	gitx "github.com/picatz/deputy/internal/gitutil"
	"github.com/picatz/deputy/internal/output"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/purlx"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/report/render"
	"github.com/picatz/deputy/internal/sarif"
	"github.com/picatz/deputy/internal/scan"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/picatz/deputy/internal/version"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/protobom/protobom/pkg/sbom"
	spdxjson "github.com/spdx/tools-golang/json"
	spdxdoc "github.com/spdx/tools-golang/spdx"
	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

// ScanResult is the structured output of a vulnerability scan suitable for
// serialization to JSON or further aggregation.
type ScanResult struct {
	// Repo is the repository path or URL that was scanned.
	Repo string `json:"repo"`
	// Ref is the git reference (branch, tag, commit) that was scanned.
	Ref string `json:"ref"`
	// Commit is the resolved commit hash of the scanned reference.
	Commit string `json:"commit"`
	// Generated is the ISO 8601 timestamp when the scan was performed.
	Generated string `json:"generated"`
	// PackagesScanned is the total number of packages analyzed for vulnerabilities.
	PackagesScanned int `json:"packagesScanned"`
	// Stats provides aggregate vulnerability counts and severity breakdown.
	Stats vulnerability.Stats `json:"stats"`
	// Vulnerabilities is the list of security vulnerabilities found in dependencies.
	Vulnerabilities []report.Vulnerability `json:"vulnerabilities"`
	// PolicyFindings contains policy evaluation results (deny/warn actions).
	PolicyFindings []report.PolicyFinding `json:"policyFindings,omitempty"`
}

// ModuleDeprecation captures information about a deprecated module and its
// suggested replacement (future enrichment hook).
type ModuleDeprecation struct {
	Module  string `json:"module"`
	Suggest string `json:"suggest"`
	URL     string `json:"url,omitempty"`
}

// Scanner bridges CLI commands to the scan service.
type Scanner struct {
	service *scan.Service
}

// NewScanner returns a Scanner configured with the provided scan service.
func NewScanner(service *scan.Service) *Scanner {
	if service == nil {
		service = scan.NewService()
	}
	return &Scanner{service: service}
}

// AddScanCommand registers the scan subcommand with the root command.
// It configures the command flags and usage examples.
func AddScanCommand(root *cobra.Command, service *scan.Service) {
	scanner := NewScanner(service)

	scanCmd := &cobra.Command{
		Use:           "scan [repo]",
		Short:         "Scan for vulnerabilities",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Scan repositories, directories, or SBOM files for security vulnerabilities using the OSV database.

VULNERABILITY DATABASE:
Queries the Open Source Vulnerabilities (OSV) database which aggregates vulnerability
data from multiple sources including CVE, GitHub Security Advisories, Go vulnerability
database, and others. Provides comprehensive coverage for Go ecosystem packages.

SUPPORTED ECOSYSTEMS:
Supports all ecosystems exposed by OSV-Scalibr (Go modules, npm, PyPI, Maven,
RubyGems, containers, operating system packages, GitHub Actions workflows/actions, and more).
Use --ecosystems to limit scanning to specific sets when you don't need the full inventory.

OUTPUT FORMATS:
• text: Human-readable colored output with severity indicators and fix suggestions
• json: Machine-readable structured output for integration with CI/CD and other tools

The scan command automatically detects your module's dependencies and queries for
known vulnerabilities. It respects go.mod files and understands Go module versioning.`,
		RunE: scanner.runScan,
		Example: `BASIC VULNERABILITY SCANNING:
  # Scan current repository at HEAD
  deputy scan

  # Scan current directory for vulnerabilities
  deputy scan .

  # Scan specific repository directory
  deputy scan /path/to/go/project
  deputy scan ~/projects/my-app

  # Scan remote repository (clones temporarily)
  deputy scan github.com/username/repo
  deputy scan https://github.com/username/repo.git

REFERENCE-SPECIFIC SCANNING:
  # Scan a specific branch
  deputy scan --ref main
  deputy scan --ref feature/auth-service
  deputy scan --ref develop

  # Scan a specific tag or release
  deputy scan --ref v1.2.3
  deputy scan --ref release-2024
  deputy scan --ref latest

  # Scan a specific commit
  deputy scan --ref abc123d
  deputy scan --ref HEAD~3
  deputy scan --ref main^

  # Scan uncommitted changes (working tree)
  deputy scan --ref WORKING
  deputy scan --ref HEAD~0

OUTPUT AND FORMATTING:
  # Save results to file
  deputy scan --output vulnerabilities.txt
  deputy scan --output /tmp/vuln-report.json --format json

  # JSON output for CI/CD integration
  deputy scan --format json | jq '.vulnerabilities'
  deputy scan --format json --output vuln-report.json

FILTERING OPTIONS:
  # Ignore vulnerabilities without available fixes
  deputy scan --ignore-unfixed

  # Focus on specific ecosystems
  deputy scan --ecosystems go

REMOTE REPOSITORY SCANNING:
  # Scan public GitHub repository
  deputy scan github.com/gin-gonic/gin
  deputy scan https://github.com/gorilla/mux

  # Scan at specific reference for remote repos
  deputy scan --ref v1.9.0 github.com/gin-gonic/gin
  deputy scan --ref main https://github.com/username/repo.git

SUBCOMMANDS:
  # Scan directory without Git context
  deputy scan dir /path/to/source

  # Scan SBOM file
  deputy scan sbom software-bill-of-materials.json
  deputy scan sbom - < sbom.json

WORKFLOW EXAMPLES:
  # CI/CD pipeline vulnerability check
  deputy scan --format json --ignore-unfixed --output vuln-report.json
  
  # Quick security check before release
  deputy scan --ref release-candidate

  # Check vulnerabilities in feature branch
  deputy scan --ref feature/new-auth-system

  # Historical vulnerability analysis
  deputy scan --ref v1.0.0  # Check old version
  deputy scan --ref v2.0.0  # Compare with newer version`,
	}

	scanCmd.Flags().StringP("ref", "r", "HEAD", "Git reference to scan (branch, tag, or commit)")
	scanCmd.PersistentFlags().StringSliceP("ecosystems", "e", []string{"all"}, "Ecosystems to scan: go, npm, pypi, maven, rubygems, cargo, nuget, hex, pub, cocoapods, packagist, github-actions, haskell, r, cpp (default: all)")
	scanCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	scanCmd.Flags().StringP("format", "f", "text", "Output format (text, json, sarif)")
	scanCmd.Flags().Bool("ignore-unfixed", false, "Ignore vulnerabilities without fixes")
	scanCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	scanCmd.Flags().StringArray("policy", nil, "Path to a CEL policy file or bundle to evaluate against the scan report (repeatable)")
	scanCmd.Flags().Bool("show-symbols", false, "Show symbol hints (OSV imports) in text output")
	scanCmd.Flags().Bool("show-db-info", false, "Show database-specific metadata (e.g., review_status) in text output")

	scanDirCmd := &cobra.Command{
		Use:           "dir <path>",
		Short:         "Scan a directory for vulnerabilities",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Scan a directory for vulnerabilities without Git context.

This subcommand is useful when you want to scan source code that isn't in a Git
repository or when you want to scan the current working state without considering
Git history. It directly analyzes the filesystem for package definitions and
dependency manifests.

FILESYSTEM ANALYSIS:
Scans go.mod files and other package manifests in the specified directory tree.
Does not require Git repository context, making it suitable for CI/CD environments
where only source code (not Git history) is available.`,
		RunE: scanner.runScanDir,
		Example: `DIRECTORY SCANNING:
  # Scan current directory
  deputy scan dir .

  # Scan specific project directory
  deputy scan dir /path/to/project
  deputy scan dir ~/projects/my-app

  # Scan with output to file
  deputy scan dir . --output security-report.txt
  deputy scan dir /project --format json --output report.json

  # Ignore unfixed vulnerabilities
  deputy scan dir . --ignore-unfixed

TYPICAL USE CASES:
  # CI/CD without Git context
  deputy scan dir /workspace --format json

  # Security audit of extracted source
  deputy scan dir ./extracted-source

  # Quick local vulnerability check
  deputy scan dir . --ignore-unfixed`,
	}
	scanDirCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	scanDirCmd.Flags().StringP("format", "f", "text", "Output format (text, json, sarif)")
	scanDirCmd.Flags().Bool("ignore-unfixed", false, "Ignore vulnerabilities without fixes")
	scanDirCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanDirCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanDirCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	scanDirCmd.Flags().StringArray("policy", nil, "Path to a CEL policy file or bundle to evaluate against the scan report (repeatable)")
	scanDirCmd.Flags().Bool("show-symbols", false, "Show symbol hints (OSV imports) in text output")
	scanDirCmd.Flags().Bool("show-db-info", false, "Show database-specific metadata (e.g., review_status) in text output")

	scanSBOMCmd := &cobra.Command{
		Use:           "sbom <file|->",
		Short:         "Scan an SBOM file for vulnerabilities",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Scan a Software Bill of Materials (SBOM) file for vulnerabilities.

SUPPORTED SBOM FORMATS:
• protobom-json: Protobom intermediate format (primary support)
• cyclonedx-json: CycloneDX JSON documents (all 1.x specs)
• spdx-json: SPDX 2.x JSON documents

This command analyzes package information extracted from SBOM documents and
queries the OSV database for known vulnerabilities in those packages.

INPUT SOURCES:
• File path: Read SBOM from a local file
• Stdin: Read SBOM from standard input using '-' or pipe

VULNERABILITY ANALYSIS:
Extracts package names and versions from the SBOM and performs batch vulnerability
queries against the OSV database. Results include CVE information, severity scores,
and available fixes where applicable.`,
		RunE: scanner.runScanSBOM,
		Example: `SBOM FILE SCANNING:
  # Scan SBOM file
  deputy scan sbom software-bill-of-materials.json
  deputy scan sbom ./build/sbom.json
  deputy scan sbom /path/to/project-sbom.json

  # Read SBOM from stdin
  deputy scan sbom -
  deputy scan sbom - < sbom.json
  cat sbom.json | deputy scan sbom -

  # Specify SBOM format explicitly
  deputy scan sbom --input-format protobom-json sbom.protobom.json
  deputy scan sbom --input-format cyclonedx-json bom.cdx.json
  deputy scan sbom --input-format spdx-json bom.spdx.json

OUTPUT AND FILTERING:
  # Save results to file
  deputy scan sbom sbom.json --output vuln-report.txt
  deputy scan sbom sbom.json --format json --output report.json

  # Filter out unfixed vulnerabilities
  deputy scan sbom sbom.json --ignore-unfixed

PIPELINE INTEGRATION:
  # Generate SBOM and scan in one pipeline
  deputy sbom . --format protobom-json | deputy scan sbom -

  # CI/CD integration
  deputy scan sbom build-artifacts/sbom.json --format json --ignore-unfixed

  # Security gate in build pipeline
  deputy scan sbom - --format json < build/sbom.json | jq '.stats.critical'

WORKFLOW EXAMPLES:
  # Analyze third-party SBOM
  deputy scan sbom vendor-provided-sbom.json

  # Security review of release artifacts
  deputy scan sbom release-v1.2.3-sbom.json --ignore-unfixed

  # Compare vulnerability status
  deputy scan sbom old-release-sbom.json --format json > old-vulns.json
  deputy scan sbom new-release-sbom.json --format json > new-vulns.json`,
	}
	scanSBOMCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	scanSBOMCmd.Flags().StringP("format", "f", "text", "Output format (text, json, sarif)")
	scanSBOMCmd.Flags().Bool("ignore-unfixed", false, "Ignore vulnerabilities without fixes")
	scanSBOMCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanSBOMCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanSBOMCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	scanSBOMCmd.Flags().String("input-format", "auto", "Input SBOM format (auto, protobom-json, cyclonedx-json, spdx-json)")
	scanSBOMCmd.Flags().StringArray("policy", nil, "Path to a CEL policy file or bundle to evaluate against the scan report (repeatable)")
	scanSBOMCmd.Flags().Bool("show-symbols", false, "Show symbol hints (OSV imports) in text output")
	scanSBOMCmd.Flags().Bool("show-db-info", false, "Show database-specific metadata (e.g., review_status) in text output")

	scanCmd.AddCommand(scanDirCmd, scanSBOMCmd)
	root.AddCommand(scanCmd)
}

// runScan executes the scan command logic, handling argument parsing,
// scan execution, policy evaluation, and output formatting.
func (s *Scanner) runScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flags := extractScanFlags(cmd)

	repoArg := ""
	if len(args) > 0 {
		repoArg = strings.TrimSpace(args[0])
	}

	beforeT, afterT := flags.parsePublishedTimes(cmd.ErrOrStderr())
	scanOpts := flags.scanOptions()
	exec, err := s.service.ScanRepository(ctx, repoArg, flags.Ref, cmd.Flags().Changed("ref"), scan.Options{
		Ecosystems:      scanOpts.Ecosystems,
		PublishedBefore: beforeT,
		PublishedAfter:  afterT,
	})
	if err != nil {
		return err
	}
	defer exec.Close()

	for _, warning := range exec.Result.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s\n", warning)
	}

	resultOut := exec.Result
	policyResult := exec.Result
	if flags.IgnoreUnfixed {
		policyResult = scan.FilterUnfixed(policyResult)
		resultOut = policyResult
	}
	report := buildScanReport(policyResult)
	policyActions, err := runScanPolicies(ctx, flags.PolicyPaths, report, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)
	report.PolicyFindings = policyFindings
	exec.Result.PolicyDecisions = actionsToPolicyDecisions(policyActions)

	out, err := openOutputWriter(cmd, flags.OutPath)
	if err != nil {
		return err
	}
	defer out.Close()

	switch strings.ToLower(flags.Format) {
	case "", FormatText:
		return s.outputText(out.Writer, cmd.ErrOrStderr(), resultOut, flags.IgnoreUnfixed, policyFindings, flags.displayOptions())
	case FormatJSON:
		return s.outputJSON(out.Writer, resultOut, policyFindings)
	case FormatSARIF:
		return s.outputSARIF(out.Writer, resultOut, policyFindings)
	default:
		return cliflags.UnsupportedFormatError("--format", flags.Format, "text|json|sarif")
	}
}

// runScanDir executes the directory scan command logic.
func (s *Scanner) runScanDir(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected 1 argument: <path>")
	}

	ctx := cmd.Context()
	flags := extractScanFlags(cmd)
	path := strings.TrimSpace(args[0])

	beforeT, afterT := flags.parsePublishedTimes(cmd.ErrOrStderr())
	scanOpts := flags.scanOptions()
	exec, err := s.service.ScanDirectory(ctx, path, scan.Options{
		Ecosystems:      scanOpts.Ecosystems,
		PublishedBefore: beforeT,
		PublishedAfter:  afterT,
	})
	if err != nil {
		return err
	}
	defer exec.Close()

	for _, warning := range exec.Result.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s\n", warning)
	}

	resultOut := exec.Result
	policyResult := exec.Result
	if flags.IgnoreUnfixed {
		policyResult = scan.FilterUnfixed(policyResult)
		resultOut = policyResult
	}
	report := buildScanReport(policyResult)
	policyActions, err := runScanPolicies(ctx, flags.PolicyPaths, report, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)
	exec.Result.PolicyDecisions = actionsToPolicyDecisions(policyActions)

	out, err := openOutputWriter(cmd, flags.OutPath)
	if err != nil {
		return err
	}
	defer out.Close()

	switch strings.ToLower(flags.Format) {
	case "", FormatText:
		return s.outputTextDir(out.Writer, cmd.ErrOrStderr(), resultOut, flags.IgnoreUnfixed, policyFindings, flags.displayOptions())
	case FormatJSON:
		return s.outputJSON(out.Writer, resultOut, policyFindings)
	case FormatSARIF:
		return s.outputSARIF(out.Writer, resultOut, policyFindings)
	default:
		return cliflags.UnsupportedFormatError("--format", flags.Format, "text|json|sarif")
	}
}

// runScanSBOM executes the SBOM scan command logic.
func (s *Scanner) runScanSBOM(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected 1 argument: <path|->")
	}

	ctx := cmd.Context()
	flags := extractScanFlags(cmd)
	input := strings.TrimSpace(args[0])

	var r io.Reader
	if input == "-" {
		r = cmd.InOrStdin()
	} else {
		f, err := os.Open(input)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer f.Close()
		r = f
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	pkgs, direct, err := parseSBOMPackages(data, flags.InputFormat)
	if err != nil {
		return fmt.Errorf("failed to parse SBOM: %w", err)
	}

	beforeT, afterT := flags.parsePublishedTimes(cmd.ErrOrStderr())
	scanOpts := flags.scanOptions()
	exec, err := s.service.ScanSBOM(ctx, pkgs, direct, scan.Options{
		Ecosystems:      scanOpts.Ecosystems,
		PublishedBefore: beforeT,
		PublishedAfter:  afterT,
	})
	if err != nil {
		return err
	}

	for _, warning := range exec.Result.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s\n", warning)
	}

	resultOut := exec.Result
	policyResult := exec.Result
	if flags.IgnoreUnfixed {
		policyResult = scan.FilterUnfixed(policyResult)
		resultOut = policyResult
	}
	report := buildScanReport(policyResult)
	policyActions, err := runScanPolicies(ctx, flags.PolicyPaths, report, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)
	exec.Result.PolicyDecisions = actionsToPolicyDecisions(policyActions)

	out, err := openOutputWriter(cmd, flags.OutPath)
	if err != nil {
		return err
	}
	defer out.Close()

	switch strings.ToLower(flags.Format) {
	case "", FormatText:
		doc := render.ScanResultsHeaderDoc("SBOM input", "", "", "")
		_ = doc.Render(out.Writer, output.UIStyles())
		if flags.IgnoreUnfixed {
			fmt.Fprintln(cmd.ErrOrStderr(), "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
		}
		render.DisplayVulnerabilities(out.Writer, resultOut, flags.displayOptions())
		render.RenderPolicyFindings(out.Writer, policyFindings)
		return nil
	case FormatJSON:
		return s.outputJSON(out.Writer, resultOut, policyFindings)
	case FormatSARIF:
		return s.outputSARIF(out.Writer, resultOut, policyFindings)
	default:
		return cliflags.UnsupportedFormatError("--format", flags.Format, "text|json|sarif")
	}
}

// Helper functions

// refOrHEAD returns RefHEAD if the input reference is empty, otherwise returns the input.
func refOrHEAD(r string) string {
	if strings.TrimSpace(r) == "" {
		return gitx.RefHEAD
	}
	return r
}

// outputText writes the scan results in a human-readable text format to the provided writer.
func (s *Scanner) outputText(w io.Writer, errW io.Writer, result scan.Result, ignoreUnfixed bool, policyFindings []report.PolicyFinding, displayOpts render.VulnerabilityDisplayOptions) error {
	displayPath := result.Target.DisplayPath
	localPath := result.Target.LocalPath
	shortRef := shortGitRef(refOrHEAD(result.Target.Ref))
	shortHash := result.Target.CommitHash
	if len(shortHash) > 7 {
		shortHash = shortHash[:7]
	}

	// Check for working tree changes
	if strings.TrimSpace(localPath) != "" {
		if repo, err := git.PlainOpen(localPath); err == nil {
			if wt, err := repo.Worktree(); err == nil {
				if st, err := wt.Status(); err == nil && !st.IsClean() {
					shortRef = "WORKING"
				}
			}
		}
	}

	doc := render.ScanResultsHeaderDoc(displayPath, shortRef, shortHash, result.Target.OriginURL)
	_ = doc.Render(w, output.UIStyles())

	if ignoreUnfixed {
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
	}

	render.DisplayVulnerabilities(w, result, displayOpts)
	render.RenderPolicyFindings(w, policyFindings)

	// Show module deprecations
	if deps := detectModuleDeprecations(result.Inventory.Packages, result.Inventory.Direct); len(deps) > 0 {
		fmt.Fprintf(w, "\n%s\n", ui.StyleHeader.Render("Module Deprecations:"))
		for _, d := range deps {
			line := fmt.Sprintf("  %s %s -> %s", ui.StyleVersion.Render("•"), ui.StyleBold.Render(d.Module), ui.StyleVersion.Render(d.Suggest))
			if d.URL != "" {
				line += " " + ui.StyleDim.Render("("+d.URL+")")
			}
			fmt.Fprintln(w, line)
		}
	}

	return nil
}

// outputTextDir writes the directory scan results in a human-readable text format.
func (s *Scanner) outputTextDir(w io.Writer, errW io.Writer, result scan.Result, ignoreUnfixed bool, policyFindings []report.PolicyFinding, displayOpts render.VulnerabilityDisplayOptions) error {
	doc := render.ScanResultsHeaderDoc(result.Target.DisplayPath, "", "", "")
	_ = doc.Render(w, output.UIStyles())

	if ignoreUnfixed {
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
	}

	render.DisplayVulnerabilities(w, result, displayOpts)
	render.RenderPolicyFindings(w, policyFindings)
	return nil
}

// outputJSON writes the scan results in JSON format to the provided writer.
func (s *Scanner) outputJSON(w io.Writer, result scan.Result, policyFindings []report.PolicyFinding) error {
	report := buildScanReport(result)
	report.PolicyFindings = policyFindings

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// outputSARIF writes the scan results in SARIF format for GitHub Security tab integration.
func (s *Scanner) outputSARIF(w io.Writer, result scan.Result, policyFindings []report.PolicyFinding) error {
	vulns := report.FlattenResult(result)

	opts := sarif.Options{
		ToolVersion: version.Value,
		Repo:        result.Target.OriginURL,
		Ref:         result.Target.EffectiveRef,
		Commit:      result.Target.CommitHash,
		StartTime:   time.Now(),
		EndTime:     time.Now(),
	}

	// Use display path as repo if no origin URL
	if opts.Repo == "" {
		opts.Repo = result.Target.DisplayPath
	}

	log := sarif.Convert(vulns, policyFindings, opts)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// parseSBOMPackages converts supported SBOM documents into package tuples for OSV queries.
func parseSBOMPackages(data []byte, inFmt string) ([]*extractor.Package, map[string]bool, error) {
	format, err := cliflags.NormalizeSBOMInputFormat(inFmt)
	if err != nil {
		return nil, nil, err
	}
	var tryOrder []string
	seen := collections.NewSet[string]()
	addFormat := func(kind string) {
		if kind == "" {
			return
		}
		if !seen.Add(kind) {
			return
		}
		tryOrder = append(tryOrder, kind)
	}

	switch format {
	case cliflags.SBOMInputAuto:
		if detected := detectSBOMFormat(data); detected != "" {
			addFormat(detected)
		}
		addFormat(cliflags.SBOMInputProtobom)
		addFormat(cliflags.SBOMInputCycloneDX)
		addFormat(cliflags.SBOMInputSPDX)
	case cliflags.SBOMInputProtobom:
		addFormat(cliflags.SBOMInputProtobom)
	case cliflags.SBOMInputCycloneDX:
		addFormat(cliflags.SBOMInputCycloneDX)
	case cliflags.SBOMInputSPDX:
		addFormat(cliflags.SBOMInputSPDX)
	}

	var lastErr error
	for _, kind := range tryOrder {
		var (
			pkgs   []*extractor.Package
			direct map[string]bool
			err    error
		)
		switch kind {
		case cliflags.SBOMInputProtobom:
			pkgs, direct, err = parseProtobomPackages(data)
		case cliflags.SBOMInputCycloneDX:
			pkgs, direct, err = parseCycloneDXPackages(data)
		case cliflags.SBOMInputSPDX:
			pkgs, direct, err = parseSPDXPackages(data)
		default:
			err = fmt.Errorf("unknown SBOM format %q", kind)
		}
		if err == nil && len(pkgs) > 0 {
			return pkgs, direct, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, nil, lastErr
	}
	return nil, nil, fmt.Errorf("unsupported or empty SBOM input; specify --input-format (protobom-json|cyclonedx-json|spdx-json)")
}

// detectSBOMFormat attempts to identify the SBOM format from the input data.
// It checks for known fields and schemas for CycloneDX, SPDX, and Protobom.
func detectSBOMFormat(data []byte) string {
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return ""
	}
	if v, ok := probe["bomFormat"].(string); ok && strings.EqualFold(v, "cyclonedx") {
		return "cyclonedx"
	}
	if schema, ok := probe["$schema"].(string); ok && strings.Contains(strings.ToLower(schema), "cyclonedx") {
		return "cyclonedx"
	}
	if _, ok := probe["spdxVersion"]; ok {
		return "spdx"
	}
	if _, ok := probe["nodeList"]; ok {
		return "protobom"
	}
	return ""
}

// parseProtobomPackages parses a Protobom JSON document and extracts package information.
func parseProtobomPackages(data []byte) ([]*extractor.Package, map[string]bool, error) {
	var doc sbom.Document
	if err := protojson.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	nodes := doc.GetNodeList().GetNodes()
	if len(nodes) == 0 {
		return nil, nil, fmt.Errorf("protobom document contained no nodes")
	}
	var pkgs []*extractor.Package
	direct := make(map[string]bool)
	for _, n := range nodes {
		if n.GetType() != sbom.Node_PACKAGE {
			continue
		}
		name := strings.TrimSpace(n.GetName())
		version := strings.TrimSpace(n.GetVersion())
		if name == "" || version == "" {
			continue
		}
		pkg := &extractor.Package{Name: name, Version: version}
		var purlStr string
		if ids := n.GetIdentifiers(); ids != nil {
			if p := ids[int32(sbom.SoftwareIdentifierType_PURL)]; p != "" {
				purlStr = p
				if pu, err := purlx.ParseLoose(purlStr); err == nil {
					pkg.PURLType = pu.Type
				}
			}
		}
		// Restore deputy-specific metadata from properties.
		// "deputy:direct" restores the direct dependency status.
		// "deputy:location" restores the file path (e.g. go.mod) needed for remediation.
		for _, prop := range n.GetProperties() {
			if prop.GetName() == "deputy:direct" && prop.GetData() == "true" {
				if purlStr != "" {
					direct[purlStr] = true
				}
			}
			if prop.GetName() == "deputy:location" {
				pkg.Locations = append(pkg.Locations, prop.GetData())
			}
		}
		pkgs = append(pkgs, pkg)
	}
	if len(pkgs) == 0 {
		return nil, nil, fmt.Errorf("protobom document did not contain package nodes with name+version")
	}
	return pkgs, direct, nil
}

// parseCycloneDXPackages parses a CycloneDX JSON document and extracts package information.
func parseCycloneDXPackages(data []byte) ([]*extractor.Package, map[string]bool, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, nil, err
	}
	if bom.Components == nil || len(*bom.Components) == 0 {
		return nil, nil, fmt.Errorf("cyclonedx document contained no components")
	}
	var pkgs []*extractor.Package
	direct := make(map[string]bool)
	for _, comp := range *bom.Components {
		name := strings.TrimSpace(comp.Name)
		version := strings.TrimSpace(comp.Version)
		if name == "" || version == "" {
			continue
		}
		pkg := &extractor.Package{Name: name, Version: version}
		if comp.PackageURL != "" {
			if pu, err := purlx.ParseLoose(comp.PackageURL); err == nil {
				pkg.PURLType = pu.Type
				// Restore full name from PURL if namespace is present (e.g. for Go, NPM)
				if pu.Namespace != "" {
					sep := "/"
					if pu.Type == "maven" || pu.Type == "gradle" {
						sep = ":"
					}
					fullName := pu.Namespace + sep + pu.Name
					// If the name in SBOM is just the short name, replace it with full name
					if pkg.Name == pu.Name {
						pkg.Name = fullName
					}
				}
			}
		}
		if comp.Properties != nil {
			for _, prop := range *comp.Properties {
				if prop.Name == "deputy:direct" && prop.Value == "true" {
					if comp.PackageURL != "" {
						direct[comp.PackageURL] = true
					}
				}
				if prop.Name == "deputy:location" {
					pkg.Locations = append(pkg.Locations, prop.Value)
				}
			}
		}
		pkgs = append(pkgs, pkg)
	}
	if len(pkgs) == 0 {
		return nil, nil, fmt.Errorf("cyclonedx document did not contain components with name+version")
	}
	return pkgs, direct, nil
}

// parseSPDXPackages parses an SPDX JSON document and extracts package information.
func parseSPDXPackages(data []byte) ([]*extractor.Package, map[string]bool, error) {
	doc, err := spdxjson.Read(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	if doc == nil || len(doc.Packages) == 0 {
		return nil, nil, fmt.Errorf("spdx document contained no packages")
	}
	var pkgs []*extractor.Package
	for _, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}
		name := strings.TrimSpace(pkg.PackageName)
		version := strings.TrimSpace(pkg.PackageVersion)
		if name == "" || version == "" {
			continue
		}
		entry := &extractor.Package{Name: name, Version: version}
		if purlStr := extractSPDXPackagePURL(pkg); purlStr != "" {
			if pu, err := purlx.ParseLoose(purlStr); err == nil {
				entry.PURLType = pu.Type
			}
		}
		pkgs = append(pkgs, entry)
	}
	if len(pkgs) == 0 {
		return nil, nil, fmt.Errorf("spdx document did not contain packages with name+version")
	}
	return pkgs, nil, nil
}

// extractSPDXPackagePURL attempts to find a Package URL (PURL) in the external references of an SPDX package.
func extractSPDXPackagePURL(pkg *spdxdoc.Package) string {
	for _, ref := range pkg.PackageExternalReferences {
		if ref == nil {
			continue
		}
		if !strings.EqualFold(ref.Category, string(spdxcommon.CategoryPackageManager)) {
			continue
		}
		if !strings.EqualFold(ref.RefType, string(spdxcommon.TypePackageManagerPURL)) {
			continue
		}
		locator := strings.TrimSpace(ref.Locator)
		if locator != "" {
			return locator
		}
	}
	return ""
}

// buildScanReport constructs a ScanResult from the scan metadata and findings.
func buildScanReport(result scan.Result) ScanResult {
	ref := strings.TrimSpace(result.Target.Ref)
	if ref != "" {
		ref = shortGitRef(ref)
	}
	generated := time.Now().UTC()
	if !result.GeneratedAt.IsZero() {
		generated = result.GeneratedAt
	}
	return ScanResult{
		Repo:            result.Target.DisplayPath,
		Ref:             ref,
		Commit:          result.Target.CommitHash,
		Generated:       generated.Format(time.RFC3339),
		PackagesScanned: result.PackagesScanned,
		Stats:           result.Stats,
		Vulnerabilities: report.FlattenResult(result),
	}
}

// runScanPolicies evaluates the provided policies against the scan report and individual vulnerabilities.
func runScanPolicies(ctx context.Context, policyPaths []string, report ScanResult, errW io.Writer) ([]policy.Action, error) {
	if len(policyPaths) == 0 {
		return nil, nil
	}
	var out []policy.Action
	reportMap, err := structToMap(report)
	if err != nil {
		return nil, err
	}
	actions, err := evaluatePoliciesForCommand(ctx, policyPaths, reportMap, "scan", "scan_report", errW)
	if err != nil {
		return nil, err
	}
	out = append(out, actions...)
	for _, vuln := range report.Vulnerabilities {
		vulnMap, err := structToMap(vuln)
		if err != nil {
			return nil, err
		}
		payload := map[string]any{
			"repo":          report.Repo,
			"ref":           report.Ref,
			"commit":        report.Commit,
			"vulnerability": vulnMap,
		}
		actions, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "scan", "scan_vulnerability", errW)
		if err != nil {
			return nil, err
		}
		out = append(out, actions...)
	}
	return out, nil
}

// actionsToPolicyFindings converts policy actions into findings suitable for the scan report.
func actionsToPolicyFindings(actions []policy.Action) []report.PolicyFinding {
	if len(actions) == 0 {
		return nil
	}
	var findings []report.PolicyFinding
	for _, act := range actions {
		actionType := strings.TrimSpace(act.Type)
		if actionType == "" || strings.EqualFold(actionType, "allow") {
			continue
		}
		f := report.PolicyFinding{
			Source:      act.Source,
			Action:      actionType,
			Reason:      act.Reason,
			Message:     act.Message,
			Remediation: act.Remediation,
			Status:      act.Status,
			Code:        act.Code,
		}
		findings = append(findings, f)
	}
	return findings
}

func actionsToPolicyDecisions(actions []policy.Action) []policy.Decision {
	if len(actions) == 0 {
		return nil
	}
	decisions := make([]policy.Decision, 0, len(actions))
	for _, act := range actions {
		decisions = append(decisions, policy.DecisionFromAction(act))
	}
	return decisions
}

var knownDeprecations = []ModuleDeprecation{
	{Module: "github.com/aws/aws-sdk-go", Suggest: "github.com/aws/aws-sdk-go-v2", URL: "https://github.com/aws/aws-sdk-go-v2"},
}

// detectModuleDeprecations checks for usage of known deprecated modules in the scanned packages.
// It only reports deprecations for direct dependencies.
func detectModuleDeprecations(pkgs []*extractor.Package, direct map[string]bool) []ModuleDeprecation {
	if len(pkgs) == 0 {
		return nil
	}
	if direct == nil {
		direct = map[string]bool{}
	}

	// Build a set of present module roots by inferring module path from package path
	present := collections.NewSet[string]()
	for _, p := range pkgs {
		if p == nil || p.Name == "" {
			continue
		}

		name := p.Name
		// normalize: trim subpackages to module root heuristic (first 3 path parts for github.com)
		parts := strings.Split(name, "/")
		if len(parts) >= 3 && parts[0] == "github.com" {
			name = strings.Join(parts[:3], "/")
		}
		present.Add(name)
	}

	// Collect matches
	var out []ModuleDeprecation
	seen := collections.NewSet[string]()
	for _, d := range knownDeprecations {
		if !moduleIsDirect(d.Module, direct) {
			continue
		}
		// match by exact or prefix
		if present.Has(d.Module) {
			if seen.Add(d.Module) {
				out = append(out, d)
			}
			continue
		}
		// Also detect subpackages
		for m := range present.All() {
			if strings.HasPrefix(m, d.Module+"/") {
				if seen.Add(d.Module) {
					out = append(out, d)
				}
				break
			}
		}
	}
	return out
}

// moduleIsDirect checks if a module is a direct dependency.
func moduleIsDirect(module string, direct map[string]bool) bool {
	if len(direct) == 0 {
		return false
	}
	if direct[module] {
		return true
	}
	for mod, directDep := range direct {
		if !directDep || mod == "stdlib" {
			continue
		}
		if strings.HasPrefix(mod, module+"/") {
			return true
		}
	}
	return false
}

// shortGitRef returns a shortened version of a git reference, removing common prefixes.
func shortGitRef(ref string) string {
	r := strings.TrimSpace(ref)
	if r == "" {
		return r
	}
	if strings.HasPrefix(r, "refs/tags/") {
		return strings.TrimPrefix(r, "refs/tags/")
	}
	if strings.HasPrefix(r, "refs/heads/") {
		return strings.TrimPrefix(r, "refs/heads/")
	}
	if strings.HasPrefix(r, "refs/") {
		if i := strings.LastIndex(r, "/"); i >= 0 && i < len(r)-1 {
			return r[i+1:]
		}
	}
	return r
}
