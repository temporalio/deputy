package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/compare"
	gitx "github.com/picatz/deputy/internal/gitutil"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/output"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/purlx"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	sbomx "github.com/picatz/deputy/internal/sbom"
	"github.com/picatz/deputy/internal/targets"
	_ "github.com/picatz/deputy/internal/targets/providers"
	ui "github.com/picatz/deputy/internal/ui"
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
	Stats analysis.VulnerabilityStats `json:"stats"`
	// Vulnerabilities is the list of security vulnerabilities found in dependencies.
	Vulnerabilities []analysis.Vulnerability `json:"vulnerabilities"`
	// PolicyFindings contains policy evaluation results (deny/warn actions).
	PolicyFindings []PolicyFinding `json:"policyFindings,omitempty"`
}

// PolicyFinding represents a policy action emitted during scan evaluation.
type PolicyFinding struct {
	// Source is the name of the policy that generated this finding.
	Source string `json:"source"`
	// Action is the policy decision type (e.g., "deny", "warn", "allow").
	Action string `json:"action"`
	// Reason explains why the policy triggered this action.
	Reason string `json:"reason,omitempty"`
	// Message provides additional context or details about the finding.
	Message string `json:"message,omitempty"`
	// Remediation suggests steps to resolve the policy violation.
	Remediation string `json:"remediation,omitempty"`
	// Status is an optional HTTP status code suggestion for proxy mode.
	Status *int `json:"status,omitempty"`
	// Code is a machine-readable identifier for the finding type.
	Code string `json:"code,omitempty"`
}

// ModuleDeprecation captures information about a deprecated module and its
// suggested replacement (future enrichment hook).
type ModuleDeprecation struct {
	Module  string `json:"module"`
	Suggest string `json:"suggest"`
	URL     string `json:"url,omitempty"`
}

// Scanner orchestrates vulnerability scans by combining inventory collection
// (scalibr), OSV lookups, and presentation helpers. The collaborators are
// fields so tests can inject deterministic doubles instead of hitting the
// network or filesystem.
type Scanner struct {
	collectInventory     func(ctx context.Context, repoPath, gitRef string, opts inv.ScanOptions) ([]*extractor.Package, error)
	queryVulnerabilities func(ctx context.Context, client analysis.OSVClient, pkgs []analysis.PkgInput) ([]analysis.Vulnerability, error)
	osvClient            analysis.OSVClient
}

// scanExecution holds the state and results of a single scan operation,
// including the target path, resolved references, inventory, and findings.
type scanExecution struct {
	displayPath     string
	localRepoPath   string
	requestedRef    string
	effectiveRef    string
	packages        []*extractor.Package
	goDirect        map[string]bool
	vulnerabilities []analysis.Vulnerability
	commitHash      string
	originURL       string
	cloned          bool
	cleanup         func()
}

// Close cleans up any resources associated with the scan execution,
// such as temporary directories created during cloning.
func (se *scanExecution) Close() {
	if se != nil && se.cleanup != nil {
		se.cleanup()
	}
}

// NewScanner returns a Scanner configured with the default inventory collection
// implementation.
func NewScanner() *Scanner {
	return &Scanner{
		collectInventory:     collectInventory,
		queryVulnerabilities: analysis.QueryOSVBatch,
		osvClient:            analysis.NewOSVClient(),
	}
}

// queryOSV executes the vulnerability query using the configured client and query function.
func (s *Scanner) queryOSV(ctx context.Context, inputs []analysis.PkgInput) ([]analysis.Vulnerability, error) {
	query := s.queryVulnerabilities
	if query == nil {
		query = analysis.QueryOSVBatch
	}
	client := s.osvClient
	if client == nil {
		client = analysis.NewOSVClient()
	}
	return query(ctx, client, inputs)
}

// executeScan performs the core scanning logic: resolving the target, collecting inventory,
// and querying for vulnerabilities. It returns a scanExecution object containing the results.
func (s *Scanner) executeScan(ctx context.Context, repoArg, ref string, refProvided bool, scanOpts inv.ScanOptions, beforeT, afterT time.Time, errW io.Writer) (*scanExecution, error) {
	targetInput := strings.TrimSpace(repoArg)
	if targetInput == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %w", err)
		}
		targetInput = wd
	}
	mOpts := map[string]string{}
	if ref != "" {
		mOpts["ref"] = ref
	}
	mat, err := targets.Open(ctx, targetInput, mOpts)
	if err != nil {
		if errors.Is(err, targets.ErrNoProvider) {
			return nil, fmt.Errorf("could not interpret repo %q as local path or remote URL", targetInput)
		}
		return nil, err
	}
	cleanup := func() {}
	if mat.Cleanup != nil {
		cleanup = mat.Cleanup
	}

	// Extract workspace from materialized target
	var ws workspace.FS
	switch src := mat.Data.(type) {
	case *repository.Source:
		ws = src.Workspace
	case workspace.FS:
		ws = src
	}

	localRepoPath := mat.Path
	if localRepoPath == "" {
		if src, ok := mat.Data.(interface{ RootPath() string }); ok {
			localRepoPath = src.RootPath()
		}
	}
	if localRepoPath == "" {
		cleanup()
		return nil, fmt.Errorf("target %q did not provide a local filesystem path", targetInput)
	}
	if abs, err := filepath.Abs(localRepoPath); err == nil {
		localRepoPath = abs
	}
	displayPath := targetInput
	if mat.Meta.Target != "" {
		displayPath = mat.Meta.Target
	}
	if pRef := mat.Meta.Provenance["ref"]; pRef != "" {
		ref = pRef
	}
	cloned := strings.EqualFold(mat.Meta.Provenance["cloned"], "true")

	effRef := refOrHEAD(ref)
	if strings.EqualFold(effRef, "HEAD") && refProvided {
		effRef = "HEAD~0"
	}

	pkgs, err := s.collectInventory(ctx, localRepoPath, effRef, scanOpts)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to collect inventory: %w", err)
	}

	goDirect := map[string]bool{"stdlib": true}
	var resolver manifestResolver = workspaceManifestResolver{ws: ws}
	if strings.EqualFold(effRef, "HEAD") || strings.EqualFold(effRef, "HEAD~0") {
		if ws != nil {
			goDirect = compare.CollectGoDirectModulesFromWorkspace(ws)
		}
	} else {
		if repo, err := git.PlainOpen(localRepoPath); err == nil {
			if h, err := gitx.ResolveRevisionEnhanced(repo, effRef); err == nil && h != nil {
				if direct, derr := compare.CollectGoDirectModulesFromCommit(repo, *h); derr == nil {
					goDirect = direct
				}
				resolver = gitManifestResolver{repo: repo, hash: *h}
			}
		}
	}

	inputs := packagesToInputs(pkgs, packageInputOptions{GoDirect: goDirect, Resolver: resolver})
	vulns, queryErr := s.queryOSV(ctx, inputs)
	if queryErr != nil {
		fmt.Fprintf(errW, "Warning: OSV query failed: %v\n", queryErr)
	}
	if !beforeT.IsZero() || !afterT.IsZero() {
		vulns = analysis.FilterVulnerabilitiesByPublished(vulns, afterT, beforeT)
	}

	commitHash, originURL := getRepoMetadata(localRepoPath, ref)

	return &scanExecution{
		displayPath:     displayPath,
		localRepoPath:   localRepoPath,
		requestedRef:    ref,
		effectiveRef:    effRef,
		packages:        pkgs,
		goDirect:        goDirect,
		vulnerabilities: vulns,
		commitHash:      commitHash,
		originURL:       originURL,
		cloned:          cloned,
		cleanup:         cleanup,
	}, nil
}

// AddScanCommand registers the scan subcommand with the root command.
// It configures the command flags and usage examples.
func AddScanCommand(root *cobra.Command) {
	scanner := NewScanner()

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
	scanCmd.PersistentFlags().StringSliceP("ecosystems", "e", []string{"all"}, "Ecosystems to scan (default: all supported)")
	scanCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	scanCmd.Flags().StringP("format", "f", "text", "Output format (text, json)")
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
	scanDirCmd.Flags().StringP("format", "f", "text", "Output format (text, json)")
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
	scanSBOMCmd.Flags().StringP("format", "f", "text", "Output format (text, json)")
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

	ref, _ := cmd.Flags().GetString("ref")
	ecos, _ := cmd.Flags().GetStringSlice("ecosystems")
	scanOpts := inv.ScanOptions{Ecosystems: ecos}
	outPath, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	ignoreUnfixed, _ := cmd.Flags().GetBool("ignore-unfixed")
	publishedBeforeStr, _ := cmd.Flags().GetString("published-before")
	publishedAfterStr, _ := cmd.Flags().GetString("published-after")
	asOfStr, _ := cmd.Flags().GetString("as-of")
	policyPaths, _ := cmd.Flags().GetStringArray("policy")
	showSymbols, _ := cmd.Flags().GetBool("show-symbols")
	showDBInfo, _ := cmd.Flags().GetBool("show-db-info")
	displayOpts := vulnDisplayOptions{showSymbols: showSymbols, showDatabaseInfo: showDBInfo}

	repoArg := ""
	if len(args) > 0 {
		repoArg = strings.TrimSpace(args[0])
	}
	beforeT, afterT := parsePublishedFilters(cmd.ErrOrStderr(), asOfStr, publishedBeforeStr, publishedAfterStr)
	exec, err := s.executeScan(ctx, repoArg, ref, cmd.Flags().Changed("ref"), scanOpts, beforeT, afterT, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	defer exec.Close()

	vulns := exec.vulnerabilities
	pkgs := exec.packages
	goDirect := exec.goDirect
	vulnsForPolicy := vulns
	if ignoreUnfixed {
		vulnsForPolicy = filterUnfixed(vulns)
	}
	report := buildScanReport(exec.displayPath, ref, exec.commitHash, vulnsForPolicy, len(pkgs))
	policyActions, err := runScanPolicies(ctx, policyPaths, report, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)
	report.PolicyFindings = policyFindings

	var w io.Writer = cmd.OutOrStdout()
	if outPath != "" && outPath != "-" {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(format) {
	case "", "text":
		return s.outputText(w, cmd.ErrOrStderr(), exec.displayPath, ref, exec.commitHash, exec.originURL, pkgs, goDirect, vulns, ignoreUnfixed, policyFindings, displayOpts)
	case "json":
		return s.outputJSON(w, exec.displayPath, ref, exec.commitHash, vulns, len(pkgs), ignoreUnfixed, policyFindings)
	default:
		return fmt.Errorf("unsupported --format %q (use text|json)", format)
	}
}

// runScanDir executes the directory scan command logic.
func (s *Scanner) runScanDir(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected 1 argument: <path>")
	}

	ctx := cmd.Context()
	path := strings.TrimSpace(args[0])
	outPath, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	ignoreUnfixed, _ := cmd.Flags().GetBool("ignore-unfixed")
	publishedBeforeStr, _ := cmd.Flags().GetString("published-before")
	publishedAfterStr, _ := cmd.Flags().GetString("published-after")
	asOfStr, _ := cmd.Flags().GetString("as-of")
	policyPaths, _ := cmd.Flags().GetStringArray("policy")
	showSymbols, _ := cmd.Flags().GetBool("show-symbols")
	showDBInfo, _ := cmd.Flags().GetBool("show-db-info")
	displayOpts := vulnDisplayOptions{showSymbols: showSymbols, showDatabaseInfo: showDBInfo}

	ecos, _ := cmd.Flags().GetStringSlice("ecosystems")
	scanOpts := inv.ScanOptions{Ecosystems: ecos}

	ws, err := workspace.NewDir(path)
	if err != nil {
		return fmt.Errorf("failed to open directory: %w", err)
	}
	defer ws.Close()

	pkgs, err := inv.ScanPackagesWorking(ctx, ws, scanOpts)
	if err != nil {
		return fmt.Errorf("failed to scan packages: %w", err)
	}

	goDirect := compare.CollectGoDirectModulesFromWorkspace(ws)
	inputs := packagesToInputs(pkgs, packageInputOptions{GoDirect: goDirect, Resolver: workspaceManifestResolver{ws: ws}})

	vulns, err := s.queryOSV(ctx, inputs)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: OSV query failed: %v\n", err)
	}
	beforeT, afterT := parsePublishedFilters(cmd.ErrOrStderr(), asOfStr, publishedBeforeStr, publishedAfterStr)
	if !beforeT.IsZero() || !afterT.IsZero() {
		vulns = analysis.FilterVulnerabilitiesByPublished(vulns, afterT, beforeT)
	}
	vulnsForPolicy := vulns
	if ignoreUnfixed {
		vulnsForPolicy = filterUnfixed(vulns)
	}
	report := buildScanReport(path, "", "", vulnsForPolicy, len(pkgs))
	policyActions, err := runScanPolicies(ctx, policyPaths, report, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)

	var w io.Writer = cmd.OutOrStdout()
	if outPath != "" && outPath != "-" {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(format) {
	case "", "text":
		return s.outputTextDir(w, cmd.ErrOrStderr(), path, vulns, ignoreUnfixed, policyFindings, displayOpts)
	case "json":
		return s.outputJSON(w, path, "", "", vulns, len(pkgs), ignoreUnfixed, policyFindings)
	default:
		return fmt.Errorf("unsupported --format %q (use text|json)", format)
	}
}

// runScanSBOM executes the SBOM scan command logic.
func (s *Scanner) runScanSBOM(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected 1 argument: <path|->")
	}

	ctx := cmd.Context()
	input := strings.TrimSpace(args[0])
	outPath, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	ignoreUnfixed, _ := cmd.Flags().GetBool("ignore-unfixed")
	publishedBeforeStr, _ := cmd.Flags().GetString("published-before")
	publishedAfterStr, _ := cmd.Flags().GetString("published-after")
	asOfStr, _ := cmd.Flags().GetString("as-of")
	inFmt, _ := cmd.Flags().GetString("input-format")
	policyPaths, _ := cmd.Flags().GetStringArray("policy")
	showSymbols, _ := cmd.Flags().GetBool("show-symbols")
	showDBInfo, _ := cmd.Flags().GetBool("show-db-info")
	displayOpts := vulnDisplayOptions{showSymbols: showSymbols, showDatabaseInfo: showDBInfo}

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

	pkgs, direct, err := parseSBOMPackages(data, inFmt)
	if err != nil {
		return fmt.Errorf("failed to parse SBOM: %w", err)
	}

	inputs := packagesToInputs(pkgs, packageInputOptions{DirectPackages: direct})

	vulns, err := s.queryOSV(ctx, inputs)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: OSV query failed: %v\n", err)
	}
	beforeT, afterT := parsePublishedFilters(cmd.ErrOrStderr(), asOfStr, publishedBeforeStr, publishedAfterStr)
	if !beforeT.IsZero() || !afterT.IsZero() {
		vulns = analysis.FilterVulnerabilitiesByPublished(vulns, afterT, beforeT)
	}
	vulnsForPolicy := vulns
	if ignoreUnfixed {
		vulnsForPolicy = filterUnfixed(vulns)
	}
	report := buildScanReport("sbom", "", "", vulnsForPolicy, len(pkgs))
	policyActions, err := runScanPolicies(ctx, policyPaths, report, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)

	var w io.Writer = cmd.OutOrStdout()
	if outPath != "" && outPath != "-" {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(format) {
	case "", "text":
		doc := scanResultsHeaderDoc("SBOM input", "", "", "")
		_ = doc.Render(w, output.UIStyles())
		vulnsEff := vulns
		if ignoreUnfixed {
			vulnsEff = filterUnfixed(vulns)
			fmt.Fprintln(cmd.ErrOrStderr(), "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
		}
		DisplayVulnerabilities(w, vulnsEff, displayOpts)
		DisplayPolicyFindings(w, policyFindings)
		return nil
	case "json":
		return s.outputJSON(w, "sbom", "", "", vulns, len(pkgs), ignoreUnfixed, policyFindings)
	default:
		return fmt.Errorf("unsupported --format %q (use text|json)", format)
	}
}

func scanResultsHeaderDoc(target, ref, commitHash, originURL string) output.Doc {
	var doc output.Doc
	doc.AddBlank()
	doc.AddLine(output.Span{Text: "Scan Results:", Style: output.StyleHeader})
	doc.AddLine(output.Span{Text: "  Target: "}, output.Span{Text: target, Style: output.StylePackageName})
	if strings.TrimSpace(ref) != "" {
		spans := []output.Span{
			{Text: "  Ref: "},
			{Text: ref, Style: output.StyleVersion},
		}
		if strings.TrimSpace(commitHash) != "" {
			spans = append(spans,
				output.Span{Text: " ("},
				output.Span{Text: commitHash, Style: output.StyleVersion},
				output.Span{Text: ")"},
			)
		}
		doc.AddLine(spans...)
	}
	if strings.TrimSpace(originURL) != "" {
		doc.AddLine(output.Span{Text: "  Origin: "}, output.Span{Text: originURL, Style: output.StyleMeta})
	}
	return doc
}

// Helper functions

// collectInventory determines whether to scan the working directory or a specific commit
// based on the provided git reference, and delegates to the appropriate scanning function.
func collectInventory(ctx context.Context, repoPath, gitRef string, opts inv.ScanOptions) ([]*extractor.Package, error) {
	ref := refOrHEAD(gitRef)
	if strings.EqualFold(ref, "HEAD") {
		if _, err := git.PlainOpen(repoPath); err == nil {
			return scanPackagesWorkingAtPath(ctx, repoPath, opts)
		}
		return scanPackagesWorkingAtPath(ctx, repoPath, opts)
	}

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	h, err := gitx.ResolveRevisionEnhanced(repo, ref)
	if err != nil {
		return nil, err
	}

	return scanPackagesAtCommit(ctx, repoPath, *h, opts)
}

// scanPackagesWorkingAtPath scans the filesystem at the given path for packages.
func scanPackagesWorkingAtPath(ctx context.Context, path string, opts inv.ScanOptions) ([]*extractor.Package, error) {
	ws, err := workspace.NewDir(path)
	if err != nil {
		return nil, err
	}
	defer ws.Close()
	return inv.ScanPackagesWorking(ctx, ws, opts)
}

// scanPackagesAtCommit scans the repository at the given commit hash for packages.
func scanPackagesAtCommit(ctx context.Context, path string, hash plumbing.Hash, opts inv.ScanOptions) ([]*extractor.Package, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, err
	}
	return inv.ScanPackagesAtCommitSnapshot(ctx, repo, hash, opts)
}

// refOrHEAD returns "HEAD" if the input reference is empty, otherwise returns the input.
func refOrHEAD(r string) string {
	if strings.TrimSpace(r) == "" {
		return "HEAD"
	}
	return r
}

// parsePublishedFilters parses the date filter flags and returns the before and after times.
func parsePublishedFilters(errW io.Writer, asOfStr, beforeStr, afterStr string) (time.Time, time.Time) {
	var beforeT, afterT time.Time
	if asOfStr != "" {
		if t, err := analysis.ParseFlexibleDate(asOfStr, "asof"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(errW, "Warning: could not parse --as-of date %q: %v\n", asOfStr, err)
		}
	}
	if beforeStr != "" && beforeT.IsZero() {
		if t, err := analysis.ParseFlexibleDate(beforeStr, "before"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(errW, "Warning: could not parse --published-before %q: %v\n", beforeStr, err)
		}
	}
	if afterStr != "" {
		if t, err := analysis.ParseFlexibleDate(afterStr, "after"); err == nil {
			afterT = t
		} else {
			fmt.Fprintf(errW, "Warning: could not parse --published-after %q: %v\n", afterStr, err)
		}
	}
	return beforeT, afterT
}

// filterUnfixed returns a slice of vulnerabilities that have at least one fixed version.
func filterUnfixed(vs []analysis.Vulnerability) []analysis.Vulnerability {
	if len(vs) == 0 {
		return vs
	}

	out := make([]analysis.Vulnerability, 0, len(vs))
	for _, v := range vs {
		if len(v.FixedVersions) > 0 {
			if fix := analysis.FindBestFixedVersion(v.FixedVersions, v.Version); fix != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// getRepoMetadata attempts to resolve the commit hash and origin URL for the given repository path and reference.
func getRepoMetadata(localRepoPath, ref string) (string, string) {
	commitHash := ""
	originURL := ""

	repo, err := git.PlainOpen(localRepoPath)
	if err != nil {
		return commitHash, originURL
	}

	// Get commit hash
	if h, err := gitx.ResolveRevisionEnhanced(repo, refOrHEAD(ref)); err == nil && h != nil {
		commitHash = h.String()
	} else if headRef, err := repo.Head(); err == nil {
		commitHash = headRef.Hash().String()
	}

	// Get origin URL
	if r, err := repo.Remote("origin"); err == nil && r != nil && r.Config() != nil && len(r.Config().URLs) > 0 {
		u := strings.TrimSpace(r.Config().URLs[0])
		if u != "" {
			switch {
			case strings.HasPrefix(u, "git@github.com:"):
				p := strings.TrimPrefix(u, "git@github.com:")
				if !strings.HasSuffix(p, ".git") {
					p += ".git"
				}
				originURL = "https://github.com/" + p
			case strings.HasPrefix(u, "ssh://git@github.com/"):
				p := strings.TrimPrefix(u, "ssh://git@github.com/")
				if !strings.HasSuffix(p, ".git") {
					p += ".git"
				}
				originURL = "https://github.com/" + p
			default:
				originURL = u
				if n := sbomx.ToHTTPSGitURL(u); n != "" {
					originURL = n
				}
			}
		}
	}

	return commitHash, originURL
}

// outputText writes the scan results in a human-readable text format to the provided writer.
func (s *Scanner) outputText(w io.Writer, errW io.Writer, repoPath, ref, commitHash, originURL string, pkgs []*extractor.Package, goDirect map[string]bool, vulns []analysis.Vulnerability, ignoreUnfixed bool, policyFindings []PolicyFinding, displayOpts vulnDisplayOptions) error {
	shortRef := shortGitRef(refOrHEAD(ref))
	shortHash := commitHash
	if len(shortHash) > 7 {
		shortHash = shortHash[:7]
	}

	// Check for working tree changes
	if repo, err := git.PlainOpen(repoPath); err == nil {
		if wt, err := repo.Worktree(); err == nil {
			if st, err := wt.Status(); err == nil && !st.IsClean() {
				shortRef = "WORKING"
			}
		}
	}

	doc := scanResultsHeaderDoc(repoPath, shortRef, shortHash, originURL)
	_ = doc.Render(w, output.UIStyles())

	vulnsEff := vulns
	if ignoreUnfixed {
		vulnsEff = filterUnfixed(vulns)
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
	}

	DisplayVulnerabilities(w, vulnsEff, displayOpts)
	DisplayPolicyFindings(w, policyFindings)

	// Show module deprecations
	if deps := detectModuleDeprecations(pkgs, goDirect); len(deps) > 0 {
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
func (s *Scanner) outputTextDir(w io.Writer, errW io.Writer, path string, vulns []analysis.Vulnerability, ignoreUnfixed bool, policyFindings []PolicyFinding, displayOpts vulnDisplayOptions) error {
	doc := scanResultsHeaderDoc(path, "", "", "")
	_ = doc.Render(w, output.UIStyles())

	vulnsEff := vulns
	if ignoreUnfixed {
		vulnsEff = filterUnfixed(vulns)
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
	}

	DisplayVulnerabilities(w, vulnsEff, displayOpts)
	DisplayPolicyFindings(w, policyFindings)
	return nil
}

// outputJSON writes the scan results in JSON format to the provided writer.
func (s *Scanner) outputJSON(w io.Writer, repo, ref, commit string, vulns []analysis.Vulnerability, pkgCount int, ignoreUnfixed bool, policyFindings []PolicyFinding) error {
	vulnsEff := vulns
	if ignoreUnfixed {
		vulnsEff = filterUnfixed(vulns)
	}

	result := buildScanReport(repo, ref, commit, vulnsEff, pkgCount)
	result.PolicyFindings = policyFindings

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// parseSBOMPackages converts supported SBOM documents into package tuples for OSV queries.
func parseSBOMPackages(data []byte, inFmt string) ([]*extractor.Package, map[string]bool, error) {
	const (
		fmtProtobom  = "protobom"
		fmtCycloneDX = "cyclonedx"
		fmtSPDX      = "spdx"
	)

	format := strings.ToLower(strings.TrimSpace(inFmt))
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
	case "", "auto":
		if detected := detectSBOMFormat(data); detected != "" {
			addFormat(detected)
		}
		addFormat(fmtProtobom)
		addFormat(fmtCycloneDX)
		addFormat(fmtSPDX)
	case "protobom", "protobom-json":
		addFormat(fmtProtobom)
	case "cyclonedx", "cyclonedx-json":
		addFormat(fmtCycloneDX)
	case "spdx", "spdx-json":
		addFormat(fmtSPDX)
	default:
		return nil, nil, fmt.Errorf("unsupported --input-format %q (use auto|protobom-json|cyclonedx-json|spdx-json)", inFmt)
	}

	var lastErr error
	for _, kind := range tryOrder {
		var (
			pkgs   []*extractor.Package
			direct map[string]bool
			err    error
		)
		switch kind {
		case fmtProtobom:
			pkgs, direct, err = parseProtobomPackages(data)
		case fmtCycloneDX:
			pkgs, direct, err = parseCycloneDXPackages(data)
		case fmtSPDX:
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
func buildScanReport(repo, ref, commit string, vulns []analysis.Vulnerability, pkgCount int) ScanResult {
	stats := analysis.CategorizeVulnerabilities(vulns)
	return ScanResult{
		Repo:            repo,
		Ref:             shortGitRef(ref),
		Commit:          commit,
		Generated:       time.Now().UTC().Format(time.RFC3339),
		PackagesScanned: pkgCount,
		Stats:           stats,
		Vulnerabilities: vulns,
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
func actionsToPolicyFindings(actions []policy.Action) []PolicyFinding {
	if len(actions) == 0 {
		return nil
	}
	var findings []PolicyFinding
	for _, act := range actions {
		actionType := strings.TrimSpace(act.Type)
		if actionType == "" || strings.EqualFold(actionType, "allow") {
			continue
		}
		f := PolicyFinding{
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
