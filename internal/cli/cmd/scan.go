package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/google/osv-scalibr/extractor"
	analysis "github.com/picatz/deputy/internal/analysis"
	cmp "github.com/picatz/deputy/internal/compare"
	gitx "github.com/picatz/deputy/internal/git"
	inv "github.com/picatz/deputy/internal/inventory"
	sbomx "github.com/picatz/deputy/internal/sbom"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"osv.dev/bindings/go/osvdev"
)

// ScanResult is the structured output of a vulnerability scan suitable for
// serialization to JSON or further aggregation.
type ScanResult struct {
	Repo            string                      `json:"repo"`
	Ref             string                      `json:"ref"`
	Commit          string                      `json:"commit"`
	Generated       string                      `json:"generated"`
	PackagesScanned int                         `json:"packagesScanned"`
	Stats           analysis.VulnerabilityStats `json:"stats"`
	Vulnerabilities []analysis.Vulnerability    `json:"vulnerabilities"`
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
	collectInventory     func(ctx context.Context, repoPath, gitRef string, ecos []string) ([]*extractor.Package, error)
	queryVulnerabilities func(ctx context.Context, client analysis.OSVClient, pkgs []analysis.PkgInput) ([]analysis.Vulnerability, error)
	osvClient            analysis.OSVClient
}

// NewScanner returns a Scanner configured with the default inventory collection
// implementation.
func NewScanner() *Scanner {
	return &Scanner{
		collectInventory:     collectInventory,
		queryVulnerabilities: analysis.QueryOSVBatch,
		osvClient:            osvdev.DefaultClient(),
	}
}

func (s *Scanner) queryOSV(ctx context.Context, inputs []analysis.PkgInput) ([]analysis.Vulnerability, error) {
	query := s.queryVulnerabilities
	if query == nil {
		query = analysis.QueryOSVBatch
	}
	client := s.osvClient
	if client == nil {
		client = osvdev.DefaultClient()
	}
	return query(ctx, client, inputs)
}

// AddScanCommand registers the scan subcommand
func AddScanCommand(root *cobra.Command) {
	scanner := NewScanner()

	scanCmd := &cobra.Command{
		Use:   "scan [repo]",
		Short: "Scan for vulnerabilities",
		Long: `Scan repositories, directories, or SBOM files for security vulnerabilities using the OSV database.

VULNERABILITY DATABASE:
Queries the Open Source Vulnerabilities (OSV) database which aggregates vulnerability
data from multiple sources including CVE, GitHub Security Advisories, Go vulnerability
database, and others. Provides comprehensive coverage for Go ecosystem packages.

SUPPORTED ECOSYSTEMS:
Currently supports Go packages with plans to expand to other ecosystems.
Uses OSV-Scalibr for reliable package detection and vulnerability matching.

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

  # Focus on specific ecosystems (future expansion)
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
	scanCmd.Flags().StringSliceP("ecosystems", "e", []string{"go"}, "Ecosystems to scan (go)")
	scanCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	scanCmd.Flags().StringP("format", "f", "text", "Output format (text, json)")
	scanCmd.Flags().Bool("ignore-unfixed", false, "Ignore vulnerabilities without fixes")
	scanCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")

	scanDirCmd := &cobra.Command{
		Use:   "dir <path>",
		Short: "Scan a directory for vulnerabilities",
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

	scanSBOMCmd := &cobra.Command{
		Use:   "sbom <file|->",
		Short: "Scan an SBOM file for vulnerabilities",
		Long: `Scan a Software Bill of Materials (SBOM) file for vulnerabilities.

SUPPORTED SBOM FORMATS:
• protobom-json: Protobom intermediate format (primary support)
• Future: CycloneDX JSON, SPDX JSON (planned)

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
  deputy scan sbom --input-format protobom-json sbom.json
  deputy scan sbom --input-format auto sbom.json

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
	scanSBOMCmd.Flags().String("input-format", "auto", "Input SBOM format (protobom-json, auto)")

	scanCmd.AddCommand(scanDirCmd, scanSBOMCmd)
	root.AddCommand(scanCmd)
}

func (s *Scanner) runScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	ref, _ := cmd.Flags().GetString("ref")
	ecos, _ := cmd.Flags().GetStringSlice("ecosystems")
	outPath, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	ignoreUnfixed, _ := cmd.Flags().GetBool("ignore-unfixed")
	publishedBeforeStr, _ := cmd.Flags().GetString("published-before")
	publishedAfterStr, _ := cmd.Flags().GetString("published-after")
	asOfStr, _ := cmd.Flags().GetString("as-of")

	repoPath := ""
	if len(args) > 0 {
		repoPath = strings.TrimSpace(args[0])
	}
	if repoPath == "" {
		var err error
		repoPath, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
	}

	localRepoPath := repoPath
	var cleanup func()

	// Handle remote repositories
	if _, err := os.Stat(repoPath); err != nil {
		u := sbomx.ToHTTPSGitURL(repoPath)
		if u == "" {
			return fmt.Errorf("could not interpret repo %q as local path or remote URL", repoPath)
		}

		auth := sbomx.AuthForURL(u)
		rn, err := sbomx.ResolveReferenceName(ctx, u, auth, ref)
		if err == nil {
			ref = rn.String()
		}

		path, cf, err := sbomx.CloneRepoToTemp(ctx, u, auth, rn)
		if err != nil {
			return fmt.Errorf("failed to clone remote repo %s: %w", u, err)
		}

		localRepoPath = path
		cleanup = cf
		defer func() {
			if cleanup != nil {
				cleanup()
			}
		}()
	}

	effRef := refOrHEAD(ref)
	if strings.EqualFold(effRef, "HEAD") {
		if cmd.Flags().Changed("ref") {
			effRef = "HEAD~0"
		}
	}

	pkgs, err := s.collectInventory(ctx, localRepoPath, effRef, ecos)
	if err != nil {
		return fmt.Errorf("failed to collect inventory: %w", err)
	}

	// Determine direct dependencies from go.mod at the specified reference
	var goModData []byte
	if strings.EqualFold(effRef, "HEAD") || strings.EqualFold(effRef, "HEAD~0") {
		b, err := os.ReadFile(filepath.Join(localRepoPath, "go.mod"))
		if err == nil {
			goModData = b
		}
	} else {
		if repo, err := git.PlainOpen(localRepoPath); err == nil {
			if h, err := gitx.ResolveRevisionEnhanced(repo, effRef); err == nil && h != nil {
				if b, err := gitx.ReadFileAtCommit(repo, *h, "go.mod"); err == nil {
					goModData = b
				}
			}
		}
	}
	deps := cmp.GetDirectDependenciesFromGoMod(goModData)

	inputs := packagesToInputs(pkgs, deps)

	vulns, err := s.queryOSV(ctx, inputs)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: OSV query failed: %v\n", err)
	}

	// Historical filtering
	var beforeT, afterT time.Time
	if asOfStr != "" {
		if t, err := analysis.ParseFlexibleDate(asOfStr, "asof"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not parse --as-of date %q: %v\n", asOfStr, err)
		}
	}
	if publishedBeforeStr != "" && beforeT.IsZero() { // as-of takes precedence
		if t, err := analysis.ParseFlexibleDate(publishedBeforeStr, "before"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not parse --published-before %q: %v\n", publishedBeforeStr, err)
		}
	}
	if publishedAfterStr != "" {
		if t, err := analysis.ParseFlexibleDate(publishedAfterStr, "after"); err == nil {
			afterT = t
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not parse --published-after %q: %v\n", publishedAfterStr, err)
		}
	}
	if !beforeT.IsZero() || !afterT.IsZero() {
		vulns = analysis.FilterVulnerabilitiesByPublished(vulns, afterT, beforeT)
	}

	var w io.Writer = os.Stdout
	if outPath != "" && outPath != "-" {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	// Get repository metadata
	commitHash, originURL := getRepoMetadata(localRepoPath, ref)

	switch strings.ToLower(format) {
	case "", "text":
		return s.outputText(w, cmd.ErrOrStderr(), repoPath, ref, commitHash, originURL, pkgs, vulns, ignoreUnfixed)
	case "json":
		return s.outputJSON(w, repoPath, ref, commitHash, vulns, len(pkgs), ignoreUnfixed)
	default:
		return fmt.Errorf("unsupported --format %q (use text|json)", format)
	}
}

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

	pkgs, err := inv.ScanPackagesWorking(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to scan packages: %w", err)
	}

	var goModData []byte
	if b, err := os.ReadFile(filepath.Join(path, "go.mod")); err == nil {
		goModData = b
	}
	deps := cmp.GetDirectDependenciesFromGoMod(goModData)

	inputs := packagesToInputs(pkgs, deps)

	vulns, err := s.queryOSV(ctx, inputs)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: OSV query failed: %v\n", err)
	}
	var beforeT, afterT time.Time
	if asOfStr != "" {
		if t, err := analysis.ParseFlexibleDate(asOfStr, "asof"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not parse --as-of date %q: %v\n", asOfStr, err)
		}
	}
	if publishedBeforeStr != "" && beforeT.IsZero() {
		if t, err := analysis.ParseFlexibleDate(publishedBeforeStr, "before"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not parse --published-before %q: %v\n", publishedBeforeStr, err)
		}
	}
	if publishedAfterStr != "" {
		if t, err := analysis.ParseFlexibleDate(publishedAfterStr, "after"); err == nil {
			afterT = t
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not parse --published-after %q: %v\n", publishedAfterStr, err)
		}
	}
	if !beforeT.IsZero() || !afterT.IsZero() {
		vulns = analysis.FilterVulnerabilitiesByPublished(vulns, afterT, beforeT)
	}

	var w io.Writer = os.Stdout
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
		return s.outputTextDir(w, cmd.ErrOrStderr(), path, vulns, ignoreUnfixed)
	case "json":
		return s.outputJSON(w, path, "", "", vulns, len(pkgs), ignoreUnfixed)
	default:
		return fmt.Errorf("unsupported --format %q (use text|json)", format)
	}
}

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

	var r io.Reader
	if input == "-" {
		r = os.Stdin
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

	pkgs, err := parseSBOMPackages(data, inFmt)
	if err != nil {
		return fmt.Errorf("failed to parse SBOM: %w", err)
	}

	inputs := packagesToInputs(pkgs, nil)

	vulns, err := s.queryOSV(ctx, inputs)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: OSV query failed: %v\n", err)
	}
	var beforeT, afterT time.Time
	if asOfStr != "" {
		if t, err := analysis.ParseFlexibleDate(asOfStr, "asof"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not parse --as-of date %q: %v\n", asOfStr, err)
		}
	}
	if publishedBeforeStr != "" && beforeT.IsZero() {
		if t, err := analysis.ParseFlexibleDate(publishedBeforeStr, "before"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not parse --published-before %q: %v\n", publishedBeforeStr, err)
		}
	}
	if publishedAfterStr != "" {
		if t, err := analysis.ParseFlexibleDate(publishedAfterStr, "after"); err == nil {
			afterT = t
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not parse --published-after %q: %v\n", publishedAfterStr, err)
		}
	}
	if !beforeT.IsZero() || !afterT.IsZero() {
		vulns = analysis.FilterVulnerabilitiesByPublished(vulns, afterT, beforeT)
	}

	var w io.Writer = os.Stdout
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
		fmt.Fprintln(w, "\nScanned SBOM input")
		vulnsEff := vulns
		if ignoreUnfixed {
			vulnsEff = filterUnfixed(vulns)
			fmt.Fprintln(cmd.ErrOrStderr(), "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
		}
		DisplayVulnerabilities(vulnsEff)
		return nil
	case "json":
		return s.outputJSON(w, "sbom", "", "", vulns, len(pkgs), ignoreUnfixed)
	default:
		return fmt.Errorf("unsupported --format %q (use text|json)", format)
	}
}

// Helper functions

func collectInventory(ctx context.Context, repoPath, gitRef string, ecos []string) ([]*extractor.Package, error) {
	ref := refOrHEAD(gitRef)
	if strings.EqualFold(ref, "HEAD") {
		if _, err := git.PlainOpen(repoPath); err == nil {
			return inv.ScanPackagesWorking(ctx, repoPath)
		}
		return inv.ScanPackagesWorking(ctx, repoPath)
	}

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	h, err := gitx.ResolveRevisionEnhanced(repo, ref)
	if err != nil {
		return nil, err
	}

	return inv.ScanPackagesAtCommitSnapshot(ctx, repoPath, *h)
}

func refOrHEAD(r string) string {
	if strings.TrimSpace(r) == "" {
		return "HEAD"
	}
	return r
}

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
			if strings.HasPrefix(u, "git@github.com:") {
				p := strings.TrimPrefix(u, "git@github.com:")
				if !strings.HasSuffix(p, ".git") {
					p += ".git"
				}
				originURL = "https://github.com/" + p
			} else if strings.HasPrefix(u, "ssh://git@github.com/") {
				p := strings.TrimPrefix(u, "ssh://git@github.com/")
				if !strings.HasSuffix(p, ".git") {
					p += ".git"
				}
				originURL = "https://github.com/" + p
			} else {
				if n := sbomx.ToHTTPSGitURL(u); n != "" {
					originURL = n
				} else {
					originURL = u
				}
			}
		}
	}

	return commitHash, originURL
}

func (s *Scanner) outputText(w io.Writer, errW io.Writer, repoPath, ref, commitHash, originURL string, pkgs []*extractor.Package, vulns []analysis.Vulnerability, ignoreUnfixed bool) error {
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

	fmt.Fprintf(w, "\nScanned %s @ %s (%s)\n", repoPath, shortRef, shortHash)
	if originURL != "" {
		fmt.Fprintln(w, "  "+ui.StyleMeta.Render("Origin: ")+originURL)
	}

	vulnsEff := vulns
	if ignoreUnfixed {
		vulnsEff = filterUnfixed(vulns)
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
	}

	DisplayVulnerabilities(vulnsEff)

	// Show module deprecations
	if deps := detectModuleDeprecations(pkgs); len(deps) > 0 {
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

func (s *Scanner) outputTextDir(w io.Writer, errW io.Writer, path string, vulns []analysis.Vulnerability, ignoreUnfixed bool) error {
	fmt.Fprintf(w, "\nScanned %s\n", path)

	vulnsEff := vulns
	if ignoreUnfixed {
		vulnsEff = filterUnfixed(vulns)
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
	}

	DisplayVulnerabilities(vulnsEff)
	return nil
}

func (s *Scanner) outputJSON(w io.Writer, repo, ref, commit string, vulns []analysis.Vulnerability, pkgCount int, ignoreUnfixed bool) error {
	vulnsEff := vulns
	if ignoreUnfixed {
		vulnsEff = filterUnfixed(vulns)
	}

	result := buildScanReport(repo, ref, commit, vulnsEff, pkgCount)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// parseSBOMPackages converts protobom JSON documents (or future formats) into
// the package tuples expected by osv-scalibr / OSV queries.
func parseSBOMPackages(data []byte, inFmt string) ([]*extractor.Package, error) {
	useProto := strings.EqualFold(inFmt, "protobom-json") || strings.EqualFold(inFmt, "auto")
	var pkgs []*extractor.Package

	if useProto {
		var doc sbom.Document
		if err := protojson.Unmarshal(data, &doc); err == nil {
			for _, n := range doc.GetNodeList().GetNodes() {
				if n.GetType() == sbom.Node_PACKAGE {
					name := n.GetName()
					ver := n.GetVersion()
					if name != "" && ver != "" {
						pkgs = append(pkgs, &extractor.Package{Name: name, Version: ver})
					}
				}
			}
		} else if strings.EqualFold(inFmt, "protobom-json") {
			return nil, fmt.Errorf("failed to parse protobom-json: %w", err)
		}
	}

	if len(pkgs) == 0 {
		return nil, fmt.Errorf("unsupported or empty SBOM input; support for CycloneDX/SPDX will be added. Try --input-format protobom-json")
	}

	return pkgs, nil
}

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

var knownDeprecations = []ModuleDeprecation{
	{Module: "github.com/aws/aws-sdk-go", Suggest: "github.com/aws/aws-sdk-go-v2", URL: "https://github.com/aws/aws-sdk-go-v2"},
}

func detectModuleDeprecations(pkgs []*extractor.Package) []ModuleDeprecation {
	if len(pkgs) == 0 {
		return nil
	}

	// Build a set of present module roots by inferring module path from package path
	present := map[string]struct{}{}
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
		present[name] = struct{}{}
	}

	// Collect matches
	var out []ModuleDeprecation
	seen := map[string]struct{}{}
	for _, d := range knownDeprecations {
		// match by exact or prefix
		if _, ok := present[d.Module]; ok {
			if _, dup := seen[d.Module]; !dup {
				out = append(out, d)
				seen[d.Module] = struct{}{}
			}
			continue
		}
		// Also detect subpackages
		for m := range present {
			if strings.HasPrefix(m, d.Module+"/") {
				if _, dup := seen[d.Module]; !dup {
					out = append(out, d)
					seen[d.Module] = struct{}{}
				}
				break
			}
		}
	}
	return out
}

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
