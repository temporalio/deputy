package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	cdx "github.com/CycloneDX/cyclonedx-go"
	git "github.com/go-git/go-git/v5"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/osv-scalibr/extractor"
	packageurl "github.com/package-url/packageurl-go"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	"github.com/temporalio/deputy/internal/services"
	cliflags "github.com/temporalio/deputy/internal/cli/flags"
	"github.com/temporalio/deputy/internal/collections"
	"github.com/temporalio/deputy/internal/container/image"
	"github.com/temporalio/deputy/internal/dockerfile"
	deperrors "github.com/temporalio/deputy/internal/errors"
	gitx "github.com/temporalio/deputy/internal/gitutil"
	"github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/output"
	"github.com/temporalio/deputy/internal/policy"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/report"
	"github.com/temporalio/deputy/internal/report/render"
	"github.com/temporalio/deputy/internal/sarif"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/targets"
	ui "github.com/temporalio/deputy/internal/ui"
	"github.com/temporalio/deputy/internal/version"
	"github.com/protobom/protobom/pkg/sbom"
	spdxjson "github.com/spdx/tools-golang/json"
	spdxdoc "github.com/spdx/tools-golang/spdx"
	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/encoding/protojson"
)

// ModuleDeprecation captures information about a deprecated module and its
// suggested replacement (future enrichment hook).
type ModuleDeprecation struct {
	Module  string `json:"module"`
	Suggest string `json:"suggest"`
	URL     string `json:"url,omitempty"`
}

// AddScanCommand registers the scan subcommand with the root command.
// It configures the command flags and usage examples.
func AddScanCommand(root *cobra.Command, c *services.Clients) {
	scanCmd := &cobra.Command{
		Use:           "scan [target]",
		Aliases:       []string{"s"},
		Short:         "Scan for vulnerabilities",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Scan repositories, directories, SBOM files, container images, or PURLs for security vulnerabilities using the OSV database.

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
known vulnerabilities. It respects go.mod files and understands Go module versioning.
If you omit a target, Deputy scans the current Git repo (or the current directory
when no repo is present). PURLs and common container image references are also
recognized at the top level.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(c, cmd, args)
		},
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

PURL SCANNING:
  # Scan a single package by PURL
  deputy scan pkg:npm/lodash@4.17.21
  deputy scan pkg:golang/github.com/gin-gonic/gin@v1.9.0

CONTAINER IMAGE SCANNING:
  # Scan a registry image without subcommand
  deputy scan ghcr.io/owner/app:1.2.3
  deputy scan docker://ghcr.io/owner/app@sha256:...

SUBCOMMANDS:
  # Scan directory without Git context
  deputy scan dir /path/to/source

  # Scan SBOM file
  deputy scan sbom software-bill-of-materials.json
  deputy scan sbom - < sbom.json

  # Scan container image
  deputy scan image docker://ghcr.io/owner/app:1.2.3

  # Scan a single PURL
  deputy scan purl pkg:npm/lodash@4.17.21

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
	scanCmd.Flags().Bool("no-verify-fixes", false, "Skip Go module proxy verification of fixed versions (offline; trusts advisory data)")
	scanCmd.Flags().String("ignore-file", "", "Path to ignore rules file (.deputyignore.yaml)")
	scanCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	scanCmd.Flags().String("filter", "", "CEL expression to filter vulnerabilities (e.g., 'vulnerability.advisory.severity.level == severity.critical')")
	scanCmd.Flags().StringArray("policy", nil, "Path to a CEL policy file or bundle to evaluate against the scan report (repeatable)")
	scanCmd.Flags().Bool("show-symbols", false, "Show symbol hints (OSV imports) in text output")
	scanCmd.Flags().Bool("show-db-info", false, "Show database-specific metadata (e.g., review_status) in text output")
	scanCmd.Flags().Bool("show-unfixable-guidance", false, "Show actionable guidance for vulnerabilities without fixes")
	scanCmd.Flags().String("source", "", "Target source override: auto, git, dir, sbom, purl, dockerfile, remote, docker-daemon, tarball")
	scanCmd.Flags().String("platform", "", "Platform for remote images (os/arch[/variant])")
	scanCmd.Flags().Bool("enrich", false, "Enrich vulnerabilities with EPSS scores and KEV status (requires network)")
	scanCmd.Flags().Bool("with-graph", false, "Build dependency graph to show paths to vulnerable packages")
	scanCmd.Flags().Bool("secrets", false, "Scan for leaked secrets and credentials in addition to vulnerabilities")
	scanCmd.Flags().Bool("detect-base-image", false, "Detect base image layers in container scans (requires network, queries deps.dev)")

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
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScanDir(c, cmd, args)
		},
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
	scanDirCmd.Flags().Bool("no-verify-fixes", false, "Skip Go module proxy verification of fixed versions (offline; trusts advisory data)")
	scanDirCmd.Flags().String("ignore-file", "", "Path to ignore rules file (.deputyignore.yaml)")
	scanDirCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanDirCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanDirCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	scanDirCmd.Flags().String("filter", "", "CEL expression to filter vulnerabilities (e.g., 'vulnerability.advisory.severity.level == severity.critical')")
	scanDirCmd.Flags().StringArray("policy", nil, "Path to a CEL policy file or bundle to evaluate against the scan report (repeatable)")
	scanDirCmd.Flags().Bool("show-symbols", false, "Show symbol hints (OSV imports) in text output")
	scanDirCmd.Flags().Bool("show-db-info", false, "Show database-specific metadata (e.g., review_status) in text output")
	scanDirCmd.Flags().Bool("show-unfixable-guidance", false, "Show actionable guidance for vulnerabilities without fixes")
	scanDirCmd.Flags().Bool("enrich", false, "Enrich vulnerabilities with EPSS scores and KEV status (requires network)")
	scanDirCmd.Flags().Bool("with-graph", false, "Build dependency graph to show paths to vulnerable packages")
	scanDirCmd.Flags().Bool("secrets", false, "Scan for leaked secrets and credentials in addition to vulnerabilities")

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
and available fixes where applicable.

IMAGE REFERENCES:
If the SBOM includes docker/oci PURLs, Deputy will also resolve and scan
those container images.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScanSBOM(c, cmd, args)
		},
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
	scanSBOMCmd.Flags().Bool("no-verify-fixes", false, "Skip Go module proxy verification of fixed versions (offline; trusts advisory data)")
	scanSBOMCmd.Flags().String("ignore-file", "", "Path to ignore rules file (.deputyignore.yaml)")
	scanSBOMCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanSBOMCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanSBOMCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	scanSBOMCmd.Flags().String("filter", "", "CEL expression to filter vulnerabilities (e.g., 'vulnerability.advisory.severity.level == severity.critical')")
	scanSBOMCmd.Flags().String("input-format", "auto", "Input SBOM format (auto, protobom-json, cyclonedx-json, spdx-json)")
	scanSBOMCmd.Flags().StringArray("policy", nil, "Path to a CEL policy file or bundle to evaluate against the scan report (repeatable)")
	scanSBOMCmd.Flags().Bool("show-symbols", false, "Show symbol hints (OSV imports) in text output")
	scanSBOMCmd.Flags().Bool("show-db-info", false, "Show database-specific metadata (e.g., review_status) in text output")
	scanSBOMCmd.Flags().Bool("show-unfixable-guidance", false, "Show actionable guidance for vulnerabilities without fixes")
	scanSBOMCmd.Flags().Bool("enrich", false, "Enrich vulnerabilities with EPSS scores and KEV status (requires network)")

	scanPURLCmd := &cobra.Command{
		Use:           "purl <purl>",
		Short:         "Scan a single PURL for vulnerabilities",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Scan a single Package URL (PURL) for vulnerabilities.

PURLs provide a canonical identifier for a package in a specific ecosystem.
The scan command uses the PURL to query OSV directly, so a version is required.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScanPURL(c, cmd, args)
		},
		Example: `PURL SCANNING:
  # Scan a single package by PURL
  deputy scan purl pkg:npm/lodash@4.17.21
  deputy scan purl pkg:golang/github.com/gin-gonic/gin@v1.9.0

OUTPUT AND FILTERING:
  # Save results to file
  deputy scan purl pkg:npm/lodash@4.17.21 --output vuln-report.json --format json

  # Filter out unfixed vulnerabilities
  deputy scan purl pkg:npm/lodash@4.17.21 --ignore-unfixed`,
	}
	scanPURLCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	scanPURLCmd.Flags().StringP("format", "f", "text", "Output format (text, json, sarif)")
	scanPURLCmd.Flags().Bool("ignore-unfixed", false, "Ignore vulnerabilities without fixes")
	scanPURLCmd.Flags().Bool("no-verify-fixes", false, "Skip Go module proxy verification of fixed versions (offline; trusts advisory data)")
	scanPURLCmd.Flags().String("ignore-file", "", "Path to ignore rules file (.deputyignore.yaml)")
	scanPURLCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanPURLCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanPURLCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	scanPURLCmd.Flags().String("filter", "", "CEL expression to filter vulnerabilities (e.g., 'vulnerability.advisory.severity.level == severity.critical')")
	scanPURLCmd.Flags().StringArray("policy", nil, "Path to a CEL policy file or bundle to evaluate against the scan report (repeatable)")
	scanPURLCmd.Flags().Bool("show-symbols", false, "Show symbol hints (OSV imports) in text output")
	scanPURLCmd.Flags().Bool("show-db-info", false, "Show database-specific metadata (e.g., review_status) in text output")
	scanPURLCmd.Flags().Bool("show-unfixable-guidance", false, "Show actionable guidance for vulnerabilities without fixes")
	scanPURLCmd.Flags().Bool("enrich", false, "Enrich vulnerabilities with EPSS scores and KEV status (requires network)")

	scanImageCmd := &cobra.Command{
		Use:           "image <ref>",
		Short:         "Scan a container image for vulnerabilities",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Scan a container image for vulnerabilities using the OSV database.

IMAGE SOURCES:
• docker:// or oci:// for remote registry images
• docker-daemon:// for local Docker daemon images
• tarball:// or oci-archive:// for image tarballs

If no scheme is provided, --source controls how the image reference is resolved.

WHAT GETS SCANNED:
• OS packages (Debian, Alpine, RHEL, etc.)
• Language packages (pip, npm, go modules, etc.)
• All layers in the image filesystem

POLICY EVALUATION:
Container image scans extract image configuration (USER, ENV, EXPOSE, etc.) for
CEL policy evaluation. Use --policy to enforce security requirements like:
• Block images running as root
• Detect sensitive environment variables
• Require healthchecks for production images
• Enforce layer count or size limits

See 'deputy policy' and policy/examples/ for container image policy examples.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScanImage(c, cmd, args)
		},
		Example: `CONTAINER IMAGE SCANNING:
  # Scan a remote image
  deputy scan image docker://ghcr.io/owner/app:1.2.3
  deputy scan image oci://ghcr.io/owner/app@sha256:...

  # Scan a local Docker daemon image
  deputy scan image docker-daemon://app:latest

  # Scan an image tarball
  deputy scan image tarball:///tmp/image.tar

SOURCE SHORTCUTS:
  # Resolve as remote image (default)
  deputy scan image ghcr.io/owner/app:1.2.3

  # Resolve as Docker daemon image
  deputy scan image --source docker-daemon app:latest

  # Resolve as tarball path
  deputy scan image --source tarball ./image.tar

POLICY ENFORCEMENT:
  # Block images running as root
  deputy scan image --policy policy/examples/dockerfile-security.yaml nginx:latest

  # Apply container-specific policies
  deputy scan image --policy policy/examples/container-image-config.yaml myapp:v1`,
	}
	scanImageCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	scanImageCmd.Flags().StringP("format", "f", "text", "Output format (text, json, sarif)")
	scanImageCmd.Flags().Bool("ignore-unfixed", false, "Ignore vulnerabilities without fixes")
	scanImageCmd.Flags().Bool("no-verify-fixes", false, "Skip Go module proxy verification of fixed versions (offline; trusts advisory data)")
	scanImageCmd.Flags().String("ignore-file", "", "Path to ignore rules file (.deputyignore.yaml)")
	scanImageCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanImageCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	scanImageCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	scanImageCmd.Flags().String("filter", "", "CEL expression to filter vulnerabilities (e.g., 'vulnerability.advisory.severity.level == severity.critical')")
	scanImageCmd.Flags().StringArray("policy", nil, "Path to a CEL policy file or bundle to evaluate against the scan report (repeatable)")
	scanImageCmd.Flags().Bool("show-symbols", false, "Show symbol hints (OSV imports) in text output")
	scanImageCmd.Flags().Bool("show-db-info", false, "Show database-specific metadata (e.g., review_status) in text output")
	scanImageCmd.Flags().Bool("show-unfixable-guidance", false, "Show actionable guidance for vulnerabilities without fixes")
	scanImageCmd.Flags().String("source", "remote", "Image source: remote, docker-daemon, tarball")
	scanImageCmd.Flags().String("platform", "", "Platform for remote images (os/arch[/variant])")
	scanImageCmd.Flags().Bool("enrich", false, "Enrich vulnerabilities with EPSS scores and KEV status (requires network)")

	scanCmd.AddCommand(scanDirCmd, scanSBOMCmd, scanPURLCmd, scanImageCmd)
	root.AddCommand(scanCmd)
}

// runScan executes the scan command logic, handling argument parsing,
// scan execution, policy evaluation, and output formatting.
func runScan(c *services.Clients, cmd *cobra.Command, args []string) error {
	target := ""
	if len(args) > 0 {
		target = strings.TrimSpace(args[0])
	}
	source, _ := cmd.Flags().GetString("source")
	platform, _ := cmd.Flags().GetString("platform")

	sourceKind, imageSource, err := resolveSourceOverride(source)
	if err != nil {
		return err
	}
	if sourceKind != "" {
		switch sourceKind {
		case "purl":
			if target == "" {
				return fmt.Errorf("expected 1 argument: <purl>")
			}
			warnRefIgnored(cmd, "purl")
			return runScanPURL(c, cmd, []string{target})
		case "sbom":
			if target == "" {
				return fmt.Errorf("expected 1 argument: <path|->")
			}
			warnRefIgnored(cmd, "sbom")
			return runScanSBOM(c, cmd, []string{target})
		case "dir":
			if target == "" {
				target = "."
			}
			warnRefIgnored(cmd, "directory")
			return runScanDir(c, cmd, []string{target})
		case "git":
			if target == "" {
				target = "."
			}
			if root, ok := gitRoot(target); ok {
				target = root
			}
			return runScanRepository(c, cmd, target)
		case "image":
			if target == "" {
				return fmt.Errorf("expected 1 argument: <image>")
			}
			warnRefIgnored(cmd, "container image")
			return runScanImageWithOptions(c, cmd, target, imageSource, platform)
		case "dockerfile":
			if target == "" {
				return fmt.Errorf("expected 1 argument: <path>")
			}
			warnRefIgnored(cmd, "dockerfile")
			return runScanDockerfile(c, cmd, target)
		case "vm", "rootfs":
			if target == "" {
				return fmt.Errorf("expected 1 argument: <path>")
			}
			warnRefIgnored(cmd, "vm image")
			return runScanVMImage(c, cmd, target)
		default:
			return fmt.Errorf("unknown --source %q", source)
		}
	}

	if target == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		if root, ok := gitRoot(wd); ok {
			return runScanRepository(c, cmd, root)
		}
		warnRefIgnored(cmd, "directory")
		return runScanDir(c, cmd, []string{wd})
	}

	if isPURLTarget(target) {
		warnRefIgnored(cmd, "purl")
		return runScanPURL(c, cmd, []string{target})
	}

	if isImageTargetScheme(target) {
		warnRefIgnored(cmd, "container image")
		return runScanImage(c, cmd, []string{target})
	}

	if isVMImageTarget(target) {
		warnRefIgnored(cmd, "vm image")
		return runScanVMImage(c, cmd, target)
	}

	if target == "-" {
		warnRefIgnored(cmd, "sbom")
		return runScanSBOM(c, cmd, []string{target})
	}

	if info, err := os.Stat(target); err == nil {
		if info.IsDir() {
			if root, ok := gitRoot(target); ok {
				return runScanRepository(c, cmd, root)
			}
			warnRefIgnored(cmd, "directory")
			return runScanDir(c, cmd, []string{target})
		}
		// Check if file is a Dockerfile
		if isDockerfilePath(target) {
			return runScanDockerfile(c, cmd, target)
		}
		warnRefIgnored(cmd, "sbom")
		return runScanSBOM(c, cmd, []string{target})
	}

	if isAmbiguousDockerHubReference(target) {
		return fmt.Errorf("target %q is ambiguous; use docker://%s:tag (or docker.io/%s:tag) for images, or github.com/%s for GitHub repos", target, target, target, target)
	}

	if looksLikeContainerReference(target) {
		warnRefIgnored(cmd, "container image")
		return runScanImageWithOptions(c, cmd, target, "", platform)
	}

	return runScanRepository(c, cmd, target)
}

func runScanRepository(c *services.Clients, cmd *cobra.Command, repoArg string) error {
	ctx := cmd.Context()
	flags := extractScanFlags(cmd)
	errW := cmd.ErrOrStderr()

	// Build proto request from flags
	req := flags.toScanRequest(repoArg, errW)

	// Show progress indicator for interactive mode (text output to TTY)
	var progress *ui.Progress
	if ui.IsTTY(errW) && (flags.Format == "" || flags.Format == FormatText) {
		progress = ui.NewProgress(errW, "Scanning for vulnerabilities")
		progress.Start(ctx)
	}

	// Call the client
	resp, err := c.Vulns.Scan(ctx, connect.NewRequest(req))
	if progress != nil {
		progress.Clear()
	}
	if err != nil {
		return err
	}

	// Convert proto response to internal result
	resultPtr := internalproto.ScanningResultFromProto(resp.Msg)
	result := *resultPtr

	for _, warning := range result.Warnings {
		fmt.Fprintf(errW, "Warning: %s\n", warning)
	}

	resultOut := result
	policyResult := result
	if flags.IgnoreUnfixed {
		policyResult = scanning.FilterUnfixed(policyResult)
		resultOut = policyResult
	}

	// Load and apply ignore rules (client-side filtering from local .deputy-ignore)
	var ignoredCount int
	workDir := result.Target.LocalPath
	if workDir == "" {
		workDir, _ = os.Getwd()
	}
	if err := flags.loadIgnoreRules(workDir); err != nil {
		fmt.Fprintf(errW, "Warning: %v\n", err)
	}
	if flags.ignoreRules != nil {
		policyResult, ignoredCount = scanning.FilterIgnored(policyResult, flags.ignoreRules)
		resultOut = policyResult
	}

	// Apply CEL filter expression if provided
	if flags.Filter != "" {
		policyResult, err = scanning.FilterByCEL(ctx, policyResult, flags.Filter)
		if err != nil {
			return fmt.Errorf("filter: %w", err)
		}
		resultOut = policyResult
	}

	// Policy evaluation - can be done client-side or server-side
	// Server-side policies are already applied, but we support client-side policies too
	policyActions, err := runScanPolicies(ctx, flags.PolicyPaths, policyResult, errW, nil)
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)
	result.PolicyActions = policyActions

	out, err := openOutputWriter(cmd, flags.OutPath)
	if err != nil {
		return err
	}
	defer out.Close()

	switch strings.ToLower(flags.Format) {
	case "", FormatText:
		if err := outputText(out.Writer, errW, resultOut, flags.IgnoreUnfixed, ignoredCount, policyFindings, flags.displayOptionsWithResult(resultOut)); err != nil {
			return err
		}
		// Show policy evaluation summary
		render.PolicyEvaluationSummary(out.Writer, len(flags.PolicyPaths), policyFindings)
		return nil
	case FormatJSON:
		// Convert filtered result back to proto for consistent JSON output
		protoResp := internalproto.ScanningResultToProto(&resultOut)
		// Add client-side policy actions
		protoResp.PolicyActions = append(protoResp.PolicyActions, policyActionsToProto(policyActions)...)
		return outputProtoJSON(out.Writer, protoResp)
	case FormatSARIF:
		return outputSARIF(out.Writer, resultOut, policyFindings)
	default:
		return cliflags.UnsupportedFormatError("--format", flags.Format, "text|json|sarif")
	}
}

// runScanDir executes the directory scan command logic.
func runScanDir(c *services.Clients, cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected 1 argument: <path>")
	}

	ctx := cmd.Context()
	flags := extractScanFlags(cmd)
	path := strings.TrimSpace(args[0])
	errW := cmd.ErrOrStderr()

	// Build proto request with directory target hint
	req := flags.toScanRequestWithHint(path, targetv1.TargetKind_TARGET_KIND_DIR, "", "", errW)

	// Show progress indicator for interactive mode (text output to TTY)
	var progress *ui.Progress
	if ui.IsTTY(errW) && (flags.Format == "" || flags.Format == FormatText) {
		progress = ui.NewProgress(errW, "Scanning for vulnerabilities")
		progress.Start(ctx)
	}

	resp, err := c.Vulns.Scan(ctx, connect.NewRequest(req))
	if progress != nil {
		progress.Clear()
	}
	if err != nil {
		return err
	}

	// Convert proto response to internal result
	resultPtr := internalproto.ScanningResultFromProto(resp.Msg)
	result := *resultPtr

	for _, warning := range result.Warnings {
		fmt.Fprintf(errW, "Warning: %s\n", warning)
	}

	resultOut := result
	policyResult := result
	if flags.IgnoreUnfixed {
		policyResult = scanning.FilterUnfixed(policyResult)
		resultOut = policyResult
	}

	// Load and apply ignore rules
	var ignoredCount int
	if err := flags.loadIgnoreRules(path); err != nil {
		fmt.Fprintf(errW, "Warning: %v\n", err)
	}
	if flags.ignoreRules != nil {
		policyResult, ignoredCount = scanning.FilterIgnored(policyResult, flags.ignoreRules)
		resultOut = policyResult
	}

	// Apply CEL filter expression if provided
	if flags.Filter != "" {
		policyResult, err = scanning.FilterByCEL(ctx, policyResult, flags.Filter)
		if err != nil {
			return fmt.Errorf("filter: %w", err)
		}
		resultOut = policyResult
	}

	policyActions, err := runScanPolicies(ctx, flags.PolicyPaths, policyResult, errW, nil)
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)
	result.PolicyActions = policyActions

	// Run secrets scan if enabled (client-side for now)
	var secretsResults *SecretsResult
	if flags.Secrets {
		secretsResults, err = runSecretsScanner(ctx, path, errW)
		if err != nil {
			fmt.Fprintf(errW, "Warning: secrets scan failed: %v\n", err)
		}
	}

	out, err := openOutputWriter(cmd, flags.OutPath)
	if err != nil {
		return err
	}
	defer out.Close()

	switch strings.ToLower(flags.Format) {
	case "", FormatText:
		if err := outputTextDir(out.Writer, errW, resultOut, flags.IgnoreUnfixed, ignoredCount, policyFindings, flags.displayOptionsWithResult(resultOut)); err != nil {
			return err
		}
		// Append secrets findings if enabled
		if secretsResults != nil {
			renderSecretsFindings(out.Writer, secretsResults)
		}
		// Show policy evaluation summary
		render.PolicyEvaluationSummary(out.Writer, len(flags.PolicyPaths), policyFindings)
		return nil
	case FormatJSON:
		// Convert filtered result back to proto for consistent JSON output
		protoResp := internalproto.ScanningResultToProto(&resultOut)
		// Add client-side policy actions
		protoResp.PolicyActions = append(protoResp.PolicyActions, policyActionsToProto(policyActions)...)
		return outputProtoJSON(out.Writer, protoResp)
	case FormatSARIF:
		return outputSARIF(out.Writer, resultOut, policyFindings)
	default:
		return cliflags.UnsupportedFormatError("--format", flags.Format, "text|json|sarif")
	}
}

// runScanVMImage executes the VM/rootfs image scan command logic.
// Supports qcow2, vmdk, vhd, vhdx, vdi, and raw disk images, as well as raw
// filesystem images (ext4, xfs).
func runScanVMImage(c *services.Clients, cmd *cobra.Command, target string) error {
	ctx := cmd.Context()
	flags := extractScanFlags(cmd)
	errW := cmd.ErrOrStderr()

	// Normalize VM target path
	path := strings.TrimSpace(target)
	if path == "" {
		return fmt.Errorf("expected a VM image path")
	}

	// Build proto request with VM image target hint
	req := flags.toScanRequestWithHint(path, targetv1.TargetKind_TARGET_KIND_VM_IMAGE, "", "", errW)

	// Show progress indicator for interactive mode
	var progress *ui.Progress
	if ui.IsTTY(errW) && (flags.Format == "" || flags.Format == FormatText) {
		progress = ui.NewProgress(errW, "Scanning VM image for vulnerabilities")
		progress.Start(ctx)
	}

	resp, err := c.Vulns.Scan(ctx, connect.NewRequest(req))
	if progress != nil {
		progress.Clear()
	}
	if err != nil {
		return fmt.Errorf("scan VM image: %w", err)
	}

	// Convert proto response to internal result
	resultPtr := internalproto.ScanningResultFromProto(resp.Msg)
	result := *resultPtr

	for _, warning := range result.Warnings {
		fmt.Fprintf(errW, "Warning: %s\n", warning)
	}

	resultOut := result
	policyResult := result
	if flags.IgnoreUnfixed {
		policyResult = scanning.FilterUnfixed(policyResult)
		resultOut = policyResult
	}

	// Load and apply ignore rules
	var ignoredCount int
	if err := flags.loadIgnoreRules(path); err != nil {
		fmt.Fprintf(errW, "Warning: %v\n", err)
	}
	if flags.ignoreRules != nil {
		policyResult, ignoredCount = scanning.FilterIgnored(policyResult, flags.ignoreRules)
		resultOut = policyResult
	}

	// Apply CEL filter expression if provided
	if flags.Filter != "" {
		policyResult, err = scanning.FilterByCEL(ctx, policyResult, flags.Filter)
		if err != nil {
			return fmt.Errorf("filter: %w", err)
		}
		resultOut = policyResult
	}

	policyActions, err := runScanPolicies(ctx, flags.PolicyPaths, policyResult, errW, nil)
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)
	result.PolicyActions = policyActions

	out, err := openOutputWriter(cmd, flags.OutPath)
	if err != nil {
		return err
	}
	defer out.Close()

	switch strings.ToLower(flags.Format) {
	case "", FormatText:
		if err := outputTextDir(out.Writer, errW, resultOut, flags.IgnoreUnfixed, ignoredCount, policyFindings, flags.displayOptionsWithResult(resultOut)); err != nil {
			return err
		}
		render.PolicyEvaluationSummary(out.Writer, len(flags.PolicyPaths), policyFindings)
		return nil
	case FormatJSON:
		protoResp := internalproto.ScanningResultToProto(&resultOut)
		protoResp.PolicyActions = append(protoResp.PolicyActions, policyActionsToProto(policyActions)...)
		return outputProtoJSON(out.Writer, protoResp)
	case FormatSARIF:
		return outputSARIF(out.Writer, resultOut, policyFindings)
	default:
		return cliflags.UnsupportedFormatError("--format", flags.Format, "text|json|sarif")
	}
}

// runScanSBOM executes the SBOM scan command logic.
func runScanSBOM(c *services.Clients, cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected 1 argument: <path|->")
	}

	ctx := cmd.Context()
	flags := extractScanFlags(cmd)
	input := strings.TrimSpace(args[0])
	errW := cmd.ErrOrStderr()

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

	pkgs, direct, imageRefs, sbomPURLs, err := parseSBOMPackages(data, flags.InputFormat)
	if err != nil {
		return fmt.Errorf("failed to parse SBOM: %w", err)
	}

	// Build proto request with SBOM target hint
	// Note: For SBOM scans, we pass the SBOM content in the target field (base64 encoded)
	// and let the server parse it. For now, we do client-side parsing and use PURL-based scanning.
	req := flags.toScanRequestWithHint(input, targetv1.TargetKind_TARGET_KIND_SBOM, "", "", errW)

	// Scan the packages from the SBOM
	resp, err := c.Vulns.Scan(ctx, connect.NewRequest(req))
	if err != nil {
		return err
	}

	// Convert proto response to internal result
	resultPtr := internalproto.ScanningResultFromProto(resp.Msg)
	result := *resultPtr

	// Handle container images referenced in SBOM
	if len(imageRefs) > 0 {
		// Default concurrency for parallel image scans. Can be overridden via
		// DEPUTY_SBOM_IMAGE_SCAN_CONCURRENCY for resource-constrained environments.
		sbomImageScanConcurrency := 4
		if v := os.Getenv("DEPUTY_SBOM_IMAGE_SCAN_CONCURRENCY"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				sbomImageScanConcurrency = n
			}
		}
		sem := make(chan struct{}, sbomImageScanConcurrency)
		var mu sync.Mutex
		type imageScanOutcome struct {
			result scanning.Result
			err    error
		}
		cache := map[string]imageScanOutcome{}

		group, groupCtx := errgroup.WithContext(ctx)
		for _, ref := range imageRefs {
			ref := ref
			key := imageRefCacheKey(ref)
			group.Go(func() error {
				sem <- struct{}{}
				defer func() { <-sem }()
				imgReq := flags.toScanRequestWithHint(ref.Ref, targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE, "remote", ref.Platform, errW)
				imgResp, err := c.Vulns.Scan(groupCtx, connect.NewRequest(imgReq))
				outcome := imageScanOutcome{err: err}
				if imgResp != nil {
					imgResultPtr := internalproto.ScanningResultFromProto(imgResp.Msg)
					outcome.result = *imgResultPtr
				}
				mu.Lock()
				cache[key] = outcome
				mu.Unlock()
				return nil
			})
		}
		_ = group.Wait()

		for _, ref := range imageRefs {
			key := imageRefCacheKey(ref)
			mu.Lock()
			outcome, ok := cache[key]
			mu.Unlock()
			if !ok {
				continue
			}
			if outcome.err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("image scan failed for %s: %v", ref.Ref, outcome.err))
				continue
			}
			result = scanning.MergeResults(result, outcome.result)
		}
	}

	// Merge SBOM packages if not already included from server response
	if len(pkgs) > 0 && len(result.Packages) == 0 {
		result.Packages = pkgs
		result.Direct = direct
	}

	for _, warning := range result.Warnings {
		fmt.Fprintf(errW, "Warning: %s\n", warning)
	}

	resultOut := result
	policyResult := result
	if flags.IgnoreUnfixed {
		policyResult = scanning.FilterUnfixed(policyResult)
		resultOut = policyResult
	}

	// Load and apply ignore rules (use cwd for SBOM scans)
	var ignoredCount int
	workDir, _ := os.Getwd()
	if err := flags.loadIgnoreRules(workDir); err != nil {
		fmt.Fprintf(errW, "Warning: %v\n", err)
	}
	if flags.ignoreRules != nil {
		policyResult, ignoredCount = scanning.FilterIgnored(policyResult, flags.ignoreRules)
		resultOut = policyResult
	}

	// Apply CEL filter expression if provided
	if flags.Filter != "" {
		policyResult, err = scanning.FilterByCEL(ctx, policyResult, flags.Filter)
		if err != nil {
			return fmt.Errorf("filter: %w", err)
		}
		resultOut = policyResult
	}

	var extra map[string]any
	if len(sbomPURLs) > 0 {
		extra = map[string]any{"sbom": map[string]any{"purls": sbomPURLs}}
	}
	policyActions, err := runScanPolicies(ctx, flags.PolicyPaths, policyResult, errW, extra)
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)
	result.PolicyActions = policyActions

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
			fmt.Fprintln(errW, "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
		}
		if ignoredCount > 0 {
			fmt.Fprintln(errW, "  "+ui.StyleMeta.Render(fmt.Sprintf("Note: %d vulnerability finding(s) ignored by rules", ignoredCount)))
		}
		render.DisplayVulnerabilities(out.Writer, resultOut, flags.displayOptions())
		render.PolicyFindings(out.Writer, policyFindings)
		// Show policy evaluation summary
		render.PolicyEvaluationSummary(out.Writer, len(flags.PolicyPaths), policyFindings)
		return nil
	case FormatJSON:
		// Convert filtered result back to proto for consistent JSON output
		protoResp := internalproto.ScanningResultToProto(&resultOut)
		// Add client-side policy actions
		protoResp.PolicyActions = append(protoResp.PolicyActions, policyActionsToProto(policyActions)...)
		return outputProtoJSON(out.Writer, protoResp)
	case FormatSARIF:
		return outputSARIF(out.Writer, resultOut, policyFindings)
	default:
		return cliflags.UnsupportedFormatError("--format", flags.Format, "text|json|sarif")
	}
}

// runScanPURL executes the PURL scan command logic.
func runScanPURL(c *services.Clients, cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected 1 argument: <purl>")
	}

	ctx := cmd.Context()
	flags := extractScanFlags(cmd)
	input := strings.TrimSpace(args[0])
	errW := cmd.ErrOrStderr()

	// Build proto request with PURL target hint
	req := flags.toScanRequestWithHint(input, targetv1.TargetKind_TARGET_KIND_PURL, "", "", errW)

	resp, err := c.Vulns.Scan(ctx, connect.NewRequest(req))
	if err != nil {
		return err
	}

	// Convert proto response to internal result
	resultPtr := internalproto.ScanningResultFromProto(resp.Msg)
	result := *resultPtr

	for _, warning := range result.Warnings {
		fmt.Fprintf(errW, "Warning: %s\n", warning)
	}

	resultOut := result
	policyResult := result
	if flags.IgnoreUnfixed {
		policyResult = scanning.FilterUnfixed(policyResult)
		resultOut = policyResult
	}

	// Load and apply ignore rules (use cwd for PURL scans)
	var ignoredCount int
	workDir, _ := os.Getwd()
	if err := flags.loadIgnoreRules(workDir); err != nil {
		fmt.Fprintf(errW, "Warning: %v\n", err)
	}
	if flags.ignoreRules != nil {
		policyResult, ignoredCount = scanning.FilterIgnored(policyResult, flags.ignoreRules)
		resultOut = policyResult
	}

	// Apply CEL filter expression if provided
	if flags.Filter != "" {
		policyResult, err = scanning.FilterByCEL(ctx, policyResult, flags.Filter)
		if err != nil {
			return fmt.Errorf("filter: %w", err)
		}
		resultOut = policyResult
	}

	policyActions, err := runScanPolicies(ctx, flags.PolicyPaths, policyResult, errW, nil)
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)
	result.PolicyActions = policyActions

	out, err := openOutputWriter(cmd, flags.OutPath)
	if err != nil {
		return err
	}
	defer out.Close()

	switch strings.ToLower(flags.Format) {
	case "", FormatText:
		if err := outputTextDir(out.Writer, errW, resultOut, flags.IgnoreUnfixed, ignoredCount, policyFindings, flags.displayOptions()); err != nil {
			return err
		}
		// Show policy evaluation summary
		render.PolicyEvaluationSummary(out.Writer, len(flags.PolicyPaths), policyFindings)
		return nil
	case FormatJSON:
		// Convert filtered result back to proto for consistent JSON output
		protoResp := internalproto.ScanningResultToProto(&resultOut)
		// Add client-side policy actions
		protoResp.PolicyActions = append(protoResp.PolicyActions, policyActionsToProto(policyActions)...)
		return outputProtoJSON(out.Writer, protoResp)
	case FormatSARIF:
		return outputSARIF(out.Writer, resultOut, policyFindings)
	default:
		return cliflags.UnsupportedFormatError("--format", flags.Format, "text|json|sarif")
	}
}

// runScanImage executes the container image scan command logic.
func runScanImage(c *services.Clients, cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected 1 argument: <image>")
	}

	input := strings.TrimSpace(args[0])
	source, _ := cmd.Flags().GetString("source")
	platform, _ := cmd.Flags().GetString("platform")
	return runScanImageWithOptions(c, cmd, input, source, platform)
}

func runScanImageWithOptions(c *services.Clients, cmd *cobra.Command, input, source, platform string) error {
	ctx := cmd.Context()
	flags := extractScanFlags(cmd)
	errW := cmd.ErrOrStderr()

	// Determine image transport from source flag
	transport := sourceToTransport(source)

	// Build proto request with container image target hint
	req := flags.toScanRequestWithHint(input, targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE, transport, platform, errW)

	// Show progress indicator for interactive mode (text output to TTY)
	var progress *ui.Progress
	if ui.IsTTY(errW) && (flags.Format == "" || flags.Format == FormatText) {
		progress = ui.NewProgress(errW, "Scanning container image")
		progress.Start(ctx)
	}

	resp, err := c.Vulns.Scan(ctx, connect.NewRequest(req))
	if progress != nil {
		progress.Clear()
	}
	if err != nil {
		return err
	}

	// Convert proto response to internal result
	resultPtr := internalproto.ScanningResultFromProto(resp.Msg)
	result := *resultPtr

	for _, warning := range result.Warnings {
		fmt.Fprintf(errW, "Warning: %s\n", warning)
	}

	resultOut := result
	policyResult := result
	if flags.IgnoreUnfixed {
		policyResult = scanning.FilterUnfixed(policyResult)
		resultOut = policyResult
	}

	// Load and apply ignore rules (use cwd for image scans)
	var ignoredCount int
	workDir, _ := os.Getwd()
	if err := flags.loadIgnoreRules(workDir); err != nil {
		fmt.Fprintf(errW, "Warning: %v\n", err)
	}
	if flags.ignoreRules != nil {
		policyResult, ignoredCount = scanning.FilterIgnored(policyResult, flags.ignoreRules)
		resultOut = policyResult
	}

	// Apply CEL filter expression if provided
	if flags.Filter != "" {
		policyResult, err = scanning.FilterByCEL(ctx, policyResult, flags.Filter)
		if err != nil {
			return fmt.Errorf("filter: %w", err)
		}
		resultOut = policyResult
	}

	policyActions, err := runScanPolicies(ctx, flags.PolicyPaths, policyResult, errW, nil)
	if err != nil {
		return err
	}
	policyFindings := actionsToPolicyFindings(policyActions)
	result.PolicyActions = policyActions

	out, err := openOutputWriter(cmd, flags.OutPath)
	if err != nil {
		return err
	}
	defer out.Close()

	switch strings.ToLower(flags.Format) {
	case "", FormatText:
		if err := outputTextContainer(out.Writer, errW, resultOut, flags.IgnoreUnfixed, ignoredCount, policyFindings, flags.displayOptions()); err != nil {
			return err
		}
		// Show policy evaluation summary
		render.PolicyEvaluationSummary(out.Writer, len(flags.PolicyPaths), policyFindings)
		return nil
	case FormatJSON:
		// Convert filtered result back to proto for consistent JSON output
		protoResp := internalproto.ScanningResultToProto(&resultOut)
		// Add client-side policy actions
		protoResp.PolicyActions = append(protoResp.PolicyActions, policyActionsToProto(policyActions)...)
		return outputProtoJSON(out.Writer, protoResp)
	case FormatSARIF:
		return outputSARIF(out.Writer, resultOut, policyFindings)
	default:
		return cliflags.UnsupportedFormatError("--format", flags.Format, "text|json|sarif")
	}
}

// sourceToTransport converts CLI source flag to proto transport string.
func sourceToTransport(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "remote", "registry":
		return "remote"
	case "oci":
		return "oci"
	case "docker-daemon", "daemon", "local":
		return "daemon"
	case "tarball", "archive", "oci-archive":
		return "tarball"
	default:
		return "remote"
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

func normalizeImageTarget(input, source string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("image reference is required")
	}
	if strings.Contains(input, "://") {
		return input, nil
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "remote", "registry":
		return "docker://" + input, nil
	case "oci":
		return "oci://" + input, nil
	case "docker-daemon", "daemon", "local":
		return "docker-daemon://" + input, nil
	case "tarball", "archive", "oci-archive":
		return "tarball://" + input, nil
	default:
		return "", fmt.Errorf("unknown image source %q", source)
	}
}

// outputText writes the scan results in a human-readable text format to the provided writer.
func outputText(w io.Writer, errW io.Writer, result scanning.Result, ignoreUnfixed bool, ignoredCount int, policyFindings []report.PolicyFinding, displayOpts render.VulnerabilityDisplayOptions) error {
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
	if ignoredCount > 0 {
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render(fmt.Sprintf("Note: %d vulnerability finding(s) ignored by rules", ignoredCount)))
	}

	render.DisplayVulnerabilities(w, result, displayOpts)
	render.PolicyFindings(w, policyFindings)

	// Show module deprecations
	if deps := detectModuleDeprecations(result.Packages, result.Direct); len(deps) > 0 {
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
func outputTextDir(w io.Writer, errW io.Writer, result scanning.Result, ignoreUnfixed bool, ignoredCount int, policyFindings []report.PolicyFinding, displayOpts render.VulnerabilityDisplayOptions) error {
	doc := render.ScanResultsHeaderDoc(result.Target.DisplayPath, "", "", "")
	_ = doc.Render(w, output.UIStyles())

	if ignoreUnfixed {
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
	}
	if ignoredCount > 0 {
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render(fmt.Sprintf("Note: %d vulnerability finding(s) ignored by rules", ignoredCount)))
	}

	render.DisplayVulnerabilities(w, result, displayOpts)
	render.PolicyFindings(w, policyFindings)
	return nil
}

// outputTextContainer writes container image scan results with container-specific context.
func outputTextContainer(w io.Writer, errW io.Writer, result scanning.Result, ignoreUnfixed bool, ignoredCount int, policyFindings []report.PolicyFinding, displayOpts render.VulnerabilityDisplayOptions) error {
	// Use container-specific header with image metadata
	doc := render.ContainerScanHeaderDoc(result.Target.DisplayPath, result.ImageInfo)
	_ = doc.Render(w, output.UIStyles())

	if ignoreUnfixed {
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
	}
	if ignoredCount > 0 {
		fmt.Fprintln(errW, "  "+ui.StyleMeta.Render(fmt.Sprintf("Note: %d vulnerability finding(s) ignored by rules", ignoredCount)))
	}

	// Show image security summary (root user, sensitive env, etc.)
	secDoc := render.ImageSecuritySummaryDoc(result.ImageInfo)
	if len(secDoc.Lines) > 0 {
		_ = secDoc.Render(w, output.UIStyles())
	}

	render.DisplayVulnerabilities(w, result, displayOpts)
	render.PolicyFindings(w, policyFindings)
	return nil
}

// outputProtoJSON writes the scan results in JSON format using protojson for
// consistent, type-safe serialization directly from the proto response.
// This is the preferred method for JSON output as it avoids conversion bugs
// and ensures the JSON structure matches the proto schema exactly.
func outputProtoJSON(w io.Writer, resp *scanv1.ScanResponse) error {
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false, // Don't emit zero values
		UseProtoNames:   true,  // Use snake_case field names from proto
	}
	data, err := opts.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal proto to JSON: %w", err)
	}
	_, err = w.Write(data)
	if err != nil {
		return err
	}
	// Add trailing newline for consistency
	_, err = w.Write([]byte("\n"))
	return err
}

// policyActionsToProto converts internal policy actions to proto format.
func policyActionsToProto(actions []policy.Action) []*policyv1.Action {
	if len(actions) == 0 {
		return nil
	}
	out := make([]*policyv1.Action, len(actions))
	for i, a := range actions {
		var actionType policyv1.ActionType
		if policy.ActionTypeIs(a.Type, policy.ActionAllow) {
			actionType = policyv1.ActionType_ACTION_TYPE_ALLOW
		} else if policy.ActionTypeIs(a.Type, policy.ActionDeny) {
			actionType = policyv1.ActionType_ACTION_TYPE_DENY
		} else if policy.ActionTypeIs(a.Type, policy.ActionWarn) {
			actionType = policyv1.ActionType_ACTION_TYPE_WARN
		} else {
			actionType = policyv1.ActionType_ACTION_TYPE_UNSPECIFIED
		}
		out[i] = &policyv1.Action{
			Type:        actionType,
			PolicyName:  a.Source, // Source is the policy name in internal types
			Reason:      a.Reason,
			Remediation: a.Remediation,
		}
	}
	return out
}

// outputSARIF writes the scan results in SARIF format for GitHub Security tab integration.
func outputSARIF(w io.Writer, result scanning.Result, policyFindings []report.PolicyFinding) error {
	vulns := report.FlattenScanningResult(result)

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

// parseSBOMPackages converts supported SBOM documents into package tuples for OSV queries
// and extracts container image references when present.
func parseSBOMPackages(data []byte, inFmt string) ([]*extractor.Package, map[string]bool, []imageSBOMRef, []string, error) {
	format, err := cliflags.NormalizeSBOMInputFormat(inFmt)
	if err != nil {
		return nil, nil, nil, nil, err
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
			pkgs      []*extractor.Package
			direct    map[string]bool
			imageRefs []imageSBOMRef
			purls     []string
			err       error
		)
		switch kind {
		case cliflags.SBOMInputProtobom:
			pkgs, direct, imageRefs, purls, err = parseProtobomPackages(data)
		case cliflags.SBOMInputCycloneDX:
			pkgs, direct, imageRefs, purls, err = parseCycloneDXPackages(data)
		case cliflags.SBOMInputSPDX:
			pkgs, direct, imageRefs, purls, err = parseSPDXPackages(data)
		default:
			err = fmt.Errorf("unknown SBOM format %q", kind)
		}
		if err == nil && (len(pkgs) > 0 || len(imageRefs) > 0) {
			return pkgs, direct, imageRefs, purls, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, nil, nil, nil, lastErr
	}
	return nil, nil, nil, nil, deperrors.Suggest(
		fmt.Errorf("unsupported or empty SBOM input"),
		"Specify --input-format (protobom-json|cyclonedx-json|spdx-json) or generate with 'deputy sbom'",
	)
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

func normalizeSBOMPURL(purlStr string) string {
	purlStr = strings.TrimSpace(purlStr)
	if purlStr == "" {
		return ""
	}
	if pu, err := purlx.ParseLoose(purlStr); err == nil {
		return pu.String()
	}
	return purlStr
}

// parseProtobomPackages parses a Protobom JSON document and extracts package information.
func parseProtobomPackages(data []byte) ([]*extractor.Package, map[string]bool, []imageSBOMRef, []string, error) {
	var doc sbom.Document
	if err := protojson.Unmarshal(data, &doc); err != nil {
		return nil, nil, nil, nil, err
	}
	nodes := doc.GetNodeList().GetNodes()
	if len(nodes) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("protobom document contained no nodes")
	}
	var pkgs []*extractor.Package
	direct := make(map[string]bool)
	var imageRefs []imageSBOMRef
	var purls []string
	for _, n := range nodes {
		if n.GetType() != sbom.Node_PACKAGE {
			continue
		}
		name := strings.TrimSpace(n.GetName())
		version := strings.TrimSpace(n.GetVersion())
		var purlStr string
		purlType := ""
		if ids := n.GetIdentifiers(); ids != nil {
			if p := ids[int32(sbom.SoftwareIdentifierType_PURL)]; p != "" {
				purlStr = p
			}
		}
		if normalized := normalizeSBOMPURL(purlStr); normalized != "" {
			purls = append(purls, normalized)
		}
		if ref, ok := imageRefFromPURL(purlStr); ok {
			imageRefs = append(imageRefs, ref)
			continue
		}
		if purlStr != "" {
			if pu, err := purlx.ParseLoose(purlStr); err == nil {
				purlType = pu.Type
				if pu.Namespace != "" {
					sep := "/"
					if pu.Type == "maven" || pu.Type == "gradle" {
						sep = ":"
					}
					fullName := pu.Namespace + sep + pu.Name
					if name == "" || name == pu.Name {
						name = fullName
					}
				} else if name == "" {
					name = pu.Name
				}
				if version == "" {
					version = strings.TrimSpace(pu.Version)
				}
			}
		}
		if name == "" || version == "" {
			continue
		}
		pkg := &extractor.Package{Name: name, Version: version, PURLType: purlType, Licenses: n.GetLicenses()}
		// Restore deputy-specific metadata from properties.
		// "deputy:direct" restores the direct dependency status.
		// "deputy:location" restores the file path (e.g. go.mod) needed for remediation.
		// "deputy:layer-*" restores container image layer details for layer-aware analysis.
		var layerDetails *extractor.LayerDetails
		for _, prop := range n.GetProperties() {
			switch prop.GetName() {
			case "deputy:direct":
				if prop.GetData() == "true" && purlStr != "" {
					direct[purlStr] = true
				}
			case "deputy:location":
				pkg.Locations = append(pkg.Locations, prop.GetData())
			case "deputy:layer-index":
				if layerDetails == nil {
					layerDetails = &extractor.LayerDetails{}
				}
				if idx, err := strconv.Atoi(prop.GetData()); err == nil {
					layerDetails.Index = idx
				}
			case "deputy:layer-diffid":
				if layerDetails == nil {
					layerDetails = &extractor.LayerDetails{}
				}
				layerDetails.DiffID = prop.GetData()
			case "deputy:layer-chainid":
				if layerDetails == nil {
					layerDetails = &extractor.LayerDetails{}
				}
				layerDetails.ChainID = prop.GetData()
			case "deputy:layer-command":
				if layerDetails == nil {
					layerDetails = &extractor.LayerDetails{}
				}
				layerDetails.Command = prop.GetData()
			case "deputy:layer-in-base-image":
				if layerDetails == nil {
					layerDetails = &extractor.LayerDetails{}
				}
				layerDetails.InBaseImage = prop.GetData() == "true"
			}
		}
		pkg.LayerDetails = layerDetails
		pkgs = append(pkgs, pkg)
	}
	imageRefs = dedupeImageRefs(imageRefs)
	purls = collections.Dedupe(purls)
	if len(pkgs) == 0 && len(imageRefs) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("protobom document did not contain package nodes with name+version or image references")
	}
	return pkgs, direct, imageRefs, purls, nil
}

// parseCycloneDXPackages parses a CycloneDX JSON document and extracts package information.
func parseCycloneDXPackages(data []byte) ([]*extractor.Package, map[string]bool, []imageSBOMRef, []string, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, nil, nil, nil, err
	}
	if bom.Components == nil || len(*bom.Components) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("cyclonedx document contained no components")
	}
	var pkgs []*extractor.Package
	direct := make(map[string]bool)
	var imageRefs []imageSBOMRef
	var purls []string
	for _, comp := range *bom.Components {
		name := strings.TrimSpace(comp.Name)
		version := strings.TrimSpace(comp.Version)
		purlStr := strings.TrimSpace(comp.PackageURL)
		purlType := ""
		if normalized := normalizeSBOMPURL(purlStr); normalized != "" {
			purls = append(purls, normalized)
		}
		if purlStr != "" {
			if ref, ok := imageRefFromPURL(purlStr); ok {
				imageRefs = append(imageRefs, ref)
				continue
			}
			if pu, err := purlx.ParseLoose(purlStr); err == nil {
				purlType = pu.Type
				if pu.Namespace != "" {
					sep := "/"
					if pu.Type == "maven" || pu.Type == "gradle" {
						sep = ":"
					}
					fullName := pu.Namespace + sep + pu.Name
					if name == "" || name == pu.Name {
						name = fullName
					}
				} else if name == "" {
					name = pu.Name
				}
				if version == "" {
					version = strings.TrimSpace(pu.Version)
				}
			}
		}
		if name == "" || version == "" {
			continue
		}
		pkg := &extractor.Package{Name: name, Version: version, PURLType: purlType, Licenses: extractCycloneDXLicenses(comp.Licenses)}
		if comp.Properties != nil {
			for _, prop := range *comp.Properties {
				if prop.Name == "deputy:direct" && prop.Value == "true" {
					if purlStr != "" {
						direct[purlStr] = true
					}
				}
				if prop.Name == "deputy:location" {
					pkg.Locations = append(pkg.Locations, prop.Value)
				}
			}
		}
		pkgs = append(pkgs, pkg)
	}
	imageRefs = dedupeImageRefs(imageRefs)
	purls = collections.Dedupe(purls)
	if len(pkgs) == 0 && len(imageRefs) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("cyclonedx document did not contain components with name+version or image references")
	}
	return pkgs, direct, imageRefs, purls, nil
}

// extractCycloneDXLicenses extracts SPDX license IDs from CycloneDX license choices.
func extractCycloneDXLicenses(licenses *cdx.Licenses) []string {
	if licenses == nil || len(*licenses) == 0 {
		return nil
	}
	var result []string
	for _, choice := range *licenses {
		if choice.License != nil {
			// Prefer SPDX ID, fall back to name
			if id := strings.TrimSpace(choice.License.ID); id != "" {
				result = append(result, id)
			} else if name := strings.TrimSpace(choice.License.Name); name != "" {
				result = append(result, name)
			}
		}
		if expr := strings.TrimSpace(choice.Expression); expr != "" {
			result = append(result, expr)
		}
	}
	return result
}

// parseSPDXPackages parses an SPDX JSON document and extracts package information.
func parseSPDXPackages(data []byte) ([]*extractor.Package, map[string]bool, []imageSBOMRef, []string, error) {
	doc, err := spdxjson.Read(bytes.NewReader(data))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if doc == nil || len(doc.Packages) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("spdx document contained no packages")
	}
	var pkgs []*extractor.Package
	var imageRefs []imageSBOMRef
	var purls []string
	for _, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}
		name := strings.TrimSpace(pkg.PackageName)
		version := strings.TrimSpace(pkg.PackageVersion)
		purlStr := extractSPDXPackagePURL(pkg)
		if normalized := normalizeSBOMPURL(purlStr); normalized != "" {
			purls = append(purls, normalized)
		}
		if ref, ok := imageRefFromPURL(purlStr); ok {
			imageRefs = append(imageRefs, ref)
			continue
		}
		if name == "" || version == "" {
			continue
		}
		entry := &extractor.Package{Name: name, Version: version, Licenses: extractSPDXLicenses(pkg)}
		if purlStr != "" {
			if pu, err := purlx.ParseLoose(purlStr); err == nil {
				entry.PURLType = pu.Type
			}
		}
		pkgs = append(pkgs, entry)
	}
	imageRefs = dedupeImageRefs(imageRefs)
	purls = collections.Dedupe(purls)
	if len(pkgs) == 0 && len(imageRefs) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("spdx document did not contain packages with name+version or image references")
	}
	return pkgs, nil, imageRefs, purls, nil
}

// extractSPDXLicenses extracts license identifiers from an SPDX package.
// Prefers concluded license, falls back to declared license.
func extractSPDXLicenses(pkg *spdxdoc.Package) []string {
	if pkg == nil {
		return nil
	}
	// Try concluded license first, then declared
	for _, lic := range []string{pkg.PackageLicenseConcluded, pkg.PackageLicenseDeclared} {
		lic = strings.TrimSpace(lic)
		if lic != "" && lic != "NONE" && lic != "NOASSERTION" {
			return []string{lic}
		}
	}
	return nil
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

type imageSBOMRef struct {
	Ref      string
	Platform string
}

func imageRefFromPURL(purlStr string) (imageSBOMRef, bool) {
	purlStr = strings.TrimSpace(purlStr)
	if purlStr == "" {
		return imageSBOMRef{}, false
	}
	pu, err := purlx.ParseLoose(purlStr)
	if err != nil {
		return imageSBOMRef{}, false
	}
	purlType := strings.ToLower(strings.TrimSpace(pu.Type))
	if !isContainerPURLType(purlType) {
		return imageSBOMRef{}, false
	}

	ref, platform := imageRefFromPackageURL(pu)
	if ref == "" {
		return imageSBOMRef{}, false
	}
	if _, err := name.ParseReference(ref, name.WeakValidation); err != nil {
		return imageSBOMRef{}, false
	}

	out := imageSBOMRef{Ref: ref, Platform: platform}
	switch purlType {
	case "oci":
		out.Ref = "oci://" + ref
		return out, true
	default:
		out.Ref = "docker://" + ref
		return out, true
	}
}

func isContainerPURLType(purlType string) bool {
	switch strings.ToLower(strings.TrimSpace(purlType)) {
	case "docker", "oci":
		return true
	default:
		return false
	}
}

func imageRefFromPackageURL(pu packageurl.PackageURL) (string, string) {
	name := strings.Trim(strings.TrimSpace(pu.Name), "/")
	namespace := strings.Trim(strings.TrimSpace(pu.Namespace), "/")
	if name == "" {
		return "", ""
	}
	ref := name
	if namespace != "" {
		ref = namespace + "/" + name
	}

	qualifiers := lowerQualifierMap(pu.Qualifiers.Map())
	if repo := repoFromQualifier(qualifiers["repository_url"]); repo != "" {
		ref = repo
	} else if registry := repoFromQualifier(qualifiers["registry_url"]); registry != "" {
		host := imageHost(ref)
		if host == "" || (!strings.Contains(host, ".") && !strings.Contains(host, ":") && host != "localhost") {
			ref = strings.TrimSuffix(registry, "/") + "/" + strings.TrimPrefix(ref, "/")
		}
	}

	platform := imagePlatformFromQualifiers(qualifiers)

	if digest := strings.TrimSpace(qualifiers["digest"]); digest != "" {
		return strings.TrimSuffix(ref, "/") + "@" + digest, platform
	}
	if tag := strings.TrimSpace(qualifiers["tag"]); tag != "" {
		return strings.TrimSuffix(ref, "/") + ":" + tag, platform
	}

	version := strings.TrimSpace(pu.Version)
	if version == "" {
		return strings.TrimSuffix(ref, "/"), platform
	}
	if looksLikeImageDigest(version) {
		return strings.TrimSuffix(ref, "/") + "@" + version, platform
	}
	return strings.TrimSuffix(ref, "/") + ":" + version, platform
}

func lowerQualifierMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for key, val := range in {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		if _, ok := out[key]; ok {
			continue
		}
		out[key] = val
	}
	return out
}

func imagePlatformFromQualifiers(qualifiers map[string]string) string {
	if qualifiers == nil {
		return ""
	}
	if platform := strings.TrimSpace(qualifiers["platform"]); platform != "" {
		return platform
	}
	osVal := strings.TrimSpace(qualifiers["os"])
	arch := strings.TrimSpace(qualifiers["arch"])
	if osVal == "" || arch == "" {
		return ""
	}
	if variant := strings.TrimSpace(qualifiers["variant"]); variant != "" {
		return fmt.Sprintf("%s/%s/%s", osVal, arch, variant)
	}
	return osVal + "/" + arch
}

func repoFromQualifier(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "//")
	if !strings.Contains(raw, "://") {
		return strings.Trim(raw, "/")
	}
	parsed, err := neturl.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	path := strings.Trim(parsed.Path, "/")
	if path == "" {
		return parsed.Host
	}
	return parsed.Host + "/" + path
}

func looksLikeImageDigest(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	if strings.HasPrefix(version, "sha256:") || strings.HasPrefix(version, "sha384:") ||
		strings.HasPrefix(version, "sha512:") || strings.HasPrefix(version, "sha1:") {
		return true
	}
	return false
}

func imageRefCacheKey(ref imageSBOMRef) string {
	if ref.Platform == "" {
		return ref.Ref
	}
	return ref.Ref + "|" + ref.Platform
}

func dedupeImageRefs(refs []imageSBOMRef) []imageSBOMRef {
	if len(refs) == 0 {
		return nil
	}
	seen := collections.NewSetWithCapacity[string](len(refs))
	out := make([]imageSBOMRef, 0, len(refs))
	for _, ref := range refs {
		ref.Ref = strings.TrimSpace(ref.Ref)
		ref.Platform = strings.TrimSpace(ref.Platform)
		if ref.Ref == "" {
			continue
		}
		key := imageRefCacheKey(ref)
		if seen.Add(key) {
			out = append(out, ref)
		}
	}
	slices.SortFunc(out, func(a, b imageSBOMRef) int {
		if a.Ref == b.Ref {
			return strings.Compare(a.Platform, b.Platform)
		}
		return strings.Compare(a.Ref, b.Ref)
	})
	return out
}

func buildScanTargetPayload(result scanning.Result) map[string]any {
	return buildTargetPayload(result.Target)
}

func buildTargetPayload(target inventory.Target) map[string]any {
	provenance := map[string]any{}
	for k, v := range target.Provenance {
		provenance[k] = v
	}
	return map[string]any{
		"kind":          string(target.Kind),
		"display":       target.DisplayPath,
		"ref":           target.Ref,
		"effective_ref": target.EffectiveRef,
		"commit":        target.CommitHash,
		"origin":        target.OriginURL,
		"local":         target.LocalPath,
		"cloned":        target.Cloned,
		"provenance":    provenance,
	}
}

func buildScanImagePayload(target inventory.Target) map[string]any {
	if target.Kind != targets.KindContainerImage {
		return nil
	}
	ref := image.RefFromProvenance(target.Provenance)
	if ref == nil || ref.IsEmpty() {
		return nil
	}
	return ref.ToMap()
}

// runScanPolicies evaluates the provided policies against the scan report and individual vulnerabilities.
// Passes proto messages directly to CEL for type-safe evaluation.
func runScanPolicies(ctx context.Context, policyPaths []string, result scanning.Result, errW io.Writer, extra map[string]any) ([]policy.Action, error) {
	if len(policyPaths) == 0 {
		return nil, nil
	}

	// Convert scanning result to proto for CEL evaluation
	scanResponse := internalproto.ScanningResultToProto(&result)

	// Build report-level payload with proto messages
	payload := map[string]any{
		"report":          scanResponse,
		"target":          scanResponse.Target,
		"findings":        scanResponse.Findings,
		"vulnerabilities": scanResponse.Findings, // Alias for backward compatibility
		"stats":           scanResponse.Stats,
	}

	// Add image info if available
	if scanResponse.ImageInfo != nil {
		payload["image"] = scanResponse.ImageInfo
		payload["image_info"] = scanResponse.ImageInfo
	}

	// Merge extra context
	for key, val := range extra {
		payload[key] = val
	}

	var out []policy.Action
	actions, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "scan", policy.EntrypointScanReport, errW)
	if err != nil {
		return nil, err
	}
	out = append(out, actions...)

	// Evaluate per-vulnerability policies
	for _, finding := range scanResponse.Findings {
		vulnPayload := map[string]any{
			"vulnerability": finding,
			"target":        scanResponse.Target,
		}
		if scanResponse.ImageInfo != nil {
			vulnPayload["image"] = scanResponse.ImageInfo
			vulnPayload["image_info"] = scanResponse.ImageInfo
		}
		for key, val := range extra {
			if _, ok := vulnPayload[key]; !ok {
				vulnPayload[key] = val
			}
		}
		actions, err := evaluatePoliciesForCommand(ctx, policyPaths, vulnPayload, "scan", policy.EntrypointScanVulnerability, errW)
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

// isDockerfilePath returns true if the path looks like a Dockerfile.
func isDockerfilePath(path string) bool {
	base := filepath.Base(path)
	baseLower := strings.ToLower(base)

	// Exact matches
	if base == "Dockerfile" || base == "Containerfile" {
		return true
	}
	// Dockerfile.* pattern (e.g., Dockerfile.prod)
	if strings.HasPrefix(base, "Dockerfile.") {
		return true
	}
	// *.dockerfile pattern (e.g., app.dockerfile)
	if strings.HasSuffix(baseLower, ".dockerfile") {
		return true
	}
	// *Dockerfile pattern (e.g., test-Dockerfile, my.Dockerfile)
	if strings.HasSuffix(base, "Dockerfile") && base != "Dockerfile" {
		return true
	}
	// Containerfile.* pattern
	if strings.HasPrefix(base, "Containerfile.") {
		return true
	}
	// *.containerfile pattern
	if strings.HasSuffix(baseLower, ".containerfile") {
		return true
	}
	// *Containerfile pattern
	if strings.HasSuffix(base, "Containerfile") && base != "Containerfile" {
		return true
	}
	return false
}

// runScanDockerfile scans a Dockerfile for policy evaluation.
func runScanDockerfile(c *services.Clients, cmd *cobra.Command, target string) error {
	ctx := cmd.Context()
	flags := extractScanFlags(cmd)
	errW := cmd.ErrOrStderr()

	// Build proto request with Dockerfile target hint
	req := flags.toScanRequestWithHint(target, targetv1.TargetKind_TARGET_KIND_DOCKERFILE, "", "", errW)

	resp, err := c.Vulns.Scan(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("scan dockerfile: %w", err)
	}

	// Convert proto response to internal result for policy evaluation
	resultPtr := internalproto.ScanningResultFromProto(resp.Msg)
	result := *resultPtr

	// Run policies
	var policyFindings []report.PolicyFinding
	if len(flags.PolicyPaths) > 0 {
		actions, err := runDockerfilePolicies(ctx, flags.PolicyPaths, result, cmd.ErrOrStderr())
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: policy evaluation failed: %v\n", err)
		} else {
			policyFindings = actionsToPolicyFindings(actions)
			// Add policy actions to proto response for JSON output
			resp.Msg.PolicyActions = internalproto.PolicyActionsToProto(actions)
		}
	}

	// Output based on format
	format := strings.ToLower(flags.Format)
	switch format {
	case "json":
		return outputDockerfileJSON(cmd.OutOrStdout(), resp.Msg)
	default:
		// Table/text output (uses internal types for rendering)
		dfResult := dockerfileResultForText(result, policyFindings)
		renderDockerfileResult(cmd.OutOrStdout(), dfResult, policyFindings)
	}

	// Check for policy denials
	for _, f := range policyFindings {
		if strings.EqualFold(f.Action, "deny") {
			return fmt.Errorf("policy violation: %s", f.Reason)
		}
	}

	return nil
}

// outputDockerfileJSON outputs Dockerfile scan results as JSON using protojson.
func outputDockerfileJSON(w io.Writer, resp *scanv1.ScanResponse) error {
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}
	data, err := opts.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal proto to JSON: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

// dockerfileResultForText builds a DockerfileScanResult for text rendering.
func dockerfileResultForText(result scanning.Result, policyFindings []report.PolicyFinding) DockerfileScanResult {
	return DockerfileScanResult{
		Path:           result.DockerfileInfo.Path,
		StageCount:     len(result.DockerfileInfo.Stages),
		Stages:         buildDockerfileStagesOutput(result.DockerfileInfo),
		Analysis:       buildDockerfileAnalysisOutput(result.DockerfileAnalysis),
		PolicyFindings: policyFindings,
	}
}

// DockerfileScanResult is the structured output of a Dockerfile scan.
type DockerfileScanResult struct {
	Path           string                   `json:"path"`
	StageCount     int                      `json:"stage_count"`
	Stages         []DockerfileStageOutput  `json:"stages"`
	Analysis       DockerfileAnalysisOutput `json:"analysis"`
	PolicyFindings []report.PolicyFinding   `json:"policy_findings,omitempty"`
}

// DockerfileStageOutput represents a stage in the scan output.
type DockerfileStageOutput struct {
	Index          int      `json:"index"`
	Name           string   `json:"name,omitempty"`
	BaseImage      string   `json:"base_image"`
	Platform       string   `json:"platform,omitempty"`
	IsScratch      bool     `json:"is_scratch"`
	IsBuilder      bool     `json:"is_builder"`
	User           string   `json:"user,omitempty"`
	IsRoot         bool     `json:"is_root"`
	ExposedPorts   []string `json:"exposed_ports,omitempty"`
	HasHealthcheck bool     `json:"has_healthcheck"`
}

// DockerfileAnalysisOutput contains static analysis results.
type DockerfileAnalysisOutput struct {
	HasMultiStage       bool     `json:"has_multi_stage"`
	FinalStageIsRoot    bool     `json:"final_stage_is_root"`
	FinalStageIsScratch bool     `json:"final_stage_is_scratch"`
	SensitiveEnvVars    []string `json:"sensitive_env_vars,omitempty"`
	HasAddURL           bool     `json:"has_add_url"`
}

func buildDockerfileStagesOutput(info *dockerfile.Info) []DockerfileStageOutput {
	if info == nil {
		return nil
	}
	out := make([]DockerfileStageOutput, len(info.Stages))
	for i, s := range info.Stages {
		out[i] = DockerfileStageOutput{
			Index:          s.Index,
			Name:           s.Name,
			BaseImage:      s.BaseImage,
			Platform:       s.Platform,
			IsScratch:      s.IsScratch,
			IsBuilder:      s.IsBuilderStage,
			User:           s.User,
			IsRoot:         s.IsRoot(),
			ExposedPorts:   s.ExposedPorts,
			HasHealthcheck: s.Healthcheck != nil,
		}
	}
	return out
}

func buildDockerfileAnalysisOutput(analysis *dockerfile.Analysis) DockerfileAnalysisOutput {
	if analysis == nil {
		return DockerfileAnalysisOutput{}
	}
	return DockerfileAnalysisOutput{
		HasMultiStage:       analysis.HasMultiStage,
		FinalStageIsRoot:    analysis.FinalStageIsRoot,
		FinalStageIsScratch: analysis.FinalStageIsScratch,
		SensitiveEnvVars:    analysis.SensitiveEnvVars,
		HasAddURL:           analysis.HasAddURL,
	}
}

func renderDockerfileResult(w io.Writer, result DockerfileScanResult, findings []report.PolicyFinding) {
	fmt.Fprintf(w, "Dockerfile: %s\n", result.Path)
	fmt.Fprintf(w, "Stages: %d\n\n", result.StageCount)

	for _, stage := range result.Stages {
		name := fmt.Sprintf("Stage %d", stage.Index)
		if stage.Name != "" {
			name = fmt.Sprintf("Stage %d (%s)", stage.Index, stage.Name)
		}
		fmt.Fprintf(w, "%s\n", name)
		fmt.Fprintf(w, "  Base: %s\n", stage.BaseImage)
		if stage.IsScratch {
			fmt.Fprintf(w, "  Type: scratch (empty)\n")
		} else if stage.IsBuilder {
			fmt.Fprintf(w, "  Type: builder stage\n")
		}
		if stage.User != "" {
			fmt.Fprintf(w, "  User: %s\n", stage.User)
		} else if !stage.IsScratch {
			fmt.Fprintf(w, "  User: root (default)\n")
		}
		if len(stage.ExposedPorts) > 0 {
			fmt.Fprintf(w, "  Ports: %s\n", strings.Join(stage.ExposedPorts, ", "))
		}
		if stage.HasHealthcheck {
			fmt.Fprintf(w, "  Healthcheck: configured\n")
		}
		fmt.Fprintln(w)
	}

	// Analysis summary
	if result.Analysis.HasMultiStage {
		fmt.Fprintf(w, "Multi-stage build detected\n")
	}
	if result.Analysis.FinalStageIsScratch {
		fmt.Fprintf(w, "Final stage uses scratch (minimal)\n")
	}
	if result.Analysis.FinalStageIsRoot {
		fmt.Fprintf(w, "Warning: Final stage runs as root\n")
	}
	if len(result.Analysis.SensitiveEnvVars) > 0 {
		fmt.Fprintf(w, "Warning: Sensitive environment variables detected: %s\n", strings.Join(result.Analysis.SensitiveEnvVars, ", "))
	}
	if result.Analysis.HasAddURL {
		fmt.Fprintf(w, "Warning: ADD with URL detected (security concern)\n")
	}

	// Policy findings
	if len(findings) > 0 {
		fmt.Fprintf(w, "\nPolicy Findings:\n")
		for _, f := range findings {
			icon := "!"
			if strings.EqualFold(f.Action, "deny") {
				icon = "X"
			}
			fmt.Fprintf(w, "  [%s] %s: %s\n", icon, f.Source, f.Reason)
			if f.Remediation != "" {
				fmt.Fprintf(w, "      Remediation: %s\n", f.Remediation)
			}
		}
	}
}

func runDockerfilePolicies(ctx context.Context, policyPaths []string, result scanning.Result, errW io.Writer) ([]policy.Action, error) {
	if len(policyPaths) == 0 || result.DockerfileInfo == nil {
		return nil, nil
	}

	var out []policy.Action

	// Build payload for dockerfile_report entrypoint
	payload := map[string]any{
		"dockerfile":          result.DockerfileInfo.ToMap(),
		"dockerfile_analysis": result.DockerfileAnalysis.ToMap(),
		"target": map[string]any{
			"kind":    string(targets.KindDockerfile),
			"display": result.Target.DisplayPath,
			"local":   result.Target.LocalPath,
		},
	}

	// Evaluate dockerfile_report policies
	actions, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "scan", policy.EntrypointDockerfileReport, errW)
	if err != nil {
		return nil, err
	}
	out = append(out, actions...)

	// Evaluate dockerfile_stage policies for each stage
	for _, stage := range result.DockerfileInfo.Stages {
		stagePayload := map[string]any{
			"dockerfile":          result.DockerfileInfo.ToMap(),
			"dockerfile_analysis": result.DockerfileAnalysis.ToMap(),
			"stage":               stage.ToMap(),
			"target": map[string]any{
				"kind":    string(targets.KindDockerfile),
				"display": result.Target.DisplayPath,
				"local":   result.Target.LocalPath,
			},
		}
		actions, err := evaluatePoliciesForCommand(ctx, policyPaths, stagePayload, "scan", policy.EntrypointDockerfileStage, errW)
		if err != nil {
			return nil, err
		}
		out = append(out, actions...)
	}

	return out, nil
}
