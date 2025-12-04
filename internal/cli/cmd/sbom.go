package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	sbomx "github.com/picatz/deputy/internal/sbom"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
)

// AddSBOMCommand registers the sbom subcommand
func AddSBOMCommand(root *cobra.Command) {
	var (
		ref, format, outPath, name, licenseSource string
		ecos                                      []string
		enrichLicenses, showContext               bool
		policyPaths                               []string
	)

	cmd := &cobra.Command{
		Use:   "sbom [repo]",
		Short: "Generate an SBOM for a repository",
		Long: `Generate a Software Bill of Materials (SBOM) for repositories at any Git reference.

SOFTWARE BILL OF MATERIALS:
An SBOM is a comprehensive inventory of all software components, dependencies, and
metadata for a given software artifact. It provides transparency into what's actually
included in your software, enabling better security analysis and compliance tracking.

SUPPORTED FORMATS:
• cyclonedx-json: CycloneDX JSON format (OWASP standard, widely supported)
• spdx-json: SPDX JSON format (Linux Foundation standard, government preferred)  
• protobom-json: Protobom intermediate format (for advanced processing)

ECOSYSTEM DETECTION:
Automatically detects and analyzes Go modules and dependencies. Uses OSV-Scalibr
for reliable package detection with support for various manifest formats including
go.mod, go.sum, and vendor directories.

LICENSE ENRICHMENT:
Optionally enriches SBOM entries with license information from multiple sources:
• deps.dev API: Fast, comprehensive license database
• Local scanning: Analyzes LICENSE files in source code
• Combined approach: Maximum coverage using both methods`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			repoPath := ""
			if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
				repoPath = args[0]
			} else {
				var err error
				repoPath, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			if ref == "" {
				ref = "HEAD"
			}

			result, err := sbomx.Generate(ctx, repoPath, sbomx.Options{
				Ref:            ref,
				Ecosystems:     ecos,
				Name:           name,
				EnrichLicenses: enrichLicenses,
				LicenseSource:  licenseSource,
			})
			if err != nil {
				return fmt.Errorf("failed to generate SBOM: %w", err)
			}

			if showContext {
				emitSBOMContext(cmd.ErrOrStderr(), result)
			}

			if err := runSBOMPolicies(ctx, policyPaths, result, cmd.ErrOrStderr()); err != nil {
				return err
			}

			doc := result.Document

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
			case "cyclonedx-json", "cyclonedx":
				return sbomx.WriteCycloneDXJSON(doc, w)
			case "spdx-json", "spdx":
				return sbomx.WriteSPDXJSON(doc, w)
			case "protobom-json", "protobom":
				return sbomx.WriteProtobomJSON(doc, w)
			default:
				return fmt.Errorf("unsupported format %q (use cyclonedx-json | spdx-json | protobom-json)", format)
			}
		},
		Example: `BASIC SBOM GENERATION:
  # Generate SBOM for current repository at HEAD
  deputy sbom

  # Generate SBOM for current directory
  deputy sbom .

  # Generate SBOM for specific repository
  deputy sbom /path/to/project
  deputy sbom ~/projects/my-app

  # Generate SBOM for remote repository
  deputy sbom github.com/username/repo
  deputy sbom https://github.com/username/repo.git

REFERENCE-SPECIFIC SBOM:
  # Generate SBOM for specific branch
  deputy sbom --ref main
  deputy sbom --ref feature/new-auth
  deputy sbom --ref develop

  # Generate SBOM for specific tag/release
  deputy sbom --ref v1.2.3
  deputy sbom --ref release-2024
  deputy sbom --ref latest

  # Generate SBOM for specific commit
  deputy sbom --ref abc123d
  deputy sbom --ref HEAD~3

  # Generate SBOM for working tree (uncommitted changes)
  deputy sbom --ref HEAD~0

OUTPUT FORMATS:
  # CycloneDX JSON (default, widely supported)
  deputy sbom --format cyclonedx-json
  deputy sbom --format cyclonedx

  # SPDX JSON (government/enterprise preferred)
  deputy sbom --format spdx-json  
  deputy sbom --format spdx

  # Protobom JSON (for advanced processing)
  deputy sbom --format protobom-json
  deputy sbom --format protobom

OUTPUT AND STORAGE:
  # Save to file
  deputy sbom --output project-sbom.json
  deputy sbom --output /artifacts/sbom.json --format spdx

  # Different formats for different uses
  deputy sbom --format cyclonedx --output supply-chain.json
  deputy sbom --format spdx --output compliance-report.json

LICENSE ENRICHMENT:
  # Add license information from deps.dev
  deputy sbom --enrich-licenses
  deputy sbom --enrich-licenses --license-source depsdev

  # Scan local files for license information
  deputy sbom --enrich-licenses --license-source scan

  # Use both sources for maximum coverage
  deputy sbom --enrich-licenses --license-source both

CUSTOMIZATION:
  # Custom document name
  deputy sbom --name "MyProject SBOM v1.2.3"
  deputy sbom --name "Production Release SBOM"

  # Limit to specific ecosystems (future expansion)
  deputy sbom --ecosystems go

  # Show generation context information
  deputy sbom --show-context

WORKFLOW EXAMPLES:
  # CI/CD artifact generation
  deputy sbom --format cyclonedx --output artifacts/sbom.json --enrich-licenses

  # Compliance reporting
  deputy sbom --format spdx --output compliance/project-sbom.json --license-source both

  # Supply chain analysis
  deputy sbom --format protobom | jq '.nodeList.nodes[] | select(.type == "PACKAGE")'

  # Release artifacts
  deputy sbom --ref v1.2.3 --format cyclonedx --name "MyApp v1.2.3 SBOM" --output release/

  # Security baseline
  deputy sbom --ref main --format cyclonedx | deputy scan sbom -

PIPELINE INTEGRATION:
  # Generate and immediately scan for vulnerabilities
  deputy sbom --format protobom | deputy scan sbom -

  # Multi-format generation for different consumers
  deputy sbom --format cyclonedx --output cyclonedx-sbom.json
  deputy sbom --format spdx --output spdx-sbom.json

  # Historical analysis
  deputy sbom --ref v1.0.0 --format cyclonedx --output v1.0.0-sbom.json
  deputy sbom --ref v2.0.0 --format cyclonedx --output v2.0.0-sbom.json`,
	}

	cmd.Flags().StringVar(&ref, "ref", "HEAD", "Git reference (commit, tag, branch)")
	cmd.Flags().StringVarP(&format, "format", "f", "cyclonedx-json", "SBOM format: cyclonedx-json | spdx-json | protobom-json")
	cmd.Flags().StringVarP(&outPath, "output", "o", "-", "Output file path or '-' for stdout")
	cmd.Flags().StringSliceVar(&ecos, "ecosystems", nil, "Limit to specific ecosystems (e.g., go,npm,pip). Defaults to auto-detect.")
	cmd.Flags().StringVar(&name, "name", "", "Optional document name (defaults to repo@ref)")
	cmd.Flags().BoolVar(&enrichLicenses, "enrich-licenses", false, "Enrich SBOM nodes with licenses (optional)")
	cmd.Flags().StringVar(&licenseSource, "license-source", "depsdev", "License enrichment source: depsdev | scan | both")
	cmd.Flags().BoolVar(&showContext, "show-context", false, "Print a context header to stderr with repo, ref, and commit hash")
	cmd.Flags().StringArrayVar(&policyPaths, "policy", nil, "Path to CEL policy files or bundles to evaluate against SBOM results (repeatable)")

	root.AddCommand(cmd)
}

// runSBOMPolicies evaluates policies against the generated SBOM result.
// It checks both the overall report and individual components.
func runSBOMPolicies(ctx context.Context, policyPaths []string, result sbomx.Result, errW io.Writer) error {
	if len(policyPaths) == 0 {
		return nil
	}
	reportMap, err := structToMap(result)
	if err != nil {
		return err
	}
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, reportMap, "sbom", "sbom_report", errW); err != nil {
		return err
	}
	for _, pkg := range result.Packages {
		pkgMap, err := structToMap(pkg)
		if err != nil {
			return err
		}
		payload := map[string]any{
			"repo":      result.RepoPath,
			"ref":       result.Ref,
			"commit":    result.Commit,
			"component": pkgMap,
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "sbom", "sbom_component", errW); err != nil {
			return err
		}
	}
	return nil
}

// emitSBOMContext prints context information (repo, ref, commit) to the provided writer.
func emitSBOMContext(w io.Writer, result sbomx.Result) {
	if w == nil {
		return
	}
	repo := strings.TrimSpace(result.RepoPath)
	if repo == "" {
		repo = "(unknown)"
	}
	ref := shortGitRef(refOrHEAD(result.Ref))
	if ref == "" {
		ref = "HEAD"
	}
	commit := strings.TrimSpace(result.Commit)
	if commit == "" {
		commit = "unknown"
	} else if len(commit) > 7 {
		commit = commit[:7]
	}
	origin := strings.TrimSpace(result.Origin)
	if origin == "" {
		origin = repo
	}
	fmt.Fprintf(w, "%s\n", ui.StyleHeader.Render("Context"))
	fmt.Fprintf(w, "  Repo:   %s\n", repo)
	fmt.Fprintf(w, "  Ref:    %s\n", ref)
	fmt.Fprintf(w, "  Commit: %s\n", commit)
	if origin != repo {
		fmt.Fprintf(w, "  Origin: %s\n", origin)
	}
}
