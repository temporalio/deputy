package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/picatz/deputy/internal/cli/flags"
	"github.com/picatz/deputy/internal/services"
	"github.com/picatz/deputy/internal/policy"
	sbomx "github.com/picatz/deputy/internal/sbom"
	"github.com/picatz/deputy/internal/targets"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
)

// AddSBOMCommand registers the sbom subcommand
func AddSBOMCommand(root *cobra.Command, c *services.Clients) {
	// Client available for future use when SBOM operations move to proto API
	_ = c

	var (
		ref, format, outPath, name, licenseSource string
		source, platform                          string
		ecos                                      []string
		enrichLicenses, showContext, enrich       bool
		enrichConcurrency                         int
		policyPaths                               []string
	)

	cmd := &cobra.Command{
		Use:           "sbom [target]",
		Aliases:       []string{"bom"},
		Short:         "Generate an SBOM for a repository or container image",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Generate a Software Bill of Materials (SBOM) for repositories and container images.

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

CONTAINER IMAGES:
When the target is a container image, Deputy uses the OSV-Scalibr image pipeline to
inspect the image layers and generate a package inventory. Image references support
Docker and OCI registries, local Docker daemon images, and tarball archives.

LICENSE ENRICHMENT:
Optionally enriches SBOM entries with license information from multiple sources:

  --license-source depsdev (default):
    Uses the deps.dev API for fast, comprehensive license lookups across
    Go, npm, Cargo, Maven, PyPI, NuGet, and RubyGems ecosystems.

  --license-source scan:
    Multi-source license detection with ecosystem-specific registry lookups:
    • Local workspace: Scans LICENSE, COPYING, COPYRIGHT files in source
    • Go modules: Downloads from proxy.golang.org and scans archives
    • Rust crates: Queries crates.io API for license metadata
    • PHP packages: Queries Packagist API for composer packages
    • Dart packages: Queries pub.dev API for Flutter/Dart packages
    • CocoaPods: Queries CocoaPods trunk for iOS/macOS packages
    • Hex.pm: Queries Hex.pm API for Erlang/Elixir packages
    • GitHub: Fetches LICENSE files directly from repositories
    • Container images: Extracts org.opencontainers.image.licenses labels

  --license-source both:
    Combines deps.dev API lookups with registry scanning for maximum coverage.
    Uses deps.dev as primary source, then fills gaps with registry scans.

METADATA ENRICHMENT:
The --enrich flag adds comprehensive metadata from deps.dev:
• CPE identifiers: Common Platform Enumeration for vulnerability correlation
• Supplier information: Package maintainer/owner from repository metadata
• External references: VCS URLs, homepage, issue tracker, documentation
• Publish dates: When each package version was released`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate args (cobra.MaximumNArgs moved here to allow subcommands)
			if len(args) > 1 {
				return fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
			}
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

			licenseSource = flags.NormalizeLicenseSource(licenseSource)
			sourceKind, imageSource, err := resolveSourceOverride(source)
			if err != nil {
				return err
			}
			if sourceKind == "purl" || sourceKind == "sbom" {
				return fmt.Errorf("--source %q is not supported for SBOM generation", source)
			}

			isImage := sourceKind == "image"
			if !isImage {
				if isImageTargetScheme(repoPath) {
					isImage = true
				} else if looksLikeContainerReference(repoPath) {
					if isAmbiguousDockerHubReference(repoPath) {
						return fmt.Errorf("target %q is ambiguous; use docker://%s:tag (or docker.io/%s:tag) for images, or github.com/%s for GitHub repos", repoPath, repoPath, repoPath, repoPath)
					}
					isImage = true
				}
			}

			var result sbomx.Result
			if isImage {
				target := repoPath
				if !isImageTargetScheme(target) {
					imgSource := imageSource
					if imgSource == "" {
						imgSource = "remote"
					}
					target, err = normalizeImageTarget(target, imgSource)
					if err != nil {
						return err
					}
				}
				warnRefIgnored(cmd, "image")
				targetOpts := &targets.OpenOptions{}
				if strings.TrimSpace(platform) != "" {
					targetOpts.Platform = platform
				}
				result, err = sbomx.GenerateImage(ctx, target, targetOpts, sbomx.Options{
					Ecosystems:        ecos,
					Name:              name,
					EnrichLicenses:    enrichLicenses,
					LicenseSource:     licenseSource,
					Enrich:            enrich,
					EnrichConcurrency: enrichConcurrency,
				})
				if err != nil {
					return fmt.Errorf("failed to generate SBOM: %w", err)
				}
			} else {
				if ref == "" {
					ref = "HEAD"
				}
				result, err = sbomx.Generate(ctx, repoPath, sbomx.Options{
					Ref:               ref,
					Ecosystems:        ecos,
					Name:              name,
					EnrichLicenses:    enrichLicenses,
					LicenseSource:     licenseSource,
					Enrich:            enrich,
					EnrichConcurrency: enrichConcurrency,
				})
				if err != nil {
					return fmt.Errorf("failed to generate SBOM: %w", err)
				}
			}

			if showContext {
				emitSBOMContext(cmd.ErrOrStderr(), result)
			}

			if err := runSBOMPolicies(ctx, policyPaths, result, cmd.ErrOrStderr()); err != nil {
				return err
			}

			doc := result.Document

			var w io.Writer = cmd.OutOrStdout()
			if outPath != "" && outPath != "-" {
				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			fmtFmt, err := flags.NormalizeSBOMOutputFormat(format)
			if err != nil {
				return err
			}
			switch fmtFmt {
			case flags.SBOMOutputCycloneDXJSON:
				return sbomx.WriteCycloneDXJSON(doc, w)
			case flags.SBOMOutputSPDXJSON:
				return sbomx.WriteSPDXJSON(doc, w)
			case flags.SBOMOutputProtobomJSON:
				return sbomx.WriteProtobomJSON(doc, w)
			default:
				return flags.UnsupportedFormatError("", format, "cyclonedx-json | spdx-json | protobom-json")
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

CONTAINER IMAGES:
  # Generate SBOM for a remote container image
  deputy sbom docker://ghcr.io/owner/app:1.2.3

  # Generate SBOM for a local Docker daemon image
  deputy sbom --source docker-daemon ubuntu:latest

  # Generate SBOM from an OCI tarball
  deputy sbom --source tarball ./image.tar

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
	cmd.Flags().StringVar(&name, "name", "", "Optional document name (defaults to repo@ref or image reference)")
	cmd.Flags().BoolVar(&enrichLicenses, "enrich-licenses", false, "Enrich SBOM nodes with licenses (optional)")
	cmd.Flags().StringVar(&licenseSource, "license-source", "depsdev", "License enrichment source: depsdev | scan | both")
	cmd.Flags().BoolVar(&enrich, "enrich", false, "Enrich SBOM with CPEs, external refs, suppliers, and publish dates from deps.dev")
	cmd.Flags().IntVar(&enrichConcurrency, "enrich-concurrency", 10, "Max concurrent deps.dev requests during enrichment")
	cmd.Flags().StringVar(&source, "source", "", "Target source override: auto, git, dir, image, remote, docker-daemon, tarball")
	cmd.Flags().StringVar(&platform, "platform", "", "Container image platform (os/arch[/variant])")
	cmd.Flags().BoolVar(&showContext, "show-context", false, "Print a context header to stderr with repo or image details")
	cmd.Flags().StringArrayVar(&policyPaths, "policy", nil, "Path to CEL policy files or bundles to evaluate against SBOM results (repeatable)")

	// Add subcommands
	addSBOMEnrichCommand(cmd)
	addSBOMDiffCommand(cmd)

	root.AddCommand(cmd)
}

// runSBOMPolicies evaluates policies against the generated SBOM result.
// It checks both the overall report and individual components.
func runSBOMPolicies(ctx context.Context, policyPaths []string, result sbomx.Result, errW io.Writer) error {
	if len(policyPaths) == 0 {
		return nil
	}
	// Build target payload for CEL evaluation
	targetPayload := buildTargetPayload(result.Target)
	var imagePayload any
	if img := buildScanImagePayload(result.Target); img != nil {
		imagePayload = img
	}

	// Pass Go struct directly to CEL
	reportPayload := map[string]any{
		"sbom":     result,
		"target":   targetPayload,
		"packages": result.Packages,
	}
	if imagePayload != nil {
		reportPayload["image"] = imagePayload
	}
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, reportPayload, "sbom", policy.EntrypointSBOMReport, errW); err != nil {
		return err
	}

	// Extract context fields
	repo := strings.TrimSpace(result.RepoPath)
	if repo == "" {
		repo = strings.TrimSpace(result.Target.DisplayPath)
	}
	ref := strings.TrimSpace(result.Ref)
	if ref == "" {
		ref = strings.TrimSpace(result.Target.Ref)
	}
	commit := strings.TrimSpace(result.Commit)
	if commit == "" {
		commit = strings.TrimSpace(result.Target.CommitHash)
	}

	// Evaluate per-component policies with Go structs directly
	for _, pkg := range result.Packages {
		compPayload := map[string]any{
			"repo":      repo,
			"ref":       ref,
			"commit":    commit,
			"component": pkg, // Pass extractor.Package directly
			"target":    targetPayload,
		}
		if imagePayload != nil {
			compPayload["image"] = imagePayload
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, compPayload, "sbom", policy.EntrypointSBOMComponent, errW); err != nil {
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
	fmt.Fprintf(w, "%s\n", ui.StyleHeader.Render("Context"))

	if result.Target.Kind == targets.KindContainerImage {
		display := strings.TrimSpace(result.Target.DisplayPath)
		if display == "" {
			display = strings.TrimSpace(result.RepoPath)
		}
		if display == "" {
			display = "(unknown)"
		}
		fmt.Fprintf(w, "  Image:     %s\n", display)
		if registry := strings.TrimSpace(result.Target.Provenance["registry"]); registry != "" {
			fmt.Fprintf(w, "  Registry:  %s\n", registry)
		}
		if repo := strings.TrimSpace(result.Target.Provenance["repository"]); repo != "" {
			fmt.Fprintf(w, "  Repository: %s\n", repo)
		}
		if tag := strings.TrimSpace(result.Target.Provenance["tag"]); tag != "" {
			fmt.Fprintf(w, "  Tag:       %s\n", tag)
		}
		if digest := strings.TrimSpace(result.Target.Provenance["digest"]); digest != "" {
			fmt.Fprintf(w, "  Digest:    %s\n", digest)
		}
		if platform := strings.TrimSpace(result.Target.Provenance["platform"]); platform != "" {
			fmt.Fprintf(w, "  Platform:  %s\n", platform)
		}
		return
	}

	repo := strings.TrimSpace(result.RepoPath)
	if repo == "" {
		repo = strings.TrimSpace(result.Target.DisplayPath)
	}
	if repo == "" {
		repo = "(unknown)"
	}
	ref := strings.TrimSpace(result.Ref)
	if ref == "" {
		ref = strings.TrimSpace(result.Target.Ref)
	}
	ref = shortGitRef(refOrHEAD(ref))
	if ref == "" {
		ref = "HEAD"
	}
	commit := strings.TrimSpace(result.Commit)
	if commit == "" {
		commit = strings.TrimSpace(result.Target.CommitHash)
	}
	switch {
	case commit == "":
		commit = "unknown"
	case len(commit) > 7:
		commit = commit[:7]
	}
	origin := strings.TrimSpace(result.Origin)
	if origin == "" {
		origin = strings.TrimSpace(result.Target.OriginURL)
	}
	if origin == "" {
		origin = repo
	}
	fmt.Fprintf(w, "  Repo:   %s\n", repo)
	fmt.Fprintf(w, "  Ref:    %s\n", ref)
	fmt.Fprintf(w, "  Commit: %s\n", commit)
	if origin != repo {
		fmt.Fprintf(w, "  Origin: %s\n", origin)
	}

	// Show completeness scoring if document is available
	emitSBOMCompleteness(w, result)
}

// emitSBOMCompleteness prints SBOM completeness scoring information.
func emitSBOMCompleteness(w io.Writer, result sbomx.Result) {
	if w == nil || result.Document == nil {
		return
	}

	score := sbomx.CalculateCompleteness(result.Document)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", ui.StyleHeader.Render("SBOM Completeness"))
	fmt.Fprintf(w, "  Score:        %.1f%% (%d components)\n",
		score.Score*100, score.TotalComponents)

	// Show NTIA compliance status
	if score.NTIACompliant {
		fmt.Fprintf(w, "  NTIA Status:  Compliant (all minimum elements present)\n")
	} else {
		fmt.Fprintf(w, "  NTIA Status:  Non-compliant\n")
		if len(score.NTIAMissing) > 0 {
			fmt.Fprintf(w, "  Missing:      %s\n", strings.Join(score.NTIAMissing, ", "))
		}
	}

	// Show field coverage breakdown
	fmt.Fprintf(w, "  Coverage:\n")
	fmt.Fprintf(w, "    - PURL:       %3.0f%%\n", score.HasPURL*100)
	fmt.Fprintf(w, "    - Version:    %3.0f%%\n", score.HasVersion*100)
	fmt.Fprintf(w, "    - Licenses:   %3.0f%%\n", score.HasLicenses*100)
	fmt.Fprintf(w, "    - Hashes:     %3.0f%%\n", score.HasHashes*100)
	fmt.Fprintf(w, "    - CPE:        %3.0f%%\n", score.HasCPE*100)
	fmt.Fprintf(w, "    - Supplier:   %3.0f%%\n", score.HasSupplier*100)
	fmt.Fprintf(w, "    - Ext. Refs:  %3.0f%%\n", score.HasExternalRefs*100)
}
