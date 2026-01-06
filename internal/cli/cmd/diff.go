package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	pb "deps.dev/api/v3"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/cli/flags"
	"github.com/picatz/deputy/internal/compare"
	gitx "github.com/picatz/deputy/internal/gitutil"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/license"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/output"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/report/render"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/picatz/deputy/internal/scan"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// AddDiffCommand registers the diff subcommand which compares dependency
// inventories between two Git references (or working tree) and optionally
// performs vulnerability scanning on changed modules.
func AddDiffCommand(root *cobra.Command, service *scan.Service) {
	var (
		repoPath                                       string
		skipVulnScan                                   bool
		enrichLicenses                                 bool
		licenseSource                                  string
		publishedBeforeStr, publishedAfterStr, asOfStr string
		ignoreUnfixed                                  bool
		showUnchanged                                  bool
		unchangedThreshold                             string
		ecosystems                                     []string
		debugMatcher                                   bool
		policyPaths                                    []string
		useLocalDaemon                                 bool
		outputFormat                                   string
	)

	if service == nil {
		service = scan.NewService()
	}

	cmd := &cobra.Command{
		Use:           "diff [base] [target]",
		Aliases:       []string{"d"},
		Short:         "Compare dependency changes between Git references or container images",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Compare dependencies between Git references or container images with comprehensive vulnerability analysis.

DEPENDENCY CHANGE ANALYSIS:
Analyzes differences in dependencies between two Git references or container images, including:
• Added dependencies (new packages introduced)
• Removed dependencies (packages no longer used)
• Updated dependencies (version changes)
• Direct vs indirect dependency classification

CONTAINER IMAGE DIFF:
When both arguments are container image references, performs a semantic diff between images:
• Package changes across image layers
• Vulnerability additions, removals, and fixes
• Configuration changes (user, ports, volumes, etc.)
• Layer-by-layer analysis

SUPPORTED REFERENCE TYPES:
• Branch names: main, develop, feature-branch, bugfix/issue-123
• Tags: v1.0.0, release-2023, latest
• Commit SHAs: 1a2b3c4, 1a2b3c4d5e6f7890abcdef123456789
• Remote references: origin/main, upstream/develop, fork/feature
• Git revision expressions: HEAD~3, main^, HEAD@{yesterday}, @{upstream}
• Time-based refs: HEAD@{N.second.ago}, HEAD@{N.minute.ago}, etc.
• Relative references: HEAD~1, main~5, tag^{tree}
• Working tree: WORKING, WORKTREE, WT, . (current uncommitted changes)

USAGE PATTERNS:
• No arguments: Compare default branch → HEAD (auto-detected)
  If go.mod/go.sum have uncommitted changes, compares default branch → WORKING
• One argument: Compare default branch → <ref>
• Two arguments: Compare <base> → <target>

The tool automatically detects the repository's default branch by checking:
1. Remote HEAD symref (most reliable for GitHub/GitLab repos)
2. Current branch if it's a likely default (main, master, develop)
3. Common default branch names in local branches
4. Falls back to any available branch or HEAD

OPTIMIZATION:
Only analyzes changes when go.mod or go.sum files are modified between references.
License information can be included with --licenses flag via deps.dev API or local scanning.

VULNERABILITY SCANNING:
Automatically scans added and updated packages for known vulnerabilities using OSV.
Reports CVE identifiers when available, otherwise shows GO- or GHSA- identifiers.
Uses batch queries to the OSV API for efficient scanning.
Can be disabled with --skip-vuln-scan for faster execution.`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Determine repo path first - we need it to check for Git refs
			repo := repoPath
			if repo == "" {
				var err error
				repo, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			// Check if both arguments are container image references
			// BUT only if they don't look like Git refs in the current repo context
			if len(args) == 2 && isContainerDiffInContext(args[0], args[1], repo) {
				opts := containerDiffOpts{
					skipVulnScan:   skipVulnScan,
					policyPaths:    policyPaths,
					useLocalDaemon: useLocalDaemon,
					format:         outputFormat,
				}
				return runContainerDiff(cmd.Context(), service, args[0], args[1], opts, cmd.OutOrStdout(), cmd.ErrOrStderr())
			}
			scanOpts := inv.ScanOptions{Ecosystems: ecosystems}
			matcher, matcherErr := inv.GetDependencyMatcher(scanOpts)
			if matcherErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: dependency matcher unavailable, falling back to full scans: %v\n", matcherErr)
			}
			baseRef, targetRef, err := gitx.ParseReferences(repo, args, matcher)
			if err != nil {
				return fmt.Errorf("failed to parse references: %w", err)
			}
			return runDiffAnalysis(cmd.Context(), service, repo, baseRef, targetRef, !skipVulnScan, enrichLicenses, licenseSource, publishedAfterStr, publishedBeforeStr, asOfStr, ignoreUnfixed, showUnchanged, unchangedThreshold, policyPaths, scanOpts, matcher, debugMatcher, outputFormat, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
		Example: `BASIC USAGE:
  # Compare current work with default branch (beginner-friendly)
  deputy diff

  # Tip: Just 'deputy' runs the same comparison (default command)

  # Compare default branch with a feature branch  
  deputy diff feature-branch
  deputy diff my-awesome-feature

  # Compare your current work with another branch
  # (Base is the branch, target is your work)
  deputy diff main WORKING
  deputy diff main .
  deputy diff feature-branch WORKING
  deputy diff feature-branch .

BRANCH COMPARISONS:
  # Compare two specific branches
  deputy diff main develop
  deputy diff master feature/new-auth
  deputy diff develop release/v2.0

TAG AND RELEASE COMPARISONS:
  # Compare releases or versions
  deputy diff v1.0.0 v2.0.0
  deputy diff release-2023 release-2024
  deputy diff latest HEAD

COMMIT COMPARISONS:
  # Compare specific commits
  deputy diff 1a2b3c4 main
  deputy diff abc123def main
  deputy diff HEAD~5 HEAD

REMOTE BRANCH COMPARISONS:
  # Compare with remote branches (useful for forks)
  deputy diff origin/main feature-branch
  deputy diff upstream/main origin/main
  deputy diff main origin/develop

ADVANCED GIT EXPRESSIONS:
  # Compare relative to HEAD
  deputy diff HEAD~3 HEAD
  deputy diff HEAD^ HEAD
  deputy diff main~1 main

  # Time-based comparisons
  deputy diff "HEAD@{yesterday}" HEAD
  deputy diff "main@{1.week.ago}" main
  deputy diff "main@{3.month.ago}" main
  deputy diff "HEAD@{1.year.ago}" HEAD

  # Compare with upstream
  deputy diff @{upstream} HEAD
  deputy diff main @{upstream}

REPOSITORY OPTIONS:
  # Analyze specific repository
  deputy diff --repo /path/to/project main feature
  deputy diff --repo ~/projects/my-app main HEAD

  # Skip vulnerability scanning for speed
  deputy diff --skip-vuln-scan main feature
  deputy diff --skip-vuln-scan HEAD~5 HEAD

  # Include license information for dependencies
  deputy diff --licenses main feature
  deputy diff --licenses --license-source=both v1.0.0 v2.0.0

WORKFLOW EXAMPLES:
  # Before merging a PR
  deputy diff main feature/user-auth

  # Check what changed in last 3 commits
  deputy diff HEAD~3 HEAD

  # Compare your fork with upstream
  deputy diff upstream/main main

  # Check dependency changes between releases
  deputy diff v1.2.0 v1.3.0

  # Fast dependency check without vulnerability scan
  deputy diff --skip-vuln-scan main develop

  # Check uncommitted dependency changes
  deputy diff HEAD WORKING

CONTAINER IMAGE EXAMPLES:
  # Compare two image tags
  deputy diff nginx:1.24 nginx:1.25

  # Compare images across registries
  deputy diff ghcr.io/org/app:v1.0 ghcr.io/org/app:v2.0

  # Compare with explicit OCI scheme
  deputy diff oci://alpine:3.18 oci://alpine:3.19

  # Skip vulnerability scanning for faster diff
  deputy diff --skip-vuln-scan myapp:old myapp:new

  # Use locally cached images from Docker daemon (avoids rate limits)
  docker pull nginx:1.24 && docker pull nginx:1.25
  deputy diff --local-daemon nginx:1.24 nginx:1.25

  # Explicit docker-daemon scheme (equivalent to --local-daemon)
  deputy diff docker-daemon://nginx:1.24 docker-daemon://nginx:1.25

ERROR HANDLING:
If you specify an invalid reference, deputy will suggest similar valid references
and provide guidance on supported reference types.

PERFORMANCE TIPS:
• Use --skip-vuln-scan for faster analysis when you only need dependency changes
• The tool optimizes by checking if go.mod/go.sum actually changed first
• Remote branch comparisons are cached locally for better performance`,
	}

	cmd.Flags().StringVarP(&repoPath, "repo", "r", "", "Path to the repository (defaults to current directory)")
	cmd.Flags().BoolVarP(&skipVulnScan, "skip-vuln-scan", "s", false, "Skip vulnerability scanning (faster execution)")
	cmd.Flags().BoolVar(&enrichLicenses, "licenses", false, "Include license information for changed dependencies")
	cmd.Flags().StringVar(&licenseSource, "license-source", "depsdev", "License information source: depsdev | scan | both")
	cmd.Flags().StringVar(&publishedBeforeStr, "published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	cmd.Flags().StringVar(&publishedAfterStr, "published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	cmd.Flags().StringVar(&asOfStr, "as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	cmd.Flags().BoolVar(&ignoreUnfixed, "ignore-unfixed", false, "Ignore vulnerabilities without fixes in diff scan output")
	cmd.Flags().BoolVar(&showUnchanged, "show-unchanged", false, "Always show vulnerabilities in unchanged dependencies (overrides quiet behavior)")
	cmd.Flags().StringVar(&unchangedThreshold, "unchanged-threshold", "critical", "Auto-show unchanged vulns at or above this severity: none|low|med|high|critical|any")
	cmd.Flags().StringSliceVar(&ecosystems, "ecosystems", []string{"all"}, "Ecosystems to include: go, npm, pypi, maven, rubygems, cargo, nuget, hex, pub, cocoapods, packagist, github-actions, haskell, r, cpp (default: all)")
	cmd.Flags().BoolVar(&debugMatcher, "debug-matcher", false, "Print which changed files were considered dependency manifests/lockfiles")
	cmd.Flags().StringArrayVar(&policyPaths, "policy", nil, "Path to CEL policy files or bundles to evaluate against diff results (repeatable)")
	cmd.Flags().BoolVar(&useLocalDaemon, "local-daemon", false, "Use local Docker daemon instead of pulling from remote registry (requires 'docker pull' first)")
	cmd.Flags().StringVar(&outputFormat, "format", "text", "Output format: text | json")

	root.AddCommand(cmd)
}

// DiffPolicyReport captures the full context of a diff operation for policy evaluation.
type DiffPolicyReport struct {
	Repo            string                 `json:"repo"`
	BaseRef         string                 `json:"baseRef"`
	TargetRef       string                 `json:"targetRef"`
	Changes         []compare.Change       `json:"changes"`
	Vulnerabilities []report.Vulnerability `json:"vulnerabilities"`
}

// runDiffAnalysis orchestrates dependency inventory collection for the base and
// target references, computes a dependency diff, and optionally queries OSV to
// enrich added/updated modules with vulnerability data.
func runDiffAnalysis(ctx context.Context, service *scan.Service, repoPath, baseRef, targetRef string, enableVulnScan bool, enrichLicenses bool, licenseSource string, publishedAfterStr, publishedBeforeStr, asOfStr string, ignoreUnfixed bool, showUnchanged bool, unchangedThreshold string, policyPaths []string, scanOpts inv.ScanOptions, matcher *inv.DependencyMatcher, debugMatcher bool, outputFormat string, outW io.Writer, errW io.Writer) error {
	ctx, span := otel.StartSpan(ctx, "deputy.diff",
		trace.WithAttributes(
			attribute.String("deputy.target.path", repoPath),
			attribute.String("deputy.diff.base_ref", baseRef),
			attribute.String("deputy.diff.target_ref", targetRef),
			attribute.Bool("deputy.diff.vuln_scan", enableVulnScan),
		))
	defer span.End()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if outW == nil {
		outW = io.Discard
	}
	if errW == nil {
		errW = io.Discard
	}
	if service == nil {
		service = scan.NewService()
	}

	// Validate and normalize output format early
	outputFormat = strings.ToLower(strings.TrimSpace(outputFormat))
	if outputFormat != "" && outputFormat != "text" && outputFormat != "json" {
		return fmt.Errorf("unsupported --format %q (use text|json)", outputFormat)
	}
	isJSON := outputFormat == "json"

	dispTarget := targetRef
	if isWorkingPseudoRef(targetRef) {
		dispTarget = "WORKING"
	}
	if !isJSON {
		doc := render.DiffHeaderDoc(baseRef, dispTarget)
		_ = doc.Render(outW, output.UIStyles())
	}

	// Check if dependency files have changed (optimization for non-working refs)
	if !isWorkingPseudoRef(targetRef) {
		changedFiles, err := gitx.CheckFilesChanged(repoPath, baseRef, targetRef)
		if err != nil {
			otel.SetSpanError(span, err)
			return fmt.Errorf("error checking files changed: %w", err)
		}

		if debugMatcher && !isJSON {
			renderMatcherDebug(outW, changedFiles, matcher)
		}

		if matcher != nil && !matcher.AnyMatch(changedFiles) {
			if isJSON {
				emptyReport := DiffPolicyReport{
					Repo:            repoPath,
					BaseRef:         baseRef,
					TargetRef:       targetRef,
					Changes:         []compare.Change{},
					Vulnerabilities: []report.Vulnerability{},
				}
				enc := json.NewEncoder(outW)
				enc.SetIndent("", "  ")
				otel.SetSpanOK(span)
				return enc.Encode(emptyReport)
			}
			fmt.Fprintln(outW, ui.StyleAdded.Render("No dependency changes detected."))
			otel.SetSpanOK(span)
			return nil
		}
	}

	// Open repository and resolve references
	repoSrc, err := repository.Open(repoPath)
	if err != nil {
		otel.SetSpanError(span, err)
		return fmt.Errorf("error opening Git repository at %s: %w\nMake sure you're running this from within a valid Git repository", repoPath, err)
	}
	defer repoSrc.Close()
	repo := repoSrc.Repo

	baseHash, err := gitx.ResolveRevisionEnhanced(repo, baseRef)
	if err != nil {
		otel.SetSpanError(span, err)
		suggestions := gitx.GetReferenceSuggestions(repo, baseRef)
		if len(suggestions) > 0 {
			return fmt.Errorf("error resolving base reference %q: %v\nDid you mean one of these?\n  %s", baseRef, err, strings.Join(suggestions, "\n  "))
		}
		return err
	}

	// Scan target packages
	var targetPackages []*extractor.Package
	var targetHash *plumbing.Hash

	if isWorkingPseudoRef(targetRef) {
		tp, err := inv.ScanPackagesWorking(ctx, repoSrc.Workspace, scanOpts)
		if err != nil {
			otel.SetSpanError(span, err)
			return fmt.Errorf("error scanning working tree packages: %w", err)
		}
		targetPackages = tp
	} else {
		th, err := gitx.ResolveRevisionEnhanced(repo, targetRef)
		if err != nil {
			otel.SetSpanError(span, err)
			suggestions := gitx.GetReferenceSuggestions(repo, targetRef)
			if len(suggestions) > 0 {
				return fmt.Errorf("error resolving target reference %q: %v\nDid you mean one of these?\n  %s", targetRef, err, strings.Join(suggestions, "\n  "))
			}
			return err
		}
		targetHash = th
	}

	// Scan base packages
	basePackages, err := inv.ScanPackagesAtCommitSnapshot(ctx, repo, *baseHash, scanOpts)
	if err != nil {
		otel.SetSpanError(span, err)
		return fmt.Errorf("error scanning base reference packages: %w", err)
	}

	// Scan target packages if not already done
	if targetPackages == nil && targetHash != nil {
		tp, err := inv.ScanPackagesAtCommitSnapshot(ctx, repo, *targetHash, scanOpts)
		if err != nil {
			otel.SetSpanError(span, err)
			return fmt.Errorf("error scanning target reference packages: %w", err)
		}
		targetPackages = tp
	}

	// Determine direct dependencies from target go.mod for accurate classification
	targetGoDirect := map[string]bool{"stdlib": true}
	var targetManifestRes scan.ManifestResolver
	switch {
	case isWorkingPseudoRef(targetRef):
		targetGoDirect = compare.CollectGoDirectModulesFromWorkspace(repoSrc.Workspace)
		targetManifestRes = scan.NewWorkspaceManifestResolver(repoSrc.Workspace)
	case targetHash != nil:
		if direct, err := compare.CollectGoDirectModulesFromCommit(repo, *targetHash); err == nil {
			targetGoDirect = direct
		}
		targetManifestRes = scan.NewGitManifestResolver(repo, *targetHash)
	default:
		// Fallback: use workspace for current state
		targetGoDirect = compare.CollectGoDirectModulesFromWorkspace(repoSrc.Workspace)
		targetManifestRes = scan.NewWorkspaceManifestResolver(repoSrc.Workspace)
	}

	targetPkgInputs := scan.PackagesToInputs(targetPackages, scan.PackageInputOptions{GoDirect: targetGoDirect, Resolver: targetManifestRes})

	baseGoDirect := map[string]bool{"stdlib": true}
	var baseManifestRes scan.ManifestResolver
	if isWorkingPseudoRef(baseRef) {
		baseGoDirect = compare.CollectGoDirectModulesFromWorkspace(repoSrc.Workspace)
		baseManifestRes = scan.NewWorkspaceManifestResolver(repoSrc.Workspace)
	} else {
		baseManifestRes = scan.NewGitManifestResolver(repo, *baseHash)
		if direct, err := compare.CollectGoDirectModulesFromCommit(repo, *baseHash); err == nil {
			baseGoDirect = direct
		}
	}

	basePkgInputs := scan.PackagesToInputs(basePackages, scan.PackageInputOptions{GoDirect: baseGoDirect, Resolver: baseManifestRes})
	pkgDirect := scan.MergeDirectMaps(scan.BuildPackageDirectMap(basePkgInputs), scan.BuildPackageDirectMap(targetPkgInputs))
	goDirect := mergeGoDirectMaps(baseGoDirect, targetGoDirect)
	manifestRes := targetManifestRes
	pkgInputs := targetPkgInputs

	// Collect main modules to exclude from comparison (the project itself shouldn't appear as a dependency)
	excludeMainModules := compare.CollectMainModulesFromWorkspace(repoSrc.Workspace)
	if baseHash != nil {
		if baseMains, err := compare.CollectMainModulesFromCommit(repo, *baseHash); err == nil {
			for mod := range baseMains {
				excludeMainModules[mod] = true
			}
		}
	}
	if targetHash != nil {
		if targetMains, err := compare.CollectMainModulesFromCommit(repo, *targetHash); err == nil {
			for mod := range targetMains {
				excludeMainModules[mod] = true
			}
		}
	}

	// Compare packages
	changes := compare.ComparePackagesWithOptions(basePackages, targetPackages, compare.CompareOptions{
		GoDirect:           goDirect,
		PkgDirect:          pkgDirect,
		ExcludeMainModules: excludeMainModules,
	})
	if len(changes) == 0 {
		if isJSON {
			emptyReport := DiffPolicyReport{
				Repo:            repoPath,
				BaseRef:         baseRef,
				TargetRef:       targetRef,
				Changes:         []compare.Change{},
				Vulnerabilities: []report.Vulnerability{},
			}
			enc := json.NewEncoder(outW)
			enc.SetIndent("", "  ")
			return enc.Encode(emptyReport)
		}
		fmt.Fprintln(outW, "No package changes detected.")
		otel.SetSpanOK(span)
		return nil
	}

	// Normalize license source
	licenseSource = flags.NormalizeLicenseSource(licenseSource)

	// Detailed dependency change rendering (legacy style) with optional enrichment
	// Skip text rendering in JSON mode
	if !isJSON {
		displayDetailedDependencyChanges(ctx, repoSrc.Workspace, changes, enrichLicenses, licenseSource, outW, errW)
	}

	// Scan for vulnerabilities if enabled
	if enableVulnScan {
		// Show progress indicator for interactive mode
		var progress *ui.Progress
		if ui.IsTTY(errW) && !isJSON {
			fmt.Fprintln(errW) // Visual spacing (cleared with spinner)
			progress = ui.NewProgress(errW, "Scanning for vulnerabilities")
			progress.Start(ctx)
		}

		inputs := pkgInputs
		if inputs == nil {
			inputs = scan.PackagesToInputs(targetPackages, scan.PackageInputOptions{GoDirect: goDirect, Resolver: manifestRes})
		}
		beforeT, afterT := flags.ParsePublishedFilters(errW, asOfStr, publishedBeforeStr, publishedAfterStr)
		result := service.ScanInputs(
			ctx,
			scan.Target{DisplayPath: repoPath, LocalPath: repoPath, Ref: targetRef, EffectiveRef: targetRef},
			targetPackages,
			pkgDirect,
			inputs,
			scan.Options{PublishedBefore: beforeT, PublishedAfter: afterT},
		)

		if progress != nil {
			progress.Clear()
			// Move cursor up to clear the blank line we added for spacing
			fmt.Fprint(errW, "\033[A\033[K")
		}

		for _, warning := range result.Warnings {
			fmt.Fprintf(errW, "Warning: %s\n", warning)
		}
		if ignoreUnfixed {
			result = scan.FilterUnfixed(result)
			fmt.Fprintf(errW, "  %s\n", ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
		}

		reportVulns := report.FlattenResult(result)

		policyReport := DiffPolicyReport{
			Repo:            repoPath,
			BaseRef:         baseRef,
			TargetRef:       targetRef,
			Changes:         changes,
			Vulnerabilities: reportVulns,
		}
		if err := runDiffPolicies(ctx, policyPaths, policyReport, errW); err != nil {
			otel.SetSpanError(span, err)
			return err
		}

		// JSON output mode
		if isJSON {
			enc := json.NewEncoder(outW)
			enc.SetIndent("", "  ")
			otel.SetSpanOK(span)
			return enc.Encode(policyReport)
		}

		changedVulns, unchangedVulns := splitVulnsByChange(reportVulns, changes)

		_, unchangedStats := consolidateReportVulnerabilities(unchangedVulns)

		// Decide whether to show unchanged set based on threshold
		showUnchangedEff := showUnchanged
		reason := ""
		if !showUnchangedEff {
			thr := strings.ToLower(strings.TrimSpace(unchangedThreshold))
			switch thr {
			case "", "critical":
				if unchangedStats.CriticalSev > 0 {
					showUnchangedEff = true
					reason = "Critical severity present"
				}
			case "high":
				if unchangedStats.CriticalSev+unchangedStats.HighSeverity > 0 {
					showUnchangedEff = true
					reason = ">= High severity present"
				}
			case "med", "medium", "moderate":
				if unchangedStats.CriticalSev+unchangedStats.HighSeverity+unchangedStats.MedSeverity > 0 {
					showUnchangedEff = true
					reason = ">= Medium severity present"
				}
			case "low":
				if unchangedStats.CriticalSev+unchangedStats.HighSeverity+unchangedStats.MedSeverity+unchangedStats.LowSeverity > 0 {
					showUnchangedEff = true
					reason = ">= Low severity present"
				}
			case "any", "all":
				if unchangedStats.UniqueVulns > 0 {
					showUnchangedEff = true
					reason = "Vulnerabilities present"
				}
			case "none", "off", "never":
				// never auto-show
			default:
				// fallback to critical if unknown value
				if unchangedStats.CriticalSev > 0 {
					showUnchangedEff = true
					reason = "Critical severity present"
				}
			}
		}

		// Combined cohesive output
		all := append([]report.Vulnerability{}, changedVulns...)
		if showUnchangedEff {
			all = append(all, unchangedVulns...)
		}

		_, changedCons := resultFromReportVulnerabilities(changedVulns)
		_, unchangedCons := resultFromReportVulnerabilities(unchangedVulns)

		if len(all) > 0 {
			fmt.Fprintln(outW)
			fmt.Fprintln(outW, ui.StyleDowngraded.Render("∴ ")+ui.StyleHeader.Render("Vulnerabilities"))
			render.VulnerabilityList(outW, changedCons, render.VulnerabilityDisplayOptions{})
			if showUnchangedEff && len(unchangedVulns) > 0 {
				// Visual separator for unchanged dependencies, include reason if any
				title := "Unchanged dependencies"
				if reason != "" {
					title += " (" + reason + ")"
				}
				sep := ui.StyleDim.Render(strings.Repeat("─", 3) + " " + title + " " + strings.Repeat("─", 3))
				fmt.Fprintln(outW)
				fmt.Fprintln(outW, sep)
				render.VulnerabilityList(outW, unchangedCons, render.VulnerabilityDisplayOptions{})
			}
		}
		allResult, allCons := resultFromReportVulnerabilities(all)

		// Handle the case where there are hidden unchanged vulnerabilities
		if len(all) == 0 && len(unchangedVulns) > 0 {
			// Don't say "No vulnerabilities found" when there ARE vulnerabilities, just hidden
			fmt.Fprintln(outW)
			fmt.Fprintf(outW, "%s No vulnerabilities in changed dependencies\n",
				ui.StyleAdded.Render("✓"))
			fmt.Fprintf(outW, "  %s %d vulnerabilities in unchanged dependencies (use %s to see)\n",
				ui.StyleMeta.Render("→"),
				len(unchangedVulns),
				ui.StyleSymbol.Render("--show-unchanged"))
		} else {
			render.VulnerabilitySummaryAndActions(outW, allCons, allResult.Stats)
		}
		otel.SetSpanOK(span)
		return nil
	}

	// No vulnerability scanning - output changes only
	if isJSON {
		noVulnReport := DiffPolicyReport{
			Repo:            repoPath,
			BaseRef:         baseRef,
			TargetRef:       targetRef,
			Changes:         changes,
			Vulnerabilities: []report.Vulnerability{},
		}
		enc := json.NewEncoder(outW)
		enc.SetIndent("", "  ")
		otel.SetSpanOK(span)
		return enc.Encode(noVulnReport)
	}

	// Display results (no vulnerabilities scanned)
	render.DisplayVulnerabilities(outW, scan.Result{})
	otel.SetSpanOK(span)
	return nil
}

// isWorkingPseudoRef reports whether the provided reference token should be
// treated as the current working tree (including uncommitted changes) rather
// than a resolved commit object.
func isWorkingPseudoRef(s string) bool {
	t := strings.TrimSpace(s)
	if t == "." {
		return true
	}
	u := strings.ToUpper(t)
	return u == "WORKING" || u == "WORKTREE" || u == "WT"
}

// licenseScanConcurrency determines the number of concurrent license scans to run.
// It respects the DEPUTY_LICENSE_SCAN_CONCURRENCY environment variable if set.
func licenseScanConcurrency(total int) int {
	if total <= 0 {
		return 1
	}
	if v := strings.TrimSpace(os.Getenv("DEPUTY_LICENSE_SCAN_CONCURRENCY")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > total {
				n = total
			}
			return n
		}
	}
	parallel := runtime.NumCPU() * 4
	if parallel < 8 {
		parallel = 8
	}
	if parallel > total {
		parallel = total
	}
	return parallel
}

// displayDetailedDependencyChanges renders dependency changes with symbols, arrows,
// license lookups via deps.dev and a concise summary similar to the original tool output.
func displayDetailedDependencyChanges(ctx context.Context, ws workspace.FS, changes []compare.Change, enrich bool, licenseSource string, outW io.Writer, errW io.Writer) {
	if len(changes) == 0 {
		return
	}
	fmt.Fprintln(outW)
	fmt.Fprintln(outW, ui.StyleHeader.Render("Dependency Changes:"))

	// Open deps.dev gRPC client (best‑effort). Failures degrade gracefully.
	var client pb.InsightsClient
	if certPool, err := x509.SystemCertPool(); err == nil {
		if conn, err := grpc.NewClient("api.deps.dev:443", grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(certPool, ""))); err == nil {
			client = pb.NewInsightsClient(conn)
			// closing conn when context done (fire and forget) – rely on GC otherwise
			go func() { <-ctx.Done(); _ = conn.Close() }()
		}
	}

	// Pre-fetch deps.dev licenses in parallel when requested
	type pkgKey struct {
		ecosystem string
		name      string
		version   string
	}
	resolveEcosystem := func(raw string) string {
		eco := strings.ToLower(strings.TrimSpace(raw))
		if eco == "" {
			return "go"
		}
		return eco
	}
	licMap := map[pkgKey][]string{}
	if client != nil && enrich && (licenseSource == flags.LicenseSourceDepsDev || licenseSource == flags.LicenseSourceBoth) {
		var mu sync.Mutex
		g, gctx := errgroup.WithContext(ctx)
		for _, c := range changes {
			if c.ChangeType == compare.Removed || c.TargetVersion == "" {
				continue
			}
			pk := pkgKey{ecosystem: resolveEcosystem(c.Ecosystem), name: c.Name, version: c.TargetVersion}
			if _, ok := licMap[pk]; ok {
				continue
			}
			pkCopy := pk
			g.Go(func() error {
				l := license.FetchLicensesForEcosystem(gctx, depsClient{client}, pkCopy.ecosystem, pkCopy.name, pkCopy.version)
				mu.Lock()
				licMap[pkCopy] = l
				mu.Unlock()
				return nil
			})
		}
		_ = g.Wait()
	}

	var localScan []string
	if enrich && (licenseSource == flags.LicenseSourceScan || licenseSource == flags.LicenseSourceBoth) {
		localScan = license.LocalRepoLicenseScan(ws)
	}

	var remoteFetchers map[pkgKey]chan []string
	var remoteCache map[pkgKey][]string
	var remoteTasks []pkgKey
	if enrich && (licenseSource == flags.LicenseSourceScan || licenseSource == flags.LicenseSourceBoth) {
		required := map[pkgKey]struct{}{}
		for _, c := range changes {
			if c.ChangeType == compare.Removed || c.TargetVersion == "" {
				continue
			}
			pk := pkgKey{ecosystem: resolveEcosystem(c.Ecosystem), name: c.Name, version: c.TargetVersion}
			if _, ok := required[pk]; ok {
				continue
			}
			required[pk] = struct{}{}
		}
		if len(required) > 0 {
			remoteFetchers = make(map[pkgKey]chan []string, len(required))
			remoteCache = make(map[pkgKey][]string, len(required))
			remoteTasks = make([]pkgKey, 0, len(required))
			seen := map[pkgKey]struct{}{}
			for _, c := range changes {
				if c.ChangeType == compare.Removed || c.TargetVersion == "" {
					continue
				}
				pk := pkgKey{ecosystem: resolveEcosystem(c.Ecosystem), name: c.Name, version: c.TargetVersion}
				if _, ok := seen[pk]; ok {
					continue
				}
				seen[pk] = struct{}{}
				ch := make(chan []string, 1)
				remoteFetchers[pk] = ch
				remoteTasks = append(remoteTasks, pk)
			}
			concurrency := licenseScanConcurrency(len(remoteTasks))
			if concurrency < 1 {
				concurrency = 1
			}
			sem := make(chan struct{}, concurrency)
			for _, task := range remoteTasks {
				t := task
				ch := remoteFetchers[t]
				go func() {
					defer close(ch)
					select {
					case sem <- struct{}{}:
					case <-ctx.Done():
						return
					}
					defer func() { <-sem }()
					lics := license.LookupLicensesBestEffort(ctx, t.ecosystem, t.name, t.version)
					ch <- lics
				}()
			}
		}
	}

	// Counters
	var addedN, removedN, updatedN, upgradedN, downgradedN int

	for _, c := range changes {
		// Build the license and direct/indirect annotation in the new format: [License1, License2] (direct/indirect)
		pk := pkgKey{ecosystem: resolveEcosystem(c.Ecosystem), name: c.Name, version: c.TargetVersion}
		licenses := []string{"?"}
		if l, ok := licMap[pk]; ok && len(l) > 0 {
			licenses = l
		}
		if c.ChangeType != compare.Removed && c.TargetVersion != "" && enrich && (licenseSource == flags.LicenseSourceScan || licenseSource == flags.LicenseSourceBoth) {
			if len(localScan) > 0 {
				licenses = license.MergeLicenseSources(licenses, localScan)
			}
			if remoteFetchers != nil {
				switch {
				case remoteCache[pk] != nil:
					licenses = license.MergeLicenseSources(licenses, remoteCache[pk])
				case remoteFetchers[pk] != nil:
					ch := remoteFetchers[pk]
					select {
					case rc, ok := <-ch:
						if ok && len(rc) > 0 {
							remoteCache[pk] = rc
							licenses = license.MergeLicenseSources(licenses, rc)
						} else {
							remoteCache[pk] = nil
						}
					case <-ctx.Done():
						remoteCache[pk] = nil
					}
				}
			}
		}

		// Format the combined license and direct/indirect annotation
		var licAndDepStr string
		directness := "(indirect)"
		if c.IsDirect {
			directness = "(direct)"
		}

		if len(licenses) > 0 && licenses[0] != "?" {
			licenseStr := strings.Join(licenses, ", ")
			licAndDepStr = ui.StyleLicense.Render("["+licenseStr+"]") + " " + ui.StyleVersion.Render(directness)
		} else {
			// If no licenses are available, just show the directness
			licAndDepStr = ui.StyleVersion.Render(directness)
		}

		switch c.ChangeType {
		case compare.Added:
			fmt.Fprintf(outW, "  %s %s @ %s %s\n", ui.StyleAdded.Render("+"), ui.StyleAdded.Render(c.Name), ui.StyleVersion.Render(c.TargetVersion), licAndDepStr)
			addedN++
		case compare.Removed:
			// For removed dependencies, we don't have target version license info, so just show directness
			removedDirectness := "(indirect)"
			if c.IsDirect {
				removedDirectness = "(direct)"
			}
			fmt.Fprintf(outW, "  %s %s @ %s %s\n", ui.StyleRemoved.Render("-"), ui.StyleRemoved.Render(c.Name), ui.StyleVersion.Render(c.BaseVersion), ui.StyleVersion.Render(removedDirectness))
			removedN++
		case compare.Upgraded:
			updatedN++
			upgradedN++
			oldNamePart := ""
			if c.OldName != "" && c.OldName != c.Name {
				oldNamePart = ui.StyleDim.Render(c.OldName) + " " + ui.StyleUpdateArrow.Render("→ ")
			}
			fmt.Fprintf(outW, "  %s %s%s @ %s %s %s %s\n", ui.StyleUpgraded.Render("↑"), oldNamePart, ui.StyleBold.Render(c.Name), ui.StyleVersion.Render(c.BaseVersion), ui.StyleUpdateArrow.Render("→"), ui.StyleVersion.Render(c.TargetVersion), licAndDepStr)
		case compare.Downgraded:
			updatedN++
			downgradedN++
			oldNamePart := ""
			if c.OldName != "" && c.OldName != c.Name {
				oldNamePart = ui.StyleDim.Render(c.OldName) + " " + ui.StyleDowngradeArrow.Render("→ ")
			}
			fmt.Fprintf(outW, "  %s %s%s @ %s %s %s %s\n", ui.StyleDowngraded.Render("↓"), oldNamePart, ui.StyleBold.Render(c.Name), ui.StyleVersion.Render(c.BaseVersion), ui.StyleDowngradeArrow.Render("→"), ui.StyleVersion.Render(c.TargetVersion), licAndDepStr)
		case compare.Updated:
			updatedN++
			arrowStyle := ui.StyleUpdateArrow
			symbol := ui.StyleNeutral.Render("~")
			oldNamePart := ""
			if c.OldName != "" && c.OldName != c.Name {
				oldNamePart = ui.StyleDim.Render(c.OldName) + " " + arrowStyle.Render("→ ")
			}
			fmt.Fprintf(outW, "  %s %s%s @ %s %s %s %s\n", symbol, oldNamePart, ui.StyleBold.Render(c.Name), ui.StyleVersion.Render(c.BaseVersion), arrowStyle.Render("→"), ui.StyleVersion.Render(c.TargetVersion), licAndDepStr)
		}
	}

	fmt.Fprintln(outW)
	fmt.Fprintln(outW, ui.StyleHeader.Render("Summary:"))
	if addedN > 0 {
		fmt.Fprintf(outW, "  %s %d package%s added\n", ui.StyleAdded.Render("+"), addedN, plural(addedN))
	}
	if removedN > 0 {
		fmt.Fprintf(outW, "  %s %d package%s removed\n", ui.StyleRemoved.Render("-"), removedN, plural(removedN))
	}
	if updatedN > 0 {
		if upgradedN > 0 {
			fmt.Fprintf(outW, "  %s %d package%s upgraded\n", ui.StyleUpgraded.Render("↑"), upgradedN, plural(upgradedN))
		}
		if downgradedN > 0 {
			fmt.Fprintf(outW, "  %s %d package%s downgraded\n", ui.StyleDowngraded.Render("↓"), downgradedN, plural(downgradedN))
		}
		other := updatedN - (upgradedN + downgradedN)
		if other > 0 {
			fmt.Fprintf(outW, "  %s %d package%s changed\n", ui.StyleNeutral.Render("~"), other, plural(other))
		}
	}
}

// splitVulnsByChange partitions vulnerabilities into those affecting changed
// dependencies versus those in unchanged modules. Changes marked as Added,
// Updated, Upgraded, or Downgraded are treated as "changed" for classification
// purposes.
func splitVulnsByChange(vulns []report.Vulnerability, changes []compare.Change) (changed, unchanged []report.Vulnerability) {
	if len(vulns) == 0 {
		return nil, nil
	}
	changedSet := map[string]bool{}
	for _, c := range changes {
		switch c.ChangeType {
		case compare.Added, compare.Updated, compare.Upgraded, compare.Downgraded:
			// treat as changed
		default:
			continue
		}
		info := compare.ParseGoPackage(&extractor.Package{Name: c.Name})
		changedSet[info.CanonicalName] = true
	}
	for _, v := range vulns {
		info := compare.ParseGoPackage(&extractor.Package{Name: v.Package})
		if changedSet[info.CanonicalName] {
			changed = append(changed, v)
		} else {
			unchanged = append(unchanged, v)
		}
	}
	return changed, unchanged
}

func resultFromReportVulnerabilities(vulns []report.Vulnerability) (scan.Result, []vulnerability.Consolidated) {
	if len(vulns) == 0 {
		return scan.Result{}, nil
	}
	findings, advisories := report.SplitVulnerabilities(vulns)
	cons := vulnerability.Consolidate(findings, advisories)
	stats := vulnerability.StatsFromConsolidated(cons, len(findings))
	return scan.Result{
		Findings:   findings,
		Advisories: advisories,
		Stats:      stats,
	}, cons
}

func consolidateReportVulnerabilities(vulns []report.Vulnerability) ([]vulnerability.Consolidated, vulnerability.Stats) {
	result, cons := resultFromReportVulnerabilities(vulns)
	return cons, result.Stats
}

// depsClient adapts a deps.dev InsightsClient to the internal analysis.DepsClient interface.
type depsClient struct{ pb.InsightsClient }

func (d depsClient) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
	return d.InsightsClient.GetVersion(ctx, req)
}

// plural returns "s" if n is not 1, otherwise empty string.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// renderMatcherDebug prints a human-friendly breakdown of which changed files
// were considered dependency-related by the matcher when --debug-matcher is
// enabled.
func renderMatcherDebug(w io.Writer, files []string, matcher *inv.DependencyMatcher) {
	fmt.Fprintln(w, ui.StyleMeta.Render("Matcher debug (changed files considered by dependency scanner):"))
	if len(files) == 0 {
		fmt.Fprintln(w, "  (no changed files detected between refs)")
		return
	}
	if matcher == nil {
		for _, f := range files {
			fmt.Fprintf(w, "  ? %s\n", f)
		}
		fmt.Fprintln(w, "  (matcher unavailable; treating all files as potential dependency changes)")
		return
	}
	for _, f := range files {
		if matcher.Matches(f) {
			fmt.Fprintf(w, "  %s %s\n", ui.StyleAdded.Render("+match"), f)
		} else {
			fmt.Fprintf(w, "  %s %s\n", ui.StyleDim.Render("-skip"), f)
		}
	}
}

// mergeGoDirectMaps combines multiple direct dependency maps into one.
func mergeGoDirectMaps(maps ...map[string]bool) map[string]bool {
	merged := map[string]bool{"stdlib": true}
	for _, m := range maps {
		for module, direct := range m {
			if direct {
				merged[module] = true
			}
		}
	}
	return merged
}

// runDiffPolicies evaluates the configured policies against the diff report.
func runDiffPolicies(ctx context.Context, policyPaths []string, report DiffPolicyReport, errW io.Writer) error {
	if len(policyPaths) == 0 {
		return nil
	}
	reportMap, err := structToMap(report)
	if err != nil {
		return err
	}
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, reportMap, "diff", policy.EntrypointDiffReport, errW); err != nil {
		return err
	}
	for _, change := range report.Changes {
		changeMap, err := structToMap(change)
		if err != nil {
			return err
		}
		payload := map[string]any{
			"repo":      report.Repo,
			"baseRef":   report.BaseRef,
			"targetRef": report.TargetRef,
			"change":    changeMap,
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "diff", policy.EntrypointDiffDependencyChange, errW); err != nil {
			return err
		}
	}
	for _, vuln := range report.Vulnerabilities {
		vulnMap, err := structToMap(vuln)
		if err != nil {
			return err
		}
		payload := map[string]any{
			"repo":          report.Repo,
			"baseRef":       report.BaseRef,
			"targetRef":     report.TargetRef,
			"vulnerability": vulnMap,
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "diff", policy.EntrypointDiffVulnerability, errW); err != nil {
			return err
		}
	}
	return nil
}
