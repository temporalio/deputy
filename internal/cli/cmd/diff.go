package cmd

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "deps.dev/api/v3"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	analysis "github.com/picatz/deputy/internal/analysis"
	cmp "github.com/picatz/deputy/internal/compare"
	gitx "github.com/picatz/deputy/internal/gitutil"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"osv.dev/bindings/go/osvdev"
)

// AddDiffCommand registers the diff subcommand which compares dependency
// inventories between two Git references (or working tree) and optionally
// performs vulnerability scanning on changed modules.
func AddDiffCommand(root *cobra.Command) {
	var repoPath string
	var skipVulnScan bool
	var useLicenseCheck bool
	var enrichLicenses bool
	var licenseSource string
	var publishedBeforeStr, publishedAfterStr, asOfStr string
	var ignoreUnfixed bool
	var showUnchanged bool
	var unchangedThreshold string
	var ecosystems []string
	var debugMatcher bool
	var policyPaths []string

	cmd := &cobra.Command{
		Use:   "diff [base] [target]",
		Short: "Compare dependency changes between Git references",
		Long: `Compare dependencies between Git references with comprehensive vulnerability analysis.

DEPENDENCY CHANGE ANALYSIS:
Analyzes differences in Go module dependencies between two Git references, including:
• Added dependencies (new packages introduced)  
• Removed dependencies (packages no longer used)
• Updated dependencies (version changes)
• Direct vs indirect dependency classification

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
			repo := repoPath
			if repo == "" {
				var err error
				repo, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
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
			return runDiffAnalysis(cmd.Context(), repo, baseRef, targetRef, !skipVulnScan, useLicenseCheck, enrichLicenses, licenseSource, publishedAfterStr, publishedBeforeStr, asOfStr, ignoreUnfixed, showUnchanged, unchangedThreshold, policyPaths, scanOpts, matcher, debugMatcher, cmd.ErrOrStderr())
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
	cmd.Flags().BoolVar(&useLicenseCheck, "use-licensecheck", false, "(Deprecated) Alias for --licenses --license-source=scan")
	cmd.Flags().BoolVar(&enrichLicenses, "licenses", false, "Include license information for changed dependencies")
	cmd.Flags().StringVar(&licenseSource, "license-source", "depsdev", "License information source: depsdev | scan | both")
	cmd.Flags().StringVar(&publishedBeforeStr, "published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	cmd.Flags().StringVar(&publishedAfterStr, "published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	cmd.Flags().StringVar(&asOfStr, "as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	cmd.Flags().BoolVar(&ignoreUnfixed, "ignore-unfixed", false, "Ignore vulnerabilities without fixes in diff scan output")
	cmd.Flags().BoolVar(&showUnchanged, "show-unchanged", false, "Always show vulnerabilities in unchanged dependencies (overrides quiet behavior)")
	cmd.Flags().StringVar(&unchangedThreshold, "unchanged-threshold", "critical", "Auto-show unchanged vulns at or above this severity: none|low|med|high|critical|any")
	cmd.Flags().StringSliceVar(&ecosystems, "ecosystems", []string{"all"}, "Ecosystems to include when scanning (default: all supported)")
	cmd.Flags().BoolVar(&debugMatcher, "debug-matcher", false, "Print which changed files were considered dependency manifests/lockfiles")
	cmd.Flags().StringArrayVar(&policyPaths, "policy", nil, "Path to CEL policy files or bundles to evaluate against diff results (repeatable)")

	root.AddCommand(cmd)
}

// DiffPolicyReport captures the full context of a diff operation for policy evaluation.
type DiffPolicyReport struct {
	Repo            string                   `json:"repo"`
	BaseRef         string                   `json:"baseRef"`
	TargetRef       string                   `json:"targetRef"`
	Changes         []cmp.Change             `json:"changes"`
	Vulnerabilities []analysis.Vulnerability `json:"vulnerabilities"`
}

// runDiffAnalysis orchestrates dependency inventory collection for the base and
// target references, computes a dependency diff, and optionally queries OSV to
// enrich added/updated modules with vulnerability data.
func runDiffAnalysis(ctx context.Context, repoPath, baseRef, targetRef string, enableVulnScan bool, useLicenseCheck bool, enrichLicenses bool, licenseSource string, publishedAfterStr, publishedBeforeStr, asOfStr string, ignoreUnfixed bool, showUnchanged bool, unchangedThreshold string, policyPaths []string, scanOpts inv.ScanOptions, matcher *inv.DependencyMatcher, debugMatcher bool, errW io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if errW == nil {
		errW = os.Stderr
	}

	dispTarget := targetRef
	if isWorkingPseudoRef(targetRef) {
		dispTarget = "WORKING"
	}
	fmt.Printf("Comparing dependencies: %s → %s\n", baseRef, dispTarget)

	// Check if dependency files have changed (optimization for non-working refs)
	if !isWorkingPseudoRef(targetRef) {
		changedFiles, err := gitx.CheckFilesChanged(repoPath, baseRef, targetRef)
		if err != nil {
			return fmt.Errorf("error checking files changed: %w", err)
		}

		if debugMatcher {
			renderMatcherDebug(changedFiles, matcher)
		}

		if matcher != nil && !matcher.AnyMatch(changedFiles) {
			fmt.Println("No dependency changes detected.")
			return nil
		}
	}

	// Open repository and resolve references
	repoSrc, err := repository.Open(repoPath)
	if err != nil {
		return fmt.Errorf("error opening Git repository at %s: %w\nMake sure you're running this from within a valid Git repository", repoPath, err)
	}
	defer repoSrc.Close()
	repo := repoSrc.Repo

	baseHash, err := gitx.ResolveRevisionEnhanced(repo, baseRef)
	if err != nil {
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
		fmt.Println("Scanning packages in working tree...")
		tp, err := inv.ScanPackagesWorking(ctx, repoSrc.Workspace, scanOpts)
		if err != nil {
			return fmt.Errorf("error scanning working tree packages: %w", err)
		}
		targetPackages = tp
	} else {
		th, err := gitx.ResolveRevisionEnhanced(repo, targetRef)
		if err != nil {
			suggestions := gitx.GetReferenceSuggestions(repo, targetRef)
			if len(suggestions) > 0 {
				return fmt.Errorf("error resolving target reference %q: %v\nDid you mean one of these?\n  %s", targetRef, err, strings.Join(suggestions, "\n  "))
			}
			return err
		}
		targetHash = th
	}

	// Scan base packages
	fmt.Printf("Scanning packages in base reference %s...\n", baseHash.String()[:7])
	basePackages, err := inv.ScanPackagesAtCommitSnapshot(ctx, repo, *baseHash, scanOpts)
	if err != nil {
		return fmt.Errorf("error scanning base reference packages: %w", err)
	}

	// Scan target packages if not already done
	if targetPackages == nil && targetHash != nil {
		fmt.Printf("Scanning packages in target reference %s...\n", targetHash.String()[:7])
		tp, err := inv.ScanPackagesAtCommitSnapshot(ctx, repo, *targetHash, scanOpts)
		if err != nil {
			return fmt.Errorf("error scanning target reference packages: %w", err)
		}
		targetPackages = tp
	}

	// Determine direct dependencies from target go.mod for accurate classification
	targetGoDirect := map[string]bool{"stdlib": true}
	var targetManifestRes manifestResolver
	if isWorkingPseudoRef(targetRef) {
		if repoSrc != nil {
			targetGoDirect = cmp.CollectGoDirectModulesFromWorkspace(repoSrc.Workspace)
			targetManifestRes = workspaceManifestResolver{ws: repoSrc.Workspace}
		} else {
			targetGoDirect = cmp.CollectGoDirectModulesFromDisk(repoPath)
			targetManifestRes = osManifestResolver(repoPath)
		}
	} else if targetHash != nil {
		if direct, err := cmp.CollectGoDirectModulesFromCommit(repo, *targetHash); err == nil {
			targetGoDirect = direct
		}
		targetManifestRes = gitManifestResolver{repo: repo, hash: *targetHash}
	} else {
		targetManifestRes = osManifestResolver(repoPath)
	}

	targetPkgInputs := packagesToInputs(targetPackages, packageInputOptions{GoDirect: targetGoDirect, Resolver: targetManifestRes})

	baseGoDirect := map[string]bool{"stdlib": true}
	var baseManifestRes manifestResolver
	if isWorkingPseudoRef(baseRef) {
		if repoSrc != nil {
			baseGoDirect = cmp.CollectGoDirectModulesFromWorkspace(repoSrc.Workspace)
			baseManifestRes = workspaceManifestResolver{ws: repoSrc.Workspace}
		} else {
			baseGoDirect = cmp.CollectGoDirectModulesFromDisk(repoPath)
			baseManifestRes = osManifestResolver(repoPath)
		}
	} else {
		baseManifestRes = gitManifestResolver{repo: repo, hash: *baseHash}
		if direct, err := cmp.CollectGoDirectModulesFromCommit(repo, *baseHash); err == nil {
			baseGoDirect = direct
		}
	}

	basePkgInputs := packagesToInputs(basePackages, packageInputOptions{GoDirect: baseGoDirect, Resolver: baseManifestRes})
	pkgDirect := mergeDirectMaps(buildPackageDirectMap(basePkgInputs), buildPackageDirectMap(targetPkgInputs))
	goDirect := mergeGoDirectMaps(baseGoDirect, targetGoDirect)
	manifestRes := targetManifestRes
	pkgInputs := targetPkgInputs

	// Compare packages
	changes := cmp.ComparePackages(basePackages, targetPackages, goDirect, pkgDirect, nil)
	if len(changes) == 0 {
		fmt.Println("No package changes detected.")
		return nil
	}

	// Determine enrichment modes
	if useLicenseCheck && !enrichLicenses { // backward compatibility
		enrichLicenses = true
		if licenseSource == "depsdev" {
			licenseSource = "scan"
		}
	}

	// Detailed dependency change rendering (legacy style) with optional enrichment
	displayDetailedDependencyChanges(ctx, repoSrc.Workspace, changes, enrichLicenses, licenseSource)

	// Scan for vulnerabilities if enabled
	var vulns []analysis.Vulnerability
	if enableVulnScan {
		fmt.Printf("\nScanning dependencies for vulnerabilities...\n")

		inputs := pkgInputs
		if inputs == nil {
			inputs = packagesToInputs(targetPackages, packageInputOptions{GoDirect: goDirect, Resolver: manifestRes})
		}
		vv, err := analysis.QueryOSVBatch(ctx, osvdev.DefaultClient(), inputs)
		if err != nil {
			fmt.Printf("Warning: Vulnerability scanning failed: %v\n", err)
		} else {
			vulns = vv
		}

		// Historical filtering
		var beforeT, afterT time.Time
		if asOfStr != "" {
			if t, err := analysis.ParseFlexibleDate(asOfStr, "asof"); err == nil {
				beforeT = t
			} else {
				fmt.Printf("Warning: could not parse --as-of date %q: %v\n", asOfStr, err)
			}
		}
		if publishedBeforeStr != "" && beforeT.IsZero() {
			if t, err := analysis.ParseFlexibleDate(publishedBeforeStr, "before"); err == nil {
				beforeT = t
			} else {
				fmt.Printf("Warning: could not parse --published-before %q: %v\n", publishedBeforeStr, err)
			}
		}
		if publishedAfterStr != "" {
			if t, err := analysis.ParseFlexibleDate(publishedAfterStr, "after"); err == nil {
				afterT = t
			} else {
				fmt.Printf("Warning: could not parse --published-after %q: %v\n", publishedAfterStr, err)
			}
		}
		if !beforeT.IsZero() || !afterT.IsZero() {
			vulns = analysis.FilterVulnerabilitiesByPublished(vulns, afterT, beforeT)
		}

		policyVulns := vulns
		if ignoreUnfixed {
			policyVulns = filterUnfixed(vulns)
		}

		report := DiffPolicyReport{
			Repo:            repoPath,
			BaseRef:         baseRef,
			TargetRef:       targetRef,
			Changes:         changes,
			Vulnerabilities: policyVulns,
		}
		if err := runDiffPolicies(ctx, policyPaths, report, errW); err != nil {
			return err
		}

		changedVulns, unchangedVulns := splitVulnsByChange(vulns, changes)

		// Optional: ignore unfixed across both sets
		if ignoreUnfixed {
			changedVulns = filterUnfixed(changedVulns)
			unchangedVulns = filterUnfixed(unchangedVulns)
			fmt.Printf("  %s\n", ui.StyleMeta.Render("Note: ignoring unfixed vulnerabilities (--ignore-unfixed)"))
		}

		// Decide whether to show unchanged set based on threshold
		showUnchangedEff := showUnchanged
		reason := ""
		if !showUnchangedEff {
			stats := analysis.CategorizeVulnerabilities(unchangedVulns)
			thr := strings.ToLower(strings.TrimSpace(unchangedThreshold))
			switch thr {
			case "", "critical":
				if stats.CriticalSev > 0 {
					showUnchangedEff = true
					reason = "Critical severity present"
				}
			case "high":
				if stats.CriticalSev+stats.HighSeverity > 0 {
					showUnchangedEff = true
					reason = ">= High severity present"
				}
			case "med", "medium", "moderate":
				if stats.CriticalSev+stats.HighSeverity+stats.MedSeverity > 0 {
					showUnchangedEff = true
					reason = ">= Medium severity present"
				}
			case "low":
				if stats.CriticalSev+stats.HighSeverity+stats.MedSeverity+stats.LowSeverity > 0 {
					showUnchangedEff = true
					reason = ">= Low severity present"
				}
			case "any", "all":
				if stats.UniqueVulns > 0 {
					showUnchangedEff = true
					reason = "Vulnerabilities present"
				}
			case "none", "off", "never":
				// never auto-show
			default:
				// fallback to critical if unknown value
				if stats.CriticalSev > 0 {
					showUnchangedEff = true
					reason = "Critical severity present"
				}
			}
		}

		// Combined cohesive output
		fmt.Println("\n" + ui.StyleDowngraded.Render("∴ ") + ui.StyleHeader.Render("Vulnerabilities"))
		RenderVulnerabilityList(changedVulns)
		if showUnchangedEff && len(unchangedVulns) > 0 {
			// Visual separator for unchanged dependencies, include reason if any
			title := "Unchanged dependencies"
			if reason != "" {
				title += " (" + reason + ")"
			}
			sep := ui.StyleDim.Render(strings.Repeat("─", 3) + " " + title + " " + strings.Repeat("─", 3))
			fmt.Println("\n" + sep)
			RenderVulnerabilityList(unchangedVulns)
		}
		all := append([]analysis.Vulnerability{}, changedVulns...)
		if showUnchangedEff {
			all = append(all, unchangedVulns...)
		}
		RenderVulnerabilitySummaryAndActions(all)
		return nil
	}

	// Display results (no vulnerabilities scanned)
	DisplayVulnerabilities(vulns)
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
func displayDetailedDependencyChanges(ctx context.Context, ws workspace.FS, changes []cmp.Change, enrich bool, licenseSource string) {
	if len(changes) == 0 {
		return
	}
	fmt.Printf("\n%s\n", ui.StyleHeader.Render("Dependency Changes:"))

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
	type pkgKey struct{ name, version string }
	licMap := map[pkgKey][]string{}
	if client != nil && enrich && (licenseSource == "depsdev" || licenseSource == "both") {
		var mu sync.Mutex
		g, gctx := errgroup.WithContext(ctx)
		for _, c := range changes {
			if c.ChangeType == cmp.Removed || c.TargetVersion == "" {
				continue
			}
			pk := pkgKey{c.Name, c.TargetVersion}
			if _, ok := licMap[pk]; ok {
				continue
			}
			pkCopy := pk
			g.Go(func() error {
				l := analysis.FetchLicensesForPackage(gctx, depsClient{client}, pkCopy.name, pkCopy.version)
				mu.Lock()
				licMap[pkCopy] = l
				mu.Unlock()
				return nil
			})
		}
		_ = g.Wait()
	}

	var localScan []string
	if enrich && (licenseSource == "scan" || licenseSource == "both") {
		localScan = analysis.LocalRepoLicenseScan(ws)
	}

	var remoteFetchers map[pkgKey]chan []string
	var remoteCache map[pkgKey][]string
	var remoteTasks []struct {
		pk      pkgKey
		name    string
		version string
	}
	if enrich && (licenseSource == "scan" || licenseSource == "both") {
		required := map[pkgKey]struct{}{}
		for _, c := range changes {
			if c.ChangeType == cmp.Removed || c.TargetVersion == "" {
				continue
			}
			pk := pkgKey{c.Name, c.TargetVersion}
			if _, ok := required[pk]; ok {
				continue
			}
			required[pk] = struct{}{}
		}
		if len(required) > 0 {
			remoteFetchers = make(map[pkgKey]chan []string, len(required))
			remoteCache = make(map[pkgKey][]string, len(required))
			remoteTasks = make([]struct {
				pk      pkgKey
				name    string
				version string
			}, 0, len(required))
			seen := map[pkgKey]struct{}{}
			for _, c := range changes {
				if c.ChangeType == cmp.Removed || c.TargetVersion == "" {
					continue
				}
				pk := pkgKey{c.Name, c.TargetVersion}
				if _, ok := seen[pk]; ok {
					continue
				}
				seen[pk] = struct{}{}
				ch := make(chan []string, 1)
				remoteFetchers[pk] = ch
				remoteTasks = append(remoteTasks, struct {
					pk      pkgKey
					name    string
					version string
				}{pk: pk, name: c.Name, version: c.TargetVersion})
			}
			concurrency := licenseScanConcurrency(len(remoteTasks))
			if concurrency < 1 {
				concurrency = 1
			}
			sem := make(chan struct{}, concurrency)
			for _, task := range remoteTasks {
				t := task
				ch := remoteFetchers[t.pk]
				go func() {
					defer close(ch)
					select {
					case sem <- struct{}{}:
					case <-ctx.Done():
						return
					}
					defer func() { <-sem }()
					lics := analysis.RemoteModuleLicenseScan(ctx, t.name, t.version)
					ch <- lics
				}()
			}
		}
	}

	// Counters
	var addedN, removedN, updatedN, upgradedN, downgradedN int

	for _, c := range changes {
		// Build the license and direct/indirect annotation in the new format: [License1, License2] (direct/indirect)
		licenses := []string{"?"}
		if l, ok := licMap[pkgKey{c.Name, c.TargetVersion}]; ok && len(l) > 0 {
			licenses = l
		}
		if c.ChangeType != cmp.Removed && c.TargetVersion != "" && enrich && (licenseSource == "scan" || licenseSource == "both") {
			if len(localScan) > 0 {
				licenses = analysis.MergeLicenseSources(licenses, localScan)
			}
			if remoteFetchers != nil {
				pk := pkgKey{c.Name, c.TargetVersion}
				if rc, ok := remoteCache[pk]; ok {
					if len(rc) > 0 {
						licenses = analysis.MergeLicenseSources(licenses, rc)
					}
				} else if ch, ok := remoteFetchers[pk]; ok {
					select {
					case rc, ok := <-ch:
						if ok && len(rc) > 0 {
							remoteCache[pk] = rc
							licenses = analysis.MergeLicenseSources(licenses, rc)
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
		case cmp.Added:
			fmt.Printf("  %s %s @ %s %s\n", ui.StyleAdded.Render("+"), ui.StyleAdded.Render(c.Name), ui.StyleVersion.Render(c.TargetVersion), licAndDepStr)
			addedN++
		case cmp.Removed:
			// For removed dependencies, we don't have target version license info, so just show directness
			removedDirectness := "(indirect)"
			if c.IsDirect {
				removedDirectness = "(direct)"
			}
			fmt.Printf("  %s %s @ %s %s\n", ui.StyleRemoved.Render("-"), ui.StyleRemoved.Render(c.Name), ui.StyleVersion.Render(c.BaseVersion), ui.StyleVersion.Render(removedDirectness))
			removedN++
		case cmp.Upgraded:
			updatedN++
			upgradedN++
			oldNamePart := ""
			if c.OldName != "" && c.OldName != c.Name {
				oldNamePart = ui.StyleDim.Render(c.OldName) + " " + ui.StyleUpdateArrow.Render("→ ")
			}
			fmt.Printf("  %s %s%s @ %s %s %s %s\n", ui.StyleUpgraded.Render("↑"), oldNamePart, ui.StyleBold.Render(c.Name), ui.StyleVersion.Render(c.BaseVersion), ui.StyleUpdateArrow.Render("→"), ui.StyleVersion.Render(c.TargetVersion), licAndDepStr)
		case cmp.Downgraded:
			updatedN++
			downgradedN++
			oldNamePart := ""
			if c.OldName != "" && c.OldName != c.Name {
				oldNamePart = ui.StyleDim.Render(c.OldName) + " " + ui.StyleDowngradeArrow.Render("→ ")
			}
			fmt.Printf("  %s %s%s @ %s %s %s %s\n", ui.StyleDowngraded.Render("↓"), oldNamePart, ui.StyleBold.Render(c.Name), ui.StyleVersion.Render(c.BaseVersion), ui.StyleDowngradeArrow.Render("→"), ui.StyleVersion.Render(c.TargetVersion), licAndDepStr)
		case cmp.Updated:
			updatedN++
			arrowStyle := ui.StyleUpdateArrow
			symbol := ui.StyleNeutral.Render("~")
			oldNamePart := ""
			if c.OldName != "" && c.OldName != c.Name {
				oldNamePart = ui.StyleDim.Render(c.OldName) + " " + arrowStyle.Render("→ ")
			}
			fmt.Printf("  %s %s%s @ %s %s %s %s\n", symbol, oldNamePart, ui.StyleBold.Render(c.Name), ui.StyleVersion.Render(c.BaseVersion), arrowStyle.Render("→"), ui.StyleVersion.Render(c.TargetVersion), licAndDepStr)
		}
	}

	fmt.Printf("\n%s\n", ui.StyleHeader.Render("Summary:"))
	if addedN > 0 {
		fmt.Printf("  %s %d package%s added\n", ui.StyleAdded.Render("+"), addedN, plural(addedN))
	}
	if removedN > 0 {
		fmt.Printf("  %s %d package%s removed\n", ui.StyleRemoved.Render("-"), removedN, plural(removedN))
	}
	if updatedN > 0 {
		if upgradedN > 0 {
			fmt.Printf("  %s %d package%s upgraded\n", ui.StyleUpgraded.Render("↑"), upgradedN, plural(upgradedN))
		}
		if downgradedN > 0 {
			fmt.Printf("  %s %d package%s downgraded\n", ui.StyleDowngraded.Render("↓"), downgradedN, plural(downgradedN))
		}
		other := updatedN - (upgradedN + downgradedN)
		if other > 0 {
			fmt.Printf("  %s %d package%s changed\n", ui.StyleNeutral.Render("~"), other, plural(other))
		}
	}
}

// splitVulnsByChange partitions vulnerabilities into those affecting changed
// dependencies versus those in unchanged modules. Changes marked as Added,
// Updated, Upgraded, or Downgraded are treated as "changed" for classification
// purposes.
func splitVulnsByChange(vulns []analysis.Vulnerability, changes []cmp.Change) (changed, unchanged []analysis.Vulnerability) {
	if len(vulns) == 0 {
		return nil, nil
	}
	changedSet := map[string]bool{}
	for _, c := range changes {
		switch c.ChangeType {
		case cmp.Added, cmp.Updated, cmp.Upgraded, cmp.Downgraded:
			// treat as changed
		default:
			continue
		}
		info := cmp.ParseGoPackage(&extractor.Package{Name: c.Name})
		changedSet[info.CanonicalName] = true
	}
	for _, v := range vulns {
		info := cmp.ParseGoPackage(&extractor.Package{Name: v.Package})
		if changedSet[info.CanonicalName] {
			changed = append(changed, v)
		} else {
			unchanged = append(unchanged, v)
		}
	}
	return changed, unchanged
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
func renderMatcherDebug(files []string, matcher *inv.DependencyMatcher) {
	fmt.Println(ui.StyleMeta.Render("Matcher debug (changed files considered by dependency scanner):"))
	if len(files) == 0 {
		fmt.Println("  (no changed files detected between refs)")
		return
	}
	if matcher == nil {
		for _, f := range files {
			fmt.Printf("  ? %s\n", f)
		}
		fmt.Println("  (matcher unavailable; treating all files as potential dependency changes)")
		return
	}
	for _, f := range files {
		if matcher.Matches(f) {
			fmt.Printf("  %s %s\n", ui.StyleAdded.Render("+match"), f)
		} else {
			fmt.Printf("  %s %s\n", ui.StyleDim.Render("-skip"), f)
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
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, reportMap, "diff", "diff_report", errW); err != nil {
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
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "diff", "diff_dependency_change", errW); err != nil {
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
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "diff", "diff_vulnerability", errW); err != nil {
			return err
		}
	}
	return nil
}
