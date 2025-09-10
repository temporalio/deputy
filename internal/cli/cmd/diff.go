package cmd

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pb "deps.dev/api/v3"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	analysis "github.com/picatz/deputy/internal/analysis"
	cmp "github.com/picatz/deputy/internal/compare"
	gitx "github.com/picatz/deputy/internal/git"
	inv "github.com/picatz/deputy/internal/inventory"
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
Provides license information for changed packages via the deps.dev API.

VULNERABILITY SCANNING:
Automatically scans added and updated packages for known vulnerabilities using OSV.
Reports CVE identifiers when available, otherwise shows GO- or GHSA- identifiers.
Uses batch queries to the OSV API for efficient scanning.
Can be disabled with --skip-vuln-scan for faster execution.`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			repo := repoPath
			if repo == "" {
				repo = mustGetwd()
			}
			baseRef, targetRef, err := gitx.ParseReferences(repo, args)
			if err != nil {
				return fmt.Errorf("failed to parse references: %w", err)
			}
			return runDiffAnalysis(cmd.Context(), repo, baseRef, targetRef, !skipVulnScan, useLicenseCheck, enrichLicenses, licenseSource, publishedAfterStr, publishedBeforeStr, asOfStr)
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
	cmd.Flags().BoolVar(&useLicenseCheck, "use-licensecheck", false, "(Deprecated) Alias for --enrich-licenses --license-source=scan")
	cmd.Flags().BoolVar(&enrichLicenses, "enrich-licenses", false, "Enrich changed modules with licenses (deps.dev, scan, or both)")
	cmd.Flags().StringVar(&licenseSource, "license-source", "depsdev", "License enrichment source: depsdev | scan | both")
	cmd.Flags().StringVar(&publishedBeforeStr, "published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	cmd.Flags().StringVar(&publishedAfterStr, "published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	cmd.Flags().StringVar(&asOfStr, "as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")

	root.AddCommand(cmd)
}

func mustGetwd() string {
	wd, _ := os.Getwd()
	return wd
}

// runDiffAnalysis orchestrates dependency inventory collection for the base and
// target references, computes a dependency diff, and optionally queries OSV to
// enrich added/updated modules with vulnerability data.
func runDiffAnalysis(ctx context.Context, repoPath, baseRef, targetRef string, enableVulnScan bool, useLicenseCheck bool, enrichLicenses bool, licenseSource string, publishedAfterStr, publishedBeforeStr, asOfStr string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

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

		containsDepChanges := false
		for _, f := range changedFiles {
			b := filepath.Base(f)
			if b == "go.mod" || b == "go.sum" {
				containsDepChanges = true
				break
			}
		}

		if !containsDepChanges {
			fmt.Println("No dependency changes detected.")
			return nil
		}
	}

	// Open repository and resolve references
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("error opening Git repository at %s: %w\nMake sure you're running this from within a valid Git repository", repoPath, err)
	}

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
		tp, err := inv.ScanPackagesWorking(ctx, repoPath)
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
	fmt.Printf("Scanning packages in base reference %s...\n", baseHash.String()[:8])
	basePackages, err := inv.ScanPackagesAtCommitSnapshot(ctx, repoPath, *baseHash)
	if err != nil {
		return fmt.Errorf("error scanning base reference packages: %w", err)
	}

	// Scan target packages if not already done
	if targetPackages == nil && targetHash != nil {
		fmt.Printf("Scanning packages in target reference %s...\n", targetHash.String()[:8])
		tp, err := inv.ScanPackagesAtCommitSnapshot(ctx, repoPath, *targetHash)
		if err != nil {
			return fmt.Errorf("error scanning target reference packages: %w", err)
		}
		targetPackages = tp
	}

	// Compare packages
	changes := cmp.ComparePackages(basePackages, targetPackages)
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
	displayDetailedDependencyChanges(ctx, changes, enrichLicenses, licenseSource)

	// Scan for vulnerabilities if enabled
	var vulns []analysis.Vulnerability
	if enableVulnScan {
		fmt.Printf("\nScanning for vulnerabilities...\n")
		inputs := make([]analysis.PkgInput, 0, len(changes))
		for _, c := range changes {
			if c.ChangeType != cmp.Removed && c.TargetVersion != "" {
				inputs = append(inputs, analysis.PkgInput{
					Name:     c.Name,
					Version:  c.TargetVersion,
					IsDirect: c.IsDirect,
				})
			}
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
	}

	// Display results
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

// displayDetailedDependencyChanges renders dependency changes with symbols, arrows,
// license lookups via deps.dev and a concise summary similar to the original tool output.
func displayDetailedDependencyChanges(ctx context.Context, changes []cmp.Change, enrich bool, licenseSource string) {
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

	// Counters
	var addedN, removedN, updatedN, upgradedN, downgradedN int

	for _, c := range changes {
		depType := ui.StyleVersion.Render("[indirect]")
		if c.IsDirect {
			depType = ui.StyleUpgraded.Render("[direct]")
		}

		licenses := []string{"?"}
		if l, ok := licMap[pkgKey{c.Name, c.TargetVersion}]; ok && len(l) > 0 {
			licenses = l
		}
		if c.ChangeType != cmp.Removed && c.TargetVersion != "" && enrich && (licenseSource == "scan" || licenseSource == "both") {
			if lc := analysis.LocalRepoLicenseScan("."); lc != nil {
				licenses = analysis.MergeLicenseSources(licenses, lc)
			}
			if rc := analysis.RemoteModuleLicenseScan(ctx, c.Name, c.TargetVersion); rc != nil {
				licenses = analysis.MergeLicenseSources(licenses, rc)
			}
		}
		licStr := ""
		if len(licenses) > 0 && licenses[0] != "?" {
			licStr = ui.StyleLicense.Render("[" + strings.Join(licenses, ", ") + "]")
		}

		switch c.ChangeType {
		case cmp.Added:
			fmt.Printf("  %s %s @ %s %s %s\n", ui.StyleAdded.Render("+"), ui.StyleAdded.Render(c.Name), ui.StyleVersion.Render(c.TargetVersion), depType, licStr)
			addedN++
		case cmp.Removed:
			fmt.Printf("  %s %s @ %s %s\n", ui.StyleRemoved.Render("-"), ui.StyleRemoved.Render(c.Name), ui.StyleVersion.Render(c.BaseVersion), depType)
			removedN++
		case cmp.Updated:
			updatedN++
			verCmp := cmp.CompareGoPackageVersions(c)
			var symbol string
			var symStyle = ui.StyleNeutral
			var arrowStyle = ui.StyleUpdateArrow
			switch verCmp {
			case 1:
				symbol = "↑"
				symStyle = ui.StyleUpgraded
				upgradedN++
			case -1:
				symbol = "↓"
				symStyle = ui.StyleDowngraded
				arrowStyle = ui.StyleDowngradeArrow
				downgradedN++
			default:
				symbol = "~"
			}
			oldNamePart := ""
			if c.OldName != "" && c.OldName != c.Name {
				oldNamePart = ui.StyleDim.Render(c.OldName) + " " + arrowStyle.Render("→ ")
			}
			fmt.Printf("  %s %s%s @ %s %s %s %s %s\n", symStyle.Render(symbol), oldNamePart, ui.StyleBold.Render(c.Name), ui.StyleVersion.Render(c.BaseVersion), arrowStyle.Render("→"), ui.StyleVersion.Render(c.TargetVersion), depType, licStr)
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

// depsClient adapts a deps.dev InsightsClient to the internal analysis.DepsClient interface.
type depsClient struct{ pb.InsightsClient }

func (d depsClient) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
	return d.InsightsClient.GetVersion(ctx, req)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
