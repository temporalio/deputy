package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/go-git/go-git/v5"
	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/compare"
	gitx "github.com/picatz/deputy/internal/gitutil"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/output"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/report/render"
	"github.com/picatz/deputy/internal/scan"
	ui "github.com/picatz/deputy/internal/ui"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// isContainerDiffInContext returns true if both arguments appear to be container image references,
// taking into account the Git repository context. If we're in a Git repo and the refs look like
// valid Git refs (tags, branches), we prefer Git diff over container diff.
func isContainerDiffInContext(base, target, repoPath string) bool {
	// If either ref has an explicit image scheme, it's definitely a container diff
	if isImageTargetScheme(base) || isImageTargetScheme(target) {
		return true
	}

	// Check if we're in a Git repository and the refs might be Git refs
	if repoPath != "" {
		if repo, err := git.PlainOpen(repoPath); err == nil {
			// Check if both refs resolve as Git refs
			baseIsGitRef := isValidGitRef(repo, base)
			targetIsGitRef := isValidGitRef(repo, target)

			// If both are valid Git refs, prefer Git diff
			if baseIsGitRef && targetIsGitRef {
				return false
			}
		}
	}

	// Fall back to the standard container detection
	return isContainerDiff(base, target)
}

// isValidGitRef checks if a reference is a valid Git ref (tag, branch, commit, or special ref).
func isValidGitRef(repo *git.Repository, ref string) bool {
	// Check for special working tree refs
	upper := strings.ToUpper(strings.TrimSpace(ref))
	if upper == "WORKING" || upper == "WORKTREE" || upper == "WT" || strings.TrimSpace(ref) == "." {
		return true
	}

	// Try to resolve the ref using the enhanced resolver
	if _, err := gitx.ResolveRevisionEnhanced(repo, ref); err == nil {
		return true
	}

	return false
}

// isContainerDiff returns true if both arguments appear to be container image references.
// This is used to route diff commands to container diff logic instead of Git diff.
func isContainerDiff(base, target string) bool {
	return isContainerImageRef(base) && isContainerImageRef(target)
}

// isContainerImageRef returns true if the reference appears to be a container image.
func isContainerImageRef(ref string) bool {
	// Check for explicit image schemes
	if isImageTargetScheme(ref) {
		return true
	}
	// Check if it looks like a container reference without scheme
	if looksLikeContainerReference(ref) {
		return true
	}
	return false
}

// containerDiffOpts holds options for container image diff operations.
type containerDiffOpts struct {
	skipVulnScan   bool
	policyPaths    []string
	useLocalDaemon bool   // Use docker-daemon:// instead of oci:// for local Docker images
	format         string // Output format: text (default) or json
}

// runContainerDiff performs a semantic diff between two container images.
// It compares packages, vulnerabilities, configuration, and layers.
func runContainerDiff(ctx context.Context, service *scan.Service, baseRef, targetRef string, opts containerDiffOpts, outW, errW io.Writer) error {
	ctx, span := otel.StartSpan(ctx, "deputy.container_diff",
		trace.WithAttributes(
			attribute.String("deputy.container_diff.base_ref", baseRef),
			attribute.String("deputy.container_diff.target_ref", targetRef),
			attribute.Bool("deputy.container_diff.vuln_scan", !opts.skipVulnScan),
			attribute.Bool("deputy.container_diff.local_daemon", opts.useLocalDaemon),
		))
	defer span.End()

	if outW == nil {
		outW = io.Discard
	}
	if errW == nil {
		errW = io.Discard
	}
	if service == nil {
		service = scan.NewService()
	}

	// Normalize references based on source (local daemon vs remote registry)
	baseOCI := normalizeImageReference(baseRef, opts.useLocalDaemon)
	targetOCI := normalizeImageReference(targetRef, opts.useLocalDaemon)

	// For JSON output, skip the progress messages
	isJSON := strings.ToLower(strings.TrimSpace(opts.format)) == "json"

	if !isJSON {
		// Render header
		doc := render.DiffHeaderDoc(baseOCI, targetOCI)
		_ = doc.Render(outW, output.UIStyles())
		fmt.Fprintln(outW)
		if opts.useLocalDaemon {
			fmt.Fprintln(outW, ui.StyleMeta.Render("Scanning container images from local Docker daemon..."))
		} else {
			fmt.Fprintln(outW, ui.StyleMeta.Render("Scanning container images..."))
		}
	}

	// Perform the diff (scans both images in parallel)
	scanOpts := scan.ContainerDiffOptions{
		ScanVulnerabilities: !opts.skipVulnScan,
		ScanOptions:         scan.Options{},
	}
	result, err := service.CompareContainerImages(ctx, baseOCI, targetOCI, scanOpts)
	if err != nil {
		otel.SetSpanError(span, err)
		return fmt.Errorf("compare container images: %w", err)
	}

	// Run policies
	if len(opts.policyPaths) > 0 {
		if err := runContainerDiffPolicies(ctx, opts.policyPaths, result.Report, errW); err != nil {
			otel.SetSpanError(span, err)
			return err
		}
	}

	// Gather additional context for rendering
	ctx2 := containerDiffContext{
		Report: result.Report,
	}
	if result.BaseResult != nil {
		ctx2.BasePackageCount = len(result.BaseResult.Inventory.Packages)
		ctx2.BaseDistro = extractDistroFromPackages(result.BaseResult.Inventory.Packages)
		if result.BaseResult.ImageInfo != nil {
			ctx2.BaseSize = result.BaseResult.ImageInfo.Metadata.Size
			ctx2.BaseArch = result.BaseResult.ImageInfo.Metadata.Architecture
		}
	}
	if result.TargetResult != nil {
		ctx2.TargetPackageCount = len(result.TargetResult.Inventory.Packages)
		ctx2.TargetDistro = extractDistroFromPackages(result.TargetResult.Inventory.Packages)
		if result.TargetResult.ImageInfo != nil {
			ctx2.TargetSize = result.TargetResult.ImageInfo.Metadata.Size
			ctx2.TargetArch = result.TargetResult.ImageInfo.Metadata.Architecture
		}
	}

	// Output based on format
	if isJSON {
		return renderContainerDiffJSON(outW, ctx2)
	}
	renderContainerDiffResult(outW, ctx2)

	otel.SetSpanOK(span)
	return nil
}

// containerDiffContext holds all the information needed to render a container diff.
type containerDiffContext struct {
	Report             *compare.ImageDiffReport
	BasePackageCount   int
	TargetPackageCount int
	BaseDistro         string
	TargetDistro       string
	BaseSize           int64
	TargetSize         int64
	BaseArch           string
	TargetArch         string
}

// extractDistroFromPackages extracts the OS distribution from package ecosystem info.
// It looks for patterns like "Debian:11", "Alpine:3.18", etc.
func extractDistroFromPackages(pkgs []*extractor.Package) string {
	if len(pkgs) == 0 {
		return ""
	}

	// Count ecosystems to find the most common one (for mixed images)
	ecosystemCounts := make(map[string]int)
	for _, pkg := range pkgs {
		eco := pkg.Ecosystem()
		if eco == "" {
			continue
		}
		// Only count OS-level ecosystems (those with version suffixes like "Debian:11")
		if strings.Contains(eco, ":") {
			ecosystemCounts[eco]++
		}
	}

	if len(ecosystemCounts) == 0 {
		return ""
	}

	// Find the most common ecosystem
	var mostCommon string
	var maxCount int
	for eco, count := range ecosystemCounts {
		if count > maxCount {
			maxCount = count
			mostCommon = eco
		}
	}

	// Format nicely: "Debian:11" -> "Debian 11", "Alpine:3.18" -> "Alpine 3.18"
	if mostCommon != "" {
		parts := strings.SplitN(mostCommon, ":", 2)
		if len(parts) == 2 {
			return parts[0] + " " + parts[1]
		}
		return mostCommon
	}
	return ""
}

// normalizeImageReference ensures the image reference has the appropriate scheme.
// If useLocalDaemon is true, uses docker-daemon:// to pull from local Docker.
// Otherwise uses oci:// for remote registry pulls.
func normalizeImageReference(ref string, useLocalDaemon bool) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ref
	}
	// Already has a scheme - respect it
	if strings.Contains(ref, "://") {
		return ref
	}
	// Add appropriate prefix based on source
	if useLocalDaemon {
		return "docker-daemon://" + ref
	}
	return "oci://" + ref
}

// ContainerDiffJSONOutput represents the JSON output for container diff.
type ContainerDiffJSONOutput struct {
	BaseImage        compare.ImageRef              `json:"baseImage"`
	TargetImage      compare.ImageRef              `json:"targetImage"`
	BaseContext      ImageContext                  `json:"baseContext,omitempty"`
	TargetContext    ImageContext                  `json:"targetContext,omitempty"`
	PackageChanges   []compare.ImagePackageChange  `json:"packageChanges,omitempty"`
	Vulnerabilities  []compare.VulnerabilityChange `json:"vulnerabilities,omitempty"`
	ConfigChanges    *compare.ImageConfigDiff      `json:"configChanges,omitempty"`
	LayerAnalysis    *compare.LayerDiffAnalysis    `json:"layerAnalysis,omitempty"`
	Summary          compare.ImageDiffSummary      `json:"summary"`
	VulnSummary      *VulnSummaryJSON              `json:"vulnerabilitySummary,omitempty"`
	Recommendations  []RecommendationJSON          `json:"recommendations,omitempty"`
}

// ImageContext provides additional context about an image.
type ImageContext struct {
	Distro       string `json:"distro,omitempty"`
	PackageCount int    `json:"packageCount"`
	Size         int64  `json:"size,omitempty"`
	Architecture string `json:"architecture,omitempty"`
}

// VulnSummaryJSON provides vulnerability summary counts.
type VulnSummaryJSON struct {
	CriticalHighCount int `json:"criticalHighCount"`
	FixableCount      int `json:"fixableCount"`
	UnfixedCount      int `json:"unfixedCount"`
}

// RecommendationJSON represents a recommended action.
type RecommendationJSON struct {
	Priority    int                  `json:"priority"`
	Action      string               `json:"action"`
	Description string               `json:"description,omitempty"`
	Packages    []PackageFixJSON     `json:"packages,omitempty"`
}

// PackageFixJSON represents a package with available fix.
type PackageFixJSON struct {
	Package        string           `json:"package"`
	CurrentVersion string           `json:"currentVersion"`
	FixedVersion   string           `json:"fixedVersion"`
	VulnCount      int              `json:"vulnCount"`
	LayerContext   *LayerContextJSON `json:"layerContext,omitempty"`
}

type LayerContextJSON struct {
	LayerIndex  int    `json:"layerIndex"`
	InBaseImage bool   `json:"inBaseImage"`
	Command     string `json:"command,omitempty"`
}

// renderContainerDiffJSON outputs the container diff as JSON.
func renderContainerDiffJSON(w io.Writer, ctx containerDiffContext) error {
	output := ContainerDiffJSONOutput{
		Summary: compare.ImageDiffSummary{},
	}

	if ctx.Report != nil {
		output.BaseImage = ctx.Report.BaseImage
		output.TargetImage = ctx.Report.TargetImage
		output.PackageChanges = ctx.Report.PackageChanges
		output.Vulnerabilities = ctx.Report.VulnerabilityChanges
		output.ConfigChanges = ctx.Report.ConfigChanges
		output.LayerAnalysis = ctx.Report.LayerAnalysis
		output.Summary = ctx.Report.Summary
	}

	output.BaseContext = ImageContext{
		Distro:       ctx.BaseDistro,
		PackageCount: ctx.BasePackageCount,
		Size:         ctx.BaseSize,
		Architecture: ctx.BaseArch,
	}
	output.TargetContext = ImageContext{
		Distro:       ctx.TargetDistro,
		PackageCount: ctx.TargetPackageCount,
		Size:         ctx.TargetSize,
		Architecture: ctx.TargetArch,
	}

	// Build vulnerability summary
	if len(output.Vulnerabilities) > 0 {
		vulnSummary := buildVulnSummaryJSON(output.Vulnerabilities)
		output.VulnSummary = &vulnSummary
		output.Recommendations = buildRecommendationsJSON(output.Vulnerabilities, vulnSummary)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func buildVulnSummaryJSON(changes []compare.VulnerabilityChange) VulnSummaryJSON {
	var summary VulnSummaryJSON
	for _, v := range changes {
		if v.ChangeType != compare.VulnAdded && v.ChangeType != compare.VulnPersisted {
			continue
		}
		sev := strings.ToUpper(v.Severity)
		if sev == "CRITICAL" || sev == "HIGH" {
			summary.CriticalHighCount++
		}
		if len(v.FixedVersions) > 0 {
			summary.FixableCount++
		} else {
			summary.UnfixedCount++
		}
	}
	return summary
}

func buildRecommendationsJSON(changes []compare.VulnerabilityChange, summary VulnSummaryJSON) []RecommendationJSON {
	var recs []RecommendationJSON
	priority := 1

	// Check for persisted critical/high vulnerabilities suggesting base image update
	var persistedCriticalHigh int
	for _, v := range changes {
		if v.ChangeType == compare.VulnPersisted {
			sev := strings.ToUpper(v.Severity)
			if sev == "CRITICAL" || sev == "HIGH" {
				persistedCriticalHigh++
			}
		}
	}
	if persistedCriticalHigh > 0 {
		recs = append(recs, RecommendationJSON{
			Priority:    priority,
			Action:      "Consider a newer base image",
			Description: fmt.Sprintf("%d critical/high vulnerabilities persist", persistedCriticalHigh),
		})
		priority++
	}

	// Fixable packages
	if summary.FixableCount > 0 {
		rec := RecommendationJSON{
			Priority:    priority,
			Action:      "Upgrade packages with available fixes",
			Description: fmt.Sprintf("%d vulnerabilities can be resolved", summary.FixableCount),
		}
		rec.Packages = buildFixablePackagesJSON(changes)
		recs = append(recs, rec)
		priority++
	}

	// Unfixed
	if summary.UnfixedCount > 0 {
		recs = append(recs, RecommendationJSON{
			Priority:    priority,
			Action:      "Monitor unfixed vulnerabilities",
			Description: "Check upstream for patches or consider alternatives",
		})
	}

	return recs
}

func buildFixablePackagesJSON(changes []compare.VulnerabilityChange) []PackageFixJSON {
	type pkgFix struct {
		pkg         string
		version     string
		fix         string
		count       int
		layerIdx    int
		layerCmd    string
		inBaseImage bool
		hasLayer    bool
	}
	pkgFixes := make(map[string]*pkgFix)

	for _, v := range changes {
		if len(v.FixedVersions) == 0 {
			continue
		}
		if v.ChangeType != compare.VulnAdded && v.ChangeType != compare.VulnPersisted {
			continue
		}
		key := v.Package
		if pf, ok := pkgFixes[key]; ok {
			pf.count++
			// Update fix version if this vuln has a better in-band fix
			currentVersion := v.TargetVersion
			if currentVersion == "" {
				currentVersion = v.BaseVersion
			}
			betterFix := findBestFixVersion(v.FixedVersions, currentVersion)
			if betterFix != "" && (pf.fix == "" || compareVersionStrings(betterFix, pf.fix) > 0) {
				pf.fix = betterFix
			}
		} else {
			version := v.TargetVersion
			if version == "" {
				version = v.BaseVersion
			}
			// Use findBestFixVersion for in-band preference
			fix := findBestFixVersion(v.FixedVersions, version)
			pf := &pkgFix{
				pkg:     v.Package,
				version: version,
				fix:     fix,
				count:   1,
			}
			// Capture layer info if available
			if v.LayerDetails != nil {
				pf.hasLayer = true
				pf.layerIdx = v.LayerDetails.Index
				pf.layerCmd = v.LayerDetails.Command
				pf.inBaseImage = v.LayerDetails.InBaseImage
			}
			pkgFixes[key] = pf
		}
	}

	sorted := make([]*pkgFix, 0, len(pkgFixes))
	for _, pf := range pkgFixes {
		sorted = append(sorted, pf)
	}
	slices.SortFunc(sorted, func(a, b *pkgFix) int {
		if a.count != b.count {
			return b.count - a.count
		}
		return strings.Compare(a.pkg, b.pkg)
	})

	result := make([]PackageFixJSON, 0, len(sorted))
	for _, pf := range sorted {
		fix := PackageFixJSON{
			Package:        pf.pkg,
			CurrentVersion: pf.version,
			FixedVersion:   pf.fix,
			VulnCount:      pf.count,
		}
		if pf.hasLayer {
			fix.LayerContext = &LayerContextJSON{
				LayerIndex:  pf.layerIdx,
				InBaseImage: pf.inBaseImage,
				Command:     pf.layerCmd,
			}
		}
		result = append(result, fix)
	}
	return result
}

// renderContainerDiffResult renders the container diff report to output.
func renderContainerDiffResult(w io.Writer, ctx containerDiffContext) {
	report := ctx.Report
	if report == nil {
		fmt.Fprintln(w, "No differences found.")
		return
	}

	// Summary section
	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleHeader.Render("Container Image Diff Summary"))
	fmt.Fprintln(w)

	// Image references with context (distro, packages, size)
	fmt.Fprintf(w, "  %s %s", ui.StyleMeta.Render("Base:"), formatImageRef(report.BaseImage))
	renderImageContext(w, ctx.BaseDistro, ctx.BasePackageCount, ctx.BaseSize, ctx.BaseArch)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s %s", ui.StyleMeta.Render("Target:"), formatImageRef(report.TargetImage))
	renderImageContext(w, ctx.TargetDistro, ctx.TargetPackageCount, ctx.TargetSize, ctx.TargetArch)
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	// Package changes section
	if len(report.PackageChanges) > 0 {
		renderContainerPackageChanges(w, report.PackageChanges)
	} else {
		if ctx.BasePackageCount == 0 && ctx.TargetPackageCount == 0 {
			fmt.Fprintln(w, ui.StyleMeta.Render("No packages detected in either image."))
		} else {
			fmt.Fprintln(w, ui.StyleMeta.Render("No package changes detected."))
		}
	}

	// Vulnerability changes section
	if len(report.VulnerabilityChanges) > 0 {
		renderContainerVulnerabilityChanges(w, report.VulnerabilityChanges)
	}

	// Configuration changes section
	if report.ConfigChanges != nil && hasConfigChanges(report.ConfigChanges) {
		renderContainerConfigChanges(w, report.ConfigChanges)
	}

	// Layer analysis section
	if report.LayerAnalysis != nil {
		renderContainerLayerAnalysis(w, report.LayerAnalysis)
	}

	// Final summary
	renderContainerDiffSummary(w, report.Summary)

	// Vulnerability summary and recommended actions (like Git diff)
	if len(report.VulnerabilityChanges) > 0 {
		renderContainerVulnerabilitySummary(w, report.VulnerabilityChanges)
	}
}

// renderImageContext renders the additional context info for an image (distro, packages, size).
func renderImageContext(w io.Writer, distro string, packageCount int, size int64, arch string) {
	var parts []string

	// Add distro if available (e.g., "Debian 11")
	if distro != "" {
		parts = append(parts, distro)
	}

	// Add package count
	if packageCount > 0 {
		parts = append(parts, fmt.Sprintf("%d packages", packageCount))
	}

	// Add size if available
	if size > 0 {
		parts = append(parts, formatBytes(size))
	}

	// Add architecture if available
	if arch != "" {
		parts = append(parts, arch)
	}

	if len(parts) > 0 {
		fmt.Fprintf(w, " %s", ui.StyleDim.Render("("+strings.Join(parts, ", ")+")"))
	}
}

// formatBytes formats bytes as a human-readable string.
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func formatImageRef(ref compare.ImageRef) string {
	if ref.Reference != "" {
		return ref.Reference
	}
	if ref.Repository != "" {
		result := ref.Repository
		if ref.Tag != "" {
			result += ":" + ref.Tag
		} else if ref.Digest != "" {
			result += "@" + ref.Digest
		}
		if ref.Registry != "" {
			result = ref.Registry + "/" + result
		}
		return result
	}
	return "(unknown)"
}

func renderContainerPackageChanges(w io.Writer, changes []compare.ImagePackageChange) {
	fmt.Fprintln(w, ui.StyleHeader.Render("Package Changes:"))

	var added, removed, upgraded, downgraded int
	for _, c := range changes {
		layerInfo := formatLayerInfo(c.TargetLayerDetails)
		if c.ChangeType == compare.Removed {
			layerInfo = formatLayerInfo(c.BaseLayerDetails)
		}

		switch c.ChangeType {
		case compare.Added:
			added++
			fmt.Fprintf(w, "  %s %s @ %s %s\n",
				ui.StyleAdded.Render("+"),
				ui.StyleAdded.Render(c.Name),
				ui.StyleVersion.Render(c.TargetVersion),
				layerInfo,
			)
		case compare.Removed:
			removed++
			fmt.Fprintf(w, "  %s %s @ %s %s\n",
				ui.StyleRemoved.Render("-"),
				ui.StyleRemoved.Render(c.Name),
				ui.StyleVersion.Render(c.BaseVersion),
				layerInfo,
			)
		case compare.Upgraded:
			upgraded++
			fmt.Fprintf(w, "  %s %s @ %s %s %s %s\n",
				ui.StyleUpgraded.Render("↑"),
				ui.StyleBold.Render(c.Name),
				ui.StyleVersion.Render(c.BaseVersion),
				ui.StyleUpdateArrow.Render("→"),
				ui.StyleVersion.Render(c.TargetVersion),
				layerInfo,
			)
		case compare.Downgraded:
			downgraded++
			fmt.Fprintf(w, "  %s %s @ %s %s %s %s\n",
				ui.StyleDowngraded.Render("↓"),
				ui.StyleBold.Render(c.Name),
				ui.StyleVersion.Render(c.BaseVersion),
				ui.StyleDowngradeArrow.Render("→"),
				ui.StyleVersion.Render(c.TargetVersion),
				layerInfo,
			)
		case compare.Updated:
			fmt.Fprintf(w, "  %s %s @ %s %s %s %s\n",
				ui.StyleNeutral.Render("~"),
				ui.StyleBold.Render(c.Name),
				ui.StyleVersion.Render(c.BaseVersion),
				ui.StyleUpdateArrow.Render("→"),
				ui.StyleVersion.Render(c.TargetVersion),
				layerInfo,
			)
		}
	}
	fmt.Fprintln(w)
}

func formatLayerInfo(ld *compare.LayerDetails) string {
	if ld == nil {
		return ""
	}
	layerIdx := fmt.Sprintf("L%d", ld.Index)
	if ld.InBaseImage {
		return ui.StyleDim.Render(fmt.Sprintf("[%s, base]", layerIdx))
	}
	return ui.StyleDim.Render(fmt.Sprintf("[%s]", layerIdx))
}

func renderContainerVulnerabilityChanges(w io.Writer, changes []compare.VulnerabilityChange) {
	// Consolidate duplicate vulnerabilities (same CVE under different advisory IDs)
	changes = consolidateVulnerabilityChanges(changes)

	// Group vulnerabilities by change type for cleaner output
	var fixed, added, persisted []compare.VulnerabilityChange
	for _, v := range changes {
		switch v.ChangeType {
		case compare.VulnFixed:
			fixed = append(fixed, v)
		case compare.VulnAdded:
			added = append(added, v)
		case compare.VulnPersisted:
			persisted = append(persisted, v)
		case compare.VulnRemoved:
			// Removed (package removed entirely) - less important, skip for now
		}
	}

	// Sort all slices by severity (critical first), then by ID
	sortVulnsBySeverity(fixed)
	sortVulnsBySeverity(added)
	sortVulnsBySeverity(persisted)

	// Check if we have anything to show
	if len(fixed) == 0 && len(added) == 0 && len(persisted) == 0 {
		return
	}

	fmt.Fprintln(w, ui.StyleHeader.Render("Vulnerabilities:"))

	// Show fixed vulnerabilities first (good news)
	if len(fixed) > 0 {
		fmt.Fprintf(w, "  %s %d fixed by upgrade:\n", ui.StyleAdded.Render("✓"), len(fixed))
		renderVulnSummaryBySeverity(w, fixed)
	}

	// Show new vulnerabilities (concerns)
	if len(added) > 0 {
		fmt.Fprintf(w, "  %s %d new vulnerabilities:\n", ui.StyleRemoved.Render("!"), len(added))
		renderVulnList(w, added)
	}

	// Show persisted vulnerabilities (still present)
	if len(persisted) > 0 {
		// Count by severity
		critical, high, med, low := countBySeverity(persisted)
		hasFixable := countFixable(persisted)

		// Build header with severity breakdown and fix availability inline
		fixablePart := ""
		if hasFixable > 0 {
			fixablePart = fmt.Sprintf(" %s",
				ui.StyleUpgraded.Render(fmt.Sprintf("[%d fixable]", hasFixable)),
			)
		}

		if critical+high > 0 {
			fmt.Fprintf(w, "  %s %d existing vulnerabilities %s%s:\n",
				ui.StyleDowngraded.Render("~"),
				len(persisted),
				formatSeverityBreakdown(critical, high, med, low),
				fixablePart,
			)
		} else {
			fmt.Fprintf(w, "  %s %d existing vulnerabilities %s%s:\n",
				ui.StyleDim.Render("="),
				len(persisted),
				formatSeverityBreakdown(critical, high, med, low),
				fixablePart,
			)
		}
		renderVulnList(w, persisted)
	}

	fmt.Fprintln(w)
}

// consolidateVulnerabilityChanges merges vulnerabilities that share aliases (same CVE).
// This prevents showing GHSA-xxx and GO-xxx separately when they're the same issue.
func consolidateVulnerabilityChanges(changes []compare.VulnerabilityChange) []compare.VulnerabilityChange {
	if len(changes) == 0 {
		return nil
	}

	// Group by package + change type first, then by CVE/alias within each group
	type groupKey struct {
		pkg        string
		changeType compare.VulnChangeType
	}
	groups := make(map[groupKey][]compare.VulnerabilityChange)
	var groupOrder []groupKey

	for _, v := range changes {
		key := groupKey{pkg: v.Package, changeType: v.ChangeType}
		if _, exists := groups[key]; !exists {
			groupOrder = append(groupOrder, key)
		}
		groups[key] = append(groups[key], v)
	}

	var result []compare.VulnerabilityChange

	for _, key := range groupOrder {
		vulns := groups[key]
		// Build a map of CVE -> consolidated vulnerability
		cveMap := make(map[string]*compare.VulnerabilityChange)
		idToVuln := make(map[string]*compare.VulnerabilityChange)

		for i := range vulns {
			v := &vulns[i]

			// Collect all identifiers for this vuln
			allIDs := append([]string{v.ID}, v.Aliases...)
			if v.CVE != "" {
				allIDs = append(allIDs, v.CVE)
			}

			// Check if we've seen any of these IDs before
			var existing *compare.VulnerabilityChange
			for _, id := range allIDs {
				if e, ok := idToVuln[id]; ok {
					existing = e
					break
				}
			}

			if existing != nil {
				// Merge into existing
				mergeVulnerabilityChange(existing, v)
			} else {
				// New unique vulnerability
				clone := *v
				for _, id := range allIDs {
					idToVuln[id] = &clone
				}
				if v.CVE != "" {
					cveMap[v.CVE] = &clone
				}
				result = append(result, clone)
			}
		}
	}

	return result
}

// mergeVulnerabilityChange merges src into dst, preferring CVE as primary ID.
func mergeVulnerabilityChange(dst, src *compare.VulnerabilityChange) {
	// Prefer CVE as primary ID
	if src.CVE != "" && !strings.HasPrefix(dst.ID, "CVE-") && strings.HasPrefix(src.CVE, "CVE-") {
		// Swap: make CVE the primary ID, demote current ID to alias
		if dst.ID != src.CVE {
			dst.Aliases = appendUniqueString(dst.Aliases, dst.ID)
		}
		dst.ID = src.CVE
		dst.CVE = src.CVE
	}

	// Merge aliases
	dst.Aliases = appendUniqueString(dst.Aliases, src.ID)
	for _, a := range src.Aliases {
		dst.Aliases = appendUniqueString(dst.Aliases, a)
	}

	// Remove primary ID and CVE from aliases
	dst.Aliases = filterStrings(dst.Aliases, dst.ID, dst.CVE)

	// Take best severity (prefer named severity over unknown)
	if dst.Severity == "" || dst.Severity == "UNKNOWN" {
		if src.Severity != "" && src.Severity != "UNKNOWN" {
			dst.Severity = src.Severity
			dst.SeverityType = src.SeverityType
		}
	}

	// Merge fixed versions
	for _, fv := range src.FixedVersions {
		dst.FixedVersions = appendUniqueString(dst.FixedVersions, fv)
	}

	// Take summary if missing
	if dst.Summary == "" {
		dst.Summary = src.Summary
	}

	// Take CVE if missing
	if dst.CVE == "" {
		dst.CVE = src.CVE
	}
}

func appendUniqueString(slice []string, s string) []string {
	if s == "" {
		return slice
	}
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

func filterStrings(slice []string, exclude ...string) []string {
	excludeSet := make(map[string]bool)
	for _, e := range exclude {
		if e != "" {
			excludeSet[e] = true
		}
	}
	var result []string
	for _, s := range slice {
		if !excludeSet[s] {
			result = append(result, s)
		}
	}
	return result
}

// renderVulnSummaryBySeverity shows a compact summary grouped by severity.
func renderVulnSummaryBySeverity(w io.Writer, vulns []compare.VulnerabilityChange) {
	bySev := groupVulnsBySeverity(vulns)
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		if list, ok := bySev[sev]; ok && len(list) > 0 {
			sevStyle := vulnSeverityStyle(sev)
			fmt.Fprintf(w, "      %s %s\n",
				sevStyle.Render(fmt.Sprintf("%d %s", len(list), sev)),
				ui.StyleDim.Render(vulnIDList(list, 3)),
			)
		}
	}
}

// renderVulnList shows detailed vulnerability information.
func renderVulnList(w io.Writer, vulns []compare.VulnerabilityChange) {
	// Group by package for readability
	byPkg := make(map[string][]compare.VulnerabilityChange)
	var pkgOrder []string
	for _, v := range vulns {
		if _, seen := byPkg[v.Package]; !seen {
			pkgOrder = append(pkgOrder, v.Package)
		}
		byPkg[v.Package] = append(byPkg[v.Package], v)
	}

	for _, pkg := range pkgOrder {
		list := byPkg[pkg]
		if len(list) == 0 {
			continue
		}

		// Package header with version
		version := list[0].TargetVersion
		if version == "" {
			version = list[0].BaseVersion
		}
		fmt.Fprintf(w, "\n      %s %s\n",
			ui.StylePackageName.Render(pkg),
			ui.StyleVersion.Render("@"+version),
		)

		// List each vulnerability
		for _, v := range list {
			renderSingleVuln(w, v)
		}
	}
}

// renderSingleVuln renders a single vulnerability with all its details.
func renderSingleVuln(w io.Writer, v compare.VulnerabilityChange) {
	// Main line: severity label + ID + CVE alias if different
	sevLabel := vulnSeverityLabel(v.Severity)
	idPart := v.ID

	// Show CVE if it's different from the primary ID
	if v.CVE != "" && v.CVE != v.ID {
		idPart = fmt.Sprintf("%s %s", v.ID, ui.StyleAlias.Render(v.CVE))
	}

	// Fix indicator
	fixPart := ""
	if len(v.FixedVersions) > 0 {
		bestFix := findBestFixVersion(v.FixedVersions, v.TargetVersion)
		if bestFix != "" {
			fixPart = ui.StyleUpgraded.Render(fmt.Sprintf(" (↑ %s)", bestFix))
		} else {
			fixPart = ui.StyleUpgraded.Render(" (fix available)")
		}
	}

	// Layer context indicator - show where the vuln was introduced
	layerPart := ""
	if v.LayerDetails != nil {
		if v.LayerDetails.InBaseImage {
			layerPart = ui.StyleMeta.Render(" [base image]")
		} else {
			// Show layer type hint based on command
			hint := getLayerHint(v.LayerDetails.Command)
			if hint != "" {
				layerPart = ui.StyleDim.Render(fmt.Sprintf(" [%s]", hint))
			}
		}
	}

	fmt.Fprintf(w, "        %s %s%s%s\n", sevLabel, idPart, fixPart, layerPart)

	// Summary line (truncated if too long)
	if v.Summary != "" {
		summary := v.Summary
		if len(summary) > 80 {
			summary = summary[:77] + "..."
		}
		fmt.Fprintf(w, "          %s\n", ui.StyleDim.Render(summary))
	}

	// Show additional aliases if present (excluding CVE already shown)
	aliases := filterAliases(v.Aliases, v.ID, v.CVE)
	if len(aliases) > 0 {
		aliasStr := strings.Join(aliases[:min(3, len(aliases))], ", ")
		if len(aliases) > 3 {
			aliasStr += fmt.Sprintf(" +%d more", len(aliases)-3)
		}
		fmt.Fprintf(w, "          %s %s\n", ui.StyleMeta.Render("Also:"), ui.StyleAliasOther.Render(aliasStr))
	}
}

// vulnSeverityLabel returns a styled severity label like [CRITICAL].
func vulnSeverityLabel(sev string) string {
	s := strings.ToUpper(sev)
	switch s {
	case "CRITICAL":
		return ui.StyleCritical.Render("[CRITICAL]")
	case "HIGH":
		return ui.StyleRemoved.Render("[HIGH]")
	case "MEDIUM", "MODERATE":
		return ui.StyleDowngraded.Render("[MED]")
	case "LOW":
		return ui.StyleVersion.Render("[LOW]")
	default:
		return ui.StyleVersion.Render("[?]")
	}
}

// sortVulnsBySeverity sorts vulnerabilities by severity (critical first), then by ID.
func sortVulnsBySeverity(vulns []compare.VulnerabilityChange) {
	sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4, "": 5}
	slices.SortFunc(vulns, func(a, b compare.VulnerabilityChange) int {
		oa := sevOrder[strings.ToUpper(a.Severity)]
		ob := sevOrder[strings.ToUpper(b.Severity)]
		if oa != ob {
			return oa - ob
		}
		return strings.Compare(a.ID, b.ID)
	})
}

// countBySeverity returns counts of critical, high, medium, low vulnerabilities.
func countBySeverity(vulns []compare.VulnerabilityChange) (critical, high, med, low int) {
	for _, v := range vulns {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM", "MODERATE":
			med++
		default:
			low++
		}
	}
	return
}

// countFixable returns the number of vulnerabilities with available fixes.
func countFixable(vulns []compare.VulnerabilityChange) int {
	count := 0
	for _, v := range vulns {
		if len(v.FixedVersions) > 0 {
			count++
		}
	}
	return count
}

// findBestFixVersion finds the best "in-band" fix version from a list.
// It prefers fixes within the same major version band when possible.
// For example, if current is 1.37.0-r18 and fixes are [1.36.1-r21, 2.0.0],
// it will prefer the 1.x fix over jumping to 2.x.
func findBestFixVersion(fixedVersions []string, currentVersion string) string {
	if len(fixedVersions) == 0 {
		return ""
	}
	if currentVersion == "" {
		// No current version to compare, return first available
		return fixedVersions[0]
	}

	currentMajor := extractMajorVersion(currentVersion)

	// First pass: find all fixes in the same major version band
	var sameBandFixes []string
	for _, fix := range fixedVersions {
		fixMajor := extractMajorVersion(fix)
		if fixMajor == currentMajor {
			sameBandFixes = append(sameBandFixes, fix)
		}
	}

	// If we have in-band fixes, find the minimum one that's >= current
	if len(sameBandFixes) > 0 {
		// Sort and return the smallest in-band fix
		slices.SortFunc(sameBandFixes, compareVersionStrings)
		for _, fix := range sameBandFixes {
			if compareVersionStrings(fix, currentVersion) >= 0 {
				return fix
			}
		}
		// All in-band fixes are below current (backports) - return the highest one
		return sameBandFixes[len(sameBandFixes)-1]
	}

	// No in-band fixes - return the smallest fix that's >= current
	sorted := slices.Clone(fixedVersions)
	slices.SortFunc(sorted, compareVersionStrings)
	for _, fix := range sorted {
		if compareVersionStrings(fix, currentVersion) >= 0 {
			return fix
		}
	}

	// All fixes are below current (all backports) - return first available
	return fixedVersions[0]
}

// extractMajorVersion extracts the major version component from a version string.
// Handles various formats: "1.2.3", "v1.2.3", "1.2.3-r4" (Alpine), etc.
func extractMajorVersion(version string) string {
	v := strings.TrimPrefix(version, "v")

	// Handle empty version
	if v == "" {
		return ""
	}

	// Extract first numeric segment
	var major strings.Builder
	for _, c := range v {
		if c >= '0' && c <= '9' {
			major.WriteRune(c)
		} else {
			break
		}
	}
	return major.String()
}

// compareVersionStrings provides a best-effort version comparison.
// Returns negative if a < b, 0 if equal, positive if a > b.
func compareVersionStrings(a, b string) int {
	// Normalize versions
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")

	if a == b {
		return 0
	}

	// Split into components
	partsA := splitVersionParts(a)
	partsB := splitVersionParts(b)

	// Compare each component
	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		var numA, numB int
		var strA, strB string

		if i < len(partsA) {
			numA, strA = parseVersionPart(partsA[i])
		}
		if i < len(partsB) {
			numB, strB = parseVersionPart(partsB[i])
		}

		// Compare numeric parts first
		if numA != numB {
			return numA - numB
		}

		// If numeric parts equal, compare string suffixes
		if strA != strB {
			return strings.Compare(strA, strB)
		}
	}

	return 0
}

// splitVersionParts splits a version string into comparable parts.
// "1.2.3-r4" -> ["1", "2", "3", "r4"]
func splitVersionParts(v string) []string {
	var parts []string
	var current strings.Builder

	for _, c := range v {
		if c == '.' || c == '-' || c == '_' || c == '+' {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(c)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

// parseVersionPart extracts numeric prefix and remaining string from a version part.
// "r21" -> (21, "r"), "3" -> (3, ""), "alpha" -> (0, "alpha")
func parseVersionPart(part string) (int, string) {
	// Check if it starts with a letter prefix (like "r" in Alpine's "-r21")
	if len(part) > 0 && (part[0] < '0' || part[0] > '9') {
		// Find where digits start
		digitStart := -1
		for i, c := range part {
			if c >= '0' && c <= '9' {
				digitStart = i
				break
			}
		}
		if digitStart > 0 {
			prefix := part[:digitStart]
			numStr := part[digitStart:]
			num := 0
			for _, c := range numStr {
				if c >= '0' && c <= '9' {
					num = num*10 + int(c-'0')
				} else {
					break
				}
			}
			return num, prefix
		}
		return 0, part
	}

	// Starts with digit - extract numeric part
	num := 0
	suffix := ""
	foundNonDigit := false
	for i, c := range part {
		if c >= '0' && c <= '9' && !foundNonDigit {
			num = num*10 + int(c-'0')
		} else {
			foundNonDigit = true
			suffix = part[i:]
			break
		}
	}
	return num, suffix
}

// filterAliases filters out the primary ID and CVE from the alias list.
func filterAliases(aliases []string, primaryID, cve string) []string {
	var result []string
	for _, a := range aliases {
		if a != primaryID && a != cve && a != "" {
			result = append(result, a)
		}
	}
	return result
}

// formatSeverityBreakdown returns a parenthesized severity breakdown like "(2 medium, 3 low)"
func formatSeverityBreakdown(critical, high, medium, low int) string {
	var parts []string
	if critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", critical))
	}
	if high > 0 {
		parts = append(parts, fmt.Sprintf("%d high", high))
	}
	if medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", medium))
	}
	if low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", low))
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func vulnSeverityStyle(sev string) lipgloss.Style {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return ui.StyleCritical
	case "HIGH":
		return ui.StyleRemoved
	case "MEDIUM", "MODERATE":
		return ui.StyleDowngraded
	default:
		return ui.StyleDim
	}
}

func groupVulnsBySeverity(vulns []compare.VulnerabilityChange) map[string][]compare.VulnerabilityChange {
	result := make(map[string][]compare.VulnerabilityChange)
	for _, v := range vulns {
		sev := strings.ToUpper(v.Severity)
		if sev == "" {
			sev = "UNKNOWN"
		}
		result[sev] = append(result[sev], v)
	}
	return result
}

func vulnIDList(vulns []compare.VulnerabilityChange, max int) string {
	if len(vulns) == 0 {
		return ""
	}
	ids := make([]string, 0, max)
	for i, v := range vulns {
		if i >= max {
			ids = append(ids, fmt.Sprintf("+%d more", len(vulns)-max))
			break
		}
		ids = append(ids, v.ID)
	}
	return "(" + strings.Join(ids, ", ") + ")"
}

func hasConfigChanges(cc *compare.ImageConfigDiff) bool {
	return cc.UserChanged || cc.RootChanged || cc.PortsChanged ||
		cc.VolumesChanged || cc.EntrypointChanged || cc.CmdChanged ||
		cc.WorkingDirChanged || cc.HealthcheckChanged ||
		len(cc.EnvChanges) > 0 || len(cc.LabelChanges) > 0
}

func renderContainerConfigChanges(w io.Writer, cc *compare.ImageConfigDiff) {
	fmt.Fprintln(w, ui.StyleHeader.Render("Configuration Changes:"))

	// Security-critical: root user changes
	if cc.RootChanged {
		if cc.TargetIsRoot && !cc.BaseIsRoot {
			fmt.Fprintf(w, "  %s %s (security risk)\n",
				ui.StyleRemoved.Render("!"),
				ui.StyleRemoved.Render("Now running as root"),
			)
		} else if !cc.TargetIsRoot && cc.BaseIsRoot {
			fmt.Fprintf(w, "  %s %s\n",
				ui.StyleAdded.Render("✓"),
				ui.StyleAdded.Render("No longer running as root"),
			)
		}
	}

	// User changes
	if cc.UserChanged {
		baseUser := cc.BaseUser
		if baseUser == "" {
			baseUser = "(default)"
		}
		targetUser := cc.TargetUser
		if targetUser == "" {
			targetUser = "(default)"
		}
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleNeutral.Render("~"),
			ui.StyleMeta.Render("USER"),
		)
		fmt.Fprintf(w, "      %s %s\n", ui.StyleRemoved.Render("-"), ui.StyleRemoved.Render(baseUser))
		fmt.Fprintf(w, "      %s %s\n", ui.StyleAdded.Render("+"), ui.StyleAdded.Render(targetUser))
	}

	// Entrypoint changes with before/after
	if cc.EntrypointChanged {
		baseEP := formatCmdSlice(cc.BaseEntrypoint)
		targetEP := formatCmdSlice(cc.TargetEntrypoint)
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleNeutral.Render("~"),
			ui.StyleMeta.Render("ENTRYPOINT"),
		)
		fmt.Fprintf(w, "      %s %s\n", ui.StyleRemoved.Render("-"), ui.StyleRemoved.Render(baseEP))
		fmt.Fprintf(w, "      %s %s\n", ui.StyleAdded.Render("+"), ui.StyleAdded.Render(targetEP))
	}

	// CMD changes with before/after
	if cc.CmdChanged {
		baseCmd := formatCmdSlice(cc.BaseCmd)
		targetCmd := formatCmdSlice(cc.TargetCmd)
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleNeutral.Render("~"),
			ui.StyleMeta.Render("CMD"),
		)
		fmt.Fprintf(w, "      %s %s\n", ui.StyleRemoved.Render("-"), ui.StyleRemoved.Render(baseCmd))
		fmt.Fprintf(w, "      %s %s\n", ui.StyleAdded.Render("+"), ui.StyleAdded.Render(targetCmd))
	}

	// Working directory changes
	if cc.WorkingDirChanged {
		baseWD := cc.BaseWorkingDir
		if baseWD == "" {
			baseWD = "/"
		}
		targetWD := cc.TargetWorkingDir
		if targetWD == "" {
			targetWD = "/"
		}
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleNeutral.Render("~"),
			ui.StyleMeta.Render("WORKDIR"),
		)
		fmt.Fprintf(w, "      %s %s\n", ui.StyleRemoved.Render("-"), ui.StyleRemoved.Render(baseWD))
		fmt.Fprintf(w, "      %s %s\n", ui.StyleAdded.Render("+"), ui.StyleAdded.Render(targetWD))
	}

	// Port changes
	if cc.PortsChanged {
		if len(cc.PortsAdded) > 0 {
			fmt.Fprintf(w, "  %s %s %s\n",
				ui.StyleAdded.Render("+"),
				ui.StyleMeta.Render("EXPOSE"),
				ui.StyleAdded.Render(strings.Join(cc.PortsAdded, ", ")),
			)
		}
		if len(cc.PortsRemoved) > 0 {
			fmt.Fprintf(w, "  %s %s %s\n",
				ui.StyleRemoved.Render("-"),
				ui.StyleMeta.Render("EXPOSE"),
				ui.StyleRemoved.Render(strings.Join(cc.PortsRemoved, ", ")),
			)
		}
	}

	// Volume changes
	if cc.VolumesChanged {
		if len(cc.VolumesAdded) > 0 {
			fmt.Fprintf(w, "  %s %s %s\n",
				ui.StyleAdded.Render("+"),
				ui.StyleMeta.Render("VOLUME"),
				ui.StyleAdded.Render(strings.Join(cc.VolumesAdded, ", ")),
			)
		}
		if len(cc.VolumesRemoved) > 0 {
			fmt.Fprintf(w, "  %s %s %s\n",
				ui.StyleRemoved.Render("-"),
				ui.StyleMeta.Render("VOLUME"),
				ui.StyleRemoved.Render(strings.Join(cc.VolumesRemoved, ", ")),
			)
		}
	}

	// Environment variable changes
	if len(cc.EnvChanges) > 0 {
		for _, env := range cc.EnvChanges {
			renderEnvChange(w, env)
		}
	}

	// Healthcheck changes
	if cc.HealthcheckChanged {
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleNeutral.Render("~"),
			ui.StyleMeta.Render("HEALTHCHECK changed"),
		)
	}

	// Label changes
	if len(cc.LabelChanges) > 0 {
		for _, label := range cc.LabelChanges {
			renderLabelChange(w, label)
		}
	}

	fmt.Fprintln(w)
}

// formatCmdSlice formats a command slice for display.
func formatCmdSlice(cmd []string) string {
	if len(cmd) == 0 {
		return "(none)"
	}
	// Show as JSON-like array for clarity
	result := "[" + strings.Join(cmd, ", ") + "]"
	if len(result) > 50 {
		return result[:47] + "...]"
	}
	return result
}

// renderEnvChange renders a single environment variable change.
func renderEnvChange(w io.Writer, env compare.EnvChange) {
	// Mask sensitive values
	baseVal := env.BaseValue
	targetVal := env.TargetValue
	if env.IsSensitive {
		if baseVal != "" {
			baseVal = "***"
		}
		if targetVal != "" {
			targetVal = "***"
		}
	}

	switch env.ChangeType {
	case compare.Added:
		val := targetVal
		if len(val) > 30 {
			val = val[:27] + "..."
		}
		fmt.Fprintf(w, "  %s %s %s=%s\n",
			ui.StyleAdded.Render("+"),
			ui.StyleMeta.Render("ENV"),
			ui.StyleBold.Render(env.Name),
			ui.StyleAdded.Render(val),
		)
	case compare.Removed:
		fmt.Fprintf(w, "  %s %s %s\n",
			ui.StyleRemoved.Render("-"),
			ui.StyleMeta.Render("ENV"),
			ui.StyleRemoved.Render(env.Name),
		)
	case compare.Updated:
		bv := baseVal
		tv := targetVal
		if len(bv) > 40 {
			bv = bv[:37] + "..."
		}
		if len(tv) > 40 {
			tv = tv[:37] + "..."
		}
		// Use git-diff style for consistency with layer changes
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleNeutral.Render("~"),
			ui.StyleMeta.Render(fmt.Sprintf("ENV %s", env.Name)),
		)
		fmt.Fprintf(w, "      %s %s=%s\n",
			ui.StyleRemoved.Render("-"),
			env.Name,
			ui.StyleRemoved.Render(bv),
		)
		fmt.Fprintf(w, "      %s %s=%s\n",
			ui.StyleAdded.Render("+"),
			env.Name,
			ui.StyleAdded.Render(tv),
		)
	}
}

// renderLabelChange renders a single label change.
func renderLabelChange(w io.Writer, label compare.LabelChange) {
	switch label.ChangeType {
	case compare.Added:
		val := label.TargetValue
		if len(val) > 40 {
			val = val[:37] + "..."
		}
		fmt.Fprintf(w, "  %s %s %s=%s\n",
			ui.StyleAdded.Render("+"),
			ui.StyleMeta.Render("LABEL"),
			ui.StyleBold.Render(label.Key),
			ui.StyleAdded.Render(val),
		)
	case compare.Removed:
		fmt.Fprintf(w, "  %s %s %s\n",
			ui.StyleRemoved.Render("-"),
			ui.StyleMeta.Render("LABEL"),
			ui.StyleRemoved.Render(label.Key),
		)
	case compare.Updated:
		bv := label.BaseValue
		tv := label.TargetValue
		if len(bv) > 40 {
			bv = bv[:37] + "..."
		}
		if len(tv) > 40 {
			tv = tv[:37] + "..."
		}
		// Use git-diff style for consistency with layer changes
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleNeutral.Render("~"),
			ui.StyleMeta.Render(fmt.Sprintf("LABEL %s", label.Key)),
		)
		fmt.Fprintf(w, "      %s %s=%s\n",
			ui.StyleRemoved.Render("-"),
			label.Key,
			ui.StyleRemoved.Render(bv),
		)
		fmt.Fprintf(w, "      %s %s=%s\n",
			ui.StyleAdded.Render("+"),
			label.Key,
			ui.StyleAdded.Render(tv),
		)
	}
}

func renderContainerLayerAnalysis(w io.Writer, la *compare.LayerDiffAnalysis) {
	fmt.Fprintln(w, ui.StyleHeader.Render("Layer Analysis:"))

	// Show layer count summary inline
	layerDelta := la.TargetLayerCount - la.BaseLayerCount
	deltaStr := ""
	if layerDelta > 0 {
		deltaStr = ui.StyleAdded.Render(fmt.Sprintf(" (+%d)", layerDelta))
	} else if layerDelta < 0 {
		deltaStr = ui.StyleRemoved.Render(fmt.Sprintf(" (%d)", layerDelta))
	}
	fmt.Fprintf(w, "  %s %d → %d%s",
		ui.StyleMeta.Render("Layers:"),
		la.BaseLayerCount,
		la.TargetLayerCount,
		deltaStr,
	)

	// Show layer change breakdown by type
	var addedCount, removedCount, modifiedCount int
	for _, lc := range la.LayerChanges {
		switch lc.Type {
		case "added":
			addedCount++
		case "removed":
			removedCount++
		case "modified":
			modifiedCount++
		}
	}

	// Only show breakdown if there are changes
	if addedCount > 0 || removedCount > 0 || modifiedCount > 0 {
		parts := []string{}
		if addedCount > 0 {
			parts = append(parts, fmt.Sprintf("%d added", addedCount))
		}
		if removedCount > 0 {
			parts = append(parts, fmt.Sprintf("%d removed", removedCount))
		}
		if modifiedCount > 0 {
			parts = append(parts, fmt.Sprintf("%d modified", modifiedCount))
		}
		fmt.Fprintf(w, " %s", ui.StyleDim.Render("("+strings.Join(parts, ", ")+")"))
	}
	fmt.Fprintln(w)

	// Categorize layer changes
	var added, removed, modified []compare.LayerChange
	for _, lc := range la.LayerChanges {
		switch lc.Type {
		case "added":
			added = append(added, lc)
		case "removed":
			removed = append(removed, lc)
		case "modified":
			modified = append(modified, lc)
		}
	}

	hasChanges := len(added) > 0 || len(removed) > 0 || len(modified) > 0
	if !hasChanges {
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w)

	// Show removed layers first
	for _, lc := range removed {
		cmd := formatLayerCommand(lc.BaseCommand)
		fmt.Fprintf(w, "  %s %s %s\n",
			ui.StyleRemoved.Render("-"),
			ui.StyleDim.Render(fmt.Sprintf("[L%d]", lc.Index)),
			cmd,
		)
	}

	// Show added layers
	for _, lc := range added {
		cmd := formatLayerCommand(lc.TargetCommand)
		fmt.Fprintf(w, "  %s %s %s\n",
			ui.StyleAdded.Render("+"),
			ui.StyleDim.Render(fmt.Sprintf("[L%d]", lc.Index)),
			cmd,
		)
	}

	// Show modified layers (when same layer count but content differs)
	// Only show if there are no added/removed (i.e., rebuild scenario)
	if len(added) == 0 && len(removed) == 0 && len(modified) > 0 {
		// Show up to 5 most interesting modified layers
		shown := 0
		for _, lc := range modified {
			if shown >= 5 {
				remaining := len(modified) - shown
				fmt.Fprintf(w, "  %s %s\n",
					ui.StyleDim.Render("..."),
					ui.StyleDim.Render(fmt.Sprintf("and %d more modified layers", remaining)),
				)
				break
			}
			// Only show if the command actually changed meaningfully
			baseCmd := formatLayerCommand(lc.BaseCommand)
			targetCmd := formatLayerCommand(lc.TargetCommand)
			if baseCmd != targetCmd && baseCmd != "(empty layer)" && targetCmd != "(empty layer)" {
				fmt.Fprintf(w, "  %s %s\n",
					ui.StyleNeutral.Render("~"),
					ui.StyleDim.Render(fmt.Sprintf("[L%d]", lc.Index)),
				)
				fmt.Fprintf(w, "      %s %s\n",
					ui.StyleRemoved.Render("-"),
					ui.StyleDim.Render(baseCmd),
				)
				fmt.Fprintf(w, "      %s %s\n",
					ui.StyleAdded.Render("+"),
					targetCmd,
				)
				shown++
			}
		}
	}

	fmt.Fprintln(w)
}

// formatLayerCommand formats a Dockerfile command for display.
// It extracts the meaningful part (e.g., "RUN apt-get install...") and truncates if needed.
func formatLayerCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ui.StyleDim.Render("(empty layer)")
	}

	// Extract command type and simplify display
	// Common patterns: "/bin/sh -c #(nop) CMD [...]" or "/bin/sh -c apt-get..."
	if strings.Contains(cmd, "#(nop)") {
		// Metadata command like CMD, ENV, EXPOSE
		parts := strings.SplitN(cmd, "#(nop)", 2)
		if len(parts) == 2 {
			cmd = strings.TrimSpace(parts[1])
		}
	} else if strings.HasPrefix(cmd, "/bin/sh -c ") {
		// RUN command
		cmd = "RUN " + strings.TrimPrefix(cmd, "/bin/sh -c ")
	}

	// Truncate long commands but show more context
	maxLen := 70
	if len(cmd) > maxLen {
		return cmd[:maxLen-3] + "..."
	}
	return cmd
}

func renderContainerDiffSummary(w io.Writer, summary compare.ImageDiffSummary) {
	fmt.Fprintln(w, ui.StyleHeader.Render("Summary:"))
	if summary.PackagesAdded > 0 {
		fmt.Fprintf(w, "  %s %d package%s added\n", ui.StyleAdded.Render("+"), summary.PackagesAdded, plural(summary.PackagesAdded))
	}
	if summary.PackagesRemoved > 0 {
		fmt.Fprintf(w, "  %s %d package%s removed\n", ui.StyleRemoved.Render("-"), summary.PackagesRemoved, plural(summary.PackagesRemoved))
	}
	if summary.PackagesUpgraded > 0 {
		fmt.Fprintf(w, "  %s %d package%s upgraded\n", ui.StyleUpgraded.Render("↑"), summary.PackagesUpgraded, plural(summary.PackagesUpgraded))
	}
	if summary.PackagesDowngraded > 0 {
		fmt.Fprintf(w, "  %s %d package%s downgraded\n", ui.StyleDowngraded.Render("↓"), summary.PackagesDowngraded, plural(summary.PackagesDowngraded))
	}
	if summary.VulnerabilitiesAdded > 0 {
		fmt.Fprintf(w, "  %s %d vulnerabilit%s added\n", ui.StyleRemoved.Render("!"), summary.VulnerabilitiesAdded, pluralY(summary.VulnerabilitiesAdded))
	}
	if summary.VulnerabilitiesRemoved > 0 {
		fmt.Fprintf(w, "  %s %d vulnerabilit%s removed\n", ui.StyleAdded.Render("✓"), summary.VulnerabilitiesRemoved, pluralY(summary.VulnerabilitiesRemoved))
	}
	if summary.VulnerabilitiesFixed > 0 {
		fmt.Fprintf(w, "  %s %d vulnerabilit%s fixed\n", ui.StyleAdded.Render("✓"), summary.VulnerabilitiesFixed, pluralY(summary.VulnerabilitiesFixed))
	}
	if summary.LayersAdded > 0 {
		fmt.Fprintf(w, "  %s %d layer%s added\n", ui.StyleAdded.Render("+"), summary.LayersAdded, plural(summary.LayersAdded))
	}
	if summary.LayersRemoved > 0 {
		fmt.Fprintf(w, "  %s %d layer%s removed\n", ui.StyleRemoved.Render("-"), summary.LayersRemoved, plural(summary.LayersRemoved))
	}
	if summary.ConfigChanged {
		fmt.Fprintf(w, "  %s Configuration changed\n", ui.StyleNeutral.Render("~"))
	}
}

// renderContainerVulnerabilitySummary renders vulnerability summary and recommended actions,
// consistent with the Git diff output style.
func renderContainerVulnerabilitySummary(w io.Writer, changes []compare.VulnerabilityChange) {
	if len(changes) == 0 {
		return
	}

	// Consolidate and categorize vulnerabilities
	changes = consolidateVulnerabilityChanges(changes)

	// Count by category and severity
	var criticalHigh, fixable, unfixed int
	var persistedCriticalHigh int

	for _, v := range changes {
		sev := strings.ToUpper(v.Severity)
		isCriticalHigh := sev == "CRITICAL" || sev == "HIGH"
		hasFixAvailable := len(v.FixedVersions) > 0

		switch v.ChangeType {
		case compare.VulnAdded:
			if isCriticalHigh {
				criticalHigh++
			}
			if hasFixAvailable {
				fixable++
			} else {
				unfixed++
			}
		case compare.VulnPersisted:
			if isCriticalHigh {
				persistedCriticalHigh++
				criticalHigh++
			}
			if hasFixAvailable {
				fixable++
			} else {
				unfixed++
			}
		}
	}

	// Only show summary if there are actionable items
	if criticalHigh == 0 && fixable == 0 && unfixed == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleHeader.Render("Vulnerability Summary:"))

	if criticalHigh > 0 {
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render(ui.StyleRemoved.Render("!")),
			ui.StyleSymbol.Render(fmt.Sprintf("%d require immediate attention ", criticalHigh))+ui.StyleRemoved.Render("(critical/high severity)"),
		)
	}
	if fixable > 0 {
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render(ui.StyleUpgraded.Render("↑")),
			ui.StyleSymbol.Render(fmt.Sprintf("%d can be fixed by upgrading", fixable)),
		)
	}
	if unfixed > 0 {
		fmt.Fprintf(w, "  %s %s\n",
			ui.StyleSymbol.Render(ui.StyleRemoved.Render("-")),
			ui.StyleSymbol.Render(fmt.Sprintf("%d have no fix available yet", unfixed)),
		)
	}

	// Recommended actions section
	if fixable > 0 || persistedCriticalHigh > 0 || unfixed > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.StyleHeader.Render("Recommended Actions:"))
		step := 1

		// Suggest upgrading base image if there are persisted critical/high vulnerabilities
		if persistedCriticalHigh > 0 {
			fmt.Fprintf(w, "  %d. %s %s\n", step,
				ui.StyleBold.Render("Consider a newer base image"),
				ui.StyleVersion.Render(fmt.Sprintf("(%d critical/high vulnerabilities persist)", persistedCriticalHigh)),
			)
			step++
		}

		// Suggest package upgrades for fixable vulnerabilities
		if fixable > 0 {
			fmt.Fprintf(w, "  %d. %s %s\n", step,
				ui.StyleBold.Render("Upgrade packages with available fixes"),
				ui.StyleVersion.Render(fmt.Sprintf("(%d vulnerabilities can be resolved)", fixable)),
			)
			renderFixablePackages(w, changes)
			step++
		}

		// Note about unfixed vulnerabilities
		if unfixed > 0 {
			fmt.Fprintf(w, "  %d. %s %s\n", step,
				ui.StyleBold.Render("Monitor unfixed vulnerabilities"),
				ui.StyleVersion.Render("(check upstream for patches / consider alternatives)"),
			)
		}
	}
}

// renderFixablePackages shows a compact list of packages with available fixes,
// including layer context to help users understand where the package was introduced.
func renderFixablePackages(w io.Writer, changes []compare.VulnerabilityChange) {
	// Group fixable vulnerabilities by package
	type pkgFix struct {
		pkg         string
		version     string
		fixes       []string
		count       int
		layerIdx    int    // Layer index where package was introduced (-1 if unknown)
		layerCmd    string // Dockerfile command that introduced the package
		inBaseImage bool   // Whether package is from the base image
	}
	pkgFixes := make(map[string]*pkgFix)

	for _, v := range changes {
		if len(v.FixedVersions) == 0 {
			continue
		}
		if v.ChangeType != compare.VulnAdded && v.ChangeType != compare.VulnPersisted {
			continue
		}

		key := v.Package
		if pf, ok := pkgFixes[key]; ok {
			pf.count++
			// Merge fix versions
			for _, fv := range v.FixedVersions {
				found := false
				for _, existing := range pf.fixes {
					if existing == fv {
						found = true
						break
					}
				}
				if !found {
					pf.fixes = append(pf.fixes, fv)
				}
			}
		} else {
			version := v.TargetVersion
			if version == "" {
				version = v.BaseVersion
			}
			pf := &pkgFix{
				pkg:      v.Package,
				version:  version,
				fixes:    append([]string{}, v.FixedVersions...),
				count:    1,
				layerIdx: -1,
			}
			// Capture layer info if available
			if v.LayerDetails != nil {
				pf.layerIdx = v.LayerDetails.Index
				pf.layerCmd = v.LayerDetails.Command
				pf.inBaseImage = v.LayerDetails.InBaseImage
			}
			pkgFixes[key] = pf
		}
	}

	// Sort by vulnerability count (most first)
	sorted := make([]*pkgFix, 0, len(pkgFixes))
	for _, pf := range pkgFixes {
		sorted = append(sorted, pf)
	}
	slices.SortFunc(sorted, func(a, b *pkgFix) int {
		if a.count != b.count {
			return b.count - a.count // descending
		}
		return strings.Compare(a.pkg, b.pkg)
	})

	// Show all fixable packages - users need complete actionable info
	for _, pf := range sorted {
		// Use in-band version preference for the fix recommendation
		bestFix := findBestFixVersion(pf.fixes, pf.version)
		vulnNote := ""
		if pf.count > 1 {
			vulnNote = fmt.Sprintf(" (%d vulns)", pf.count)
		}
		fmt.Fprintf(w, "       %s %s %s %s%s\n",
			ui.StyleUpgraded.Render("›"),
			ui.StylePackageName.Render(pf.pkg),
			ui.StyleVersion.Render(pf.version+" →"),
			ui.StyleUpgraded.Render(bestFix),
			ui.StyleDim.Render(vulnNote),
		)
		// Show layer context if available (actionable info for users)
		if pf.layerIdx >= 0 {
			layerContext := formatLayerContextWithPkg(pf.layerIdx, pf.layerCmd, pf.inBaseImage, pf.pkg)
			if layerContext != "" {
				fmt.Fprintf(w, "         %s\n", ui.StyleDim.Render(layerContext))
			}
		}
	}
}

// formatLayerContext creates a human-readable, actionable description of where
// a package was introduced and how to fix it.
func formatLayerContext(layerIdx int, cmd string, inBaseImage bool) string {
	return formatLayerContextWithPkg(layerIdx, cmd, inBaseImage, "")
}

// formatLayerContextWithPkg creates a human-readable, actionable description
// with package-specific guidance when available.
func formatLayerContextWithPkg(layerIdx int, cmd string, inBaseImage bool, pkgName string) string {
	// Determine package type and provide actionable guidance
	pkgType, action := categorizePackageSourceWithPkg(cmd, inBaseImage, pkgName)

	if pkgType == "" && !inBaseImage {
		return "" // Not enough info to be helpful
	}

	var parts []string

	// Base image packages
	if inBaseImage {
		if pkgType != "" {
			parts = append(parts, fmt.Sprintf("base image, %s", pkgType))
		} else {
			parts = append(parts, "base image")
		}
		if action == "" {
			action = "update base image"
		}
	} else if pkgType != "" {
		parts = append(parts, pkgType)
	}

	if action != "" {
		parts = append(parts, action)
	}

	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, " - ") + "]"
}

// getLayerHint returns a short, human-readable hint about the layer type.
// Used in vulnerability output to show where the vuln was introduced.
func getLayerHint(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	for _, prefix := range []string{"/bin/sh -c ", "sh -c ", "#(nop) "} {
		cmd = strings.TrimPrefix(cmd, prefix)
	}
	cmd = strings.TrimSpace(cmd)

	switch {
	case strings.Contains(cmd, "apt-get") || strings.Contains(cmd, "apt install"):
		return "apt"
	case strings.Contains(cmd, "apk add"):
		return "apk"
	case strings.Contains(cmd, "yum install") || strings.Contains(cmd, "dnf install"):
		return "yum"
	case strings.Contains(cmd, "pip install"):
		return "pip"
	case strings.Contains(cmd, "npm install"):
		return "npm"
	case strings.HasPrefix(cmd, "COPY") || strings.HasPrefix(cmd, "ADD"):
		return "copied binary"
	case strings.Contains(cmd, "go build") || strings.Contains(cmd, "go install"):
		return "go build"
	}
	return "" // No hint - don't show anything confusing
}

// categorizePackageSource determines the package type and suggests a fix action.
func categorizePackageSource(cmd string, inBaseImage bool) (pkgType string, action string) {
	return categorizePackageSourceWithPkg(cmd, inBaseImage, "")
}

// categorizePackageSourceWithPkg determines the package type and suggests a fix action,
// using the package name to provide more specific guidance.
func categorizePackageSourceWithPkg(cmd string, inBaseImage bool, pkgName string) (pkgType string, action string) {
	cmd = strings.TrimSpace(cmd)

	// Remove shell wrapper noise
	for _, prefix := range []string{
		"/bin/sh -c ",
		"sh -c ",
		"#(nop) ",
	} {
		cmd = strings.TrimPrefix(cmd, prefix)
	}
	cmd = strings.TrimSpace(cmd)

	// Check if this is a Go module (looks like a Go import path)
	isGoModule := strings.Contains(pkgName, "/") &&
		(strings.HasPrefix(pkgName, "golang.org/") ||
			strings.HasPrefix(pkgName, "github.com/") ||
			strings.HasPrefix(pkgName, "go.") ||
			strings.Contains(pkgName, ".io/") ||
			strings.Contains(pkgName, ".dev/") ||
			strings.Contains(pkgName, ".com/") ||
			strings.Contains(pkgName, ".org/"))

	// OS package managers - these are fixable by updating packages
	switch {
	case strings.Contains(cmd, "apt-get install") || strings.Contains(cmd, "apt install"):
		return "apt", "run apt-get upgrade"
	case strings.Contains(cmd, "apk add"):
		return "apk", "run apk upgrade"
	case strings.Contains(cmd, "yum install") || strings.Contains(cmd, "dnf install"):
		return "yum/dnf", "run yum update"

	// Language package managers - need rebuild
	case strings.Contains(cmd, "pip install"):
		return "pip", "update requirements.txt"
	case strings.Contains(cmd, "npm install"):
		return "npm", "update package.json"
	case strings.Contains(cmd, "go build") || strings.Contains(cmd, "go install"):
		if isGoModule {
			return "Go dep", fmt.Sprintf("go get %s@latest", pkgName)
		}
		return "Go binary", "rebuild with go get -u"

	// Binary copies - provide specific guidance based on package type
	case strings.HasPrefix(cmd, "COPY") || strings.HasPrefix(cmd, "ADD"):
		if isGoModule {
			return "Go dep in binary", fmt.Sprintf("go get %s@latest", pkgName)
		}
		// Try to extract binary name from COPY command
		binaryName := extractBinaryFromCopy(cmd)
		if binaryName != "" {
			return fmt.Sprintf("binary (%s)", binaryName), "rebuild binary"
		}
		return "binary", "rebuild binary from source"

	// Base image rootfs
	case strings.HasPrefix(cmd, "ADD") && strings.Contains(cmd, "rootfs"):
		return "rootfs", ""
	}

	// If we have a Go module but no layer command info, still provide guidance
	if isGoModule {
		return "Go dep", fmt.Sprintf("go get %s@latest", pkgName)
	}

	return "", ""
}

// extractBinaryFromCopy tries to extract the binary name from a COPY/ADD command.
func extractBinaryFromCopy(cmd string) string {
	// Common patterns:
	// COPY --from=builder /app/mybin /usr/local/bin/
	// COPY mybin /usr/local/bin/mybin
	// ADD https://example.com/mybin.tar.gz /opt/

	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		return ""
	}

	// Skip COPY/ADD and any flags
	i := 1
	for i < len(parts) && strings.HasPrefix(parts[i], "--") {
		i++
	}

	if i >= len(parts) {
		return ""
	}

	// Source path - extract just the filename
	src := parts[i]
	// Handle --from=builder style paths
	if idx := strings.LastIndex(src, "/"); idx >= 0 {
		src = src[idx+1:]
	}
	// Remove common extensions
	src = strings.TrimSuffix(src, ".tar.gz")
	src = strings.TrimSuffix(src, ".tgz")
	src = strings.TrimSuffix(src, ".tar")

	// Only return if it looks like a meaningful name
	if len(src) > 0 && len(src) < 30 && !strings.HasPrefix(src, ".") {
		return src
	}
	return ""
}

// summarizeDockerCommand extracts the most relevant part of a Dockerfile command.
func summarizeDockerCommand(cmd string) string {
	// Common patterns in container history
	cmd = strings.TrimSpace(cmd)

	// Remove shell wrapper noise
	for _, prefix := range []string{
		"/bin/sh -c ",
		"sh -c ",
		"#(nop) ",
	} {
		cmd = strings.TrimPrefix(cmd, prefix)
	}

	// Handle common Dockerfile instructions
	cmd = strings.TrimSpace(cmd)

	// If it's an apt-get/apk/yum install, highlight that
	if strings.Contains(cmd, "apt-get install") || strings.Contains(cmd, "apt install") {
		return "apt-get install"
	}
	if strings.Contains(cmd, "apk add") {
		return "apk add"
	}
	if strings.Contains(cmd, "yum install") || strings.Contains(cmd, "dnf install") {
		return "yum/dnf install"
	}
	if strings.Contains(cmd, "pip install") {
		return "pip install"
	}
	if strings.Contains(cmd, "npm install") {
		return "npm install"
	}

	// Truncate long commands
	if len(cmd) > 40 {
		cmd = cmd[:37] + "..."
	}

	return cmd
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// runContainerDiffPolicies evaluates policies against the container diff report.
func runContainerDiffPolicies(ctx context.Context, policyPaths []string, report *compare.ImageDiffReport, errW io.Writer) error {
	if len(policyPaths) == 0 || report == nil {
		return nil
	}

	// Build full report payload
	payload := scan.BuildContainerDiffPayload(report)
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "diff", policy.EntrypointContainerDiffReport, errW); err != nil {
		return err
	}

	// Evaluate per-change policies
	for _, change := range report.PackageChanges {
		changeMap, err := structToMap(change)
		if err != nil {
			continue
		}
		changePayload := map[string]any{
			"base_image":   payload["base_image"],
			"target_image": payload["target_image"],
			"change":       changeMap,
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, changePayload, "diff", policy.EntrypointContainerDiffChange, errW); err != nil {
			return err
		}
	}

	// Evaluate per-vulnerability policies
	for _, vuln := range report.VulnerabilityChanges {
		vulnMap, err := structToMap(vuln)
		if err != nil {
			continue
		}
		vulnPayload := map[string]any{
			"base_image":    payload["base_image"],
			"target_image":  payload["target_image"],
			"vulnerability": vulnMap,
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, vulnPayload, "diff", policy.EntrypointContainerDiffVulnerability, errW); err != nil {
			return err
		}
	}

	// Evaluate layer policies
	if report.LayerAnalysis != nil {
		for _, layer := range report.LayerAnalysis.LayerChanges {
			layerMap, err := structToMap(layer)
			if err != nil {
				continue
			}
			layerPayload := map[string]any{
				"base_image":   payload["base_image"],
				"target_image": payload["target_image"],
				"layer":        layerMap,
			}
			if _, err := evaluatePoliciesForCommand(ctx, policyPaths, layerPayload, "diff", policy.EntrypointContainerDiffLayer, errW); err != nil {
				return err
			}
		}
	}

	// Evaluate config policy
	if report.ConfigChanges != nil {
		configPayload := map[string]any{
			"base_image":     payload["base_image"],
			"target_image":   payload["target_image"],
			"config_changes": payload["config_changes"],
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, configPayload, "diff", policy.EntrypointContainerDiffConfig, errW); err != nil {
			return err
		}
	}

	return nil
}
