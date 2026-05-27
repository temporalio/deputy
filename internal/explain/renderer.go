package explain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/temporalio/deputy/internal/vulnerability/intel"
	"github.com/temporalio/deputy/internal/vulnerability/severity/cvss"
	"github.com/temporalio/deputy/internal/vulnerability/weakness/cwe"
)

// Config configures the vulnerability renderer.
type Config struct {
	// Enrich enables threat intelligence enrichment (EPSS, KEV).
	Enrich bool
	// DiskCache enables persistent caching for enrichment data.
	DiskCache bool
}

// Renderer renders vulnerability explanations.
type Renderer struct {
	cfg      Config
	enricher *intel.Enricher
}

// NewRenderer creates a new vulnerability renderer.
func NewRenderer(cfg Config) *Renderer {
	r := &Renderer{cfg: cfg}
	if cfg.Enrich {
		r.enricher = intel.NewEnricher(&intel.EnricherConfig{
			DiskCache: cfg.DiskCache,
		})
	}
	return r
}

// VulnData consolidates all information about a vulnerability.
type VulnData struct {
	// Core OSV data
	Vuln *osvschema.Vulnerability

	// Extracted/computed fields
	CVSSScore   float64
	CVSSVector  string
	CVSSVersion cvss.Version
	Severity    string
	CWEs        []CWEInfo

	// Temporal analysis
	Temporal TemporalInfo

	// Threat intelligence (nil if not enriched)
	Intel *intel.EnrichmentResult

	// Related vulnerabilities (resolved aliases)
	RelatedVulns []*osvschema.Vulnerability
}

// Render writes a comprehensive vulnerability explanation to the writer.
func (r *Renderer) Render(ctx context.Context, out io.Writer, vuln *osvschema.Vulnerability) error {
	if vuln == nil {
		return nil
	}

	data := r.buildVulnData(ctx, vuln)
	return r.renderText(out, data)
}

// RenderJSON writes vulnerability data as structured JSON.
func (r *Renderer) RenderJSON(ctx context.Context, out io.Writer, vuln *osvschema.Vulnerability) error {
	if vuln == nil {
		return nil
	}

	data := r.buildVulnData(ctx, vuln)
	return r.renderJSON(out, data)
}

// buildVulnData extracts and enriches all vulnerability information.
func (r *Renderer) buildVulnData(ctx context.Context, vuln *osvschema.Vulnerability) *VulnData {
	data := &VulnData{Vuln: vuln}

	// Extract CVSS info
	data.CVSSVector, data.CVSSScore = extractCVSSInfo(vuln)
	data.CVSSVersion = cvss.DetectVersion(data.CVSSVector)
	data.Severity = deriveSeverity(data.CVSSScore, vuln)

	// Extract CWEs
	data.CWEs = extractCWEs(vuln)

	// Build temporal info
	data.Temporal = TemporalInfo{
		Published: vuln.Published,
		Modified:  vuln.Modified,
	}

	// Enrich with threat intelligence
	if r.enricher != nil {
		cveID := findCVEID(vuln)
		if cveID != "" {
			result := r.enricher.Enrich(ctx, cveID)
			data.Intel = &result

			// Add KEV temporal data
			if result.KEV != nil {
				data.Temporal.KEVAdded = ParseDate(result.KEV.DateAdded)
				data.Temporal.KEVDueDate = ParseDate(result.KEV.DueDate)
			}

			// Derive severity from threat intel if CVSS unavailable
			if data.Severity == "UNKNOWN" {
				// KEV presence indicates high severity
				if result.InKEV != nil && *result.InKEV {
					data.Severity = "HIGH"
				} else if result.EPSS != nil && *result.EPSS > 0 {
					// Use EPSS to estimate severity
					epss := *result.EPSS
					switch {
					case epss >= 0.5:
						data.Severity = "HIGH"
					case epss >= 0.1:
						data.Severity = "MEDIUM"
					default:
						data.Severity = "LOW"
					}
				}
			}
		}
	}

	return data
}

// renderText renders the vulnerability in a beautiful text format.
func (r *Renderer) renderText(out io.Writer, data *VulnData) error {
	vuln := data.Vuln

	// ══════════════════════════════════════════════════════════════════════════
	// HEADER: ID, Severity, CVSS Score
	// ══════════════════════════════════════════════════════════════════════════
	r.renderHeader(out, data)

	// ══════════════════════════════════════════════════════════════════════════
	// SUMMARY: The most important one-liner
	// ══════════════════════════════════════════════════════════════════════════
	summary := vuln.Summary
	if summary == "" && vuln.Details != "" {
		// Use first sentence of details as summary if no summary provided
		summary = extractFirstSentence(vuln.Details, 120)
	}
	if summary != "" {
		fmt.Fprintln(out)
		fmt.Fprintln(out, styleSummary.Render(summary))
	}

	// ══════════════════════════════════════════════════════════════════════════
	// THREAT INTELLIGENCE: KEV, EPSS
	// ══════════════════════════════════════════════════════════════════════════
	if data.Intel != nil && (data.Intel.InKEV != nil && *data.Intel.InKEV || data.Intel.EPSS != nil) {
		fmt.Fprintln(out)
		r.renderThreatIntel(out, data)
	}

	// ══════════════════════════════════════════════════════════════════════════
	// TIMELINE: Temporal context
	// ══════════════════════════════════════════════════════════════════════════
	r.renderTimeline(out, data)

	// ══════════════════════════════════════════════════════════════════════════
	// WEAKNESS: CWE classification
	// ══════════════════════════════════════════════════════════════════════════
	if len(data.CWEs) > 0 {
		fmt.Fprintln(out)
		r.renderWeaknesses(out, data)
	}

	// ══════════════════════════════════════════════════════════════════════════
	// DETAILS: Full description
	// ══════════════════════════════════════════════════════════════════════════
	if vuln.Details != "" && vuln.Details != vuln.Summary {
		fmt.Fprintln(out)
		fmt.Fprintln(out, styleSection.Render("Description"))
		// Indent description content by 2 spaces to match other sections
		for _, line := range strings.Split(wrapText(vuln.Details, 76), "\n") {
			if line == "" {
				fmt.Fprintln(out)
			} else {
				fmt.Fprintf(out, "  %s\n", line)
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════════
	// AFFECTED PACKAGES: By ecosystem
	// ══════════════════════════════════════════════════════════════════════════
	// Note: renderAffected handles its own leading newline to avoid extra spacing
	// when there are no valid packages to display
	r.renderAffected(out, data)

	// ══════════════════════════════════════════════════════════════════════════
	// REFERENCES: Categorized
	// ══════════════════════════════════════════════════════════════════════════
	if len(vuln.References) > 0 {
		fmt.Fprintln(out)
		r.renderReferences(out, data)
	}

	// ══════════════════════════════════════════════════════════════════════════
	// QUICK LINKS: Essential external resources
	// ══════════════════════════════════════════════════════════════════════════
	r.renderQuickLinks(out, data)

	return nil
}

// renderHeader renders the ID, severity badge, and CVSS score.
func (r *Renderer) renderHeader(out io.Writer, data *VulnData) {
	vuln := data.Vuln

	// ID [SEVERITY] CVSS X.X
	parts := []string{styleID.Render(vuln.ID)}

	// Severity badge
	sevStyle := severityStyle(data.Severity)
	parts = append(parts, sevStyle.Render("["+data.Severity+"]"))

	// CVSS score with version - use severity color for score
	if data.CVSSScore > 0 {
		scoreStr := fmt.Sprintf("%.1f", data.CVSSScore)
		versionStr := ""
		if data.CVSSVersion != cvss.VersionUnknown {
			versionStr = fmt.Sprintf(" v%s", data.CVSSVersion)
		}
		parts = append(parts, sevStyle.Render(scoreStr)+styleDim.Render(versionStr))
	}

	fmt.Fprintln(out, strings.Join(parts, " "))

	// Aliases on their own indented line
	if len(vuln.Aliases) > 0 {
		aliases := make([]string, 0, len(vuln.Aliases))
		for _, a := range vuln.Aliases {
			aliases = append(aliases, styleAlias.Render(a))
		}
		fmt.Fprintf(out, "  %s\n", strings.Join(aliases, styleDim.Render(", ")))
	}

	// Attack surface summary (derived from CVSS vector) - most useful info
	if data.CVSSVector != "" {
		if surface := describeAttackSurface(data.CVSSVector); surface != "" {
			fmt.Fprintf(out, "  %s\n", styleDim.Render(surface))
		}
	}

	// CVSS vector - technical detail
	if data.CVSSVector != "" {
		fmt.Fprintf(out, "  %s\n", styleHint.Render(data.CVSSVector))
	}
}

// renderThreatIntel renders KEV and EPSS information.
func (r *Renderer) renderThreatIntel(out io.Writer, data *VulnData) {
	fmt.Fprintln(out, styleSection.Render("Threat Intelligence"))

	intel := data.Intel

	// KEV Status
	if intel.InKEV != nil && *intel.InKEV && intel.KEV != nil {
		kev := intel.KEV
		fmt.Fprintf(out, "  %s %s\n",
			styleWarning.Render(symbolWarning+" KEV"),
			styleDim.Render("Known Exploited Vulnerability"))

		// KEV dates on one line
		fmt.Fprintf(out, "    added %s  due %s %s\n",
			styleDim.Render(kev.DateAdded),
			styleDim.Render(kev.DueDate),
			r.formatKEVStatus(data.Temporal))

		if kev.KnownRansomwareCampaignUse == "Known" {
			fmt.Fprintf(out, "    %s\n", styleWarning.Render("used in ransomware campaigns"))
		}

		if kev.RequiredAction != "" {
			fmt.Fprintf(out, "    %s\n", styleDim.Render(wrapIndent(kev.RequiredAction, 4, 72)))
		}
	}

	// EPSS Score
	if intel.EPSS != nil && *intel.EPSS > 0 {
		epss := *intel.EPSS
		percentile := float64(0)
		if intel.EPSSPercentile != nil {
			percentile = *intel.EPSSPercentile
		}

		epssStyle := styleGood
		riskLevel := "low"
		if epss >= 0.5 {
			epssStyle = styleWarning
			riskLevel = "high"
		} else if epss >= 0.1 {
			epssStyle = styleCaution
			riskLevel = "elevated"
		}

		fmt.Fprintf(out, "  %s %s probability of exploitation in 30 days\n",
			styleLabel.Render("EPSS"),
			epssStyle.Render(fmt.Sprintf("%.1f%%", epss*100)))

		// Format percentile - show where this CVE ranks among all CVEs
		percentileRank := 100 - percentile*100
		var percentileDesc string
		if percentileRank < 1 {
			percentileDesc = "more likely to be exploited than 99% of CVEs"
		} else if percentileRank <= 5 {
			percentileDesc = fmt.Sprintf("more likely to be exploited than %.0f%% of CVEs", 100-percentileRank)
		} else if percentileRank <= 20 {
			percentileDesc = fmt.Sprintf("higher risk than %.0f%% of CVEs", 100-percentileRank)
		} else {
			percentileDesc = fmt.Sprintf("%.0f%% of CVEs have higher scores", percentileRank)
		}
		fmt.Fprintf(out, "    %s — %s\n",
			styleDim.Render(riskLevel+" risk"),
			styleHint.Render(percentileDesc))
	}
}

// formatKEVStatus returns a status indicator for KEV due date.
func (r *Renderer) formatKEVStatus(temporal TemporalInfo) string {
	if temporal.KEVDueDate.IsZero() {
		return ""
	}
	overdue := temporal.KEVDaysOverdue()
	remaining := temporal.KEVDaysRemaining()

	if overdue > 0 {
		return styleWarning.Render(fmt.Sprintf("(%d days overdue)", overdue))
	}
	if remaining > 0 {
		return styleDim.Render(fmt.Sprintf("(%d days remaining)", remaining))
	}
	return styleWarning.Render("(due today)")
}

// renderTimeline renders temporal information with contextual insights.
func (r *Renderer) renderTimeline(out io.Writer, data *VulnData) {
	temporal := data.Temporal

	if temporal.Published.IsZero() && temporal.Modified.IsZero() {
		return
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, styleSection.Render("Timeline"))

	// Published
	if !temporal.Published.IsZero() {
		age := FormatAge(temporal.Age())
		fmt.Fprintf(out, "  %s %s  %s\n",
			styleLabel.Render("disclosed"),
			styleEmphasis.Render(temporal.Published.Format("2006-01-02")),
			styleDim.Render(age+" ago"))
	}

	// Modified (only if different from published)
	if !temporal.Modified.IsZero() && temporal.Modified != temporal.Published {
		age := FormatAge(temporal.TimeSinceModified())
		fmt.Fprintf(out, "  %s  %s  %s\n",
			styleLabel.Render("updated"),
			styleDim.Render(temporal.Modified.Format("2006-01-02")),
			styleDim.Render(age+" ago"))
	}

	// Contextual insight based on age - single line, minimal styling
	if !temporal.Published.IsZero() {
		days := temporal.DaysSincePublished()
		var insight string

		switch {
		case days < 7:
			insight = styleCaution.Render(symbolWarning+" emerging vulnerability") + styleDim.Render(" — fixes may be incomplete")
		case days < 30:
			insight = styleDim.Render("recently disclosed — monitor for updates")
		case days > 730: // 2 years
			insight = styleDim.Render("long-standing — should be patched by now")
		case days > 365:
			insight = styleDim.Render("over a year old — verify your dependencies are updated")
		}

		if insight != "" {
			fmt.Fprintf(out, "  %s\n", insight)
		}
	}
}

// renderWeaknesses renders CWE information.
func (r *Renderer) renderWeaknesses(out io.Writer, data *VulnData) {
	fmt.Fprintln(out, styleSection.Render("Weakness"))

	for _, cweInfo := range data.CWEs {
		fmt.Fprintf(out, "  %s %s\n",
			styleCWE.Render(cweInfo.ID),
			styleDim.Render(cweInfo.Name))
		// Wrap description at 72 chars, indent continuation lines by 4 spaces
		desc := wrapText(cweInfo.Description, 72)
		for _, line := range strings.Split(desc, "\n") {
			fmt.Fprintf(out, "    %s\n", styleHint.Render(line))
		}
		fmt.Fprintf(out, "    %s\n", styleDim.Render(cweInfo.Category))
	}
}

// renderAffected renders affected packages grouped by ecosystem.
// It handles its own leading newline to avoid extra spacing when there are
// no valid packages to display (e.g., when affected entries only have git ranges).
func (r *Renderer) renderAffected(out io.Writer, data *VulnData) {
	vuln := data.Vuln

	// Filter to packages with actual names
	var validAffected []osvschema.Affected
	for _, a := range vuln.Affected {
		if a.Package.Name != "" {
			validAffected = append(validAffected, a)
		}
	}

	// Skip section entirely if no valid packages
	if len(validAffected) == 0 {
		return
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, styleSection.Render("Affected"))

	// Group by ecosystem
	byEcosystem := make(map[string][]osvschema.Affected)
	var ecosystems []string

	for _, a := range validAffected {
		eco := string(a.Package.Ecosystem)
		if eco == "" {
			eco = "Other"
		}
		if _, exists := byEcosystem[eco]; !exists {
			ecosystems = append(ecosystems, eco)
		}
		byEcosystem[eco] = append(byEcosystem[eco], a)
	}

	sort.Strings(ecosystems)

	for _, eco := range ecosystems {
		fmt.Fprintf(out, "  %s\n", styleDim.Render(eco))

		for _, a := range byEcosystem[eco] {
			// Package name
			fmt.Fprintf(out, "    %s\n", stylePackage.Render(a.Package.Name))

			// Version info
			r.renderVersionRanges(out, a)
		}
	}
}

// renderVersionRanges renders version range information for a package.
func (r *Renderer) renderVersionRanges(out io.Writer, a osvschema.Affected) {
	var ranges []string

	for _, rang := range a.Ranges {
		var introduced, fixed string
		for _, event := range rang.Events {
			if event.Introduced != "" {
				introduced = event.Introduced
			}
			if event.Fixed != "" {
				fixed = event.Fixed
			}
		}

		// Truncate git hashes to first 12 chars for readability
		if looksLikeGitHash(introduced) {
			introduced = introduced[:12]
		}
		if looksLikeGitHash(fixed) {
			fixed = fixed[:12]
		}

		if introduced != "" || fixed != "" {
			rangeStr := ""
			if introduced != "" && introduced != "0" {
				rangeStr = fmt.Sprintf("%s %s", styleLabel.Render(">="), styleVersion.Render(introduced))
			}
			if fixed != "" {
				if rangeStr != "" {
					rangeStr += ", "
				}
				rangeStr += fmt.Sprintf("%s %s", styleLabel.Render("fixed in"), styleFix.Render(fixed))
			} else if introduced != "" {
				rangeStr += styleDim.Render(" (no fix available)")
			}
			ranges = append(ranges, rangeStr)
		}
	}

	for _, r := range ranges {
		fmt.Fprintf(out, "      %s\n", r)
	}
}

// renderReferences renders categorized references.
func (r *Renderer) renderReferences(out io.Writer, data *VulnData) {
	vuln := data.Vuln

	fmt.Fprintln(out, styleSection.Render("References"))

	// Group by type
	byType := make(map[osvschema.ReferenceType][]osvschema.Reference)
	typeOrder := []osvschema.ReferenceType{
		osvschema.ReferenceAdvisory,
		osvschema.ReferenceFix,
		osvschema.ReferenceReport,
		osvschema.ReferenceArticle,
		osvschema.ReferencePackage,
		osvschema.ReferenceWeb,
		osvschema.ReferenceEvidence,
		osvschema.ReferenceDetection,
	}

	for _, ref := range vuln.References {
		refType := ref.Type
		if refType == "" {
			refType = osvschema.ReferenceWeb
		}
		byType[refType] = append(byType[refType], ref)
	}

	maxPerCategory := 100 // Show all references

	totalShown := 0
	for _, refType := range typeOrder {
		refs, ok := byType[refType]
		if !ok || len(refs) == 0 {
			continue
		}

		// Type label - inline with first link
		fmt.Fprintf(out, "  %s\n", styleDim.Render(refTypeLabel(refType)))

		shown := 0
		for _, ref := range refs {
			if shown >= maxPerCategory {
				fmt.Fprintf(out, "    %s\n", styleDim.Render(fmt.Sprintf("+%d more", len(refs)-shown)))
				break
			}
			fmt.Fprintf(out, "    %s\n", styleLink.Render(ref.URL))
			shown++
			totalShown++
		}
	}

}

// renderQuickLinks renders essential external resource links at the end.
func (r *Renderer) renderQuickLinks(out io.Writer, data *VulnData) {
	vuln := data.Vuln

	var links []string

	// OSV link (always available)
	links = append(links, "https://osv.dev/vulnerability/"+vuln.ID)

	// NVD link for CVEs
	cveID := findCVEID(vuln)
	if cveID != "" && cveID != vuln.ID {
		links = append(links, "https://nvd.nist.gov/vuln/detail/"+cveID)
	} else if strings.HasPrefix(vuln.ID, "CVE-") {
		links = append(links, "https://nvd.nist.gov/vuln/detail/"+vuln.ID)
	}

	// GitHub Advisory link for GHSA
	if strings.HasPrefix(vuln.ID, "GHSA-") {
		links = append(links, "https://github.com/advisories/"+vuln.ID)
	}

	// Go vulnerability database link
	if strings.HasPrefix(vuln.ID, "GO-") {
		links = append(links, "https://pkg.go.dev/vuln/"+vuln.ID)
	}

	if len(links) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, styleSection.Render("Quick Links"))
		for _, link := range links {
			fmt.Fprintf(out, "  %s\n", styleLink.Render(link))
		}
	}
}

// renderJSON renders the vulnerability as structured JSON.
// The output is designed to be machine-readable while providing all the context
// needed for automated processing, dashboards, or further analysis.
func (r *Renderer) renderJSON(out io.Writer, data *VulnData) error {
	vuln := data.Vuln

	result := map[string]any{
		"id":      vuln.ID,
		"summary": vuln.Summary,
	}

	if len(vuln.Aliases) > 0 {
		result["aliases"] = vuln.Aliases
	}

	// Severity with human-readable risk assessment
	severity := map[string]any{
		"level": data.Severity,
	}
	if data.CVSSScore > 0 {
		severity["cvss_score"] = data.CVSSScore
		severity["cvss_vector"] = data.CVSSVector
		if data.CVSSVersion != cvss.VersionUnknown {
			severity["cvss_version"] = string(data.CVSSVersion)
		}
		// Add attack surface analysis
		if surface := describeAttackSurface(data.CVSSVector); surface != "" {
			severity["attack_surface"] = surface
		}
		// Add structured attack characteristics
		if chars := parseAttackCharacteristics(data.CVSSVector); len(chars) > 0 {
			severity["attack_characteristics"] = chars
		}
	}
	result["severity"] = severity

	// Timeline with computed age context
	timeline := map[string]any{}
	if !data.Temporal.Published.IsZero() {
		timeline["published"] = data.Temporal.Published.Format(time.RFC3339)
		timeline["age_days"] = data.Temporal.DaysSincePublished()
		timeline["age_human"] = FormatAge(data.Temporal.Age())
	}
	if !data.Temporal.Modified.IsZero() {
		timeline["modified"] = data.Temporal.Modified.Format(time.RFC3339)
	}
	if len(timeline) > 0 {
		result["timeline"] = timeline
	}

	// Weaknesses (CWE) with full context
	if len(data.CWEs) > 0 {
		cwes := make([]map[string]any, 0, len(data.CWEs))
		for _, c := range data.CWEs {
			cwe := map[string]any{
				"id":          c.ID,
				"name":        c.Name,
				"description": c.Description,
				"category":    c.Category,
			}
			// Add link to CWE database
			if strings.HasPrefix(c.ID, "CWE-") {
				cweNum := strings.TrimPrefix(c.ID, "CWE-")
				cwe["url"] = "https://cwe.mitre.org/data/definitions/" + cweNum + ".html"
			}
			cwes = append(cwes, cwe)
		}
		result["weaknesses"] = cwes
	}

	// Threat intelligence with human-readable interpretations
	if data.Intel != nil {
		intel := map[string]any{}
		if data.Intel.EPSS != nil && *data.Intel.EPSS > 0 {
			epss := *data.Intel.EPSS
			percentile := float64(0)
			if data.Intel.EPSSPercentile != nil {
				percentile = *data.Intel.EPSSPercentile
			}

			// Determine risk level
			riskLevel := "low"
			if epss >= 0.5 {
				riskLevel = "high"
			} else if epss >= 0.1 {
				riskLevel = "elevated"
			}

			// Calculate percentile rank (top X%)
			percentileRank := 100 - percentile*100
			if percentileRank < 1 {
				percentileRank = 1
			}

			intel["epss"] = map[string]any{
				"score":           epss,
				"score_percent":   fmt.Sprintf("%.1f%%", epss*100),
				"percentile":      percentile,
				"percentile_rank": fmt.Sprintf("top %.0f%%", percentileRank),
				"risk_level":      riskLevel,
				"description":     fmt.Sprintf("%.1f%% probability of exploitation in next 30 days", epss*100),
			}
		}
		if data.Intel.InKEV != nil && *data.Intel.InKEV && data.Intel.KEV != nil {
			kev := data.Intel.KEV
			kevData := map[string]any{
				"in_catalog":      true,
				"date_added":      kev.DateAdded,
				"due_date":        kev.DueDate,
				"required_action": kev.RequiredAction,
			}
			if kev.KnownRansomwareCampaignUse == "Known" {
				kevData["ransomware_use"] = true
			} else {
				kevData["ransomware_use"] = false
			}
			// Add overdue status
			overdue := data.Temporal.KEVDaysOverdue()
			if overdue > 0 {
				kevData["days_overdue"] = overdue
				kevData["status"] = "overdue"
			} else {
				remaining := data.Temporal.KEVDaysRemaining()
				if remaining > 0 {
					kevData["days_remaining"] = remaining
					kevData["status"] = "pending"
				} else {
					kevData["status"] = "due_today"
				}
			}
			intel["kev"] = kevData
		}
		if len(intel) > 0 {
			result["threat_intel"] = intel
		}
	}

	// Affected packages with remediation info
	var affected []map[string]any
	for _, a := range vuln.Affected {
		if a.Package.Name == "" {
			continue
		}
		pkg := map[string]any{
			"name":      a.Package.Name,
			"ecosystem": string(a.Package.Ecosystem),
		}
		if a.Package.Purl != "" {
			pkg["purl"] = a.Package.Purl
		}

		var ranges []map[string]string
		var fixedVersions []string
		for _, rang := range a.Ranges {
			for _, event := range rang.Events {
				if event.Introduced != "" && !looksLikeGitHash(event.Introduced) {
					ranges = append(ranges, map[string]string{"introduced": event.Introduced})
				}
				if event.Fixed != "" {
					if !looksLikeGitHash(event.Fixed) {
						ranges = append(ranges, map[string]string{"fixed": event.Fixed})
						fixedVersions = append(fixedVersions, event.Fixed)
					}
				}
			}
		}
		if len(ranges) > 0 {
			pkg["ranges"] = ranges
		}
		if len(fixedVersions) > 0 {
			pkg["fixed_versions"] = fixedVersions
			pkg["remediation"] = fmt.Sprintf("Upgrade to %s or later", fixedVersions[len(fixedVersions)-1])
		} else {
			pkg["remediation"] = "No fix available; consider alternative packages or mitigations"
		}
		affected = append(affected, pkg)
	}
	if len(affected) > 0 {
		result["affected"] = affected
	}

	// References grouped by type for easier consumption
	if len(vuln.References) > 0 {
		refs := make([]map[string]string, 0, len(vuln.References))
		for _, ref := range vuln.References {
			r := map[string]string{"url": ref.URL}
			if ref.Type != "" {
				r["type"] = string(ref.Type)
			}
			refs = append(refs, r)
		}
		result["references"] = refs
	}

	// Useful links for further research
	links := map[string]string{}
	cveID := findCVEID(vuln)
	if cveID != "" {
		links["nvd"] = "https://nvd.nist.gov/vuln/detail/" + cveID
		links["osv"] = "https://osv.dev/vulnerability/" + cveID
	}
	if strings.HasPrefix(vuln.ID, "GHSA-") {
		links["github_advisory"] = "https://github.com/advisories/" + vuln.ID
		links["osv"] = "https://osv.dev/vulnerability/" + vuln.ID
	}
	if strings.HasPrefix(vuln.ID, "GO-") {
		links["osv"] = "https://osv.dev/vulnerability/" + vuln.ID
		links["go_vuln"] = "https://pkg.go.dev/vuln/" + vuln.ID
	}
	if len(links) > 0 {
		result["links"] = links
	}

	// Details - full description
	if vuln.Details != "" {
		result["details"] = vuln.Details
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// Helper functions

func extractCVSSInfo(vuln *osvschema.Vulnerability) (vector string, score float64) {
	if vuln == nil {
		return "", 0
	}

	// Prefer CVSS v3.x/v4
	for _, sev := range vuln.Severity {
		if sev.Type == osvschema.SeverityCVSSV3 || sev.Type == osvschema.SeverityCVSSV4 {
			return sev.Score, cvss.ParseScore(sev.Score)
		}
	}

	// Fallback to v2
	for _, sev := range vuln.Severity {
		if sev.Type == osvschema.SeverityCVSSV2 {
			return sev.Score, cvss.ParseScore(sev.Score)
		}
	}

	return "", 0
}

func deriveSeverity(cvssScore float64, vuln *osvschema.Vulnerability) string {
	if cvssScore >= 9.0 {
		return "CRITICAL"
	}
	if cvssScore >= 7.0 {
		return "HIGH"
	}
	if cvssScore >= 4.0 {
		return "MEDIUM"
	}
	if cvssScore > 0 {
		return "LOW"
	}

	// Check database_specific for GHSA severity
	if vuln != nil && vuln.DatabaseSpecific != nil {
		if sevRaw, ok := vuln.DatabaseSpecific["severity"]; ok {
			if sevStr, ok := sevRaw.(string); ok {
				return strings.ToUpper(sevStr)
			}
		}
	}

	return "UNKNOWN"
}

func extractCWEs(vuln *osvschema.Vulnerability) []CWEInfo {
	if vuln == nil || vuln.DatabaseSpecific == nil {
		return nil
	}

	cweIDs := cwe.ExtractFromDatabaseSpecific(vuln.DatabaseSpecific)
	if len(cweIDs) == 0 {
		return nil
	}

	result := make([]CWEInfo, 0, len(cweIDs))
	for _, id := range cweIDs {
		result = append(result, GetCWEInfo(id.String()))
	}
	return result
}

func findCVEID(vuln *osvschema.Vulnerability) string {
	if vuln == nil {
		return ""
	}
	if strings.HasPrefix(vuln.ID, "CVE-") {
		return vuln.ID
	}
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return ""
}

func severityStyle(severity string) lipgloss.Style {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return styleCritical
	case "HIGH":
		return styleHigh
	case "MEDIUM":
		return styleMedium
	case "LOW":
		return styleLow
	default:
		return styleUnknown
	}
}

func refTypeLabel(t osvschema.ReferenceType) string {
	labels := map[osvschema.ReferenceType]string{
		osvschema.ReferenceAdvisory:  "Advisory",
		osvschema.ReferenceFix:       "Fix",
		osvschema.ReferenceArticle:   "Article",
		osvschema.ReferenceReport:    "Report",
		osvschema.ReferenceWeb:       "Web",
		osvschema.ReferencePackage:   "Package",
		osvschema.ReferenceEvidence:  "Evidence",
		osvschema.ReferenceDetection: "Detection",
	}
	if label, ok := labels[t]; ok {
		return label
	}
	return string(t)
}

func looksLikeGitHash(s string) bool {
	if len(s) < 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}

	paragraphs := strings.Split(text, "\n\n")
	var result []string

	for i, paragraph := range paragraphs {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			continue
		}

		var lines []string
		var line strings.Builder
		for _, word := range words {
			if line.Len()+len(word)+1 > width {
				lines = append(lines, line.String())
				line.Reset()
			}
			if line.Len() > 0 {
				line.WriteString(" ")
			}
			line.WriteString(word)
		}
		if line.Len() > 0 {
			lines = append(lines, line.String())
		}

		result = append(result, strings.Join(lines, "\n"))

		// Add blank line between paragraphs (not after the last one)
		if i < len(paragraphs)-1 {
			result = append(result, "")
		}
	}

	return strings.Join(result, "\n")
}

func wrapIndent(text string, indent int, width int) string {
	wrapped := wrapText(text, width-indent)
	indentStr := strings.Repeat(" ", indent)
	lines := strings.Split(wrapped, "\n")
	for i := 1; i < len(lines); i++ {
		lines[i] = indentStr + lines[i]
	}
	return strings.Join(lines, "\n")
}

// describeAttackSurface interprets CVSS vector components into a human-readable attack surface description.
func describeAttackSurface(vector string) string {
	if vector == "" {
		return ""
	}

	components := parseCVSSComponents(vector)
	var parts []string

	// Attack Vector (AV)
	switch components["AV"] {
	case "N":
		parts = append(parts, "network-based")
	case "A":
		parts = append(parts, "adjacent network")
	case "L":
		parts = append(parts, "local access required")
	case "P":
		parts = append(parts, "physical access required")
	}

	// Privileges Required (PR)
	switch components["PR"] {
	case "N":
		parts = append(parts, "no authentication needed")
	case "L":
		parts = append(parts, "low privileges needed")
	case "H":
		parts = append(parts, "high privileges needed")
	}

	// User Interaction (UI)
	switch components["UI"] {
	case "N":
		// No user interaction - don't add (it's the dangerous default)
	case "R":
		parts = append(parts, "requires user interaction")
	}

	// Attack Complexity (AC)
	switch components["AC"] {
	case "L":
		// Low complexity - don't add (common case)
	case "H":
		parts = append(parts, "complex attack conditions")
	}

	if len(parts) == 0 {
		return ""
	}

	return strings.Join(parts, ", ")
}

// parseAttackCharacteristics returns structured attack characteristics for JSON output.
func parseAttackCharacteristics(vector string) map[string]any {
	if vector == "" {
		return nil
	}

	components := parseCVSSComponents(vector)
	chars := make(map[string]any)

	// Attack Vector
	if av, ok := components["AV"]; ok {
		switch av {
		case "N":
			chars["attack_vector"] = "network"
			chars["remote_exploitable"] = true
		case "A":
			chars["attack_vector"] = "adjacent_network"
			chars["remote_exploitable"] = true
		case "L":
			chars["attack_vector"] = "local"
			chars["remote_exploitable"] = false
		case "P":
			chars["attack_vector"] = "physical"
			chars["remote_exploitable"] = false
		}
	}

	// Privileges Required
	if pr, ok := components["PR"]; ok {
		switch pr {
		case "N":
			chars["privileges_required"] = "none"
			chars["authentication_required"] = false
		case "L":
			chars["privileges_required"] = "low"
			chars["authentication_required"] = true
		case "H":
			chars["privileges_required"] = "high"
			chars["authentication_required"] = true
		}
	}

	// User Interaction
	if ui, ok := components["UI"]; ok {
		chars["user_interaction_required"] = ui == "R"
	}

	// Attack Complexity
	if ac, ok := components["AC"]; ok {
		chars["attack_complexity"] = strings.ToLower(ac)
	}

	return chars
}

// parseCVSSComponents parses a CVSS vector string into a map of component values.
func parseCVSSComponents(vector string) map[string]string {
	components := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		if idx := strings.Index(part, ":"); idx > 0 {
			components[part[:idx]] = part[idx+1:]
		}
	}
	return components
}

// extractFirstSentence extracts the first sentence from text, truncating at maxLen.
func extractFirstSentence(text string, maxLen int) string {
	// Clean up whitespace
	text = strings.TrimSpace(text)
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "  ", " ")

	// Find first sentence ending
	for i, c := range text {
		if c == '.' || c == '!' || c == '?' {
			// Check if it's a real sentence end (not "e.g." or "v1.0")
			if i+1 < len(text) && (text[i+1] == ' ' || text[i+1] == '\n') {
				sentence := strings.TrimSpace(text[:i+1])
				if len(sentence) <= maxLen {
					return sentence
				}
				break
			}
		}
	}

	// No sentence found or too long, truncate at word boundary
	if len(text) <= maxLen {
		return text
	}

	// Find last space before maxLen
	truncated := text[:maxLen]
	lastSpace := strings.LastIndex(truncated, " ")
	if lastSpace > maxLen/2 {
		return strings.TrimSpace(truncated[:lastSpace]) + "..."
	}
	return truncated + "..."
}
