package remediation

import (
	"fmt"
	"strings"

	"github.com/temporalio/deputy/internal/vulnerability"
)

// UnfixableGuidance provides actionable advice for vulnerabilities that have no
// direct upgrade path. This helps security engineers make informed decisions
// about risk acceptance or alternative mitigations.
type UnfixableGuidance struct {
	// VulnerabilityID is the vulnerability identifier (CVE, GHSA).
	VulnerabilityID string

	// Package is the affected package name.
	Package string

	// Version is the current installed version.
	Version string

	// Ecosystem is the package ecosystem (npm, go, pypi, etc).
	Ecosystem string

	// Category classifies the type of unfixable situation.
	Category UnfixableCategory

	// Recommendations provides actionable advice specific to the situation.
	Recommendations []string

	// RiskFactors highlights aspects affecting risk assessment.
	RiskFactors []string

	// AlternativePackages suggests potential replacement packages.
	AlternativePackages []string

	// References provides links to relevant documentation.
	References []string
}

// UnfixableCategory describes why a vulnerability cannot be directly fixed.
type UnfixableCategory int

const (
	// CategoryNoFixAvailable means no patched version exists yet.
	CategoryNoFixAvailable UnfixableCategory = iota

	// CategoryTransitiveDependency means the vuln is in an indirect dependency.
	CategoryTransitiveDependency

	// CategoryAbandonedPackage means the package is no longer maintained.
	CategoryAbandonedPackage

	// CategoryIncompatibleFix means the fix requires breaking changes.
	CategoryIncompatibleFix

	// CategoryDisputed means the vulnerability classification is contested.
	CategoryDisputed
)

// String returns a human-readable category name.
func (c UnfixableCategory) String() string {
	switch c {
	case CategoryNoFixAvailable:
		return "No fix available"
	case CategoryTransitiveDependency:
		return "Transitive dependency"
	case CategoryAbandonedPackage:
		return "Abandoned package"
	case CategoryIncompatibleFix:
		return "Incompatible fix"
	case CategoryDisputed:
		return "Disputed vulnerability"
	default:
		return "Unknown"
	}
}

// AnalyzeUnfixable examines vulnerabilities with no direct fix and generates
// contextual guidance for each.
func AnalyzeUnfixable(vulns []vulnerability.Consolidated) []UnfixableGuidance {
	var guidance []UnfixableGuidance

	for _, v := range vulns {
		// Skip vulnerabilities that have fixes
		if len(v.FixedVersions) > 0 {
			continue
		}

		g := UnfixableGuidance{
			VulnerabilityID: v.PrimaryID,
			Package:         v.Package,
			Version:         v.Version,
			Ecosystem:       v.Ecosystem,
		}

		// Categorize the situation
		g.Category = categorizeUnfixable(v)

		// Generate recommendations based on category and context
		g.Recommendations = generateRecommendations(v, g.Category)

		// Identify risk factors
		g.RiskFactors = identifyRiskFactors(v)

		// Suggest alternatives when applicable
		g.AlternativePackages = suggestAlternatives(v)

		// Add relevant references
		g.References = gatherReferences(v)

		guidance = append(guidance, g)
	}

	return guidance
}

// categorizeUnfixable determines the type of unfixable situation.
func categorizeUnfixable(v vulnerability.Consolidated) UnfixableCategory {
	// Check if it's a transitive dependency
	if !v.IsDirect {
		return CategoryTransitiveDependency
	}

	// Check for disputed vulnerabilities (typically in the summary)
	lowerSummary := strings.ToLower(v.Summary)
	if strings.Contains(lowerSummary, "disputed") ||
		strings.Contains(lowerSummary, "contested") ||
		strings.Contains(lowerSummary, "not a vulnerability") {
		return CategoryDisputed
	}

	// Default to no fix available
	return CategoryNoFixAvailable
}

// generateRecommendations creates actionable advice based on the situation.
func generateRecommendations(v vulnerability.Consolidated, category UnfixableCategory) []string {
	var recs []string

	// Universal recommendations
	recs = append(recs, "Review the vulnerability details to understand actual exposure")

	switch category {
	case CategoryNoFixAvailable:
		recs = append(recs,
			"Monitor the package repository for security updates",
			"Consider implementing compensating controls (WAF rules, input validation)",
			"Evaluate if the vulnerable code path is actually exercised in your application",
			"Document the risk acceptance decision if proceeding",
		)

		// Add ecosystem-specific advice
		switch strings.ToLower(v.Ecosystem) {
		case "go":
			recs = append(recs, "Check if the vulnerability affects your specific build tags or OS")
		case "npm":
			recs = append(recs,
				"Use npm audit to track when fixes become available",
				"Consider overriding the transitive dependency version if safe",
			)
		case "pypi":
			recs = append(recs, "Check if the vulnerability affects your Python version")
		}

	case CategoryTransitiveDependency:
		recs = append(recs,
			"Identify which direct dependency pulls in the vulnerable package",
			"Check if the direct dependency has a newer version that updates the transitive",
			"File an issue with the direct dependency maintainer",
			"Consider using dependency resolution overrides as a temporary measure",
		)

		// Add ecosystem-specific override guidance
		recs = append(recs, ecosystemOverrideGuidance(v.Ecosystem, v.Package)...)

	case CategoryAbandonedPackage:
		recs = append(recs,
			"Search for actively maintained forks of the package",
			"Plan migration to an alternative package",
			"Consider vendoring and patching the code if critical",
		)

	case CategoryIncompatibleFix:
		recs = append(recs,
			"Plan upgrade in coordination with dependent code changes",
			"Review migration guides from the package maintainer",
			"Consider running both versions during transition (where possible)",
		)

	case CategoryDisputed:
		recs = append(recs,
			"Review the dispute details in the vulnerability database",
			"Assess applicability to your specific use case",
			"Document your assessment for audit purposes",
		)
	}

	return recs
}

// identifyRiskFactors highlights aspects that affect risk assessment.
func identifyRiskFactors(v vulnerability.Consolidated) []string {
	var factors []string

	// Severity-based factors
	severity := strings.ToUpper(v.Severity)
	switch severity {
	case "CRITICAL":
		factors = append(factors, "Critical severity requires immediate attention")
	case "HIGH":
		factors = append(factors, "High severity warrants prioritized review")
	}

	// Direct vs transitive
	if v.IsDirect {
		factors = append(factors, "Direct dependency - you control the version")
	} else {
		factors = append(factors, "Transitive dependency - version controlled by parent dependency")
	}

	// Check for remote exploitation indicators in summary
	lowerSummary := strings.ToLower(v.Summary)
	if strings.Contains(lowerSummary, "remote") ||
		strings.Contains(lowerSummary, "unauthenticated") ||
		strings.Contains(lowerSummary, "rce") {
		factors = append(factors, "May be remotely exploitable - higher risk")
	}

	if strings.Contains(lowerSummary, "denial of service") ||
		strings.Contains(lowerSummary, "dos") {
		factors = append(factors, "Denial of service risk - consider availability impact")
	}

	if strings.Contains(lowerSummary, "information disclosure") ||
		strings.Contains(lowerSummary, "data leak") {
		factors = append(factors, "Data exposure risk - review data handling paths")
	}

	// CWE-based factors from DatabaseSpecific
	if v.DatabaseSpecific != nil {
		if cwes, ok := v.DatabaseSpecific["cwes"]; ok {
			for cwe := range strings.SplitSeq(cwes, ",") {
				cwe = strings.TrimSpace(cwe)
				if riskNote := cweRiskNote(cwe); riskNote != "" {
					factors = append(factors, riskNote)
				}
			}
		}
	}

	return factors
}

// ecosystemOverrideGuidance returns ecosystem-specific advice for overriding
// transitive dependency versions.
func ecosystemOverrideGuidance(ecosystem, pkg string) []string {
	var guidance []string

	switch strings.ToLower(ecosystem) {
	// JavaScript/TypeScript
	case "npm":
		guidance = append(guidance,
			"Use 'overrides' in package.json to force a specific version",
			fmt.Sprintf("Example: \"overrides\": { \"%s\": \"<safe-version>\" }", pkg),
		)
	case "yarn":
		guidance = append(guidance,
			"Use 'resolutions' in package.json to force a specific version",
			fmt.Sprintf("Example: \"resolutions\": { \"%s\": \"<safe-version>\" }", pkg),
		)
	case "pnpm":
		guidance = append(guidance,
			"Use 'pnpm.overrides' in package.json to force a specific version",
			fmt.Sprintf("Example: \"pnpm\": { \"overrides\": { \"%s\": \"<safe-version>\" } }", pkg),
		)

	// Go
	case "go", "golang":
		guidance = append(guidance,
			"Use 'replace' directive in go.mod to substitute the dependency",
			fmt.Sprintf("Example: replace %s => %s <safe-version>", pkg, pkg),
		)

	// Python
	case "pypi", "pip", "poetry", "pipenv", "pdm":
		guidance = append(guidance,
			"Pin the package version in your requirements/constraints file",
			"For Poetry: use [tool.poetry.dependencies] with exact version",
			"For pip: add to constraints.txt and use pip install -c constraints.txt",
			"For PDM: use [tool.pdm.overrides] in pyproject.toml",
		)
	case "uv":
		guidance = append(guidance,
			"Use [tool.uv.override-dependencies] in pyproject.toml to force transitive versions:",
			fmt.Sprintf("  [tool.uv]\n  override-dependencies = [\"%s>=<safe-version>\"]", pkg),
			"Or use [tool.uv.constraint-dependencies] for upper bounds without overriding:",
			fmt.Sprintf("  constraint-dependencies = [\"%s>=<safe-version>\"]", pkg),
			"Then run: uv lock --upgrade-package "+pkg,
		)

	// Ruby
	case "rubygems", "gem", "bundler":
		guidance = append(guidance,
			"Use Bundler's dependency resolution to force version",
			fmt.Sprintf("Add to Gemfile: gem '%s', '>= <safe-version>'", pkg),
			"Then run: bundle update --conservative",
		)

	// Java/Maven
	case "maven":
		guidance = append(guidance,
			"Use <dependencyManagement> in pom.xml to control transitive versions",
			fmt.Sprintf("Add %s with explicit version in <dependencyManagement> section", pkg),
		)

	// Java/Gradle
	case "gradle":
		guidance = append(guidance,
			"Use dependency constraints or resolution strategy in build.gradle",
			"Example: constraints { implementation('%s:<safe-version>') }", pkg,
			"Or use: resolutionStrategy.force '%s:<safe-version>'", pkg,
		)

	// .NET/NuGet
	case "nuget", "dotnet":
		guidance = append(guidance,
			"Add a direct PackageReference to override the transitive version",
			fmt.Sprintf("Add to .csproj: <PackageReference Include=\"%s\" Version=\"<safe-version>\" />", pkg),
			"Or use Directory.Packages.props for centralized version management",
		)

	// Rust/Cargo
	case "cargo", "crates.io":
		guidance = append(guidance,
			"Use [patch] section in Cargo.toml to override the dependency",
			fmt.Sprintf("Example: [patch.crates-io]\n%s = { version = \"<safe-version>\" }", pkg),
		)

	// PHP/Composer
	case "composer", "packagist":
		guidance = append(guidance,
			"Add the package as a direct dependency with specific version",
			fmt.Sprintf("Run: composer require %s:<safe-version>", pkg),
		)

	// Elixir/Hex
	case "hex", "mix":
		guidance = append(guidance,
			"Override in mix.exs dependencies with explicit version",
			fmt.Sprintf("Add {:%s, \"~> <safe-version>\", override: true} to deps", pkg),
		)

	// Dart/Flutter
	case "pub", "dart", "flutter":
		guidance = append(guidance,
			"Use dependency_overrides in pubspec.yaml",
			fmt.Sprintf("dependency_overrides:\n  %s: ^<safe-version>", pkg),
		)

	// Swift/CocoaPods
	case "cocoapods", "pod":
		guidance = append(guidance,
			"Specify explicit version in Podfile",
			fmt.Sprintf("pod '%s', '~> <safe-version>'", pkg),
		)

	// GitHub Actions
	case "githubactions", "github-actions":
		guidance = append(guidance,
			"Pin GitHub Actions to specific commit SHAs instead of tags for supply chain security",
			fmt.Sprintf("Example: uses: %s@<full-40-char-commit-sha> # <version-tag>", pkg),
			"Use tools like 'pinact' or 'pin-github-action' to automate SHA pinning",
			"Consider using Dependabot to receive security updates for actions",
		)

	// Dockerfile / Container Images
	case "docker", "oci", "container":
		guidance = append(guidance,
			"Update base image in Dockerfile to a patched version",
			"Consider using minimal base images (distroless, alpine, chainguard)",
			"Pin base images to digest for reproducibility:",
			fmt.Sprintf("  FROM %s@sha256:<digest>", pkg),
			"For OS packages, add explicit upgrade commands in Dockerfile:",
			"  RUN apt-get update && apt-get upgrade -y",
			"Consider multi-stage builds to reduce attack surface",
		)
	}

	return guidance
}

// cweRiskNote returns a risk note for common high-risk CWEs.
func cweRiskNote(cwe string) string {
	// Common high-risk CWE patterns
	riskMap := map[string]string{
		"CWE-78":  "OS command injection - validate all inputs carefully",
		"CWE-79":  "Cross-site scripting - sanitize outputs",
		"CWE-89":  "SQL injection - use parameterized queries",
		"CWE-94":  "Code injection - review dynamic code execution",
		"CWE-119": "Buffer overflow - memory safety concern",
		"CWE-200": "Information exposure - audit data handling",
		"CWE-287": "Authentication bypass - review auth controls",
		"CWE-352": "CSRF - verify anti-CSRF tokens",
		"CWE-400": "Resource exhaustion - implement rate limiting",
		"CWE-502": "Deserialization - validate serialized data sources",
		"CWE-918": "SSRF - validate URLs and destinations",
	}

	// Extract CWE number for lookup
	cweUpper := strings.ToUpper(cwe)
	if note, ok := riskMap[cweUpper]; ok {
		return fmt.Sprintf("%s: %s", cweUpper, note)
	}

	return ""
}

// suggestAlternatives identifies potential replacement packages.
func suggestAlternatives(v vulnerability.Consolidated) []string {
	// This is a basic implementation - in practice, this could be enhanced
	// with a database of known alternatives or integration with package
	// recommendation services.

	var alternatives []string

	// Known alternatives for common problematic packages
	knownAlternatives := map[string][]string{
		"request":       {"axios", "node-fetch", "got"},
		"moment":        {"dayjs", "date-fns", "luxon"},
		"lodash":        {"lodash-es (tree-shakeable)", "ramda", "native ES6+ methods"},
		"underscore":    {"lodash", "ramda"},
		"jquery":        {"vanilla JS", "alpinejs (for simple interactions)"},
		"express":       {"fastify", "koa", "hono"},
		"body-parser":   {"express built-in (4.16+)"},
		"jade":          {"pug", "ejs", "handlebars"},
		"coffee-script": {"TypeScript", "vanilla JS"},
	}

	pkgLower := strings.ToLower(v.Package)
	// Strip scope for npm packages
	if idx := strings.LastIndex(pkgLower, "/"); idx >= 0 {
		pkgLower = pkgLower[idx+1:]
	}

	if alts, ok := knownAlternatives[pkgLower]; ok {
		alternatives = append(alternatives, alts...)
	}

	return alternatives
}

// gatherReferences collects relevant URLs for further research.
func gatherReferences(v vulnerability.Consolidated) []string {
	var refs []string

	// Add vulnerability database links based on ID
	if strings.HasPrefix(v.PrimaryID, "CVE-") {
		refs = append(refs,
			fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.PrimaryID),
			fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", v.PrimaryID),
		)
	}
	if strings.HasPrefix(v.PrimaryID, "GHSA-") {
		refs = append(refs,
			fmt.Sprintf("https://github.com/advisories/%s", v.PrimaryID),
		)
	}

	// Add OSV link
	refs = append(refs, fmt.Sprintf("https://osv.dev/vulnerability/%s", v.PrimaryID))

	return refs
}

// FormatGuidance formats a single guidance entry for display.
func FormatGuidance(g UnfixableGuidance) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s@%s\n", g.Package, g.Version))
	sb.WriteString(fmt.Sprintf("Vulnerability: %s\n", g.VulnerabilityID))
	sb.WriteString(fmt.Sprintf("Status: %s\n", g.Category.String()))
	sb.WriteString("\n")

	if len(g.RiskFactors) > 0 {
		sb.WriteString("Risk Factors:\n")
		for _, f := range g.RiskFactors {
			sb.WriteString(fmt.Sprintf("  - %s\n", f))
		}
		sb.WriteString("\n")
	}

	if len(g.Recommendations) > 0 {
		sb.WriteString("Recommendations:\n")
		for i, r := range g.Recommendations {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, r))
		}
		sb.WriteString("\n")
	}

	if len(g.AlternativePackages) > 0 {
		sb.WriteString("Consider Alternatives:\n")
		for _, a := range g.AlternativePackages {
			sb.WriteString(fmt.Sprintf("  - %s\n", a))
		}
		sb.WriteString("\n")
	}

	if len(g.References) > 0 {
		sb.WriteString("References:\n")
		for _, r := range g.References {
			sb.WriteString(fmt.Sprintf("  - %s\n", r))
		}
	}

	return sb.String()
}
