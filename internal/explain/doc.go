// Package explain provides comprehensive vulnerability explanation and analysis.
//
// This package renders detailed, context-rich vulnerability information suitable
// for developers, security engineers, and managers. It integrates multiple data
// sources to provide actionable insights.
//
// # Features
//
//   - Temporal analysis: age, time-to-fix, discovery timeline
//   - Threat intelligence: EPSS scores, KEV catalog status
//   - Cross-references: related vulnerabilities, aliases
//   - Weakness classification: CWE mappings with descriptions
//   - CVSS analysis: vector breakdown, impact metrics
//   - Affected packages: ecosystem-grouped with version ranges
//   - References: categorized by type (advisory, fix, article)
//
// # Usage
//
//	renderer := explain.NewRenderer(explain.Config{
//	    Verbose:    true,
//	    Enrichment: true,
//	})
//	renderer.Render(ctx, out, vuln)
package explain
