package scanning

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/osv-scalibr/extractor"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/ignore"
	"github.com/temporalio/deputy/internal/policy"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// FilterUnfixed drops findings without applicable fixes and recomputes stats.
func FilterUnfixed(result Result) Result {
	if len(result.Findings) == 0 {
		return result
	}
	filtered := make([]vulnerability.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		adv, ok := result.Advisories[f.AdvisoryID]
		if !ok {
			continue
		}
		if len(adv.FixedVersions) == 0 {
			continue
		}
		if vulnerability.FindBestFixedVersion(adv.FixedVersions, f.Version) == "" {
			continue
		}
		filtered = append(filtered, f)
	}
	result.Findings = filtered
	result.Advisories = filterAdvisories(filtered, result.Advisories)
	result.Stats = vulnerability.ConsolidateAll(result.Findings, result.Advisories).Stats
	return result
}

func filterAdvisories(findings []vulnerability.Finding, advisories map[string]*vulnerabilityv1.Advisory) map[string]*vulnerabilityv1.Advisory {
	if len(findings) == 0 {
		return map[string]*vulnerabilityv1.Advisory{}
	}
	out := make(map[string]*vulnerabilityv1.Advisory, len(advisories))
	for _, f := range findings {
		if adv, ok := advisories[f.AdvisoryID]; ok {
			out[f.AdvisoryID] = adv
		}
	}
	return out
}

// FilterIgnored drops findings matching ignore rules and recomputes stats.
// Returns the filtered result and count of ignored findings.
func FilterIgnored(result Result, rules *ignore.Rules) (Result, int) {
	if rules == nil || len(result.Findings) == 0 {
		return result, 0
	}
	filtered := make([]vulnerability.Finding, 0, len(result.Findings))
	ignoredCount := 0
	for _, f := range result.Findings {
		if rules.ShouldIgnore(f.AdvisoryID, f.Dependency.Name, f.Dependency.Ecosystem) {
			ignoredCount++
			continue
		}
		filtered = append(filtered, f)
	}
	if ignoredCount == 0 {
		return result, 0
	}
	result.Findings = filtered
	result.Advisories = filterAdvisories(filtered, result.Advisories)
	result.Stats = vulnerability.ConsolidateAll(result.Findings, result.Advisories).Stats
	return result, ignoredCount
}

// MergeResults combines two scan results into one aggregate result.
// The base target is preserved; packages, findings, advisories, and warnings
// are merged, and stats are recomputed from the consolidated findings.
func MergeResults(base, extra Result) Result {
	merged := base

	if extra.GeneratedAt.After(merged.GeneratedAt) {
		merged.GeneratedAt = extra.GeneratedAt
	}

	merged.Packages = append(append([]*extractor.Package{}, base.Packages...), extra.Packages...)
	merged.Direct = mergeDirect(base.Direct, extra.Direct)
	merged.Findings = append(append([]vulnerability.Finding{}, base.Findings...), extra.Findings...)
	merged.Advisories = mergeAdvisories(base.Advisories, extra.Advisories)
	merged.Warnings = append(append([]string{}, base.Warnings...), extra.Warnings...)

	merged.Stats = vulnerability.ConsolidateAll(merged.Findings, merged.Advisories).Stats

	return merged
}

func mergeDirect(base, extra map[string]bool) map[string]bool {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]bool, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		if v {
			out[k] = v
		}
	}
	return out
}

func mergeAdvisories(base, extra map[string]*vulnerabilityv1.Advisory) map[string]*vulnerabilityv1.Advisory {
	if len(base) == 0 && len(extra) == 0 {
		return map[string]*vulnerabilityv1.Advisory{}
	}
	out := make(map[string]*vulnerabilityv1.Advisory, len(base)+len(extra))
	for id, adv := range base {
		out[id] = adv
	}
	for id, adv := range extra {
		if existing, ok := out[id]; ok {
			out[id] = vulnerability.MergeAdvisory(existing, adv)
			continue
		}
		out[id] = adv
	}
	return out
}

// FilterByCEL filters findings using a CEL expression. The expression is evaluated
// per-vulnerability with the `vulnerability` variable bound to each finding's proto
// representation. Findings where the expression evaluates to true are kept.
//
// Example expressions:
//   - "vulnerability.advisory.severity.level == severity.critical"
//   - "vulnerability.package.direct && vulnerability.epss > 0.5"
//   - "vulnerability.in_kev || vulnerability.advisory.severity.level in [severity.critical, severity.high]"
//
// Returns the filtered result and an error if the CEL expression is invalid.
func FilterByCEL(ctx context.Context, result Result, expr string) (Result, error) {
	if expr == "" || len(result.Findings) == 0 {
		return result, nil
	}

	// Compile the CEL expression once
	program, err := compileCELFilter(expr)
	if err != nil {
		return result, fmt.Errorf("invalid filter expression: %w", err)
	}

	// Filter findings
	filtered := make([]vulnerability.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		adv := result.Advisories[f.AdvisoryID]

		// Build the payload for this finding (same structure as policy evaluation)
		payload := buildFindingPayload(f, adv)

		// Evaluate the expression
		out, _, err := program.ContextEval(ctx, payload)
		if err != nil {
			return result, fmt.Errorf("filter expression evaluation error: %w", err)
		}

		// Check if the result is truthy
		if keep, ok := out.Value().(bool); ok && keep {
			filtered = append(filtered, f)
		}
	}

	result.Findings = filtered
	result.Advisories = filterAdvisories(filtered, result.Advisories)
	result.Stats = vulnerability.ConsolidateAll(result.Findings, result.Advisories).Stats
	return result, nil
}

// compileCELFilter compiles a CEL filter expression for vulnerability filtering.
func compileCELFilter(expr string) (cel.Program, error) {
	env, err := policy.NewFilterEnv()
	if err != nil {
		return nil, err
	}

	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}

	return env.Program(ast)
}

// buildFindingPayload creates the CEL evaluation context for a single finding.
// This mirrors the payload structure used in policy evaluation.
func buildFindingPayload(f vulnerability.Finding, adv *vulnerabilityv1.Advisory) map[string]any {
	// Build package proto
	pkg := &dependencyv1.Package{
		Name:         f.Dependency.Name,
		Ecosystem:    f.Dependency.Ecosystem,
		Purl:         f.Dependency.PURL,
		Version:      f.Version,
		Direct:       f.Direct,
		LayerDetails: f.LayerDetails,
	}

	// Build vulnerability proto for consistent field access
	vuln := &vulnerabilityv1.Finding{
		AdvisoryId:     f.AdvisoryID,
		Advisory:       adv,
		Package:        pkg,
		Affected:       f.Affected,
		Epss:           f.EPSS,
		EpssPercentile: f.EPSSPercentile,
		InKev:          f.InKEV,
	}

	return map[string]any{
		"vulnerability": vuln,
		"severity":      policy.SeverityConstants(),
	}
}
