package scan

import (
	"context"
	"fmt"

	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/container/image"
	"github.com/picatz/deputy/internal/vulnerability"
)

// ContainerDiffOptions configures container image diff behavior.
type ContainerDiffOptions struct {
	// ScanVulnerabilities enables vulnerability scanning during diff.
	ScanVulnerabilities bool
	// ScanOptions controls vulnerability scan behavior.
	ScanOptions Options
}

// ContainerDiffResult contains the result of comparing two container images.
type ContainerDiffResult struct {
	// Report contains the structured diff report.
	Report *compare.ImageDiffReport

	// BaseResult is the full scan result for the base image.
	BaseResult *Result
	// TargetResult is the full scan result for the target image.
	TargetResult *Result
}

// CompareContainerImages compares two container images and returns a diff report.
// It scans both images for packages and optionally vulnerabilities, then computes
// the differences between them.
func (s *Service) CompareContainerImages(ctx context.Context, baseRef, targetRef string, opts ContainerDiffOptions) (*ContainerDiffResult, error) {
	// Scan both images in parallel
	type scanResult struct {
		result *Execution
		err    error
	}

	baseCh := make(chan scanResult, 1)
	targetCh := make(chan scanResult, 1)

	go func() {
		exec, err := s.ScanContainerImage(ctx, baseRef, nil, opts.ScanOptions)
		baseCh <- scanResult{result: exec, err: err}
	}()

	go func() {
		exec, err := s.ScanContainerImage(ctx, targetRef, nil, opts.ScanOptions)
		targetCh <- scanResult{result: exec, err: err}
	}()

	// Wait for both scans
	baseRes := <-baseCh
	targetRes := <-targetCh

	if baseRes.err != nil {
		return nil, fmt.Errorf("scan base image %q: %w", baseRef, baseRes.err)
	}
	if targetRes.err != nil {
		if baseRes.result != nil {
			baseRes.result.Close()
		}
		return nil, fmt.Errorf("scan target image %q: %w", targetRef, targetRes.err)
	}

	defer baseRes.result.Close()
	defer targetRes.result.Close()

	// Build the diff report
	report := buildContainerDiffReport(&baseRes.result.Result, &targetRes.result.Result)

	return &ContainerDiffResult{
		Report:       report,
		BaseResult:   &baseRes.result.Result,
		TargetResult: &targetRes.result.Result,
	}, nil
}

// buildContainerDiffReport constructs an ImageDiffReport from two scan results.
func buildContainerDiffReport(baseResult, targetResult *Result) *compare.ImageDiffReport {
	report := &compare.ImageDiffReport{
		BaseImage:   extractImageRef(baseResult),
		TargetImage: extractImageRef(targetResult),
	}

	// Compare packages with layer tracking
	report.PackageChanges = compareImagePackages(baseResult, targetResult)

	// Compare vulnerabilities
	report.VulnerabilityChanges = compareImageVulnerabilities(baseResult, targetResult)

	// Compare configuration (only if both results have ImageInfo)
	if baseResult != nil && targetResult != nil &&
		baseResult.ImageInfo != nil && targetResult.ImageInfo != nil {
		baseInput := toImageInput(baseResult.ImageInfo)
		targetInput := toImageInput(targetResult.ImageInfo)
		report.ConfigChanges = compare.CompareImageConfigs(baseInput, targetInput)
		report.LayerAnalysis = compare.AnalyzeLayerDiff(baseInput, targetInput)
	}

	// Calculate summary
	report.Summary = compare.CalculateImageDiffSummary(report)

	return report
}

func extractImageRef(result *Result) compare.ImageRef {
	if result == nil {
		return compare.ImageRef{}
	}
	ref := compare.ImageRef{
		Reference: result.Target.DisplayPath,
	}
	if result.Target.Provenance != nil {
		ref.Registry = result.Target.Provenance["registry"]
		ref.Repository = result.Target.Provenance["repository"]
		ref.Tag = result.Target.Provenance["tag"]
		ref.Digest = result.Target.Provenance["digest"]
	}
	return ref
}

func toImageInput(info *image.Info) *compare.ImageInput {
	if info == nil {
		return nil
	}

	input := &compare.ImageInput{
		Config: compare.ImageConfigInput{
			User:           info.Config.User,
			Env:            info.Config.Env,
			SensitiveEnv:   info.Config.HasSensitiveEnv(),
			Entrypoint:     info.Config.Entrypoint,
			Cmd:            info.Config.Cmd,
			WorkingDir:     info.Config.WorkingDir,
			ExposedPorts:   info.Config.ExposedPorts,
			Volumes:        info.Config.Volumes,
			Labels:         info.Config.Labels,
			IsRoot:         info.Config.IsRootUser(),
			HasHealthcheck: info.Config.Healthcheck != nil,
		},
		Metadata: compare.ImageMetadataInput{
			LayerCount: info.Metadata.LayerCount,
		},
	}

	for _, h := range info.History {
		input.History = append(input.History, compare.ImageHistoryInput{
			CreatedBy:  h.CreatedBy,
			Created:    h.Created,
			EmptyLayer: h.EmptyLayer,
		})
	}

	return input
}

func compareImagePackages(baseResult, targetResult *Result) []compare.ImagePackageChange {
	if baseResult == nil || targetResult == nil {
		return nil
	}

	// Use existing ComparePackages logic
	baseChanges := compare.ComparePackages(
		baseResult.Inventory.Packages,
		targetResult.Inventory.Packages,
		nil, nil, nil,
	)

	// Build layer lookup maps for both images
	baseLayerMap := buildPackageLayerMap(baseResult)
	targetLayerMap := buildPackageLayerMap(targetResult)

	// Convert to ImagePackageChange with layer details
	changes := make([]compare.ImagePackageChange, 0, len(baseChanges))
	for _, c := range baseChanges {
		ipc := compare.ImagePackageChange{
			Change:             c,
			BaseLayerDetails:   baseLayerMap[c.Name],
			TargetLayerDetails: targetLayerMap[c.Name],
		}
		// For removed packages, use old name if different
		if c.ChangeType == compare.Removed && c.OldName != "" {
			ipc.BaseLayerDetails = baseLayerMap[c.OldName]
		}
		changes = append(changes, ipc)
	}

	return changes
}

func buildPackageLayerMap(result *Result) map[string]*containerv1.LayerDetails {
	layerMap := make(map[string]*containerv1.LayerDetails)

	for _, finding := range result.Findings {
		if finding.LayerDetails == nil {
			continue
		}
		// Each finding is for a single dependency
		layerMap[finding.Dependency.Name] = &containerv1.LayerDetails{
			Index:       finding.LayerDetails.Index,
			DiffId:      finding.LayerDetails.DiffId,
			ChainId:     finding.LayerDetails.ChainId,
			Command:     finding.LayerDetails.Command,
			InBaseImage: finding.LayerDetails.InBaseImage,
		}
	}

	return layerMap
}

func compareImageVulnerabilities(baseResult, targetResult *Result) []compare.VulnerabilityChange {
	if baseResult == nil || targetResult == nil {
		return nil
	}

	// Build map of findings by advisory ID
	baseFindings := make(map[string]vulnerability.Finding)
	targetFindings := make(map[string]vulnerability.Finding)

	for _, f := range baseResult.Findings {
		baseFindings[f.AdvisoryID] = f
	}
	for _, f := range targetResult.Findings {
		targetFindings[f.AdvisoryID] = f
	}

	var changes []compare.VulnerabilityChange

	// Find removed/fixed vulnerabilities
	for advisoryID, baseFinding := range baseFindings {
		baseAdvisory := baseResult.Advisories[advisoryID]
		targetFinding, exists := targetFindings[advisoryID]
		if !exists {
			changeType := compare.VulnRemoved
			// Check if it was fixed by an upgrade
			if wasFixedByUpgrade(baseFinding, targetResult) {
				changeType = compare.VulnFixed
			}
			// Removed/fixed: only base layer details, no target
			changes = append(changes, buildVulnerabilityChange(
				advisoryID, changeType, baseAdvisory,
				baseFinding.Dependency.Name, baseFinding.Dependency.Ecosystem,
				baseFinding.Version, "",
				baseFinding.LayerDetails, nil,
			))
		} else {
			// Vulnerability persists: has both base and target layer details
			targetAdvisory := targetResult.Advisories[advisoryID]
			changes = append(changes, buildVulnerabilityChange(
				advisoryID, compare.VulnPersisted, targetAdvisory,
				targetFinding.Dependency.Name, targetFinding.Dependency.Ecosystem,
				baseFinding.Version, targetFinding.Version,
				baseFinding.LayerDetails, targetFinding.LayerDetails,
			))
		}
	}

	// Find added vulnerabilities
	for advisoryID, targetFinding := range targetFindings {
		if _, exists := baseFindings[advisoryID]; !exists {
			targetAdvisory := targetResult.Advisories[advisoryID]
			// Added: only target layer details, no base
			changes = append(changes, buildVulnerabilityChange(
				advisoryID, compare.VulnAdded, targetAdvisory,
				targetFinding.Dependency.Name, targetFinding.Dependency.Ecosystem,
				"", targetFinding.Version,
				nil, targetFinding.LayerDetails,
			))
		}
	}

	return changes
}

// buildVulnerabilityChange constructs a VulnerabilityChange with full advisory metadata.
func buildVulnerabilityChange(
	advisoryID string,
	changeType compare.VulnChangeType,
	advisory vulnerabilityv1.Advisory,
	pkgName, ecosystem, baseVersion, targetVersion string,
	baseLayerDetails, targetLayerDetails *containerv1.LayerDetails,
) compare.VulnerabilityChange {
	var sevLevel, sevType string
	if advisory.Severity != nil {
		sevLevel = advisory.Severity.Level.String()
		sevType = advisory.Severity.Type.String()
	}
	change := compare.VulnerabilityChange{
		ID:                 advisoryID,
		ChangeType:         changeType,
		Severity:           sevLevel,
		SeverityType:       sevType,
		PackageName:        pkgName,
		Ecosystem:          ecosystem,
		BaseVersion:        baseVersion,
		TargetVersion:      targetVersion,
		FixedVersions:      advisory.FixedVersions,
		Summary:            advisory.Summary,
		Aliases:            advisory.Aliases,
		BaseLayerDetails:   convertLayerDetails(baseLayerDetails),
		TargetLayerDetails: convertLayerDetails(targetLayerDetails),
	}

	// Format published date if available
	if pub := vulnerability.AdvisoryPublished(&advisory); !pub.IsZero() {
		change.Published = pub.Format("2006-01-02")
	}

	return change
}

func wasFixedByUpgrade(finding vulnerability.Finding, targetResult *Result) bool {
	// A vulnerability is "fixed by upgrade" if:
	// 1. The package still exists in the target image (wasn't removed)
	// 2. The package version changed (was actually upgraded)
	//
	// If the package was removed entirely, it's VulnRemoved, not VulnFixed.
	// If the package exists but version didn't change, something else removed the vuln
	// (which shouldn't happen, but we handle it as VulnRemoved to be safe).
	pkgName := finding.Dependency.Name
	baseVersion := finding.Version

	for _, pkg := range targetResult.Inventory.Packages {
		if pkg.Name == pkgName {
			// Package exists - check if version changed
			targetVersion := pkg.Version
			if targetVersion != baseVersion {
				// Version changed, this is a fix by upgrade
				return true
			}
			// Same version but vulnerability gone - unusual case
			// Treat as removed (not fixed) since version didn't change
			return false
		}
	}
	// Package no longer exists
	return false
}

func convertLayerDetails(ld *containerv1.LayerDetails) *containerv1.LayerDetails {
	if ld == nil {
		return nil
	}
	return &containerv1.LayerDetails{
		Index:       ld.Index,
		DiffId:      ld.DiffId,
		ChainId:     ld.ChainId,
		Command:     ld.Command,
		InBaseImage: ld.InBaseImage,
	}
}

// BuildContainerDiffPayload converts an ImageDiffReport to a map suitable for policy evaluation.
func BuildContainerDiffPayload(report *compare.ImageDiffReport) map[string]any {
	payload := map[string]any{
		"base_image": map[string]any{
			"registry":   report.BaseImage.Registry,
			"repository": report.BaseImage.Repository,
			"tag":        report.BaseImage.Tag,
			"digest":     report.BaseImage.Digest,
			"reference":  report.BaseImage.Reference,
		},
		"target_image": map[string]any{
			"registry":   report.TargetImage.Registry,
			"repository": report.TargetImage.Repository,
			"tag":        report.TargetImage.Tag,
			"digest":     report.TargetImage.Digest,
			"reference":  report.TargetImage.Reference,
		},
		"summary": map[string]any{
			"packages_added":          report.Summary.PackagesAdded,
			"packages_removed":        report.Summary.PackagesRemoved,
			"packages_upgraded":       report.Summary.PackagesUpgraded,
			"packages_downgraded":     report.Summary.PackagesDowngraded,
			"vulnerabilities_added":   report.Summary.VulnerabilitiesAdded,
			"vulnerabilities_removed": report.Summary.VulnerabilitiesRemoved,
			"vulnerabilities_fixed":   report.Summary.VulnerabilitiesFixed,
			"layers_added":            report.Summary.LayersAdded,
			"layers_removed":          report.Summary.LayersRemoved,
			"config_changed":          report.Summary.ConfigChanged,
		},
	}

	// Add package changes
	if len(report.PackageChanges) > 0 {
		changes := make([]map[string]any, 0, len(report.PackageChanges))
		for _, c := range report.PackageChanges {
			change := map[string]any{
				"name":           c.Name,
				"old_name":       c.OldName,
				"target_version": c.TargetVersion,
				"base_version":   c.BaseVersion,
				"change_type":    c.ChangeType.String(),
				"ecosystem":      c.Ecosystem,
				"is_direct":      c.IsDirect,
			}
			if c.BaseLayerDetails != nil {
				change["base_layer_details"] = layerDetailsToMap(c.BaseLayerDetails)
			}
			if c.TargetLayerDetails != nil {
				change["target_layer_details"] = layerDetailsToMap(c.TargetLayerDetails)
			}
			changes = append(changes, change)
		}
		payload["package_changes"] = changes
	}

	// Add vulnerability changes
	if len(report.VulnerabilityChanges) > 0 {
		vulns := make([]map[string]any, 0, len(report.VulnerabilityChanges))
		for _, v := range report.VulnerabilityChanges {
			vuln := map[string]any{
				"id":             v.ID,
				"change_type":    v.ChangeType.String(),
				"severity":       v.Severity,
				"severity_type":  v.SeverityType,
				"package":        v.PackageName,
				"ecosystem":      v.Ecosystem,
				"base_version":   v.BaseVersion,
				"target_version": v.TargetVersion,
				"fixed_versions": v.FixedVersions,
				"summary":        v.Summary,
				"aliases":        v.Aliases,
				"published":      v.Published,
			}
			if v.BaseLayerDetails != nil {
				vuln["base_layer_details"] = layerDetailsToMap(v.BaseLayerDetails)
			}
			if v.TargetLayerDetails != nil {
				vuln["target_layer_details"] = layerDetailsToMap(v.TargetLayerDetails)
			}
			vulns = append(vulns, vuln)
		}
		payload["vulnerability_changes"] = vulns
	}

	// Add config changes
	if report.ConfigChanges != nil {
		payload["config_changes"] = configChangesToMap(report.ConfigChanges)
	}

	// Add layer analysis
	if report.LayerAnalysis != nil {
		payload["layer_analysis"] = layerAnalysisToMap(report.LayerAnalysis)
	}

	return payload
}

func layerDetailsToMap(ld *containerv1.LayerDetails) map[string]any {
	return map[string]any{
		"index":         ld.Index,
		"diff_id":       ld.DiffId,
		"chain_id":      ld.ChainId,
		"command":       ld.Command,
		"in_base_image": ld.InBaseImage,
	}
}

func configChangesToMap(cc *compare.ImageConfigDiff) map[string]any {
	return map[string]any{
		"user_changed":        cc.UserChanged,
		"base_user":           cc.BaseUser,
		"target_user":         cc.TargetUser,
		"root_changed":        cc.RootChanged,
		"base_is_root":        cc.BaseIsRoot,
		"target_is_root":      cc.TargetIsRoot,
		"ports_changed":       cc.PortsChanged,
		"ports_added":         cc.PortsAdded,
		"ports_removed":       cc.PortsRemoved,
		"volumes_changed":     cc.VolumesChanged,
		"volumes_added":       cc.VolumesAdded,
		"volumes_removed":     cc.VolumesRemoved,
		"entrypoint_changed":  cc.EntrypointChanged,
		"cmd_changed":         cc.CmdChanged,
		"working_dir_changed": cc.WorkingDirChanged,
		"healthcheck_changed": cc.HealthcheckChanged,
	}
}

func layerAnalysisToMap(la *compare.LayerDiffAnalysis) map[string]any {
	result := map[string]any{
		"base_layer_count":   la.BaseLayerCount,
		"target_layer_count": la.TargetLayerCount,
		"common_layers":      la.CommonLayers,
	}

	if len(la.LayerChanges) > 0 {
		changes := make([]map[string]any, 0, len(la.LayerChanges))
		for _, lc := range la.LayerChanges {
			changes = append(changes, map[string]any{
				"index":          lc.Index,
				"change_type":    lc.ChangeType.String(),
				"base_command":   lc.BaseCommand,
				"target_command": lc.TargetCommand,
			})
		}
		result["layer_changes"] = changes
	}

	return result
}
