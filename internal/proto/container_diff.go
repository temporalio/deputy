package proto

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"google.golang.org/protobuf/types/known/timestamppb"

	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	diffv1 "github.com/picatz/deputy/gen/deputy/diff/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/container/image"
	"github.com/picatz/deputy/internal/scanning"
	"github.com/picatz/deputy/internal/vulnerability"
)

// BuildContainerDiffResponseFromScanning constructs the proto response from scanning.Result.
// This is used by the DiffHandler which uses the scanning package directly.
func BuildContainerDiffResponseFromScanning(baseResult, targetResult *scanning.Result) *diffv1.DiffContainerImagesResponse {
	now := timestamppb.Now()

	response := &diffv1.DiffContainerImagesResponse{
		BaseImage:     extractContainerImageRefFromScanning(baseResult),
		TargetImage:   extractContainerImageRefFromScanning(targetResult),
		GeneratedAt:   now,
		BaseContext:   extractContainerContextFromScanning(baseResult),
		TargetContext: extractContainerContextFromScanning(targetResult),
	}

	// Compare packages
	response.PackageChanges = compareContainerPackagesFromScanning(baseResult, targetResult)

	// Compare vulnerabilities
	response.VulnerabilityChanges, response.Advisories = compareContainerVulnerabilitiesFromScanning(baseResult, targetResult)

	// Compare configuration
	if baseResult != nil && targetResult != nil &&
		baseResult.ImageInfo != nil && targetResult.ImageInfo != nil {
		response.ConfigChanges = compareContainerConfigs(baseResult.ImageInfo, targetResult.ImageInfo)
		response.LayerAnalysis = compareContainerLayers(baseResult.ImageInfo, targetResult.ImageInfo)
	}

	// Calculate summary
	response.Summary = calculateContainerDiffSummary(response)

	return response
}

// Helper functions for scanning.Result (used by DiffHandler)

func extractContainerImageRefFromScanning(result *scanning.Result) *diffv1.ContainerImageRef {
	if result == nil {
		return &diffv1.ContainerImageRef{}
	}
	ref := &diffv1.ContainerImageRef{
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

func extractContainerContextFromScanning(result *scanning.Result) *diffv1.ContainerImageContext {
	if result == nil {
		return &diffv1.ContainerImageContext{}
	}

	ctx := &diffv1.ContainerImageContext{
		PackageCount: int32(len(result.Packages)),
	}

	// Extract distro from packages
	ctx.Distro = extractDistroFromPackages(result.Packages)

	// Extract metadata from ImageInfo
	if result.ImageInfo != nil {
		ctx.Size = result.ImageInfo.Metadata.Size
		ctx.Architecture = result.ImageInfo.Metadata.Architecture
	}

	return ctx
}

func extractDistroFromPackages(pkgs []*extractor.Package) string {
	if len(pkgs) == 0 {
		return ""
	}

	// Count ecosystems to find the most common one
	ecosystemCounts := make(map[string]int)
	for _, pkg := range pkgs {
		eco := pkg.Ecosystem().String()
		if eco == "" {
			continue
		}
		if strings.Contains(eco, ":") {
			ecosystemCounts[eco]++
		}
	}

	if len(ecosystemCounts) == 0 {
		return ""
	}

	var mostCommon string
	var maxCount int
	for eco, count := range ecosystemCounts {
		if count > maxCount {
			maxCount = count
			mostCommon = eco
		}
	}

	// Format nicely: "Debian:11" -> "Debian 11"
	if mostCommon != "" {
		parts := strings.SplitN(mostCommon, ":", 2)
		if len(parts) == 2 {
			return parts[0] + " " + parts[1]
		}
		return mostCommon
	}
	return ""
}

func compareContainerPackagesFromScanning(baseResult, targetResult *scanning.Result) []*diffv1.ContainerPackageChange {
	if baseResult == nil || targetResult == nil {
		return nil
	}

	// Use existing ComparePackages logic
	baseChanges := compare.ComparePackages(
		baseResult.Packages,
		targetResult.Packages,
		nil, nil, nil,
	)

	// Build layer lookup maps
	baseLayerMap := buildPackageLayerMapFromScanning(baseResult)
	targetLayerMap := buildPackageLayerMapFromScanning(targetResult)

	// Convert to proto
	changes := make([]*diffv1.ContainerPackageChange, 0, len(baseChanges))
	for _, c := range baseChanges {
		change := &diffv1.ContainerPackageChange{
			Name:               c.Name,
			Ecosystem:          c.Ecosystem,
			ChangeKind:         convertChangeKind(c.ChangeType),
			BaseVersion:        c.BaseVersion,
			TargetVersion:      c.TargetVersion,
			OldName:            c.OldName,
			IsDirect:           c.IsDirect,
			BaseLayerDetails:   baseLayerMap[c.Name],
			TargetLayerDetails: targetLayerMap[c.Name],
		}
		// For removed packages, use old name if different
		if c.ChangeType == compare.Removed && c.OldName != "" {
			change.BaseLayerDetails = baseLayerMap[c.OldName]
		}
		changes = append(changes, change)
	}

	return changes
}

func buildPackageLayerMapFromScanning(result *scanning.Result) map[string]*containerv1.LayerDetails {
	layerMap := make(map[string]*containerv1.LayerDetails)

	for _, finding := range result.Findings {
		if finding.LayerDetails == nil {
			continue
		}
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

func compareContainerVulnerabilitiesFromScanning(baseResult, targetResult *scanning.Result) ([]*diffv1.ContainerVulnerabilityChange, map[string]*vulnerabilityv1.Advisory) {
	if baseResult == nil || targetResult == nil {
		return nil, nil
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

	var changes []*diffv1.ContainerVulnerabilityChange
	advisories := make(map[string]*vulnerabilityv1.Advisory)

	// Find removed/fixed vulnerabilities
	for advisoryID, baseFinding := range baseFindings {
		baseAdvisory := baseResult.Advisories[advisoryID]
		_, exists := targetFindings[advisoryID]
		if !exists {
			changeKind := diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_REMOVED
			// Check if it was fixed by an upgrade
			if wasVulnFixedByUpgradeFromScanning(baseFinding, targetResult) {
				changeKind = diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_FIXED
			}
			change := buildVulnChangeProto(advisoryID, changeKind, baseAdvisory,
				baseFinding.Dependency.Name, baseFinding.Dependency.Ecosystem,
				baseFinding.Version, "",
				baseFinding.LayerDetails, nil)
			changes = append(changes, change)
			advisories[advisoryID] = baseAdvisory
		} else {
			// Vulnerability persists
			targetFinding := targetFindings[advisoryID]
			targetAdvisory := targetResult.Advisories[advisoryID]
			change := buildVulnChangeProto(advisoryID, diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_PERSISTED, targetAdvisory,
				targetFinding.Dependency.Name, targetFinding.Dependency.Ecosystem,
				baseFinding.Version, targetFinding.Version,
				baseFinding.LayerDetails, targetFinding.LayerDetails)
			changes = append(changes, change)
			advisories[advisoryID] = targetAdvisory
		}
	}

	// Find added vulnerabilities
	for advisoryID, targetFinding := range targetFindings {
		if _, exists := baseFindings[advisoryID]; !exists {
			targetAdvisory := targetResult.Advisories[advisoryID]
			change := buildVulnChangeProto(advisoryID, diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_ADDED, targetAdvisory,
				targetFinding.Dependency.Name, targetFinding.Dependency.Ecosystem,
				"", targetFinding.Version,
				nil, targetFinding.LayerDetails)
			changes = append(changes, change)
			advisories[advisoryID] = targetAdvisory
		}
	}

	return changes, advisories
}

func wasVulnFixedByUpgradeFromScanning(finding vulnerability.Finding, targetResult *scanning.Result) bool {
	pkgName := finding.Dependency.Name
	baseVersion := finding.Version

	for _, pkg := range targetResult.Packages {
		if pkg.Name == pkgName {
			if pkg.Version != baseVersion {
				return true
			}
			return false
		}
	}
	return false
}

func convertChangeKind(ct compare.ChangeType) diffv1.ChangeKind {
	switch ct {
	case compare.Added:
		return diffv1.ChangeKind_CHANGE_KIND_ADDED
	case compare.Removed:
		return diffv1.ChangeKind_CHANGE_KIND_REMOVED
	case compare.Upgraded:
		return diffv1.ChangeKind_CHANGE_KIND_UPGRADED
	case compare.Downgraded:
		return diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED
	case compare.Updated:
		return diffv1.ChangeKind_CHANGE_KIND_UPDATED
	default:
		return diffv1.ChangeKind_CHANGE_KIND_UNSPECIFIED
	}
}

func buildVulnChangeProto(
	advisoryID string,
	changeKind diffv1.VulnerabilityChangeKind,
	advisory *vulnerabilityv1.Advisory,
	pkgName, ecosystem, baseVersion, targetVersion string,
	baseLayerDetails, targetLayerDetails *containerv1.LayerDetails,
) *diffv1.ContainerVulnerabilityChange {
	var sevLevel, sevType string
	var fixedVersions []string
	var summary string
	var aliases []string
	if advisory != nil {
		if advisory.Severity != nil {
			sevLevel = advisory.Severity.Level.String()
			sevType = advisory.Severity.Type.String()
		}
		fixedVersions = advisory.FixedVersions
		summary = advisory.Summary
		aliases = advisory.Aliases
	}

	change := &diffv1.ContainerVulnerabilityChange{
		Id:            advisoryID,
		ChangeKind:    changeKind,
		Severity:      sevLevel,
		SeverityType:  sevType,
		PackageName:   pkgName,
		Ecosystem:     ecosystem,
		BaseVersion:   baseVersion,
		TargetVersion: targetVersion,
		FixedVersions: fixedVersions,
		Summary:       summary,
		Aliases:       aliases,
	}

	// Format published date if available
	if pub := vulnerability.AdvisoryPublished(advisory); !pub.IsZero() {
		change.Published = pub.Format("2006-01-02")
	}

	// Copy layer details
	if baseLayerDetails != nil {
		change.BaseLayerDetails = &containerv1.LayerDetails{
			Index:       baseLayerDetails.Index,
			DiffId:      baseLayerDetails.DiffId,
			ChainId:     baseLayerDetails.ChainId,
			Command:     baseLayerDetails.Command,
			InBaseImage: baseLayerDetails.InBaseImage,
		}
	}
	if targetLayerDetails != nil {
		change.TargetLayerDetails = &containerv1.LayerDetails{
			Index:       targetLayerDetails.Index,
			DiffId:      targetLayerDetails.DiffId,
			ChainId:     targetLayerDetails.ChainId,
			Command:     targetLayerDetails.Command,
			InBaseImage: targetLayerDetails.InBaseImage,
		}
	}

	return change
}

func compareContainerConfigs(baseInfo, targetInfo *image.Info) *diffv1.ContainerConfigDiff {
	if baseInfo == nil || targetInfo == nil {
		return nil
	}

	diff := &diffv1.ContainerConfigDiff{}

	// User comparison
	if baseInfo.Config.User != targetInfo.Config.User {
		diff.UserChanged = true
		diff.BaseUser = baseInfo.Config.User
		diff.TargetUser = targetInfo.Config.User
	}

	// Root user comparison
	baseIsRoot := baseInfo.Config.IsRootUser()
	targetIsRoot := targetInfo.Config.IsRootUser()
	if baseIsRoot != targetIsRoot {
		diff.RootChanged = true
		diff.BaseIsRoot = baseIsRoot
		diff.TargetIsRoot = targetIsRoot
	}

	// Ports comparison
	basePorts := make(map[string]bool)
	for _, p := range baseInfo.Config.ExposedPorts {
		basePorts[p] = true
	}
	targetPorts := make(map[string]bool)
	for _, p := range targetInfo.Config.ExposedPorts {
		targetPorts[p] = true
	}
	for p := range targetPorts {
		if !basePorts[p] {
			diff.PortsAdded = append(diff.PortsAdded, p)
		}
	}
	for p := range basePorts {
		if !targetPorts[p] {
			diff.PortsRemoved = append(diff.PortsRemoved, p)
		}
	}
	diff.PortsChanged = len(diff.PortsAdded) > 0 || len(diff.PortsRemoved) > 0

	// Volumes comparison
	baseVols := make(map[string]bool)
	for _, v := range baseInfo.Config.Volumes {
		baseVols[v] = true
	}
	targetVols := make(map[string]bool)
	for _, v := range targetInfo.Config.Volumes {
		targetVols[v] = true
	}
	for v := range targetVols {
		if !baseVols[v] {
			diff.VolumesAdded = append(diff.VolumesAdded, v)
		}
	}
	for v := range baseVols {
		if !targetVols[v] {
			diff.VolumesRemoved = append(diff.VolumesRemoved, v)
		}
	}
	diff.VolumesChanged = len(diff.VolumesAdded) > 0 || len(diff.VolumesRemoved) > 0

	// Entrypoint comparison
	if !slicesEqual(baseInfo.Config.Entrypoint, targetInfo.Config.Entrypoint) {
		diff.EntrypointChanged = true
		diff.BaseEntrypoint = baseInfo.Config.Entrypoint
		diff.TargetEntrypoint = targetInfo.Config.Entrypoint
	}

	// Cmd comparison
	if !slicesEqual(baseInfo.Config.Cmd, targetInfo.Config.Cmd) {
		diff.CmdChanged = true
		diff.BaseCmd = baseInfo.Config.Cmd
		diff.TargetCmd = targetInfo.Config.Cmd
	}

	// Working dir comparison
	if baseInfo.Config.WorkingDir != targetInfo.Config.WorkingDir {
		diff.WorkingDirChanged = true
		diff.BaseWorkingDir = baseInfo.Config.WorkingDir
		diff.TargetWorkingDir = targetInfo.Config.WorkingDir
	}

	// Healthcheck comparison
	baseHasHealth := baseInfo.Config.Healthcheck != nil
	targetHasHealth := targetInfo.Config.Healthcheck != nil
	diff.HealthcheckChanged = baseHasHealth != targetHasHealth

	// Environment variable comparison
	diff.EnvChanges = compareEnvVars(baseInfo.Config.Env, targetInfo.Config.Env)

	// Label comparison
	diff.LabelChanges = compareLabels(baseInfo.Config.Labels, targetInfo.Config.Labels)

	return diff
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func compareEnvVars(baseEnv, targetEnv []string) []*diffv1.EnvChange {
	baseMap := make(map[string]string)
	for _, e := range baseEnv {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			baseMap[parts[0]] = parts[1]
		}
	}

	targetMap := make(map[string]string)
	for _, e := range targetEnv {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			targetMap[parts[0]] = parts[1]
		}
	}

	var changes []*diffv1.EnvChange

	// Find added and updated
	for name, targetVal := range targetMap {
		baseVal, exists := baseMap[name]
		if !exists {
			changes = append(changes, &diffv1.EnvChange{
				Name:        name,
				ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_ADDED,
				TargetValue: targetVal,
				IsSensitive: isSensitiveEnvVar(name),
			})
		} else if baseVal != targetVal {
			changes = append(changes, &diffv1.EnvChange{
				Name:        name,
				ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_UPDATED,
				BaseValue:   baseVal,
				TargetValue: targetVal,
				IsSensitive: isSensitiveEnvVar(name),
			})
		}
	}

	// Find removed
	for name, baseVal := range baseMap {
		if _, exists := targetMap[name]; !exists {
			changes = append(changes, &diffv1.EnvChange{
				Name:        name,
				ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_REMOVED,
				BaseValue:   baseVal,
				IsSensitive: isSensitiveEnvVar(name),
			})
		}
	}

	return changes
}

func isSensitiveEnvVar(name string) bool {
	upper := strings.ToUpper(name)
	sensitivePatterns := []string{"PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "API_KEY"}
	for _, p := range sensitivePatterns {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

func compareLabels(baseLabels, targetLabels map[string]string) []*diffv1.LabelChange {
	var changes []*diffv1.LabelChange

	// Find added and updated
	for key, targetVal := range targetLabels {
		baseVal, exists := baseLabels[key]
		if !exists {
			changes = append(changes, &diffv1.LabelChange{
				Key:         key,
				ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_ADDED,
				TargetValue: targetVal,
			})
		} else if baseVal != targetVal {
			changes = append(changes, &diffv1.LabelChange{
				Key:         key,
				ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_UPDATED,
				BaseValue:   baseVal,
				TargetValue: targetVal,
			})
		}
	}

	// Find removed
	for key, baseVal := range baseLabels {
		if _, exists := targetLabels[key]; !exists {
			changes = append(changes, &diffv1.LabelChange{
				Key:        key,
				ChangeKind: diffv1.ChangeKind_CHANGE_KIND_REMOVED,
				BaseValue:  baseVal,
			})
		}
	}

	return changes
}

func compareContainerLayers(baseInfo, targetInfo *image.Info) *diffv1.LayerDiffAnalysis {
	if baseInfo == nil || targetInfo == nil {
		return nil
	}

	analysis := &diffv1.LayerDiffAnalysis{
		BaseLayerCount:   int32(baseInfo.Metadata.LayerCount),
		TargetLayerCount: int32(targetInfo.Metadata.LayerCount),
	}

	// Compare layers by history
	baseLen := len(baseInfo.History)
	targetLen := len(targetInfo.History)
	maxLen := baseLen
	if targetLen > maxLen {
		maxLen = targetLen
	}

	for i := 0; i < maxLen; i++ {
		var change diffv1.LayerChange
		change.Index = int32(i)

		hasBase := i < baseLen
		hasTarget := i < targetLen

		if hasBase {
			change.BaseCommand = baseInfo.History[i].CreatedBy
		}
		if hasTarget {
			change.TargetCommand = targetInfo.History[i].CreatedBy
		}

		if hasBase && hasTarget {
			if baseInfo.History[i].CreatedBy == targetInfo.History[i].CreatedBy {
				change.ChangeKind = diffv1.LayerChangeKind_LAYER_CHANGE_KIND_UNCHANGED
				analysis.CommonLayers++
			} else {
				change.ChangeKind = diffv1.LayerChangeKind_LAYER_CHANGE_KIND_MODIFIED
			}
		} else if hasTarget {
			change.ChangeKind = diffv1.LayerChangeKind_LAYER_CHANGE_KIND_ADDED
		} else {
			change.ChangeKind = diffv1.LayerChangeKind_LAYER_CHANGE_KIND_REMOVED
		}

		// Only include non-unchanged layers in the response
		if change.ChangeKind != diffv1.LayerChangeKind_LAYER_CHANGE_KIND_UNCHANGED {
			analysis.LayerChanges = append(analysis.LayerChanges, &change)
		}
	}

	return analysis
}

func calculateContainerDiffSummary(response *diffv1.DiffContainerImagesResponse) *diffv1.ContainerDiffSummary {
	summary := &diffv1.ContainerDiffSummary{}

	// Count package changes
	for _, c := range response.PackageChanges {
		switch c.ChangeKind {
		case diffv1.ChangeKind_CHANGE_KIND_ADDED:
			summary.PackagesAdded++
		case diffv1.ChangeKind_CHANGE_KIND_REMOVED:
			summary.PackagesRemoved++
		case diffv1.ChangeKind_CHANGE_KIND_UPGRADED:
			summary.PackagesUpgraded++
		case diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED:
			summary.PackagesDowngraded++
		}
	}

	// Count vulnerability changes
	for _, v := range response.VulnerabilityChanges {
		switch v.ChangeKind {
		case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_ADDED:
			summary.VulnerabilitiesAdded++
		case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_REMOVED:
			summary.VulnerabilitiesRemoved++
		case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_FIXED:
			summary.VulnerabilitiesFixed++
		}
	}

	// Count layer changes
	if response.LayerAnalysis != nil {
		for _, l := range response.LayerAnalysis.LayerChanges {
			switch l.ChangeKind {
			case diffv1.LayerChangeKind_LAYER_CHANGE_KIND_ADDED:
				summary.LayersAdded++
			case diffv1.LayerChangeKind_LAYER_CHANGE_KIND_REMOVED:
				summary.LayersRemoved++
			}
		}
	}

	// Check for config changes
	if response.ConfigChanges != nil {
		cc := response.ConfigChanges
		summary.ConfigChanged = cc.UserChanged || cc.RootChanged || cc.PortsChanged ||
			cc.VolumesChanged || cc.EntrypointChanged || cc.CmdChanged ||
			cc.WorkingDirChanged || cc.HealthcheckChanged ||
			len(cc.EnvChanges) > 0 || len(cc.LabelChanges) > 0
	}

	return summary
}

// ContainerDiffResponseToReport converts a proto response to the internal ImageDiffReport format.
// This allows reusing existing rendering functions.
func ContainerDiffResponseToReport(resp *diffv1.DiffContainerImagesResponse) *compare.ImageDiffReport {
	if resp == nil {
		return nil
	}

	report := &compare.ImageDiffReport{
		BaseImage:   protoImageRefToCompare(resp.BaseImage),
		TargetImage: protoImageRefToCompare(resp.TargetImage),
	}

	// Convert package changes
	for _, pc := range resp.PackageChanges {
		report.PackageChanges = append(report.PackageChanges, compare.ImagePackageChange{
			Change: compare.Change{
				Name:          pc.Name,
				Ecosystem:     pc.Ecosystem,
				ChangeType:    protoChangeKindToCompare(pc.ChangeKind),
				BaseVersion:   pc.BaseVersion,
				TargetVersion: pc.TargetVersion,
				OldName:       pc.OldName,
				IsDirect:      pc.IsDirect,
			},
			BaseLayerDetails:   pc.BaseLayerDetails,
			TargetLayerDetails: pc.TargetLayerDetails,
		})
	}

	// Convert vulnerability changes
	for _, vc := range resp.VulnerabilityChanges {
		report.VulnerabilityChanges = append(report.VulnerabilityChanges, compare.VulnerabilityChange{
			ID:                 vc.Id,
			ChangeType:         protoVulnChangeKindToCompare(vc.ChangeKind),
			Severity:           vc.Severity,
			SeverityType:       vc.SeverityType,
			PackageName:        vc.PackageName,
			Ecosystem:          vc.Ecosystem,
			BaseVersion:        vc.BaseVersion,
			TargetVersion:      vc.TargetVersion,
			FixedVersions:      vc.FixedVersions,
			Summary:            vc.Summary,
			Aliases:            vc.Aliases,
			Published:          vc.Published,
			BaseLayerDetails:   vc.BaseLayerDetails,
			TargetLayerDetails: vc.TargetLayerDetails,
		})
	}

	// Convert config changes
	if resp.ConfigChanges != nil {
		cc := resp.ConfigChanges
		configDiff := &compare.ImageConfigDiff{
			UserChanged:        cc.UserChanged,
			BaseUser:           cc.BaseUser,
			TargetUser:         cc.TargetUser,
			RootChanged:        cc.RootChanged,
			BaseIsRoot:         cc.BaseIsRoot,
			TargetIsRoot:       cc.TargetIsRoot,
			PortsChanged:       cc.PortsChanged,
			PortsAdded:         cc.PortsAdded,
			PortsRemoved:       cc.PortsRemoved,
			VolumesChanged:     cc.VolumesChanged,
			VolumesAdded:       cc.VolumesAdded,
			VolumesRemoved:     cc.VolumesRemoved,
			EntrypointChanged:  cc.EntrypointChanged,
			BaseEntrypoint:     cc.BaseEntrypoint,
			TargetEntrypoint:   cc.TargetEntrypoint,
			CmdChanged:         cc.CmdChanged,
			BaseCmd:            cc.BaseCmd,
			TargetCmd:          cc.TargetCmd,
			WorkingDirChanged:  cc.WorkingDirChanged,
			BaseWorkingDir:     cc.BaseWorkingDir,
			TargetWorkingDir:   cc.TargetWorkingDir,
			HealthcheckChanged: cc.HealthcheckChanged,
		}
		// Convert env changes
		for _, ec := range cc.EnvChanges {
			configDiff.EnvChanges = append(configDiff.EnvChanges, compare.EnvChange{
				Name:        ec.Name,
				ChangeType:  protoChangeKindToCompare(ec.ChangeKind),
				BaseValue:   ec.BaseValue,
				TargetValue: ec.TargetValue,
				IsSensitive: ec.IsSensitive,
			})
		}
		// Convert label changes
		for _, lc := range cc.LabelChanges {
			configDiff.LabelChanges = append(configDiff.LabelChanges, compare.LabelChange{
				Key:         lc.Key,
				ChangeType:  protoChangeKindToCompare(lc.ChangeKind),
				BaseValue:   lc.BaseValue,
				TargetValue: lc.TargetValue,
			})
		}
		report.ConfigChanges = configDiff
	}

	// Convert layer analysis
	if resp.LayerAnalysis != nil {
		la := resp.LayerAnalysis
		layerAnalysis := &compare.LayerDiffAnalysis{
			BaseLayerCount:   int(la.BaseLayerCount),
			TargetLayerCount: int(la.TargetLayerCount),
			CommonLayers:     int(la.CommonLayers),
		}
		for _, lc := range la.LayerChanges {
			layerAnalysis.LayerChanges = append(layerAnalysis.LayerChanges, compare.LayerChange{
				Index:         int(lc.Index),
				ChangeType:    protoLayerChangeKindToCompare(lc.ChangeKind),
				BaseCommand:   lc.BaseCommand,
				TargetCommand: lc.TargetCommand,
			})
		}
		report.LayerAnalysis = layerAnalysis
	}

	// Convert summary
	if resp.Summary != nil {
		s := resp.Summary
		report.Summary = compare.ImageDiffSummary{
			PackagesAdded:         int(s.PackagesAdded),
			PackagesRemoved:       int(s.PackagesRemoved),
			PackagesUpgraded:      int(s.PackagesUpgraded),
			PackagesDowngraded:    int(s.PackagesDowngraded),
			VulnerabilitiesAdded:  int(s.VulnerabilitiesAdded),
			VulnerabilitiesRemoved: int(s.VulnerabilitiesRemoved),
			VulnerabilitiesFixed:  int(s.VulnerabilitiesFixed),
			LayersAdded:           int(s.LayersAdded),
			LayersRemoved:         int(s.LayersRemoved),
			ConfigChanged:         s.ConfigChanged,
		}
	}

	return report
}

// ContainerDiffResponseContext provides additional context for rendering.
type ContainerDiffResponseContext struct {
	BaseDistro         string
	BasePackageCount   int
	BaseSize           int64
	BaseArch           string
	TargetDistro       string
	TargetPackageCount int
	TargetSize         int64
	TargetArch         string
}

// ExtractContainerDiffContext extracts display context from a proto response.
func ExtractContainerDiffContext(resp *diffv1.DiffContainerImagesResponse) ContainerDiffResponseContext {
	ctx := ContainerDiffResponseContext{}
	if resp.BaseContext != nil {
		ctx.BaseDistro = resp.BaseContext.Distro
		ctx.BasePackageCount = int(resp.BaseContext.PackageCount)
		ctx.BaseSize = resp.BaseContext.Size
		ctx.BaseArch = resp.BaseContext.Architecture
	}
	if resp.TargetContext != nil {
		ctx.TargetDistro = resp.TargetContext.Distro
		ctx.TargetPackageCount = int(resp.TargetContext.PackageCount)
		ctx.TargetSize = resp.TargetContext.Size
		ctx.TargetArch = resp.TargetContext.Architecture
	}
	return ctx
}

func protoImageRefToCompare(ref *diffv1.ContainerImageRef) compare.ImageRef {
	if ref == nil {
		return compare.ImageRef{}
	}
	return compare.ImageRef{
		Reference:  ref.Reference,
		Registry:   ref.Registry,
		Repository: ref.Repository,
		Tag:        ref.Tag,
		Digest:     ref.Digest,
	}
}

func protoChangeKindToCompare(kind diffv1.ChangeKind) compare.ChangeType {
	switch kind {
	case diffv1.ChangeKind_CHANGE_KIND_ADDED:
		return compare.Added
	case diffv1.ChangeKind_CHANGE_KIND_REMOVED:
		return compare.Removed
	case diffv1.ChangeKind_CHANGE_KIND_UPGRADED:
		return compare.Upgraded
	case diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED:
		return compare.Downgraded
	case diffv1.ChangeKind_CHANGE_KIND_UPDATED:
		return compare.Updated
	default:
		return compare.Added // Default to Added for unspecified
	}
}

func protoVulnChangeKindToCompare(kind diffv1.VulnerabilityChangeKind) compare.VulnChangeType {
	switch kind {
	case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_ADDED:
		return compare.VulnAdded
	case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_REMOVED:
		return compare.VulnRemoved
	case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_FIXED:
		return compare.VulnFixed
	case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_PERSISTED:
		return compare.VulnPersisted
	default:
		return compare.VulnAdded
	}
}

func protoLayerChangeKindToCompare(kind diffv1.LayerChangeKind) compare.LayerChangeType {
	switch kind {
	case diffv1.LayerChangeKind_LAYER_CHANGE_KIND_ADDED:
		return compare.LayerAdded
	case diffv1.LayerChangeKind_LAYER_CHANGE_KIND_REMOVED:
		return compare.LayerRemoved
	case diffv1.LayerChangeKind_LAYER_CHANGE_KIND_MODIFIED:
		return compare.LayerModified
	case diffv1.LayerChangeKind_LAYER_CHANGE_KIND_UNCHANGED:
		return compare.LayerSame
	default:
		return compare.LayerSame
	}
}

// ImageDiffReportToProto converts an internal ImageDiffReport to proto DiffContainerImagesResponse.
func ImageDiffReportToProto(report *compare.ImageDiffReport) *diffv1.DiffContainerImagesResponse {
	if report == nil {
		return nil
	}

	resp := &diffv1.DiffContainerImagesResponse{
		BaseImage:   imageRefToProto(report.BaseImage),
		TargetImage: imageRefToProto(report.TargetImage),
	}

	// Convert package changes
	for _, pc := range report.PackageChanges {
		resp.PackageChanges = append(resp.PackageChanges, &diffv1.ContainerPackageChange{
			Name:               pc.Name,
			Ecosystem:          pc.Ecosystem,
			ChangeKind:         ChangeKindToProto(pc.ChangeType),
			BaseVersion:        pc.BaseVersion,
			TargetVersion:      pc.TargetVersion,
			OldName:            pc.OldName,
			IsDirect:           pc.IsDirect,
			BaseLayerDetails:   pc.BaseLayerDetails,
			TargetLayerDetails: pc.TargetLayerDetails,
		})
	}

	// Convert vulnerability changes
	for _, vc := range report.VulnerabilityChanges {
		resp.VulnerabilityChanges = append(resp.VulnerabilityChanges, &diffv1.ContainerVulnerabilityChange{
			Id:                 vc.ID,
			ChangeKind:         vulnChangeTypeToProto(vc.ChangeType),
			Severity:           vc.Severity,
			SeverityType:       vc.SeverityType,
			PackageName:        vc.PackageName,
			Ecosystem:          vc.Ecosystem,
			BaseVersion:        vc.BaseVersion,
			TargetVersion:      vc.TargetVersion,
			FixedVersions:      vc.FixedVersions,
			Summary:            vc.Summary,
			Aliases:            vc.Aliases,
			Published:          vc.Published,
			BaseLayerDetails:   vc.BaseLayerDetails,
			TargetLayerDetails: vc.TargetLayerDetails,
		})
	}

	// Convert config changes
	if report.ConfigChanges != nil {
		cc := report.ConfigChanges
		resp.ConfigChanges = &diffv1.ContainerConfigDiff{
			UserChanged:        cc.UserChanged,
			BaseUser:           cc.BaseUser,
			TargetUser:         cc.TargetUser,
			RootChanged:        cc.RootChanged,
			BaseIsRoot:         cc.BaseIsRoot,
			TargetIsRoot:       cc.TargetIsRoot,
			PortsChanged:       cc.PortsChanged,
			PortsAdded:         cc.PortsAdded,
			PortsRemoved:       cc.PortsRemoved,
			VolumesChanged:     cc.VolumesChanged,
			VolumesAdded:       cc.VolumesAdded,
			VolumesRemoved:     cc.VolumesRemoved,
			EntrypointChanged:  cc.EntrypointChanged,
			BaseEntrypoint:     cc.BaseEntrypoint,
			TargetEntrypoint:   cc.TargetEntrypoint,
			CmdChanged:         cc.CmdChanged,
			BaseCmd:            cc.BaseCmd,
			TargetCmd:          cc.TargetCmd,
			WorkingDirChanged:  cc.WorkingDirChanged,
			BaseWorkingDir:     cc.BaseWorkingDir,
			TargetWorkingDir:   cc.TargetWorkingDir,
			HealthcheckChanged: cc.HealthcheckChanged,
		}
		for _, ec := range cc.EnvChanges {
			resp.ConfigChanges.EnvChanges = append(resp.ConfigChanges.EnvChanges, &diffv1.EnvChange{
				Name:        ec.Name,
				ChangeKind:  ChangeKindToProto(ec.ChangeType),
				BaseValue:   ec.BaseValue,
				TargetValue: ec.TargetValue,
				IsSensitive: ec.IsSensitive,
			})
		}
		for _, lc := range cc.LabelChanges {
			resp.ConfigChanges.LabelChanges = append(resp.ConfigChanges.LabelChanges, &diffv1.LabelChange{
				Key:         lc.Key,
				ChangeKind:  ChangeKindToProto(lc.ChangeType),
				BaseValue:   lc.BaseValue,
				TargetValue: lc.TargetValue,
			})
		}
	}

	// Convert layer analysis
	if report.LayerAnalysis != nil {
		la := report.LayerAnalysis
		resp.LayerAnalysis = &diffv1.LayerDiffAnalysis{
			BaseLayerCount:   int32(la.BaseLayerCount),
			TargetLayerCount: int32(la.TargetLayerCount),
			CommonLayers:     int32(la.CommonLayers),
		}
		for _, lc := range la.LayerChanges {
			resp.LayerAnalysis.LayerChanges = append(resp.LayerAnalysis.LayerChanges, &diffv1.LayerChange{
				Index:         int32(lc.Index),
				ChangeKind:    layerChangeTypeToProto(lc.ChangeType),
				BaseCommand:   lc.BaseCommand,
				TargetCommand: lc.TargetCommand,
			})
		}
	}

	// Convert summary
	resp.Summary = &diffv1.ContainerDiffSummary{
		PackagesAdded:          int32(report.Summary.PackagesAdded),
		PackagesRemoved:        int32(report.Summary.PackagesRemoved),
		PackagesUpgraded:       int32(report.Summary.PackagesUpgraded),
		PackagesDowngraded:     int32(report.Summary.PackagesDowngraded),
		VulnerabilitiesAdded:   int32(report.Summary.VulnerabilitiesAdded),
		VulnerabilitiesRemoved: int32(report.Summary.VulnerabilitiesRemoved),
		VulnerabilitiesFixed:   int32(report.Summary.VulnerabilitiesFixed),
		LayersAdded:            int32(report.Summary.LayersAdded),
		LayersRemoved:          int32(report.Summary.LayersRemoved),
		ConfigChanged:          report.Summary.ConfigChanged,
	}

	return resp
}

func imageRefToProto(ref compare.ImageRef) *diffv1.ContainerImageRef {
	return &diffv1.ContainerImageRef{
		Reference:  ref.Reference,
		Registry:   ref.Registry,
		Repository: ref.Repository,
		Tag:        ref.Tag,
		Digest:     ref.Digest,
	}
}

func vulnChangeTypeToProto(ct compare.VulnChangeType) diffv1.VulnerabilityChangeKind {
	switch ct {
	case compare.VulnAdded:
		return diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_ADDED
	case compare.VulnRemoved:
		return diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_REMOVED
	case compare.VulnFixed:
		return diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_FIXED
	case compare.VulnPersisted:
		return diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_PERSISTED
	default:
		return diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_UNSPECIFIED
	}
}

func layerChangeTypeToProto(ct compare.LayerChangeType) diffv1.LayerChangeKind {
	switch ct {
	case compare.LayerAdded:
		return diffv1.LayerChangeKind_LAYER_CHANGE_KIND_ADDED
	case compare.LayerRemoved:
		return diffv1.LayerChangeKind_LAYER_CHANGE_KIND_REMOVED
	case compare.LayerModified:
		return diffv1.LayerChangeKind_LAYER_CHANGE_KIND_MODIFIED
	case compare.LayerSame:
		return diffv1.LayerChangeKind_LAYER_CHANGE_KIND_UNCHANGED
	default:
		return diffv1.LayerChangeKind_LAYER_CHANGE_KIND_UNSPECIFIED
	}
}
