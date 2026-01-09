package compare

import (
	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
)

// BuildContainerDiffPayload converts an ImageDiffReport to a map suitable for policy evaluation.
func BuildContainerDiffPayload(report *ImageDiffReport) map[string]any {
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

func configChangesToMap(cc *ImageConfigDiff) map[string]any {
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

func layerAnalysisToMap(la *LayerDiffAnalysis) map[string]any {
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
