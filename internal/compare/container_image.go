package compare

import (
	"cmp"
	"slices"
	"time"

	"github.com/picatz/deputy/internal/dependency"
)

// ImageRef identifies a container image for comparison.
type ImageRef struct {
	Registry   string `json:"registry,omitempty"`
	Repository string `json:"repository,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Digest     string `json:"digest,omitempty"`
	Reference  string `json:"reference,omitempty"` // Full reference string
}

// String returns a human-readable image reference.
func (r ImageRef) String() string {
	if r.Reference != "" {
		return r.Reference
	}
	ref := r.Registry
	if r.Repository != "" {
		if ref != "" {
			ref += "/"
		}
		ref += r.Repository
	}
	if r.Digest != "" {
		ref += "@" + r.Digest
	} else if r.Tag != "" {
		ref += ":" + r.Tag
	}
	return ref
}

// ImageDiffReport contains the complete comparison between two container images.
type ImageDiffReport struct {
	// BaseImage is the source/older image being compared from.
	BaseImage ImageRef `json:"baseImage"`
	// TargetImage is the destination/newer image being compared to.
	TargetImage ImageRef `json:"targetImage"`

	// PackageChanges lists all dependency changes between images.
	PackageChanges []ImagePackageChange `json:"packageChanges,omitempty"`

	// VulnerabilityChanges lists vulnerability differences.
	VulnerabilityChanges []VulnerabilityChange `json:"vulnerabilityChanges,omitempty"`

	// ConfigChanges describes configuration differences between images.
	ConfigChanges *ImageConfigDiff `json:"configChanges,omitempty"`

	// LayerAnalysis provides layer-by-layer comparison.
	LayerAnalysis *LayerDiffAnalysis `json:"layerAnalysis,omitempty"`

	// Summary provides aggregate statistics.
	Summary ImageDiffSummary `json:"summary"`
}

// ImageDiffSummary provides aggregate statistics for the diff.
type ImageDiffSummary struct {
	PackagesAdded      int `json:"packagesAdded"`
	PackagesRemoved    int `json:"packagesRemoved"`
	PackagesUpgraded   int `json:"packagesUpgraded"`
	PackagesDowngraded int `json:"packagesDowngraded"`

	VulnerabilitiesAdded   int `json:"vulnerabilitiesAdded"`
	VulnerabilitiesRemoved int `json:"vulnerabilitiesRemoved"`
	VulnerabilitiesFixed   int `json:"vulnerabilitiesFixed"` // Removed by upgrade

	LayersAdded   int `json:"layersAdded"`
	LayersRemoved int `json:"layersRemoved"`

	ConfigChanged bool `json:"configChanged"`
}

// ImagePackageChange represents a package difference between two images.
// Extends the base Change type with container-specific layer information.
type ImagePackageChange struct {
	Change

	// BaseLayerDetails indicates which layer the package was in the base image.
	// Nil if the package was not in the base image (added).
	BaseLayerDetails *dependency.LayerDetails `json:"baseLayerDetails,omitempty"`

	// TargetLayerDetails indicates which layer the package is in the target image.
	// Nil if the package is not in the target image (removed).
	TargetLayerDetails *dependency.LayerDetails `json:"targetLayerDetails,omitempty"`
}

// VulnerabilityChange represents a vulnerability difference between two images.
type VulnerabilityChange struct {
	// ID is the vulnerability identifier (CVE, GHSA, etc.)
	ID string `json:"id"`

	// ChangeType indicates if the vulnerability was added, removed, or fixed.
	ChangeType VulnChangeType `json:"changeType"`

	// Type is the string representation of ChangeType.
	Type string `json:"type"`

	// Severity of the vulnerability (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN).
	Severity string `json:"severity,omitempty"`

	// SeverityType indicates the scoring system (CVSS_V3, GHSA, etc.).
	SeverityType string `json:"severityType,omitempty"`

	// Package affected by the vulnerability.
	Package string `json:"package,omitempty"`

	// BaseVersion is the package version in the base image.
	BaseVersion string `json:"baseVersion,omitempty"`

	// TargetVersion is the package version in the target image.
	TargetVersion string `json:"targetVersion,omitempty"`

	// FixedVersions lists versions where this vulnerability is resolved.
	FixedVersions []string `json:"fixedVersions,omitempty"`

	// LayerDetails describes where the vulnerability was introduced.
	LayerDetails *dependency.LayerDetails `json:"layerDetails,omitempty"`

	// Summary is a brief description of the vulnerability.
	Summary string `json:"summary,omitempty"`

	// CVE is the CVE identifier if assigned.
	CVE string `json:"cve,omitempty"`

	// Aliases contains alternate identifiers (CVE, GHSA, etc.).
	Aliases []string `json:"aliases,omitempty"`

	// Published is the ISO 8601 timestamp when the vulnerability was first published.
	Published string `json:"published,omitempty"`
}

// VulnChangeType classifies vulnerability changes.
type VulnChangeType int

const (
	// VulnAdded means the vulnerability is new in the target image.
	VulnAdded VulnChangeType = iota
	// VulnRemoved means the vulnerability was in base but not in target.
	VulnRemoved
	// VulnFixed means the vulnerability was removed by a package upgrade.
	VulnFixed
	// VulnPersisted means the vulnerability exists in both images.
	VulnPersisted
)

func (v VulnChangeType) String() string {
	switch v {
	case VulnAdded:
		return "added"
	case VulnRemoved:
		return "removed"
	case VulnFixed:
		return "fixed"
	case VulnPersisted:
		return "persisted"
	default:
		return "unknown"
	}
}

// ImageConfigDiff describes configuration differences between images.
type ImageConfigDiff struct {
	// UserChanged indicates the container user changed.
	UserChanged bool   `json:"userChanged,omitempty"`
	BaseUser    string `json:"baseUser,omitempty"`
	TargetUser  string `json:"targetUser,omitempty"`

	// RootChanged indicates root user status changed.
	RootChanged  bool `json:"rootChanged,omitempty"`
	BaseIsRoot   bool `json:"baseIsRoot,omitempty"`
	TargetIsRoot bool `json:"targetIsRoot,omitempty"`

	// EnvChanges lists environment variable differences.
	EnvChanges []EnvChange `json:"envChanges,omitempty"`

	// PortsChanged indicates exposed ports changed.
	PortsChanged bool     `json:"portsChanged,omitempty"`
	PortsAdded   []string `json:"portsAdded,omitempty"`
	PortsRemoved []string `json:"portsRemoved,omitempty"`

	// VolumesChanged indicates volumes changed.
	VolumesChanged bool     `json:"volumesChanged,omitempty"`
	VolumesAdded   []string `json:"volumesAdded,omitempty"`
	VolumesRemoved []string `json:"volumesRemoved,omitempty"`

	// LabelChanges lists label differences.
	LabelChanges []LabelChange `json:"labelChanges,omitempty"`

	// EntrypointChanged indicates the entrypoint changed.
	EntrypointChanged bool     `json:"entrypointChanged,omitempty"`
	BaseEntrypoint    []string `json:"baseEntrypoint,omitempty"`
	TargetEntrypoint  []string `json:"targetEntrypoint,omitempty"`

	// CmdChanged indicates the default command changed.
	CmdChanged bool     `json:"cmdChanged,omitempty"`
	BaseCmd    []string `json:"baseCmd,omitempty"`
	TargetCmd  []string `json:"targetCmd,omitempty"`

	// WorkingDirChanged indicates the working directory changed.
	WorkingDirChanged bool   `json:"workingDirChanged,omitempty"`
	BaseWorkingDir    string `json:"baseWorkingDir,omitempty"`
	TargetWorkingDir  string `json:"targetWorkingDir,omitempty"`

	// HealthcheckChanged indicates healthcheck configuration changed.
	HealthcheckChanged bool `json:"healthcheckChanged,omitempty"`
}

// EnvChange represents an environment variable difference.
type EnvChange struct {
	Name        string     `json:"name"`
	ChangeType  ChangeType `json:"changeType"`
	Type        string     `json:"type"`
	BaseValue   string     `json:"baseValue,omitempty"`
	TargetValue string     `json:"targetValue,omitempty"`
	IsSensitive bool       `json:"isSensitive,omitempty"`
}

// LabelChange represents a label difference.
type LabelChange struct {
	Key         string     `json:"key"`
	ChangeType  ChangeType `json:"changeType"`
	Type        string     `json:"type"`
	BaseValue   string     `json:"baseValue,omitempty"`
	TargetValue string     `json:"targetValue,omitempty"`
}

// LayerDiffAnalysis provides layer-by-layer comparison.
type LayerDiffAnalysis struct {
	// BaseLayerCount is the number of layers in the base image.
	BaseLayerCount int `json:"baseLayerCount"`
	// TargetLayerCount is the number of layers in the target image.
	TargetLayerCount int `json:"targetLayerCount"`

	// CommonLayers is the number of layers shared between images.
	CommonLayers int `json:"commonLayers"`

	// LayerChanges describes individual layer differences.
	LayerChanges []LayerChange `json:"layerChanges,omitempty"`
}

// LayerChange represents a difference in a specific layer.
type LayerChange struct {
	Index      int             `json:"index"`
	ChangeType LayerChangeType `json:"changeType"`
	Type       string          `json:"type"`

	// BaseDiffID is the layer digest in the base image (if present).
	BaseDiffID string `json:"baseDiffId,omitempty"`
	// TargetDiffID is the layer digest in the target image (if present).
	TargetDiffID string `json:"targetDiffId,omitempty"`

	// BaseCommand is the Dockerfile command in base image.
	BaseCommand string `json:"baseCommand,omitempty"`
	// TargetCommand is the Dockerfile command in target image.
	TargetCommand string `json:"targetCommand,omitempty"`

	// PackagesInLayer lists packages introduced by this layer.
	PackagesInLayer []string `json:"packagesInLayer,omitempty"`
}

// LayerChangeType classifies layer changes.
type LayerChangeType int

const (
	// LayerSame means the layer is identical in both images.
	LayerSame LayerChangeType = iota
	// LayerAdded means the layer exists only in target.
	LayerAdded
	// LayerRemoved means the layer exists only in base.
	LayerRemoved
	// LayerModified means the layer position or content differs.
	LayerModified
)

func (l LayerChangeType) String() string {
	switch l {
	case LayerSame:
		return "same"
	case LayerAdded:
		return "added"
	case LayerRemoved:
		return "removed"
	case LayerModified:
		return "modified"
	default:
		return "unknown"
	}
}

// ImageConfigInput is a simplified representation of image configuration
// for comparison purposes, avoiding import cycles with scan package.
type ImageConfigInput struct {
	User          string
	Env           []string
	SensitiveEnv  []string
	Entrypoint    []string
	Cmd           []string
	WorkingDir    string
	ExposedPorts  []string
	Volumes       []string
	Labels        map[string]string
	IsRoot        bool
	HasHealthcheck bool
}

// ImageMetadataInput holds metadata for comparison.
type ImageMetadataInput struct {
	LayerCount int
}

// ImageHistoryInput represents a single layer's history.
type ImageHistoryInput struct {
	CreatedBy  string
	Created    time.Time
	EmptyLayer bool
}

// ImageInput combines configuration and metadata for comparison.
type ImageInput struct {
	Config   ImageConfigInput
	Metadata ImageMetadataInput
	History  []ImageHistoryInput
}

// CompareImageConfigs compares two image configurations.
func CompareImageConfigs(base, target *ImageInput) *ImageConfigDiff {
	if base == nil || target == nil {
		return nil
	}

	diff := &ImageConfigDiff{}

	// Compare user
	if base.Config.User != target.Config.User {
		diff.UserChanged = true
		diff.BaseUser = base.Config.User
		diff.TargetUser = target.Config.User
	}

	// Compare root status
	if base.Config.IsRoot != target.Config.IsRoot {
		diff.RootChanged = true
		diff.BaseIsRoot = base.Config.IsRoot
		diff.TargetIsRoot = target.Config.IsRoot
	}

	// Compare environment variables
	diff.EnvChanges = compareEnvVars(base.Config.Env, target.Config.Env, base.Config.SensitiveEnv)

	// Compare ports
	basePortSet := toSet(base.Config.ExposedPorts)
	targetPortSet := toSet(target.Config.ExposedPorts)
	diff.PortsAdded, diff.PortsRemoved = diffSets(basePortSet, targetPortSet)
	diff.PortsChanged = len(diff.PortsAdded) > 0 || len(diff.PortsRemoved) > 0

	// Compare volumes
	baseVolSet := toSet(base.Config.Volumes)
	targetVolSet := toSet(target.Config.Volumes)
	diff.VolumesAdded, diff.VolumesRemoved = diffSets(baseVolSet, targetVolSet)
	diff.VolumesChanged = len(diff.VolumesAdded) > 0 || len(diff.VolumesRemoved) > 0

	// Compare labels
	diff.LabelChanges = compareLabels(base.Config.Labels, target.Config.Labels)

	// Compare entrypoint
	if !slices.Equal(base.Config.Entrypoint, target.Config.Entrypoint) {
		diff.EntrypointChanged = true
		diff.BaseEntrypoint = base.Config.Entrypoint
		diff.TargetEntrypoint = target.Config.Entrypoint
	}

	// Compare cmd
	if !slices.Equal(base.Config.Cmd, target.Config.Cmd) {
		diff.CmdChanged = true
		diff.BaseCmd = base.Config.Cmd
		diff.TargetCmd = target.Config.Cmd
	}

	// Compare working directory
	if base.Config.WorkingDir != target.Config.WorkingDir {
		diff.WorkingDirChanged = true
		diff.BaseWorkingDir = base.Config.WorkingDir
		diff.TargetWorkingDir = target.Config.WorkingDir
	}

	// Compare healthcheck
	diff.HealthcheckChanged = base.Config.HasHealthcheck != target.Config.HasHealthcheck

	return diff
}

// AnalyzeLayerDiff compares layer history between two images.
func AnalyzeLayerDiff(base, target *ImageInput) *LayerDiffAnalysis {
	if base == nil || target == nil {
		return nil
	}

	analysis := &LayerDiffAnalysis{
		BaseLayerCount:   base.Metadata.LayerCount,
		TargetLayerCount: target.Metadata.LayerCount,
	}

	// Build diffID sets based on command content
	baseDiffIDs := make(map[string]int)
	for i, h := range base.History {
		if !h.EmptyLayer && len(h.CreatedBy) > 0 {
			baseDiffIDs[h.CreatedBy] = i
		}
	}

	targetDiffIDs := make(map[string]int)
	for i, h := range target.History {
		if !h.EmptyLayer && len(h.CreatedBy) > 0 {
			targetDiffIDs[h.CreatedBy] = i
		}
	}

	// Count common layers
	for cmd := range baseDiffIDs {
		if _, exists := targetDiffIDs[cmd]; exists {
			analysis.CommonLayers++
		}
	}

	// Build layer changes
	maxLayers := max(len(base.History), len(target.History))
	for i := 0; i < maxLayers; i++ {
		lc := LayerChange{Index: i}

		var baseCmd, targetCmd string
		if i < len(base.History) {
			baseCmd = base.History[i].CreatedBy
			lc.BaseCommand = baseCmd
		}
		if i < len(target.History) {
			targetCmd = target.History[i].CreatedBy
			lc.TargetCommand = targetCmd
		}

		if baseCmd == "" && targetCmd != "" {
			lc.ChangeType = LayerAdded
		} else if baseCmd != "" && targetCmd == "" {
			lc.ChangeType = LayerRemoved
		} else if baseCmd != targetCmd {
			lc.ChangeType = LayerModified
		} else {
			lc.ChangeType = LayerSame
		}
		lc.Type = lc.ChangeType.String()

		// Only include non-same layers in output
		if lc.ChangeType != LayerSame {
			analysis.LayerChanges = append(analysis.LayerChanges, lc)
		}
	}

	return analysis
}

// CalculateImageDiffSummary calculates summary statistics from a report.
func CalculateImageDiffSummary(report *ImageDiffReport) ImageDiffSummary {
	summary := ImageDiffSummary{}

	for _, c := range report.PackageChanges {
		switch c.ChangeType {
		case Added:
			summary.PackagesAdded++
		case Removed:
			summary.PackagesRemoved++
		case Upgraded:
			summary.PackagesUpgraded++
		case Downgraded:
			summary.PackagesDowngraded++
		}
	}

	for _, v := range report.VulnerabilityChanges {
		switch v.ChangeType {
		case VulnAdded:
			summary.VulnerabilitiesAdded++
		case VulnRemoved:
			summary.VulnerabilitiesRemoved++
		case VulnFixed:
			summary.VulnerabilitiesFixed++
		}
	}

	if report.LayerAnalysis != nil {
		for _, l := range report.LayerAnalysis.LayerChanges {
			switch l.ChangeType {
			case LayerAdded:
				summary.LayersAdded++
			case LayerRemoved:
				summary.LayersRemoved++
			}
		}
	}

	if report.ConfigChanges != nil {
		cc := report.ConfigChanges
		summary.ConfigChanged = cc.UserChanged || cc.RootChanged ||
			len(cc.EnvChanges) > 0 || cc.PortsChanged || cc.VolumesChanged ||
			len(cc.LabelChanges) > 0 || cc.EntrypointChanged || cc.CmdChanged ||
			cc.WorkingDirChanged || cc.HealthcheckChanged
	}

	return summary
}

func compareEnvVars(baseEnv, targetEnv, sensitiveEnv []string) []EnvChange {
	baseMap := parseEnvVars(baseEnv)
	targetMap := parseEnvVars(targetEnv)
	sensitiveSet := toSet(sensitiveEnv)

	var changes []EnvChange

	for name, baseVal := range baseMap {
		targetVal, exists := targetMap[name]
		if !exists {
			changes = append(changes, EnvChange{
				Name:        name,
				ChangeType:  Removed,
				Type:        Removed.String(),
				BaseValue:   baseVal,
				IsSensitive: sensitiveSet[name],
			})
		} else if baseVal != targetVal {
			changes = append(changes, EnvChange{
				Name:        name,
				ChangeType:  Updated,
				Type:        Updated.String(),
				BaseValue:   baseVal,
				TargetValue: targetVal,
				IsSensitive: sensitiveSet[name],
			})
		}
	}

	for name, targetVal := range targetMap {
		if _, exists := baseMap[name]; !exists {
			changes = append(changes, EnvChange{
				Name:        name,
				ChangeType:  Added,
				Type:        Added.String(),
				TargetValue: targetVal,
				IsSensitive: sensitiveSet[name],
			})
		}
	}

	slices.SortFunc(changes, func(a, b EnvChange) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return changes
}

func parseEnvVars(env []string) map[string]string {
	result := make(map[string]string)
	for _, e := range env {
		if idx := indexOf(e, '='); idx >= 0 {
			result[e[:idx]] = e[idx+1:]
		} else {
			result[e] = ""
		}
	}
	return result
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func compareLabels(baseLabels, targetLabels map[string]string) []LabelChange {
	var changes []LabelChange

	for key, baseVal := range baseLabels {
		targetVal, exists := targetLabels[key]
		if !exists {
			changes = append(changes, LabelChange{
				Key:        key,
				ChangeType: Removed,
				Type:       Removed.String(),
				BaseValue:  baseVal,
			})
		} else if baseVal != targetVal {
			changes = append(changes, LabelChange{
				Key:         key,
				ChangeType:  Updated,
				Type:        Updated.String(),
				BaseValue:   baseVal,
				TargetValue: targetVal,
			})
		}
	}

	for key, targetVal := range targetLabels {
		if _, exists := baseLabels[key]; !exists {
			changes = append(changes, LabelChange{
				Key:         key,
				ChangeType:  Added,
				Type:        Added.String(),
				TargetValue: targetVal,
			})
		}
	}

	slices.SortFunc(changes, func(a, b LabelChange) int {
		return cmp.Compare(a.Key, b.Key)
	})

	return changes
}

func toSet(items []string) map[string]bool {
	result := make(map[string]bool)
	for _, item := range items {
		result[item] = true
	}
	return result
}

func diffSets(base, target map[string]bool) (added, removed []string) {
	for item := range target {
		if !base[item] {
			added = append(added, item)
		}
	}
	for item := range base {
		if !target[item] {
			removed = append(removed, item)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}
