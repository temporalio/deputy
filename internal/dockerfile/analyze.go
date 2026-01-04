package dockerfile

import (
	"github.com/picatz/deputy/internal/security"
)

// Analyze performs static analysis on parsed Dockerfile info.
// It enriches the info with computed fields like sensitive env detection.
func Analyze(info *Info) *Analysis {
	if info == nil {
		return &Analysis{}
	}

	a := &Analysis{
		StageCount:        len(info.Stages),
		HasMultiStage:     len(info.Stages) > 1,
		BuilderStageCount: 0,
	}

	for i := range info.Stages {
		stage := &info.Stages[i]

		if stage.IsBuilderStage {
			a.BuilderStageCount++
		}

		// Check for sensitive env vars
		sensitive := stage.HasSensitiveEnv()
		if len(sensitive) > 0 {
			a.SensitiveEnvVars = append(a.SensitiveEnvVars, sensitive...)
		}

		// Check for ADD with URLs
		for _, add := range stage.AddCommands {
			if add.FromURL {
				a.HasAddURL = true
				a.AddURLSources = append(a.AddURLSources, add.Sources...)
			}
		}

		// Check for root user in final stage
		if info.FinalStage != nil && i == len(info.Stages)-1 {
			a.FinalStageIsRoot = stage.IsRoot()
			a.FinalStageIsScratch = stage.IsScratch
		}
	}

	// Deduplicate sensitive env vars
	a.SensitiveEnvVars = uniqueStrings(a.SensitiveEnvVars)

	return a
}

// Analysis contains computed analysis results from a Dockerfile.
type Analysis struct {
	// StageCount is the total number of stages.
	StageCount int `json:"stage_count"`

	// HasMultiStage is true if the Dockerfile uses multi-stage builds.
	HasMultiStage bool `json:"has_multi_stage"`

	// BuilderStageCount is the number of builder-only stages.
	BuilderStageCount int `json:"builder_stage_count"`

	// FinalStageIsRoot is true if the final stage runs as root.
	FinalStageIsRoot bool `json:"final_stage_is_root"`

	// FinalStageIsScratch is true if the final stage uses FROM scratch.
	FinalStageIsScratch bool `json:"final_stage_is_scratch"`

	// SensitiveEnvVars lists env var names that may contain secrets.
	SensitiveEnvVars []string `json:"sensitive_env_vars,omitempty"`

	// HasAddURL is true if any ADD instruction uses a URL source.
	HasAddURL bool `json:"has_add_url"`

	// AddURLSources lists URL sources used in ADD instructions.
	AddURLSources []string `json:"add_url_sources,omitempty"`
}

// detectSensitiveEnvVars returns env var names that match sensitive patterns.
func detectSensitiveEnvVars(envVars map[string]string) []string {
	return security.DetectSensitiveEnvNames(envVars)
}

// uniqueStrings returns a deduplicated slice.
func uniqueStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	result := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
