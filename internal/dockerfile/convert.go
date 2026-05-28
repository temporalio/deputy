package dockerfile

import "github.com/temporalio/deputy/internal/policy/celconv"

// ToMap converts Info to a map for CEL policy evaluation.
func (i *Info) ToMap() map[string]any {
	if i == nil {
		return map[string]any{
			"path":        "",
			"stages":      []any{},
			"args":        map[string]any{},
			"final_stage": map[string]any{},
		}
	}

	stages := make([]any, len(i.Stages))
	for idx, s := range i.Stages {
		stages[idx] = s.ToMap()
	}

	result := map[string]any{
		"path":   i.Path,
		"stages": stages,
		"args":   celconv.ToAnyMap(i.Args),
	}

	if i.FinalStage != nil {
		result["final_stage"] = i.FinalStage.ToMap()
	} else {
		result["final_stage"] = map[string]any{}
	}

	return result
}

// ToMap converts Stage to a map for CEL policy evaluation.
func (s *Stage) ToMap() map[string]any {
	m := map[string]any{
		"index":            s.Index,
		"name":             s.Name,
		"base_image":       s.BaseImage,
		"platform":         s.Platform,
		"is_scratch":       s.IsScratch,
		"is_builder_stage": s.IsBuilderStage,
		"user":             s.User,
		"is_root":          s.IsRoot(),
		"workdir":          s.Workdir,
		"env_vars":         celconv.ToAnyMap(s.EnvVars),
		"sensitive_env":    celconv.ToAnySlice(s.HasSensitiveEnv()),
		"exposed_ports":    celconv.ToAnySlice(s.ExposedPorts),
		"labels":           celconv.ToAnyMap(s.Labels),
		"entrypoint":       celconv.ToAnySlice(s.Entrypoint),
		"cmd":              celconv.ToAnySlice(s.Cmd),
		"shell":            celconv.ToAnySlice(s.Shell),
		"stop_signal":      s.StopSignal,
		"on_build":         celconv.ToAnySlice(s.OnBuild),
		"copy_from_stages": celconv.ToAnySlice(s.CopyFromStages),
	}

	// Base image resolved
	if s.BaseImageResolved != nil {
		m["base_image_resolved"] = s.BaseImageResolved.ToMap()
	} else {
		m["base_image_resolved"] = map[string]any{}
	}

	// Run commands
	runs := make([]any, len(s.RunCommands))
	for i, r := range s.RunCommands {
		runs[i] = r.ToMap()
	}
	m["run_commands"] = runs

	// Copy commands
	copies := make([]any, len(s.CopyCommands))
	for i, c := range s.CopyCommands {
		copies[i] = c.ToMap()
	}
	m["copy_commands"] = copies

	// Add commands
	adds := make([]any, len(s.AddCommands))
	for i, a := range s.AddCommands {
		adds[i] = a.ToMap()
	}
	m["add_commands"] = adds

	// Healthcheck
	if s.Healthcheck != nil {
		m["healthcheck"] = s.Healthcheck.ToMap()
	} else {
		m["healthcheck"] = nil
	}

	return m
}

// ToMap converts ImageRef to a map for CEL policy evaluation.
func (r *ImageRef) ToMap() map[string]any {
	if r == nil {
		return map[string]any{
			"full":       "",
			"registry":   "",
			"repository": "",
			"tag":        "",
			"digest":     "",
		}
	}
	return map[string]any{
		"full":       r.Full,
		"registry":   r.Registry,
		"repository": r.Repository,
		"tag":        r.Tag,
		"digest":     r.Digest,
	}
}

// ToMap converts RunCommand to a map for CEL policy evaluation.
func (r *RunCommand) ToMap() map[string]any {
	return map[string]any{
		"command":  r.Command,
		"shell":    r.Shell,
		"mounts":   celconv.ToAnySlice(r.Mounts),
		"network":  r.Network,
		"security": r.Security,
	}
}

// ToMap converts CopyCommand to a map for CEL policy evaluation.
func (c *CopyCommand) ToMap() map[string]any {
	return map[string]any{
		"sources":     celconv.ToAnySlice(c.Sources),
		"destination": c.Destination,
		"from":        c.From,
		"chown":       c.Chown,
		"chmod":       c.Chmod,
	}
}

// ToMap converts AddCommand to a map for CEL policy evaluation.
func (a *AddCommand) ToMap() map[string]any {
	return map[string]any{
		"sources":     celconv.ToAnySlice(a.Sources),
		"destination": a.Destination,
		"from_url":    a.FromURL,
		"chown":       a.Chown,
		"chmod":       a.Chmod,
	}
}

// ToMap converts HealthcheckConfig to a map for CEL policy evaluation.
func (h *HealthcheckConfig) ToMap() map[string]any {
	if h == nil {
		return nil
	}
	return map[string]any{
		"test":           celconv.ToAnySlice(h.Test),
		"interval":       h.Interval,
		"timeout":        h.Timeout,
		"start_period":   h.StartPeriod,
		"start_interval": h.StartInterval,
		"retries":        h.Retries,
		"disabled":       h.Disabled,
	}
}

// ToMap converts Analysis to a map for CEL policy evaluation.
func (a *Analysis) ToMap() map[string]any {
	if a == nil {
		return map[string]any{}
	}
	return map[string]any{
		"stage_count":            a.StageCount,
		"has_multi_stage":        a.HasMultiStage,
		"builder_stage_count":    a.BuilderStageCount,
		"final_stage_is_root":    a.FinalStageIsRoot,
		"final_stage_is_scratch": a.FinalStageIsScratch,
		"sensitive_env_vars":     celconv.ToAnySlice(a.SensitiveEnvVars),
		"has_add_url":            a.HasAddURL,
		"add_url_sources":        celconv.ToAnySlice(a.AddURLSources),
	}
}
