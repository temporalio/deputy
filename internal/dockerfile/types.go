package dockerfile

// Info contains parsed Dockerfile data for policy evaluation.
type Info struct {
	// Path is the Dockerfile location.
	Path string `json:"path"`

	// Stages contains all build stages.
	Stages []Stage `json:"stages"`

	// Args are ARG instructions with their default values.
	Args map[string]string `json:"args,omitempty"`

	// FinalStage points to the last stage (what gets built by default).
	FinalStage *Stage `json:"final_stage,omitempty"`
}

// Stage represents a FROM ... AS stage in a Dockerfile.
type Stage struct {
	// Index is the 0-based stage position.
	Index int `json:"index"`

	// Name is the AS alias (empty if unnamed).
	Name string `json:"name,omitempty"`

	// BaseImage is the FROM image reference as written.
	BaseImage string `json:"base_image"`

	// BaseImageResolved is the parsed image reference after ARG substitution.
	BaseImageResolved *ImageRef `json:"base_image_resolved,omitempty"`

	// Platform from --platform flag.
	Platform string `json:"platform,omitempty"`

	// IsScratch is true if FROM scratch.
	IsScratch bool `json:"is_scratch"`

	// IsBuilderStage is true if this stage is only used as a COPY source.
	IsBuilderStage bool `json:"is_builder_stage"`

	// User is the final USER directive value (empty = root).
	User string `json:"user,omitempty"`

	// Workdir is the final WORKDIR value.
	Workdir string `json:"workdir,omitempty"`

	// EnvVars are ENV declarations.
	EnvVars map[string]string `json:"env_vars,omitempty"`

	// ExposedPorts from EXPOSE instructions.
	ExposedPorts []string `json:"exposed_ports,omitempty"`

	// Labels from LABEL instructions.
	Labels map[string]string `json:"labels,omitempty"`

	// Healthcheck configuration.
	Healthcheck *HealthcheckConfig `json:"healthcheck,omitempty"`

	// RunCommands are RUN instructions in order.
	RunCommands []RunCommand `json:"run_commands,omitempty"`

	// CopyCommands are COPY instructions.
	CopyCommands []CopyCommand `json:"copy_commands,omitempty"`

	// AddCommands for ADD instructions (security concern: remote URLs).
	AddCommands []AddCommand `json:"add_commands,omitempty"`

	// CopyFromStages tracks COPY --from references to other stages.
	CopyFromStages []string `json:"copy_from_stages,omitempty"`

	// Entrypoint is the ENTRYPOINT instruction.
	Entrypoint []string `json:"entrypoint,omitempty"`

	// Cmd is the CMD instruction.
	Cmd []string `json:"cmd,omitempty"`

	// Shell is the SHELL instruction.
	Shell []string `json:"shell,omitempty"`

	// StopSignal is the STOPSIGNAL instruction.
	StopSignal string `json:"stop_signal,omitempty"`

	// OnBuild contains ONBUILD instructions.
	OnBuild []string `json:"on_build,omitempty"`
}

// ImageRef is a parsed image reference.
type ImageRef struct {
	// Full is the complete reference string.
	Full string `json:"full"`

	// Registry is the registry host (e.g., "docker.io", "gcr.io").
	Registry string `json:"registry"`

	// Repository is the image repository (e.g., "library/nginx", "myorg/app").
	Repository string `json:"repository"`

	// Tag is the image tag (e.g., "latest", "v1.0.0").
	Tag string `json:"tag,omitempty"`

	// Digest is the image digest (e.g., "sha256:...").
	Digest string `json:"digest,omitempty"`
}

// RunCommand represents a RUN instruction.
type RunCommand struct {
	// Command is the command string or exec form.
	Command string `json:"command"`

	// Shell is true if shell form, false if exec form.
	Shell bool `json:"shell"`

	// Mounts are --mount flags used.
	Mounts []string `json:"mounts,omitempty"`

	// Network is the --network flag value.
	Network string `json:"network,omitempty"`

	// Security is the --security flag value.
	Security string `json:"security,omitempty"`
}

// CopyCommand represents a COPY instruction.
type CopyCommand struct {
	// Sources are the source paths.
	Sources []string `json:"sources"`

	// Destination is the target path.
	Destination string `json:"destination"`

	// From is the --from stage/image reference.
	From string `json:"from,omitempty"`

	// Chown is the --chown value.
	Chown string `json:"chown,omitempty"`

	// Chmod is the --chmod value.
	Chmod string `json:"chmod,omitempty"`
}

// AddCommand represents an ADD instruction.
type AddCommand struct {
	// Sources are the source paths or URLs.
	Sources []string `json:"sources"`

	// Destination is the target path.
	Destination string `json:"destination"`

	// FromURL is true if any source is a URL (security concern).
	FromURL bool `json:"from_url"`

	// Chown is the --chown value.
	Chown string `json:"chown,omitempty"`

	// Chmod is the --chmod value.
	Chmod string `json:"chmod,omitempty"`
}

// HealthcheckConfig represents HEALTHCHECK configuration.
type HealthcheckConfig struct {
	// Test is the health check command.
	Test []string `json:"test,omitempty"`

	// Interval between checks.
	Interval string `json:"interval,omitempty"`

	// Timeout for each check.
	Timeout string `json:"timeout,omitempty"`

	// StartPeriod before checks count.
	StartPeriod string `json:"start_period,omitempty"`

	// StartInterval between checks during start period.
	StartInterval string `json:"start_interval,omitempty"`

	// Retries before marking unhealthy.
	Retries int `json:"retries,omitempty"`

	// Disabled is true if HEALTHCHECK NONE.
	Disabled bool `json:"disabled,omitempty"`
}

// IsRoot returns true if the stage runs as root (empty user or "root" or "0").
func (s *Stage) IsRoot() bool {
	user := s.User
	if user == "" || user == "root" || user == "0" {
		return true
	}
	return false
}

// HasSensitiveEnv returns environment variable names that may contain secrets.
func (s *Stage) HasSensitiveEnv() []string {
	return detectSensitiveEnvVars(s.EnvVars)
}
