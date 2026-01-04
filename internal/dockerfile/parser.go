package dockerfile

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// ParseFile parses a Dockerfile from the given path.
func ParseFile(path string) (*Info, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open dockerfile: %w", err)
	}
	defer f.Close()

	info, err := Parse(f)
	if err != nil {
		return nil, err
	}
	info.Path = path
	return info, nil
}

// ParseBytes parses a Dockerfile from the given byte slice.
func ParseBytes(data []byte) (*Info, error) {
	return Parse(strings.NewReader(string(data)))
}

// Parse parses a Dockerfile from the given reader.
func Parse(r io.Reader) (*Info, error) {
	result, err := parser.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("parse dockerfile: %w", err)
	}

	stages, metaArgs, err := instructions.Parse(result.AST, nil)
	if err != nil {
		return nil, fmt.Errorf("parse instructions: %w", err)
	}

	info := &Info{
		Args:   make(map[string]string),
		Stages: make([]Stage, 0, len(stages)),
	}

	// Collect ARG defaults (before FROM)
	for _, arg := range metaArgs {
		for _, kv := range arg.Args {
			if kv.Value != nil {
				info.Args[kv.Key] = *kv.Value
			} else {
				info.Args[kv.Key] = ""
			}
		}
	}

	// Track COPY --from references for builder stage detection
	copyFromRefs := make(map[string]bool)

	// First pass: collect all stages and COPY --from references
	for i, stage := range stages {
		s := convertStage(i, stage, info.Args)
		info.Stages = append(info.Stages, s)

		// Track COPY --from references
		for _, from := range s.CopyFromStages {
			copyFromRefs[from] = true
		}
	}

	// Second pass: mark builder stages
	for i := range info.Stages {
		stage := &info.Stages[i]
		// A stage is a builder if:
		// 1. It has a name (AS alias)
		// 2. That name is referenced in COPY --from
		// 3. It's not the final stage
		if i < len(info.Stages)-1 && stage.Name != "" {
			if copyFromRefs[stage.Name] {
				stage.IsBuilderStage = true
			}
		}
	}

	// Set final stage pointer
	if len(info.Stages) > 0 {
		info.FinalStage = &info.Stages[len(info.Stages)-1]
	}

	return info, nil
}

func convertStage(index int, stage instructions.Stage, args map[string]string) Stage {
	s := Stage{
		Index:     index,
		Name:      stage.Name,
		BaseImage: stage.BaseName,
		Platform:  stage.Platform,
		IsScratch: strings.ToLower(stage.BaseName) == "scratch",
		EnvVars:   make(map[string]string),
		Labels:    make(map[string]string),
	}

	// Resolve ARG substitution in base image
	resolvedBase := resolveArgs(stage.BaseName, args)
	s.BaseImageResolved = parseImageRef(resolvedBase)

	// Process all commands in the stage
	for _, cmd := range stage.Commands {
		switch c := cmd.(type) {
		case *instructions.RunCommand:
			s.RunCommands = append(s.RunCommands, convertRunCommand(c))

		case *instructions.CopyCommand:
			cc := convertCopyCommand(c)
			s.CopyCommands = append(s.CopyCommands, cc)
			if cc.From != "" {
				s.CopyFromStages = append(s.CopyFromStages, cc.From)
			}

		case *instructions.AddCommand:
			s.AddCommands = append(s.AddCommands, convertAddCommand(c))

		case *instructions.EnvCommand:
			for _, kv := range c.Env {
				s.EnvVars[kv.Key] = kv.Value
			}

		case *instructions.LabelCommand:
			for _, kv := range c.Labels {
				s.Labels[kv.Key] = kv.Value
			}

		case *instructions.UserCommand:
			s.User = c.User

		case *instructions.WorkdirCommand:
			s.Workdir = c.Path

		case *instructions.ExposeCommand:
			s.ExposedPorts = append(s.ExposedPorts, c.Ports...)

		case *instructions.EntrypointCommand:
			s.Entrypoint = c.CmdLine

		case *instructions.CmdCommand:
			s.Cmd = c.CmdLine

		case *instructions.ShellCommand:
			s.Shell = c.Shell

		case *instructions.StopSignalCommand:
			s.StopSignal = c.Signal

		case *instructions.HealthCheckCommand:
			s.Healthcheck = convertHealthcheck(c)

		case *instructions.OnbuildCommand:
			s.OnBuild = append(s.OnBuild, c.Expression)
		}
	}

	return s
}

func convertRunCommand(c *instructions.RunCommand) RunCommand {
	rc := RunCommand{
		Command: strings.Join(c.CmdLine, " "),
		Shell:   c.PrependShell,
	}

	// Extract flags used (mount, network, security are in FlagsUsed)
	for _, flag := range c.FlagsUsed {
		if strings.HasPrefix(flag, "mount=") {
			rc.Mounts = append(rc.Mounts, strings.TrimPrefix(flag, "mount="))
		} else if strings.HasPrefix(flag, "network=") {
			rc.Network = strings.TrimPrefix(flag, "network=")
		} else if strings.HasPrefix(flag, "security=") {
			rc.Security = strings.TrimPrefix(flag, "security=")
		}
	}

	return rc
}

func convertCopyCommand(c *instructions.CopyCommand) CopyCommand {
	cc := CopyCommand{
		From:  c.From,
		Chown: c.Chown,
		Chmod: c.Chmod,
	}

	// SourcesAndDest contains sources followed by destination
	if len(c.SourcesAndDest.SourcePaths) > 0 {
		cc.Sources = c.SourcesAndDest.SourcePaths
	}
	cc.Destination = c.SourcesAndDest.DestPath

	return cc
}

func convertAddCommand(c *instructions.AddCommand) AddCommand {
	ac := AddCommand{
		Chown: c.Chown,
		Chmod: c.Chmod,
	}

	// SourcesAndDest contains sources followed by destination
	if len(c.SourcesAndDest.SourcePaths) > 0 {
		ac.Sources = c.SourcesAndDest.SourcePaths
		// Check if any source is a URL
		for _, src := range ac.Sources {
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
				ac.FromURL = true
				break
			}
		}
	}
	ac.Destination = c.SourcesAndDest.DestPath

	return ac
}

func convertHealthcheck(c *instructions.HealthCheckCommand) *HealthcheckConfig {
	if c.Health == nil {
		return nil
	}

	hc := &HealthcheckConfig{
		Test:    c.Health.Test,
		Retries: c.Health.Retries,
	}

	// Check for HEALTHCHECK NONE
	if len(c.Health.Test) > 0 && c.Health.Test[0] == "NONE" {
		hc.Disabled = true
		return hc
	}

	if c.Health.Interval != 0 {
		hc.Interval = c.Health.Interval.String()
	}
	if c.Health.Timeout != 0 {
		hc.Timeout = c.Health.Timeout.String()
	}
	if c.Health.StartPeriod != 0 {
		hc.StartPeriod = c.Health.StartPeriod.String()
	}
	if c.Health.StartInterval != 0 {
		hc.StartInterval = c.Health.StartInterval.String()
	}

	return hc
}

// resolveArgs substitutes ARG variables in a string.
func resolveArgs(s string, args map[string]string) string {
	return os.Expand(s, func(key string) string {
		if val, ok := args[key]; ok {
			return val
		}
		return ""
	})
}

// parseImageRef parses an image reference string into components.
func parseImageRef(ref string) *ImageRef {
	if ref == "" || strings.ToLower(ref) == "scratch" {
		return &ImageRef{Full: ref}
	}

	ir := &ImageRef{Full: ref}

	// Try to parse with go-containerregistry for accurate parsing
	parsed, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		// Fallback: simple parsing
		return parseImageRefSimple(ref)
	}

	ir.Registry = parsed.Context().RegistryStr()
	ir.Repository = parsed.Context().RepositoryStr()

	switch p := parsed.(type) {
	case name.Tag:
		ir.Tag = p.TagStr()
	case name.Digest:
		ir.Digest = p.DigestStr()
	}

	// Handle implicit tag
	if ir.Tag == "" && ir.Digest == "" {
		ir.Tag = "latest"
	}

	return ir
}

// parseImageRefSimple is a fallback parser for image references.
func parseImageRefSimple(ref string) *ImageRef {
	ir := &ImageRef{Full: ref}

	// Handle digest
	if idx := strings.Index(ref, "@"); idx != -1 {
		ir.Digest = ref[idx+1:]
		ref = ref[:idx]
	}

	// Handle tag
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		// Make sure it's not a port number
		afterColon := ref[idx+1:]
		if !strings.Contains(afterColon, "/") {
			ir.Tag = afterColon
			ref = ref[:idx]
		}
	}

	// Split registry/repository
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 1 {
		// No slash: library image
		ir.Registry = "docker.io"
		ir.Repository = "library/" + parts[0]
	} else if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost" {
		// First part looks like a registry
		ir.Registry = parts[0]
		ir.Repository = parts[1]
	} else {
		// Docker Hub user/repo
		ir.Registry = "docker.io"
		ir.Repository = ref
	}

	// Default tag
	if ir.Tag == "" && ir.Digest == "" {
		ir.Tag = "latest"
	}

	return ir
}
