// deputy-extractor-gradle-sandbox is an external plugin that extracts Maven dependencies
// by running Gradle in a Docker container.
//
// This plugin provides the most accurate dependency resolution by actually running
// Gradle to resolve all dependencies, including:
//   - BOM-managed versions
//   - Version catalog references
//   - Dynamic versions (resolved to concrete versions)
//   - Transitive dependencies
//
// The plugin runs `gradle dependencies` in a sandboxed Docker container with:
//   - Read-only access to the project source
//   - Network access for dependency resolution
//   - No access to host filesystem beyond the project
//
// Requirements:
//   - Docker must be running and accessible
//   - The gradle:8-jdk17 image (or custom image via GRADLE_SANDBOX_IMAGE) must be pullable
//
// Installation:
//
//	go install github.com/temporalio/deputy/plugins/gradle-sandbox@latest
//
// The binary will be named "deputy-extractor-gradle-sandbox" and discovered automatically
// if it's in your PATH.
//
// Configuration via environment variables:
//   - GRADLE_SANDBOX_IMAGE: Docker image to use (default: gradle:8-jdk17)
//   - GRADLE_SANDBOX_TIMEOUT: Timeout in seconds (default: 300)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/temporalio/deputy/sdk/plugin"
)

const (
	defaultImage   = "gradle:8-jdk17"
	defaultTimeout = 300 // seconds
)

func main() {
	plugin.Main(&gradleSandboxExtractor{
		image:   getEnvOrDefault("GRADLE_SANDBOX_IMAGE", defaultImage),
		timeout: getDurationEnv("GRADLE_SANDBOX_TIMEOUT", defaultTimeout),
	})
}

type gradleSandboxExtractor struct {
	image   string
	timeout time.Duration
	client  *client.Client
}

func (e *gradleSandboxExtractor) Name() string {
	return "java/gradlesandbox"
}

func (e *gradleSandboxExtractor) DisplayName() string {
	return "Gradle Sandbox"
}

func (e *gradleSandboxExtractor) Ecosystem() string {
	return "maven"
}

func (e *gradleSandboxExtractor) Version() int {
	return 1
}

func (e *gradleSandboxExtractor) Description() string {
	return "Extracts Maven dependencies by running Gradle in a Docker container for accurate version resolution"
}

func (e *gradleSandboxExtractor) FilePatterns() []string {
	return []string{"settings.gradle", "settings.gradle.kts"}
}

func (e *gradleSandboxExtractor) FileRequired(path string, isDir bool, mode uint32, size int64) bool {
	if isDir {
		return false
	}
	base := filepath.Base(path)
	required := base == "settings.gradle" || base == "settings.gradle.kts"
	if required {
		fmt.Fprintf(os.Stderr, "gradle-sandbox: FileRequired(%s) = true\n", path)
	}
	return required
}

func (e *gradleSandboxExtractor) Extract(path string, contents []byte, root string) ([]*plugin.Package, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	// Check if Docker is available
	cli, err := e.getDockerClient(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gradle-sandbox: Docker not available: %v\n", err)
		return nil, nil
	}

	// Get the project directory
	projectDir := filepath.Dir(filepath.Join(root, path))
	fmt.Fprintf(os.Stderr, "gradle-sandbox: extracting from %s (root=%s)\n", path, projectDir)

	// Run Gradle dependencies in a container
	deps, err := e.runGradleDependencies(ctx, cli, projectDir)
	if err != nil {
		// Return empty result on error (don't fail the scan)
		fmt.Fprintf(os.Stderr, "gradle-sandbox: error running Gradle: %v\n", err)
		return nil, nil
	}
	fmt.Fprintf(os.Stderr, "gradle-sandbox: found %d dependencies\n", len(deps))

	// Convert to packages
	packages := make([]*plugin.Package, 0, len(deps))
	seen := make(map[string]bool)

	for _, dep := range deps {
		if dep.Group == "" || dep.Name == "" || dep.Version == "" {
			continue
		}

		key := fmt.Sprintf("%s:%s:%s", dep.Group, dep.Name, dep.Version)
		if seen[key] {
			continue
		}
		seen[key] = true

		packages = append(packages, plugin.NewPackage(
			fmt.Sprintf("%s:%s", dep.Group, dep.Name),
			dep.Version,
			"maven",
		))
	}

	return packages, nil
}

// getDockerClient returns the Docker client, initializing it if needed.
func (e *gradleSandboxExtractor) getDockerClient(ctx context.Context) (*client.Client, error) {
	if e.client != nil {
		return e.client, nil
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Verify Docker daemon is responsive
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = cli.Ping(pingCtx, client.PingOptions{})
	if err != nil {
		return nil, fmt.Errorf("Docker daemon not responsive: %w", err)
	}

	e.client = cli
	return cli, nil
}

type gradleDep struct {
	Group   string `json:"group"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Scope   string `json:"scope"`
}

func (e *gradleSandboxExtractor) runGradleDependencies(ctx context.Context, cli *client.Client, projectDir string) ([]gradleDep, error) {
	// Get absolute path
	absProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		return nil, fmt.Errorf("getting absolute path: %w", err)
	}

	// Gradle init script to output dependencies as JSON
	initScript := `
allprojects {
    task deputyDeps {
        doLast {
            def deps = []
            configurations.each { config ->
                if (config.canBeResolved) {
                    try {
                        config.resolvedConfiguration.resolvedArtifacts.each { artifact ->
                            def id = artifact.moduleVersion.id
                            deps << [
                                group: id.group,
                                name: id.name,
                                version: id.version,
                                scope: config.name
                            ]
                        }
                    } catch (Exception e) {
                        // Skip unresolvable configurations
                    }
                }
            }
            def json = groovy.json.JsonOutput.toJson(deps)
            println "DEPUTY_DEPS_START"
            println json
            println "DEPUTY_DEPS_END"
        }
    }
}
`

	// Write init script to temp file
	initFile, err := os.CreateTemp("", "deputy-gradle-init-*.gradle")
	if err != nil {
		return nil, fmt.Errorf("creating init script: %w", err)
	}
	defer os.Remove(initFile.Name())

	if _, err := initFile.WriteString(initScript); err != nil {
		initFile.Close()
		return nil, fmt.Errorf("writing init script: %w", err)
	}
	initFile.Close()

	// Ensure image exists
	if err := e.ensureImage(ctx, cli); err != nil {
		return nil, fmt.Errorf("ensuring image: %w", err)
	}

	// Create container configuration
	// Use --project-cache-dir to avoid needing write access to /project/.gradle
	containerConfig := &container.Config{
		Image:        e.image,
		Cmd:          []string{"gradle", "--init-script", "/init.gradle", "--project-cache-dir", "/tmp/gradle-cache", "deputyDeps", "-q", "--no-daemon"},
		WorkingDir:   "/project",
		AttachStdout: true,
		AttachStderr: true,
	}

	hostConfig := &container.HostConfig{
		NetworkMode: network.NetworkHost,
		AutoRemove:  false, // We handle removal ourselves
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeBind,
				Source:   absProjectDir,
				Target:   "/project",
				ReadOnly: true,
			},
			{
				Type:     mount.TypeBind,
				Source:   initFile.Name(),
				Target:   "/init.gradle",
				ReadOnly: true,
			},
		},
		// Provide a tmpfs for Gradle's cache since project is read-only
		Tmpfs: map[string]string{
			"/tmp/gradle-cache": "rw,noexec,nosuid,size=512m",
		},
	}

	// Create container
	createResp, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:     containerConfig,
		HostConfig: hostConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("creating container: %w", err)
	}
	containerID := createResp.ID

	// Ensure cleanup
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = cli.ContainerRemove(cleanupCtx, containerID, client.ContainerRemoveOptions{Force: true})
	}()

	// Attach to container for output
	attachResp, err := cli.ContainerAttach(ctx, containerID, client.ContainerAttachOptions{
		Stream: true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching to container: %w", err)
	}
	defer attachResp.Close()

	// Start container
	if _, err := cli.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
		return nil, fmt.Errorf("starting container: %w", err)
	}

	// Read output
	var stdout, stderr strings.Builder
	outputDone := make(chan error, 1)
	go func() {
		_, err := stdcopy.StdCopy(&stdout, &stderr, attachResp.Reader)
		outputDone <- err
	}()

	// Wait for container to finish
	waitResult := cli.ContainerWait(ctx, containerID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	statusCh, errCh := waitResult.Result, waitResult.Error

	select {
	case err := <-errCh:
		if err != nil {
			return nil, fmt.Errorf("waiting for container: %w", err)
		}
		return nil, fmt.Errorf("unexpected error channel state")
	case status := <-statusCh:
		// Wait for output to be fully read before checking status
		<-outputDone

		// Parse the output first - Gradle may have output dependencies before failing
		// (e.g., failure due to problems report directory not being writable)
		deps, parseErr := parseGradleOutput(stdout.String())

		if status.StatusCode != 0 {
			// If we got dependencies despite the failure, return them
			// This handles cases where Gradle completes the task but fails on reporting
			if len(deps) > 0 {
				fmt.Fprintf(os.Stderr, "gradle-sandbox: container exited with code %d but extracted %d dependencies\n", status.StatusCode, len(deps))
				return deps, nil
			}
			fmt.Fprintf(os.Stderr, "gradle-sandbox: container exited with code %d\nstdout: %s\nstderr: %s\n", status.StatusCode, stdout.String(), stderr.String())
			return nil, fmt.Errorf("gradle exited with code %d", status.StatusCode)
		}

		if parseErr != nil {
			return nil, fmt.Errorf("parsing gradle output: %w", parseErr)
		}
		return deps, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}
}

// ensureImage ensures the image exists, pulling if needed.
func (e *gradleSandboxExtractor) ensureImage(ctx context.Context, cli *client.Client) error {
	// Check if image exists locally
	_, err := cli.ImageInspect(ctx, e.image)
	if err == nil {
		return nil // Image exists
	}
	if !errdefs.IsNotFound(err) {
		return fmt.Errorf("inspecting image: %w", err)
	}

	// Pull the image
	fmt.Fprintf(os.Stderr, "gradle-sandbox: pulling image %s\n", e.image)
	pullResp, err := cli.ImagePull(ctx, e.image, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pulling image: %w", err)
	}
	defer pullResp.Close()

	// Consume the pull output (required to complete the pull)
	_, err = io.Copy(io.Discard, pullResp)
	if err != nil {
		return fmt.Errorf("reading pull response: %w", err)
	}

	return nil
}

func parseGradleOutput(output string) ([]gradleDep, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	var inDeps bool
	var jsonBuilder strings.Builder
	var allDeps []gradleDep

	for scanner.Scan() {
		line := scanner.Text()
		if line == "DEPUTY_DEPS_START" {
			inDeps = true
			jsonBuilder.Reset()
			continue
		}
		if line == "DEPUTY_DEPS_END" {
			inDeps = false
			if jsonBuilder.Len() > 0 {
				var deps []gradleDep
				if err := json.Unmarshal([]byte(jsonBuilder.String()), &deps); err == nil {
					allDeps = append(allDeps, deps...)
				}
			}
			continue
		}
		if inDeps {
			jsonBuilder.WriteString(line)
		}
	}

	return allDeps, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getDurationEnv(key string, defaultSeconds int) time.Duration {
	if v := os.Getenv(key); v != "" {
		if seconds, err := strconv.Atoi(v); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return time.Duration(defaultSeconds) * time.Second
}
