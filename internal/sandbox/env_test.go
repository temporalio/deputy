package sandbox

import (
	"os"
	"testing"
)

func TestGetDockerCLI(t *testing.T) {
	// Save original value
	orig := os.Getenv(EnvDockerCLI)
	defer os.Setenv(EnvDockerCLI, orig)

	// Test default
	os.Unsetenv(EnvDockerCLI)
	if got := GetDockerCLI(); got != "docker" {
		t.Errorf("GetDockerCLI() = %q, want %q", got, "docker")
	}

	// Test with custom value
	os.Setenv(EnvDockerCLI, "/usr/local/bin/nerdctl")
	if got := GetDockerCLI(); got != "/usr/local/bin/nerdctl" {
		t.Errorf("GetDockerCLI() = %q, want %q", got, "/usr/local/bin/nerdctl")
	}

	// Test with finch
	os.Setenv(EnvDockerCLI, "finch")
	if got := GetDockerCLI(); got != "finch" {
		t.Errorf("GetDockerCLI() = %q, want %q", got, "finch")
	}
}

func TestGetDockerHost(t *testing.T) {
	// Save original values
	origDeputy := os.Getenv(EnvDockerHost)
	origDocker := os.Getenv("DOCKER_HOST")
	defer func() {
		os.Setenv(EnvDockerHost, origDeputy)
		os.Setenv("DOCKER_HOST", origDocker)
	}()

	// Test default (no env vars)
	os.Unsetenv(EnvDockerHost)
	os.Unsetenv("DOCKER_HOST")
	if got := GetDockerHost(); got != "" {
		t.Errorf("GetDockerHost() = %q, want empty string", got)
	}

	// Test DOCKER_HOST fallback
	os.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	if got := GetDockerHost(); got != "unix:///var/run/docker.sock" {
		t.Errorf("GetDockerHost() = %q, want %q", got, "unix:///var/run/docker.sock")
	}

	// Test DEPUTY_DOCKER_HOST takes precedence
	os.Setenv(EnvDockerHost, "tcp://192.168.1.100:2375")
	if got := GetDockerHost(); got != "tcp://192.168.1.100:2375" {
		t.Errorf("GetDockerHost() = %q, want %q", got, "tcp://192.168.1.100:2375")
	}
}

func TestGetRunscPath(t *testing.T) {
	// Save original value
	orig := os.Getenv(EnvRunscPath)
	defer os.Setenv(EnvRunscPath, orig)

	// Test default
	os.Unsetenv(EnvRunscPath)
	if got := GetRunscPath(); got != "runsc" {
		t.Errorf("GetRunscPath() = %q, want %q", got, "runsc")
	}

	// Test with custom value
	os.Setenv(EnvRunscPath, "/opt/gvisor/runsc")
	if got := GetRunscPath(); got != "/opt/gvisor/runsc" {
		t.Errorf("GetRunscPath() = %q, want %q", got, "/opt/gvisor/runsc")
	}
}
