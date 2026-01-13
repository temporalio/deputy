package sandbox

import "os"

// Environment variable names for sandbox configuration.
// These allow users to customize sandbox runtime behavior without
// modifying code or configuration files.
const (
	// EnvDockerCLI specifies the path to a Docker-compatible CLI.
	// Supports docker, nerdctl, finch, podman, or any compatible CLI.
	// Used by container-based runtimes (Docker, gVisor in Docker mode).
	// Default: "docker"
	//
	// Example:
	//   DEPUTY_DOCKER_CLI=/usr/local/bin/nerdctl deputy exec -- ls
	//   DEPUTY_DOCKER_CLI=finch deputy exec -- ls
	EnvDockerCLI = "DEPUTY_DOCKER_CLI"

	// EnvDockerHost specifies the Docker daemon socket.
	// This is passed through to the Docker client via DOCKER_HOST.
	// Useful for remote Docker daemons or custom socket paths.
	// Default: Uses Docker's default socket detection
	//
	// Example:
	//   DEPUTY_DOCKER_HOST=unix:///var/run/docker.sock deputy exec -- ls
	//   DEPUTY_DOCKER_HOST=tcp://192.168.1.100:2375 deputy exec -- ls
	EnvDockerHost = "DEPUTY_DOCKER_HOST"

	// EnvRunscPath specifies the path to the runsc (gVisor) binary.
	// Used by the gVisor runtime for standalone mode.
	// Default: "runsc"
	//
	// Example:
	//   DEPUTY_RUNSC_PATH=/opt/gvisor/runsc deputy exec --runtime gvisor -- ls
	EnvRunscPath = "DEPUTY_RUNSC_PATH"
)

// GetDockerCLI returns the Docker CLI path from environment or default.
func GetDockerCLI() string {
	if cli := os.Getenv(EnvDockerCLI); cli != "" {
		return cli
	}
	return "docker"
}

// GetDockerHost returns the Docker host from DEPUTY_DOCKER_HOST or DOCKER_HOST.
// DEPUTY_DOCKER_HOST takes precedence to allow Deputy-specific configuration.
func GetDockerHost() string {
	if host := os.Getenv(EnvDockerHost); host != "" {
		return host
	}
	return os.Getenv("DOCKER_HOST")
}

// GetRunscPath returns the runsc path from environment or default.
func GetRunscPath() string {
	if path := os.Getenv(EnvRunscPath); path != "" {
		return path
	}
	return "runsc"
}
