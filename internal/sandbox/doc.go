// Package sandbox provides isolated execution environments for Deputy.
//
// The sandbox package enables secure execution of plugins, AI agents,
// remediation commands, and user-specified commands (`deputy exec`) in
// isolated environments. It supports multiple runtime backends and
// integrates with Deputy's policy engine for fine-grained control.
//
// # Architecture
//
// The sandbox system consists of three main components:
//
//   - Runtime interface: Abstract interface that sandbox backends implement
//   - Manager: Coordinates runtime discovery, policy evaluation, and execution
//   - Runtimes: Concrete implementations (Docker, gVisor, None, plugins)
//
// # Supported Runtimes
//
// Built-in runtimes:
//
//   - Docker: Container isolation via Docker Engine/Desktop (cross-platform)
//   - gVisor: Application-level sandboxing with user-space kernel (Linux)
//   - sandbox-exec: macOS seatbelt sandbox (deprecated, best-effort)
//   - None: No sandboxing for trusted execution
//
// External plugin runtimes can be added via executables named `deputy-sandbox-*`
// that implement the SandboxRuntimeService proto interface.
//
// # Usage
//
// Create a sandbox manager and execute commands:
//
//	mgr, err := sandbox.NewManager(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	req := &sandboxv1.ExecuteRequest{
//	    Command:      []string{"npm", "install"},
//	    WorkspaceDir: "/path/to/project",
//	    Config: &sandboxv1.SandboxConfig{
//	        Mode:        sandboxv1.Mode_MODE_WORKSPACE_WRITE,
//	        NetworkMode: sandboxv1.NetworkMode_NETWORK_MODE_BRIDGE,
//	    },
//	}
//
//	for event, err := range mgr.Execute(ctx, req) {
//	    if err != nil {
//	        log.Printf("error: %v", err)
//	        break
//	    }
//	    // Handle event (output, completion, etc.)
//	}
//
// # Policy Integration
//
// The sandbox manager evaluates policies at three entrypoints:
//
//   - sandbox_execution: Before any sandbox execution begins
//   - sandbox_command: For each command within a sandbox session
//   - sandbox_network: When the sandbox requests network access
//
// Policies can deny execution, warn, or override sandbox configuration:
//
//	policies:
//	  - name: require-container-for-agents
//	    entrypoints: ["sandbox_execution"]
//	    rules:
//	      - action: deny
//	        when: |
//	          context.source == 2 &&
//	          requested_config.runtime == 1
//	        reason: "AI agents must run in container isolation"
//
// # Configuration
//
// Sandbox behavior is configured via `.deputy.yaml`:
//
//	sandbox:
//	  default_runtime: docker
//	  default_mode: workspace-write
//	  default_network_mode: none
//	  default_limits:
//	    memory: 512m
//	    cpu: "1.0"
//
// # Security Considerations
//
// The sandbox system provides defense-in-depth but is not a complete security
// boundary. Container escapes are possible with sufficient privileges or
// vulnerabilities. For maximum isolation, use gVisor or Firecracker (future).
// macOS sandbox-exec is deprecated by Apple and should be treated as
// best-effort isolation only.
//
// Key security features:
//
//   - Network isolation by default (NETWORK_MODE_NONE)
//   - Filesystem isolation (workspace-only writes by default)
//   - Resource limits (memory, CPU, PIDs)
//   - Capability dropping (all capabilities dropped by default)
//   - Policy-driven access control
package sandbox
