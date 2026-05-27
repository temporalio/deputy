package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"connectrpc.com/connect"
	agentv1 "github.com/temporalio/deputy/gen/deputy/agent/v1"
	"github.com/temporalio/deputy/gen/deputy/agent/v1/agentv1connect"
)

// externalPluginHandler wraps an external agent plugin process as AgentPluginHandler.
// External plugins are discovered via PATH as executables named "deputy-plugin-<name>".
// They communicate via gRPC/Connect over a Unix socket.
type externalPluginHandler struct {
	name     string
	execPath string

	mu       sync.Mutex
	cmd      *exec.Cmd
	client   agentv1connect.AgentPluginClient
	sockPath string
}

// NewExternalPluginHandler creates a handler from an external executable.
// It starts the plugin process and verifies it implements the protocol.
// Returns the handler and a closer function to clean up resources.
func NewExternalPluginHandler(ctx context.Context, name, execPath string) (agentv1connect.AgentPluginHandler, func() error, error) {
	p := &externalPluginHandler{
		name:     name,
		execPath: execPath,
	}

	// Start the plugin and get its info
	if err := p.start(ctx); err != nil {
		return nil, nil, fmt.Errorf("start plugin: %w", err)
	}

	// Verify plugin is reachable
	_, err := p.client.GetInfo(ctx, connect.NewRequest(&agentv1.GetInfoRequest{}))
	if err != nil {
		p.close()
		return nil, nil, fmt.Errorf("get plugin info: %w", err)
	}

	return p, p.close, nil
}

// start launches the plugin process and establishes communication.
func (p *externalPluginHandler) start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil {
		return nil // Already started
	}

	// Create a temporary directory for the socket
	tmpDir, err := os.MkdirTemp("", "deputy-agent-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}

	p.sockPath = filepath.Join(tmpDir, "agent.sock")

	// Start the plugin with the socket path
	p.cmd = exec.CommandContext(ctx, p.execPath, "--socket", p.sockPath)
	p.cmd.Stdout = io.Discard
	p.cmd.Stderr = io.Discard

	if err := p.cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("start plugin process: %w", err)
	}

	// Wait for the socket to be ready
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p.sockPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if _, err := os.Stat(p.sockPath); err != nil {
		p.cmd.Process.Kill()
		os.RemoveAll(tmpDir)
		return fmt.Errorf("plugin socket not created")
	}

	// Create HTTP client with Unix socket transport
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", p.sockPath)
			},
		},
	}

	// Create the Connect client
	p.client = agentv1connect.NewAgentPluginClient(
		httpClient,
		"http://localhost", // Ignored, we use the socket
	)

	return nil
}

// Ensure externalPluginHandler implements AgentPluginHandler.
var _ agentv1connect.AgentPluginHandler = (*externalPluginHandler)(nil)

// GetInfo returns metadata about the external plugin.
func (p *externalPluginHandler) GetInfo(ctx context.Context, req *connect.Request[agentv1.GetInfoRequest]) (*connect.Response[agentv1.GetInfoResponse], error) {
	return p.client.GetInfo(ctx, req)
}

// Execute runs the plugin and streams events.
func (p *externalPluginHandler) Execute(ctx context.Context, req *connect.Request[agentv1.ExecuteRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	clientStream, err := p.client.Execute(ctx, req)
	if err != nil {
		return err
	}
	defer clientStream.Close()

	for clientStream.Receive() {
		if err := stream.Send(clientStream.Msg()); err != nil {
			return err
		}
	}
	return clientStream.Err()
}

// Resume continues a previous session.
func (p *externalPluginHandler) Resume(ctx context.Context, req *connect.Request[agentv1.ResumeRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	clientStream, err := p.client.Resume(ctx, req)
	if err != nil {
		return err
	}
	defer clientStream.Close()

	for clientStream.Receive() {
		if err := stream.Send(clientStream.Msg()); err != nil {
			return err
		}
	}
	return clientStream.Err()
}

// Approve handles an approval request.
func (p *externalPluginHandler) Approve(ctx context.Context, req *connect.Request[agentv1.ApproveRequest]) (*connect.Response[agentv1.ApproveResponse], error) {
	return p.client.Approve(ctx, req)
}

// Cancel requests graceful termination.
func (p *externalPluginHandler) Cancel(ctx context.Context, req *connect.Request[agentv1.CancelRequest]) (*connect.Response[agentv1.CancelResponse], error) {
	return p.client.Cancel(ctx, req)
}

// close stops the plugin process and cleans up resources.
func (p *externalPluginHandler) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Signal(os.Interrupt)
		// Give it a moment to shut down gracefully
		done := make(chan error, 1)
		go func() {
			done <- p.cmd.Wait()
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			p.cmd.Process.Kill()
		}
		p.cmd = nil
	}

	if p.sockPath != "" {
		os.RemoveAll(filepath.Dir(p.sockPath))
		p.sockPath = ""
	}

	return nil
}
