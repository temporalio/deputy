package providers

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	cloudv1 "github.com/picatz/deputy/gen/deputy/cloud/v1"
	"github.com/picatz/deputy/gen/deputy/cloud/v1/cloudv1connect"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/picatz/deputy/internal/targets"
)

func init() {
	targets.RegisterProvider(&cloudPluginProvider{
		logger:  slog.Default(),
		plugins: make(map[string]*cloudPluginClient),
	})
}

const (
	// CloudPluginPrefix is the executable name prefix for cloud provider plugins.
	CloudPluginPrefix = "deputy-cloud-"

	// priorityCloudPlugin is slightly lower than built-in cloud providers
	// to prefer native implementations when available.
	priorityCloudPlugin = 60

	cloudPluginSocketWaitTimeout = 10 * time.Second
)

// cloudPluginProvider implements [targets.Provider] for cloud resources
// provided by external plugins (deputy-cloud-* executables).
type cloudPluginProvider struct {
	logger *slog.Logger

	mu      sync.RWMutex
	plugins map[string]*cloudPluginClient
}

type cloudPluginClient struct {
	name       string
	execPath   string
	socketDir  string
	socketPath string
	cmd        *exec.Cmd
	client     cloudv1connect.CloudProviderServiceClient
	info       *cloudv1.GetProviderInfoResponse
}

func (p *cloudPluginProvider) Priority() int { return priorityCloudPlugin }

// Detect returns true if any discovered cloud plugin handles the target.
func (p *cloudPluginProvider) Detect(ctx context.Context, target string) bool {
	// Quick check: if target doesn't look like a URI scheme, skip
	if !strings.Contains(target, "://") {
		return false
	}

	// Check all discovered plugins
	plugins := discoverCloudPlugins()
	for name, execPath := range plugins {
		plugin, err := p.getPlugin(ctx, name, execPath)
		if err != nil {
			p.logger.Debug("cloud plugin unavailable", "name", name, "error", err)
			continue
		}

		// Ask the plugin if it handles this target
		resp, err := plugin.client.Detect(ctx, connect.NewRequest(&cloudv1.DetectRequest{
			Target: target,
		}))
		if err != nil {
			p.logger.Debug("cloud plugin detect failed", "name", name, "error", err)
			continue
		}

		if resp.Msg.GetDetected() {
			p.logger.Debug("cloud plugin detected target",
				"name", name,
				"target", target,
				"scheme", resp.Msg.GetScheme(),
				"resource_type", resp.Msg.GetResourceType(),
			)
			return true
		}
	}

	return false
}

// Open materializes a cloud resource via the appropriate plugin.
func (p *cloudPluginProvider) Open(ctx context.Context, target string, opts *targets.OpenOptions) (targets.Materialized, error) {
	// Find the plugin that handles this target
	plugins := discoverCloudPlugins()
	for name, execPath := range plugins {
		plugin, err := p.getPlugin(ctx, name, execPath)
		if err != nil {
			continue
		}

		// Check if this plugin handles the target
		detectResp, err := plugin.client.Detect(ctx, connect.NewRequest(&cloudv1.DetectRequest{
			Target: target,
		}))
		if err != nil || !detectResp.Msg.GetDetected() {
			continue
		}

		// This plugin handles it - open the resource
		return p.openWithPlugin(ctx, plugin, target, opts)
	}

	return targets.Materialized{}, fmt.Errorf("no cloud plugin found for target: %s", target)
}

func (p *cloudPluginProvider) openWithPlugin(
	ctx context.Context,
	plugin *cloudPluginClient,
	target string,
	opts *targets.OpenOptions,
) (targets.Materialized, error) {
	requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())

	// Open the resource via the plugin
	stream, err := plugin.client.Open(ctx, connect.NewRequest(&cloudv1.OpenResourceRequest{
		Target:      target,
		OpenOptions: OpenOptionsToProto(opts),
		RequestId:   requestID,
	}))
	if err != nil {
		return targets.Materialized{}, fmt.Errorf("plugin open failed: %w", err)
	}
	defer stream.Close()

	// Process events until we get a ready or error event
	var readyEvent *cloudv1.ReadyEvent
	for stream.Receive() {
		event := stream.Msg()

		switch details := event.GetDetails().(type) {
		case *cloudv1.OpenResourceEvent_Progress:
			progress := details.Progress
			p.logger.Debug("cloud plugin progress",
				"plugin", plugin.name,
				"phase", progress.GetPhase(),
				"message", progress.GetMessage(),
				"percent", progress.GetPercent(),
			)

		case *cloudv1.OpenResourceEvent_Ready:
			readyEvent = details.Ready

		case *cloudv1.OpenResourceEvent_Error:
			errEvent := details.Error
			return targets.Materialized{}, fmt.Errorf("plugin error [%s]: %s (remediation: %s)",
				errEvent.GetCode(),
				errEvent.GetMessage(),
				errEvent.GetRemediation(),
			)
		}
	}

	if err := stream.Err(); err != nil {
		return targets.Materialized{}, fmt.Errorf("plugin stream error: %w", err)
	}

	if readyEvent == nil {
		return targets.Materialized{}, fmt.Errorf("plugin did not return a ready event")
	}

	// Get the filesystem from the local path
	localPath := readyEvent.GetLocalPath()
	if localPath == "" {
		return targets.Materialized{}, fmt.Errorf("plugin did not provide a local path")
	}

	// Verify the path exists
	info, err := os.Stat(localPath)
	if err != nil {
		return targets.Materialized{}, fmt.Errorf("plugin local path not accessible: %w", err)
	}
	if !info.IsDir() {
		return targets.Materialized{}, fmt.Errorf("plugin local path is not a directory: %s", localPath)
	}

	// Create a workspace from the local path
	ws, err := workspace.NewDir(localPath)
	if err != nil {
		return targets.Materialized{}, fmt.Errorf("create workspace: %w", err)
	}

	// Build provenance metadata from the resource
	resource := readyEvent.GetResource()
	provenance := map[string]string{
		"provider":      "plugin:" + plugin.name,
		"resource_type": resource.GetResourceType().String(),
		"resource_id":   resource.GetResourceId(),
		"region":        resource.GetRegion(),
	}
	if resource.GetAccountId() != "" {
		provenance["account_id"] = resource.GetAccountId()
	}
	if resource.GetName() != "" {
		provenance["name"] = resource.GetName()
	}
	for k, v := range resource.GetTags() {
		provenance["tag:"+k] = v
	}

	// Capture plugin reference and requestID for cleanup
	pluginRef := plugin
	reqID := requestID

	return targets.Materialized{
		FS:   ws,
		Path: localPath,
		Meta: targets.Descriptor{
			Kind:       targets.KindCloudResource,
			Target:     target,
			Options:    opts,
			Provenance: provenance,
		},
		Data: resource,
		Cleanup: func() {
			// Close the workspace
			_ = ws.Close()

			// Tell the plugin to release the resource
			_, _ = pluginRef.client.Close(context.Background(), connect.NewRequest(&cloudv1.CloseResourceRequest{
				RequestId: reqID,
			}))
		},
	}, nil
}

func (p *cloudPluginProvider) getPlugin(ctx context.Context, name, execPath string) (*cloudPluginClient, error) {
	p.mu.RLock()
	if plugin, ok := p.plugins[name]; ok {
		p.mu.RUnlock()
		return plugin, nil
	}
	p.mu.RUnlock()

	if execPath == "" {
		execPath = findCloudPluginInPath(name)
	}
	if execPath == "" {
		return nil, fmt.Errorf("cloud plugin %q not found in PATH", name)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if plugin, ok := p.plugins[name]; ok {
		return plugin, nil
	}

	plugin, err := startCloudPlugin(ctx, name, execPath)
	if err != nil {
		return nil, err
	}

	p.plugins[name] = plugin
	return plugin, nil
}

func startCloudPlugin(ctx context.Context, name, execPath string) (*cloudPluginClient, error) {
	tmpDir, err := os.MkdirTemp("", "deputy-cloud-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	socketPath := filepath.Join(tmpDir, "cloud.sock")
	cmd := exec.CommandContext(ctx, execPath, "--socket", socketPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard // Plugin logs should use structured logging via RPC, not stderr

	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("start cloud plugin %q: %w", name, err)
	}

	if err := waitForCloudSocket(socketPath, cloudPluginSocketWaitTimeout); err != nil {
		_ = cmd.Process.Kill()
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("cloud plugin %q socket not ready: %w", name, err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	client := cloudv1connect.NewCloudProviderServiceClient(httpClient, "http://localhost")
	resp, err := client.GetInfo(ctx, connect.NewRequest(&cloudv1.GetProviderInfoRequest{}))
	if err != nil {
		_ = cmd.Process.Kill()
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("cloud plugin %q info failed: %w", name, err)
	}

	return &cloudPluginClient{
		name:       name,
		execPath:   execPath,
		socketDir:  tmpDir,
		socketPath: socketPath,
		cmd:        cmd,
		client:     client,
		info:       resp.Msg,
	}, nil
}

// close gracefully shuts down the plugin process and cleans up resources.
// It sends SIGINT first, waits up to 5 seconds for graceful shutdown,
// then sends SIGKILL if the process hasn't exited. The temporary socket
// directory is removed regardless of shutdown method.
func (c *cloudPluginClient) close() error {
	if c == nil {
		return nil
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() {
			done <- c.cmd.Wait()
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = c.cmd.Process.Kill()
		}
	}

	if c.socketDir != "" {
		_ = os.RemoveAll(c.socketDir)
	}
	return nil
}

// Close releases all plugin processes managed by this provider.
// It gracefully shuts down each plugin by sending SIGINT and waiting
// up to 5 seconds before forcefully terminating with SIGKILL.
// Close is safe to call multiple times and satisfies [targets.CloseableProvider].
//
// This method should be called during application shutdown to prevent
// orphaned plugin processes. The [targets.Close] function calls this
// automatically for the default registry.
func (p *cloudPluginProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var firstErr error
	for name, plugin := range p.plugins {
		if err := plugin.close(); err != nil && firstErr == nil {
			firstErr = err
		}
		p.logger.Debug("closed cloud plugin", "name", name)
	}

	// Clear the map to allow re-initialization if needed
	p.plugins = make(map[string]*cloudPluginClient)
	return firstErr
}

func waitForCloudSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for socket")
}

// cloudPluginSearchDirs returns directories to search for cloud plugins, in priority order.
func cloudPluginSearchDirs() []string {
	var dirs []string

	// $GOPATH/bin
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		dirs = append(dirs, filepath.Join(gopath, "bin"))
	}

	// $HOME/go/bin (default Go bin location)
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
	}

	// PATH directories
	if pathEnv := os.Getenv("PATH"); pathEnv != "" {
		dirs = append(dirs, filepath.SplitList(pathEnv)...)
	}

	return dirs
}

func discoverCloudPlugins() map[string]string {
	plugins := make(map[string]string)
	seen := make(map[string]bool)

	for _, dir := range cloudPluginSearchDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			pluginName, found := strings.CutPrefix(name, CloudPluginPrefix)
			if !found {
				continue
			}
			if pluginName == "" || seen[pluginName] {
				continue
			}

			execPath := filepath.Join(dir, name)
			info, err := os.Stat(execPath)
			if err != nil || info.Mode()&0111 == 0 {
				continue
			}

			seen[pluginName] = true
			plugins[pluginName] = execPath
		}
	}

	return plugins
}

func findCloudPluginInPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return discoverCloudPlugins()[name]
}

// DiscoveredCloudPlugins returns information about all discovered cloud plugins.
// Useful for debugging and listing available plugins.
func DiscoveredCloudPlugins() []string {
	plugins := discoverCloudPlugins()
	names := make([]string, 0, len(plugins))
	for name := range plugins {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// IsCollection checks if the target is a collection URI via plugins.
func (p *cloudPluginProvider) IsCollection(ctx context.Context, target string) bool {
	// Quick check: if target doesn't look like a URI scheme, skip
	if !strings.Contains(target, "://") {
		return false
	}

	// Check all discovered plugins
	plugins := discoverCloudPlugins()
	for name, execPath := range plugins {
		plugin, err := p.getPlugin(ctx, name, execPath)
		if err != nil {
			continue
		}

		// Check if plugin supports listing
		if plugin.info.GetCapabilities() == nil || !plugin.info.GetCapabilities().GetListResources() {
			continue
		}

		// First check if plugin detects this target at all
		detectResp, err := plugin.client.Detect(ctx, connect.NewRequest(&cloudv1.DetectRequest{
			Target: target,
		}))
		if err != nil || !detectResp.Msg.GetDetected() {
			continue
		}

		// Ask the plugin if this is a collection
		resp, err := plugin.client.IsCollection(ctx, connect.NewRequest(&cloudv1.IsCollectionRequest{
			Target: target,
		}))
		if err != nil {
			p.logger.Debug("cloud plugin IsCollection failed", "name", name, "error", err)
			continue
		}

		if resp.Msg.GetIsCollection() {
			p.logger.Debug("cloud plugin detected collection",
				"name", name,
				"target", target,
				"collection_type", resp.Msg.GetCollectionType(),
			)
			return true
		}
	}

	return false
}

// List enumerates resources in a collection via plugins.
func (p *cloudPluginProvider) List(ctx context.Context, target string, opts *targets.ListOptions) (*targets.ListResult, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list cloud resources: %w", err)
	}

	// Find the plugin that handles this target
	plugins := discoverCloudPlugins()
	for name, execPath := range plugins {
		plugin, err := p.getPlugin(ctx, name, execPath)
		if err != nil {
			continue
		}

		// Check if plugin supports listing
		if plugin.info.GetCapabilities() == nil || !plugin.info.GetCapabilities().GetListResources() {
			continue
		}

		// Check if this plugin detects the target
		detectResp, err := plugin.client.Detect(ctx, connect.NewRequest(&cloudv1.DetectRequest{
			Target: target,
		}))
		if err != nil || !detectResp.Msg.GetDetected() {
			continue
		}

		// Verify it's a collection
		collResp, err := plugin.client.IsCollection(ctx, connect.NewRequest(&cloudv1.IsCollectionRequest{
			Target: target,
		}))
		if err != nil || !collResp.Msg.GetIsCollection() {
			continue
		}

		// List resources from the plugin
		listResp, err := plugin.client.List(ctx, connect.NewRequest(&cloudv1.PluginListRequest{
			Target: target,
			Filter: ListOptionsToProto(opts),
		}))
		if err != nil {
			return nil, fmt.Errorf("plugin %q list failed: %w", name, err)
		}

		// Convert CloudResource to DiscoveredTarget
		return &targets.ListResult{
			Targets:       cloudResourcesToDiscoveredTargets(plugin.name, listResp.Msg.GetResources()),
			NextPageToken: listResp.Msg.GetNextPageToken(),
		}, nil
	}

	return nil, fmt.Errorf("no cloud plugin found for collection: %s", target)
}

// cloudResourcesToDiscoveredTargets converts CloudResource protos to DiscoveredTarget protos.
func cloudResourcesToDiscoveredTargets(pluginName string, resources []*cloudv1.CloudResource) []*listv1.DiscoveredTarget {
	targets := make([]*listv1.DiscoveredTarget, 0, len(resources))
	for _, r := range resources {
		// Build URI from resource info
		// Format: <provider-scheme>://<resource-type>/<resource-id>
		scheme := strings.ToLower(r.GetProvider().String())
		scheme = strings.TrimPrefix(scheme, "cloud_provider_")
		resType := strings.ToLower(r.GetResourceType().String())
		resType = strings.TrimPrefix(resType, "cloud_resource_type_")
		resType = strings.TrimPrefix(resType, scheme+"_")
		resType = strings.ReplaceAll(resType, "_", "-")

		uri := fmt.Sprintf("%s://%s/%s", scheme, resType, r.GetResourceId())

		t := &listv1.DiscoveredTarget{
			Uri:         uri,
			Name:        r.GetName(),
			Description: r.GetDescription(),
			Metadata: map[string]string{
				"provider":      pluginName,
				"resource_id":   r.GetResourceId(),
				"resource_type": r.GetResourceType().String(),
				"region":        r.GetRegion(),
				"account_id":    r.GetAccountId(),
			},
		}

		// Copy creation timestamp
		if r.GetCreatedAt() != nil {
			t.CreatedAt = timestamppb.New(r.GetCreatedAt().AsTime())
		}

		// Add tags to metadata
		for k, v := range r.GetTags() {
			t.Metadata["tags."+k] = v
		}

		targets = append(targets, t)
	}
	return targets
}

var _ targets.Provider = (*cloudPluginProvider)(nil)
var _ targets.PriorityProvider = (*cloudPluginProvider)(nil)
var _ targets.CollectionProvider = (*cloudPluginProvider)(nil)
var _ targets.CloseableProvider = (*cloudPluginProvider)(nil)
