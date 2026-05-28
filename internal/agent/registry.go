// Package agent provides a plugin registry for AI agent implementations.
//
// Plugins implement the generated agentv1connect.AgentPluginHandler interface.
package agent

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"connectrpc.com/connect"
	agentv1 "github.com/temporalio/deputy/gen/deputy/agent/v1"
	"github.com/temporalio/deputy/gen/deputy/agent/v1/agentv1connect"
)

// PluginType identifies the type of plugin.
type PluginType string

const (
	// PluginTypeBuiltin is a plugin compiled into the Deputy binary.
	PluginTypeBuiltin PluginType = "builtin"

	// PluginTypeExternal is a plugin discovered via PATH.
	PluginTypeExternal PluginType = "external"

	// PluginTypeRemote is a plugin accessed via gRPC/Connect.
	PluginTypeRemote PluginType = "remote"

	// PluginTypeSandboxed is a plugin running in a container.
	PluginTypeSandboxed PluginType = "sandboxed"
)

// PluginEntry describes a registered plugin.
type PluginEntry struct {
	Name    string
	Type    PluginType
	Handler agentv1connect.AgentPluginHandler
	Path    string // For external plugins, the executable path
	Address string // For remote plugins, the server address
	closer  func() error
}

// Close releases resources held by this plugin entry.
func (e *PluginEntry) Close() error {
	if e.closer != nil {
		return e.closer()
	}
	return nil
}

// Registry manages agent plugin discovery and lifecycle.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]*PluginEntry
}

// NewRegistry creates an empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]*PluginEntry),
	}
}

// Register adds a plugin to the registry.
func (r *Registry) Register(entry *PluginEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry.Name == "" {
		return fmt.Errorf("plugin name is required")
	}
	if entry.Handler == nil {
		return fmt.Errorf("plugin handler is required")
	}

	if _, exists := r.plugins[entry.Name]; exists {
		return fmt.Errorf("plugin %q already registered", entry.Name)
	}

	r.plugins[entry.Name] = entry
	return nil
}

// RegisterBuiltin registers a builtin plugin handler.
func (r *Registry) RegisterBuiltin(name string, handler agentv1connect.AgentPluginHandler) error {
	return r.Register(&PluginEntry{
		Name:    name,
		Type:    PluginTypeBuiltin,
		Handler: handler,
	})
}

// RegisterSandboxed registers a sandboxed plugin handler.
func (r *Registry) RegisterSandboxed(name string, opts SandboxOptions) error {
	handler, err := NewSandboxedHandler(name, opts)
	if err != nil {
		return err
	}
	return r.Register(&PluginEntry{
		Name:    name,
		Type:    PluginTypeSandboxed,
		Handler: handler,
	})
}

// MustRegisterBuiltin registers a builtin plugin, panicking on error.
func (r *Registry) MustRegisterBuiltin(name string, handler agentv1connect.AgentPluginHandler) {
	if err := r.RegisterBuiltin(name, handler); err != nil {
		panic(err)
	}
}

// MustRegisterSandboxed registers a sandboxed plugin, panicking on error.
func (r *Registry) MustRegisterSandboxed(name string, opts SandboxOptions) {
	if err := r.RegisterSandboxed(name, opts); err != nil {
		panic(err)
	}
}

// Get retrieves a plugin handler by name.
func (r *Registry) Get(name string) (agentv1connect.AgentPluginHandler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.plugins[name]
	if !ok {
		return nil, fmt.Errorf("plugin %q not found", name)
	}
	return entry.Handler, nil
}

// GetEntry retrieves a plugin entry by name.
func (r *Registry) GetEntry(name string) (*PluginEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.plugins[name]
	if !ok {
		return nil, fmt.Errorf("plugin %q not found", name)
	}
	return entry, nil
}

// List returns all registered plugin names, sorted alphabetically.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Entries returns all registered plugin entries.
func (r *Registry) Entries() []*PluginEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries := make([]*PluginEntry, 0, len(r.plugins))
	for _, entry := range r.plugins {
		entries = append(entries, entry)
	}
	return entries
}

// Unregister removes a plugin from the registry.
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.plugins[name]
	if !ok {
		return fmt.Errorf("plugin %q not found", name)
	}

	// Close the plugin
	if err := entry.Close(); err != nil {
		// Log but don't fail
		_ = err
	}

	delete(r.plugins, name)
	return nil
}

// Close closes all registered plugins.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for _, entry := range r.plugins {
		if err := entry.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close plugin %s: %w", entry.Name, err))
		}
	}

	r.plugins = make(map[string]*PluginEntry)

	if len(errs) > 0 {
		return fmt.Errorf("errors closing plugins: %v", errs)
	}
	return nil
}

// PluginPrefix is the prefix for external plugin executables.
const PluginPrefix = "deputy-plugin-"

// DiscoverExternal searches PATH for external agent plugins.
// External plugins are executables matching the pattern "deputy-plugin-<name>".
// This performs eager discovery - plugins are started and registered immediately.
func (r *Registry) DiscoverExternal(ctx context.Context) ([]string, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil, nil
	}

	var discovered []string
	seen := make(map[string]bool)

	for _, dir := range filepath.SplitList(pathEnv) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // Skip unreadable directories
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			name := entry.Name()
			if !strings.HasPrefix(name, PluginPrefix) {
				continue
			}

			// Extract plugin name from executable name
			pluginName := strings.TrimPrefix(name, PluginPrefix)
			if pluginName == "" {
				continue
			}

			// Skip if already seen (first in PATH wins)
			if seen[pluginName] {
				continue
			}
			seen[pluginName] = true

			// Skip if already registered (builtin takes precedence)
			if _, err := r.Get(pluginName); err == nil {
				continue
			}

			execPath := filepath.Join(dir, name)

			// Verify it's executable
			info, err := os.Stat(execPath)
			if err != nil {
				continue
			}
			if info.Mode()&0111 == 0 {
				continue // Not executable
			}

			// Create external plugin handler
			handler, closer, err := NewExternalPluginHandler(ctx, pluginName, execPath)
			if err != nil {
				continue // Skip invalid plugins
			}

			if err := r.Register(&PluginEntry{
				Name:    pluginName,
				Type:    PluginTypeExternal,
				Handler: handler,
				Path:    execPath,
				closer:  closer,
			}); err != nil {
				if closer != nil {
					closer()
				}
				continue
			}

			discovered = append(discovered, pluginName)
		}
	}

	return discovered, nil
}

// FindPluginInPath searches PATH for a plugin executable by name.
// It looks for "deputy-plugin-<name>" in PATH and returns the full path if found.
// Returns empty string if not found.
func FindPluginInPath(name string) string {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return ""
	}

	execName := PluginPrefix + name

	for _, dir := range filepath.SplitList(pathEnv) {
		execPath := filepath.Join(dir, execName)
		info, err := os.Stat(execPath)
		if err != nil {
			continue
		}
		// Check if it's executable
		if info.Mode()&0111 != 0 {
			return execPath
		}
	}

	return ""
}

// GetOrDiscover retrieves a plugin by name, discovering it from PATH if not already registered.
// This enables natural usage like Get("gemini") which will auto-discover deputy-plugin-gemini.
func (r *Registry) GetOrDiscover(ctx context.Context, name string) (agentv1connect.AgentPluginHandler, error) {
	// First check if already registered
	if handler, err := r.Get(name); err == nil {
		return handler, nil
	}

	// Try to discover from PATH
	execPath := FindPluginInPath(name)
	if execPath == "" {
		return nil, fmt.Errorf("plugin %q not found (checked registry and PATH for %s%s)", name, PluginPrefix, name)
	}

	// Create and register the external plugin
	handler, closer, err := NewExternalPluginHandler(ctx, name, execPath)
	if err != nil {
		return nil, fmt.Errorf("start plugin %q: %w", name, err)
	}

	if err := r.Register(&PluginEntry{
		Name:    name,
		Type:    PluginTypeExternal,
		Handler: handler,
		Path:    execPath,
		closer:  closer,
	}); err != nil {
		if closer != nil {
			closer()
		}
		return nil, fmt.Errorf("register plugin %q: %w", name, err)
	}

	return handler, nil
}

// ListAvailable returns all available plugins: registered and discoverable from PATH.
// This combines registered plugin names with plugin names found in PATH.
func (r *Registry) ListAvailable() []string {
	// Start with registered plugins
	registered := r.List()
	seen := make(map[string]bool)
	for _, name := range registered {
		seen[name] = true
	}

	// Scan PATH for additional plugins
	pathEnv := os.Getenv("PATH")
	if pathEnv != "" {
		for _, dir := range filepath.SplitList(pathEnv) {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}

				name := entry.Name()
				if !strings.HasPrefix(name, PluginPrefix) {
					continue
				}

				pluginName := strings.TrimPrefix(name, PluginPrefix)
				if pluginName == "" || seen[pluginName] {
					continue
				}

				// Verify it's executable
				execPath := filepath.Join(dir, name)
				info, err := os.Stat(execPath)
				if err != nil || info.Mode()&0111 == 0 {
					continue
				}

				seen[pluginName] = true
			}
		}
	}

	// Return sorted list
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	slices.Sort(result)
	return result
}

// RegisterRemote registers a remote plugin at the given address.
func (r *Registry) RegisterRemote(ctx context.Context, name, address string) error {
	client := agentv1connect.NewAgentPluginClient(
		http.DefaultClient,
		address,
	)

	// Verify the remote plugin is reachable
	_, err := client.GetInfo(ctx, connect.NewRequest(&agentv1.GetInfoRequest{}))
	if err != nil {
		return fmt.Errorf("connect to remote plugin: %w", err)
	}

	// Wrap the client as a handler using ClientHandler adapter
	handler := &clientHandler{client: client}

	return r.Register(&PluginEntry{
		Name:    name,
		Type:    PluginTypeRemote,
		Handler: handler,
		Address: address,
	})
}

// clientHandler adapts AgentPluginClient to AgentPluginHandler interface.
// This is needed because remote plugins expose a client, but we need handler interface.
type clientHandler struct {
	client agentv1connect.AgentPluginClient
}

func (h *clientHandler) GetInfo(ctx context.Context, req *connect.Request[agentv1.GetInfoRequest]) (*connect.Response[agentv1.GetInfoResponse], error) {
	return h.client.GetInfo(ctx, req)
}

func (h *clientHandler) Execute(ctx context.Context, req *connect.Request[agentv1.ExecuteRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	// Call the remote Execute and stream results back
	clientStream, err := h.client.Execute(ctx, req)
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

func (h *clientHandler) Resume(ctx context.Context, req *connect.Request[agentv1.ResumeRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	clientStream, err := h.client.Resume(ctx, req)
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

func (h *clientHandler) Approve(ctx context.Context, req *connect.Request[agentv1.ApproveRequest]) (*connect.Response[agentv1.ApproveResponse], error) {
	return h.client.Approve(ctx, req)
}

func (h *clientHandler) Cancel(ctx context.Context, req *connect.Request[agentv1.CancelRequest]) (*connect.Response[agentv1.CancelResponse], error) {
	return h.client.Cancel(ctx, req)
}

// DefaultRegistry is the global plugin registry.
var DefaultRegistry = NewRegistry()

// Register adds a plugin to the default registry.
func Register(entry *PluginEntry) error {
	return DefaultRegistry.Register(entry)
}

// RegisterBuiltin registers a builtin plugin to the default registry.
func RegisterBuiltin(name string, handler agentv1connect.AgentPluginHandler) error {
	return DefaultRegistry.RegisterBuiltin(name, handler)
}

// MustRegisterBuiltin registers a builtin plugin, panicking on error.
func MustRegisterBuiltin(name string, handler agentv1connect.AgentPluginHandler) {
	DefaultRegistry.MustRegisterBuiltin(name, handler)
}

// RegisterSandboxed registers a sandboxed plugin to the default registry.
func RegisterSandboxed(name string, opts SandboxOptions) error {
	return DefaultRegistry.RegisterSandboxed(name, opts)
}

// MustRegisterSandboxed registers a sandboxed plugin to the default registry, panicking on error.
func MustRegisterSandboxed(name string, opts SandboxOptions) {
	DefaultRegistry.MustRegisterSandboxed(name, opts)
}

// Get retrieves a plugin from the default registry.
func Get(name string) (agentv1connect.AgentPluginHandler, error) {
	return DefaultRegistry.Get(name)
}

// List returns all registered plugin names from the default registry.
func List() []string {
	return DefaultRegistry.List()
}

// DiscoverExternal discovers external plugins and adds them to the default registry.
func DiscoverExternal(ctx context.Context) ([]string, error) {
	return DefaultRegistry.DiscoverExternal(ctx)
}

// GetOrDiscover retrieves a plugin from the default registry, discovering from PATH if needed.
func GetOrDiscover(ctx context.Context, name string) (agentv1connect.AgentPluginHandler, error) {
	return DefaultRegistry.GetOrDiscover(ctx, name)
}

// ListAvailable returns all available plugins from the default registry and PATH.
func ListAvailable() []string {
	return DefaultRegistry.ListAvailable()
}
