// Package registry provides a thread-safe registry for extractor plugins.
//
// This registry is the foundation for Deputy's extensible inventory extraction.
// It allows plugins to be registered at runtime without recompiling Deputy.
//
// # Plugin Sources
//
// Extractors come from three sources, in priority order:
//  1. OSV-SCALIBR extractors (built-in, Go)
//  2. Deputy custom extractors (built-in, Go)
//  3. Plugin extractors (external, any language via pluginrpc)
//
// # Usage
//
// The default registry is accessed via package-level functions:
//
//	// Register a plugin
//	registry.Register(info, "unix:///tmp/my-plugin.sock")
//
//	// List all plugins (built-in + registered)
//	extractors := registry.ListAll()
//
//	// Get registered plugins for scanning
//	plugins := registry.GetPlugins()
//
// # Thread Safety
//
// All registry operations are thread-safe and can be called concurrently.
package registry

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	pl "github.com/google/osv-scalibr/plugin/list"

	inventoryv1 "github.com/picatz/deputy/gen/deputy/inventory/v1"
	"github.com/picatz/deputy/internal/ecosystem"
	pluginclient "github.com/picatz/deputy/internal/inventory/plugin"
	dockerfilex "github.com/picatz/deputy/internal/inventory/plugins/docker/dockerfilex"
	ghactions "github.com/picatz/deputy/internal/inventory/plugins/github/actionsx"
	gradlex "github.com/picatz/deputy/internal/inventory/plugins/java/gradlex"
	rubygemspec "github.com/picatz/deputy/internal/inventory/plugins/ruby/gemspecx"
	"github.com/picatz/deputy/internal/inventory/plugins/terraform"
)

// RegisteredPlugin represents an external plugin that was registered at runtime.
type RegisteredPlugin struct {
	Info          *inventoryv1.ExtractorInfo
	PluginAddress string
	Client        *pluginclient.Client
}

// Registry holds registered extractor plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]*RegisteredPlugin
}

// New creates a new empty registry.
func New() *Registry {
	return &Registry{
		plugins: make(map[string]*RegisteredPlugin),
	}
}

// Register adds a plugin to the registry.
// Returns an error if a plugin with the same name is already registered.
func (r *Registry) Register(info *inventoryv1.ExtractorInfo, pluginAddress string) error {
	if info == nil {
		return fmt.Errorf("extractor info is required")
	}
	if info.Name == "" {
		return fmt.Errorf("extractor name is required")
	}
	if pluginAddress == "" {
		return fmt.Errorf("plugin address is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[info.Name]; exists {
		return fmt.Errorf("extractor %q is already registered", info.Name)
	}

	r.plugins[info.Name] = &RegisteredPlugin{
		Info:          info,
		PluginAddress: pluginAddress,
	}
	return nil
}

// Unregister removes a plugin from the registry.
// Returns true if the plugin was found and removed.
func (r *Registry) Unregister(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[name]; exists {
		delete(r.plugins, name)
		return true
	}
	return false
}

// Get returns a registered plugin by name, or nil if not found.
func (r *Registry) Get(name string) *RegisteredPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.plugins[name]
}

// GetPlugins returns all registered plugins.
func (r *Registry) GetPlugins() []*RegisteredPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]*RegisteredPlugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

// ListRegistered returns info for all registered plugins.
func (r *Registry) ListRegistered() []*inventoryv1.ExtractorInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	infos := make([]*inventoryv1.ExtractorInfo, 0, len(r.plugins))
	for _, p := range r.plugins {
		infos = append(infos, p.Info)
	}
	return infos
}

// ListAll returns info for all extractors: SCALIBR, Deputy built-ins, and registered plugins.
func (r *Registry) ListAll() []*inventoryv1.ExtractorInfo {
	var infos []*inventoryv1.ExtractorInfo

	// Add SCALIBR extractors
	infos = append(infos, listScalibrExtractors()...)

	// Add Deputy built-in extractors
	infos = append(infos, listDeputyExtractors()...)

	// Add registered plugins
	infos = append(infos, r.ListRegistered()...)

	// Sort by name for consistent output
	slices.SortFunc(infos, func(a, b *inventoryv1.ExtractorInfo) int {
		return strings.Compare(a.Name, b.Name)
	})

	return infos
}

// listScalibrExtractors returns info for all SCALIBR extractors.
func listScalibrExtractors() []*inventoryv1.ExtractorInfo {
	// Get all SCALIBR plugins
	plugins := pl.FromCapabilities(nil)

	var infos []*inventoryv1.ExtractorInfo
	allowedPrefixes := ecosystem.AllScalibrPrefixes()

	for _, p := range plugins {
		// Filter to only filesystem extractors we support
		name := p.Name()
		seg, _, _ := strings.Cut(name, "/")
		found := false
		for _, prefix := range allowedPrefixes {
			if seg == prefix {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		infos = append(infos, &inventoryv1.ExtractorInfo{
			Name:        name,
			DisplayName: name, // SCALIBR doesn't have display names
			Version:     int32(p.Version()),
			Description: fmt.Sprintf("SCALIBR %s extractor", name),
			Source:      inventoryv1.ExtractorSource_EXTRACTOR_SOURCE_SCALIBR,
		})
	}
	return infos
}

// listDeputyExtractors returns info for Deputy's built-in extractors.
func listDeputyExtractors() []*inventoryv1.ExtractorInfo {
	return []*inventoryv1.ExtractorInfo{
		{
			Name:         ghactions.Name,
			DisplayName:  "GitHub Actions",
			Ecosystem:    "github-actions",
			Version:      1,
			Description:  "Extracts GitHub Actions from workflow files",
			FilePatterns: []string{".github/workflows/*.yml", ".github/workflows/*.yaml"},
			Source:       inventoryv1.ExtractorSource_EXTRACTOR_SOURCE_DEPUTY,
		},
		{
			Name:         dockerfilex.Name,
			DisplayName:  "Dockerfile",
			Ecosystem:    "docker",
			Version:      1,
			Description:  "Extracts base images from Dockerfiles",
			FilePatterns: []string{"Dockerfile", "*.dockerfile", "Dockerfile.*"},
			Source:       inventoryv1.ExtractorSource_EXTRACTOR_SOURCE_DEPUTY,
		},
		{
			Name:         rubygemspec.Name,
			DisplayName:  "Ruby Gemspec",
			Ecosystem:    "rubygems",
			Version:      1,
			Description:  "Extracts dependencies from Ruby gemspec files",
			FilePatterns: []string{"*.gemspec"},
			Source:       inventoryv1.ExtractorSource_EXTRACTOR_SOURCE_DEPUTY,
		},
		{
			Name:         gradlex.VerificationMetadataName,
			DisplayName:  "Gradle Verification Metadata",
			Ecosystem:    "maven",
			Version:      1,
			Description:  "Extracts dependencies from Gradle verification-metadata.xml files",
			FilePatterns: []string{"gradle/verification-metadata.xml"},
			Source:       inventoryv1.ExtractorSource_EXTRACTOR_SOURCE_DEPUTY,
		},
		{
			Name:         gradlex.BuildGradleName,
			DisplayName:  "Gradle Build Script",
			Ecosystem:    "maven",
			Version:      1,
			Description:  "Extracts dependencies from build.gradle and build.gradle.kts files",
			FilePatterns: []string{"build.gradle", "build.gradle.kts"},
			Source:       inventoryv1.ExtractorSource_EXTRACTOR_SOURCE_DEPUTY,
		},
		{
			Name:         gradlex.GradleProjectName,
			DisplayName:  "Gradle Project",
			Ecosystem:    "maven",
			Version:      1,
			Description:  "Comprehensive Gradle project dependency extraction with version catalog and property resolution",
			FilePatterns: []string{"settings.gradle", "settings.gradle.kts"},
			Source:       inventoryv1.ExtractorSource_EXTRACTOR_SOURCE_DEPUTY,
		},
		{
			Name:         terraform.Name,
			DisplayName:  "Terraform Requirements",
			Ecosystem:    "terraform",
			Version:      1,
			Description:  "Extracts Terraform core and provider version requirements from .tf files",
			FilePatterns: []string{"*.tf", "*.tf.json"},
			Source:       inventoryv1.ExtractorSource_EXTRACTOR_SOURCE_DEPUTY,
		},
	}
}

// Discover finds extractor plugins in PATH matching "deputy-extractor-*".
// Returns a list of program names that can be registered.
func Discover() ([]string, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil, nil
	}

	var found []string
	seen := make(map[string]bool)

	for _, dir := range filepath.SplitList(pathEnv) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Skip directories we can't read
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasPrefix(name, "deputy-extractor-") {
				continue
			}
			if seen[name] {
				continue
			}

			// Verify it's executable
			path := filepath.Join(dir, name)
			if info, err := os.Stat(path); err == nil {
				// Check if executable (Unix: any execute bit set)
				if info.Mode()&0111 != 0 {
					seen[name] = true
					found = append(found, name)
				}
			}
		}
	}

	slices.Sort(found)
	return found, nil
}

// DiscoverAndRegister discovers plugins in PATH and registers them.
// Returns the names of successfully registered plugins.
func (r *Registry) DiscoverAndRegister(ctx context.Context) ([]string, error) {
	programs, err := Discover()
	if err != nil {
		return nil, err
	}

	var registered []string
	for _, prog := range programs {
		// Find the full path
		path, err := exec.LookPath(prog)
		if err != nil {
			continue
		}

		// Create a client to get the plugin info
		// Pass os.Stderr so plugin debug output is visible
		client, err := pluginclient.NewClient(ctx, path, pluginclient.WithStderr(os.Stderr))
		if err != nil {
			continue
		}

		info := client.ExtractorInfo()
		if info == nil {
			continue
		}

		// Convert to proto info
		protoInfo := &inventoryv1.ExtractorInfo{
			Name:         info.Name,
			DisplayName:  info.DisplayName,
			Ecosystem:    info.Ecosystem,
			Version:      info.Version,
			Description:  info.Description,
			FilePatterns: info.FilePatterns,
			Source:       inventoryv1.ExtractorSource_EXTRACTOR_SOURCE_PLUGIN,
		}

		// Register with the path as the "address"
		if err := r.Register(protoInfo, path); err != nil {
			continue
		}

		// Store the client for later use
		r.mu.Lock()
		if p, ok := r.plugins[info.Name]; ok {
			p.Client = client
		}
		r.mu.Unlock()

		registered = append(registered, info.Name)
	}

	return registered, nil
}

// Default is the global plugin registry.
var Default = New()

// Register adds a plugin to the default registry.
func Register(info *inventoryv1.ExtractorInfo, pluginAddress string) error {
	return Default.Register(info, pluginAddress)
}

// Unregister removes a plugin from the default registry.
func Unregister(name string) bool {
	return Default.Unregister(name)
}

// Get returns a registered plugin by name from the default registry.
func Get(name string) *RegisteredPlugin {
	return Default.Get(name)
}

// GetPlugins returns all registered plugins from the default registry.
func GetPlugins() []*RegisteredPlugin {
	return Default.GetPlugins()
}

// ListAll returns info for all extractors from the default registry.
func ListAll() []*inventoryv1.ExtractorInfo {
	return Default.ListAll()
}

// DiscoverAndRegister discovers and registers plugins using the default registry.
func DiscoverAndRegisterDefault(ctx context.Context) ([]string, error) {
	return Default.DiscoverAndRegister(ctx)
}
