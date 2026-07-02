package advisorysource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	"github.com/temporalio/deputy/gen/deputy/plugin/v1/pluginv1pluginrpc"
	"pluginrpc.com/pluginrpc"
)

// PluginProgramPrefix is the executable-name prefix Deputy discovers advisory
// source plugins by (e.g. "deputy-advisory-source-ghsa").
const PluginProgramPrefix = "deputy-advisory-source-"

// pluginSource adapts an external AdvisorySourceService plugin to the in-process
// Source interface. It is the parity anchor: a subprocess plugin is
// indistinguishable from the built-in OSV source to the Registry.
type pluginSource struct {
	programName string
	client      pluginv1pluginrpc.AdvisorySourceServiceClient
	info        *pluginv1.AdvisorySourceInfo
}

// PluginOption configures a plugin source.
type PluginOption func(*pluginOptions)

type pluginOptions struct {
	stderr io.Writer
}

// WithPluginStderr routes plugin stderr (useful for debugging plugins).
func WithPluginStderr(w io.Writer) PluginOption {
	return func(o *pluginOptions) { o.stderr = w }
}

// NewPluginSource starts (lazily, per call) the advisory-source plugin named by
// programName and returns it as a Source. It calls Info once to cache the
// plugin's declared capabilities for routing.
func NewPluginSource(ctx context.Context, programName string, opts ...PluginOption) (Source, error) {
	options := &pluginOptions{stderr: io.Discard}
	for _, opt := range opts {
		opt(options)
	}

	runner := pluginrpc.NewExecRunner(programName)
	prpcClient := pluginrpc.NewClient(runner, pluginrpc.ClientWithStderr(options.stderr))
	serviceClient, err := pluginv1pluginrpc.NewAdvisorySourceServiceClient(prpcClient)
	if err != nil {
		return nil, fmt.Errorf("create advisory source client for %s: %w", programName, err)
	}

	src := &pluginSource{programName: programName, client: serviceClient}
	resp, err := serviceClient.Info(ctx, &pluginv1.AdvisorySourceInfoRequest{})
	if err != nil {
		return nil, fmt.Errorf("advisory source %s Info: %w", programName, err)
	}
	src.info = resp.GetInfo()
	if src.info == nil {
		return nil, fmt.Errorf("advisory source %s returned no info", programName)
	}
	return src, nil
}

// Info returns the plugin's cached capability descriptor.
func (p *pluginSource) Info() *pluginv1.AdvisorySourceInfo { return p.info }

// Query sends the covered packages to the plugin and returns its proto findings
// verbatim — no conversion, because the plugin speaks exactly the aggregator's
// types — stamping the plugin's name as provenance on each finding.
func (p *pluginSource) Query(ctx context.Context, pkgs []*dependencyv1.Package) (*Result, error) {
	resp, err := p.client.Query(ctx, &pluginv1.AdvisoryQueryRequest{Packages: pkgs})
	if err != nil {
		return nil, fmt.Errorf("advisory source %s Query: %w", p.programName, err)
	}
	name := p.info.GetName()
	for _, f := range resp.GetFindings() {
		if f != nil {
			f.Sources = unionStrings(f.GetSources(), []string{name})
		}
	}
	return &Result{Findings: resp.GetFindings(), Advisories: resp.GetAdvisories()}, nil
}

// LoadPluginSources starts each named advisory-source plugin and returns the
// ones that came up, along with a joined error describing any that failed. A
// plugin that fails to start is skipped, not fatal, so one broken plugin cannot
// take down discovery of the others.
func LoadPluginSources(ctx context.Context, programNames []string, opts ...PluginOption) ([]Source, error) {
	var sources []Source
	var errs []error
	for _, name := range programNames {
		src, err := NewPluginSource(ctx, name, opts...)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sources = append(sources, src)
	}
	return sources, errors.Join(errs...)
}

// DiscoverPluginPrograms returns advisory-source plugin program names found on
// PATH (executables named deputy-advisory-source-*). Discovery is best-effort;
// callers pass the results to NewPluginSource and add them to a Registry.
func DiscoverPluginPrograms() ([]string, error) {
	dirs := strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))
	seen := map[string]bool{}
	var found []string
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // unreadable PATH element is not fatal
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, PluginProgramPrefix) || seen[name] {
				continue
			}
			if info, err := e.Info(); err == nil && info.Mode()&0o111 != 0 {
				seen[name] = true
				found = append(found, name)
			}
		}
	}
	return found, nil
}
