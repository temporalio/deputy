package advisorysource

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
)

// SourceConfig declares an external advisory source to aggregate with the
// built-in OSV source. Exactly one of Program or URL must be set: Program names
// a pluginrpc plugin executable (PATH-resolved name or path), URL is the base
// URL of a ConnectRPC AdvisorySourceService (a persistent local sidecar or
// shared remote service).
type SourceConfig struct {
	Program string
	URL     string
}

// key identifies a config for deduplication across config file and env.
func (c SourceConfig) key() string { return c.Program + "\x00" + c.URL }

var (
	configuredMu      sync.RWMutex
	configuredSources []SourceConfig
)

// SetConfiguredSources replaces the process-wide declarative list of external
// advisory sources, typically from the config file at CLI startup. Sources are
// materialized lazily when a default registry is built for a scan, so commands
// that never query advisories pay no plugin or network cost. Entries from the
// DEPUTY_ADVISORY_SOURCES environment variable are unioned in at
// materialization time.
func SetConfiguredSources(cfgs []SourceConfig) {
	configuredMu.Lock()
	defer configuredMu.Unlock()
	configuredSources = slices.Clone(cfgs)
}

// allSourceConfigs returns the declared configs plus env-var program entries,
// deduplicated in declaration order.
func allSourceConfigs() []SourceConfig {
	configuredMu.RLock()
	cfgs := slices.Clone(configuredSources)
	configuredMu.RUnlock()

	for _, program := range parseProgramList(os.Getenv(EnvAdvisorySources)) {
		cfgs = append(cfgs, SourceConfig{Program: program})
	}

	seen := make(map[string]bool, len(cfgs))
	out := make([]SourceConfig, 0, len(cfgs))
	for _, c := range cfgs {
		if seen[c.key()] {
			continue
		}
		seen[c.key()] = true
		out = append(out, c)
	}
	return out
}

// materializeSources constructs Sources from declarative configs. A source
// that fails to load (or an invalid config) is skipped and reported in the
// joined error, so one broken source cannot fail the scan; the coverage report
// then reflects which sources actually answered.
func materializeSources(ctx context.Context, cfgs []SourceConfig) ([]Source, error) {
	var sources []Source
	var errs []error
	for _, c := range cfgs {
		switch {
		case c.Program != "" && c.URL != "":
			errs = append(errs, fmt.Errorf("advisory source config: set exactly one of program or url, got both (%q, %q)", c.Program, c.URL))
		case c.Program != "":
			src, err := NewPluginSource(ctx, c.Program)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			sources = append(sources, src)
		case c.URL != "":
			src, err := NewConnectSource(ctx, c.URL)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			sources = append(sources, src)
		default:
			errs = append(errs, errors.New("advisory source config: set exactly one of program or url, got neither"))
		}
	}
	return sources, errors.Join(errs...)
}
