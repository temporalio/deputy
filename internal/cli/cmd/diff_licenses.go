package cmd

import (
	"context"
	"crypto/x509"
	"strings"
	"sync"

	pb "deps.dev/api/v3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/temporalio/deputy/internal/cli/flags"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/license"
)

// licensePkgKey identifies a package version for license lookup dedup.
type licensePkgKey struct {
	ecosystem string
	name      string
	version   string
}

// licenseEcosystem normalizes a change's ecosystem for license lookups,
// defaulting to Go which is the only ecosystem the git diff currently emits.
func licenseEcosystem(raw string) string {
	eco := strings.ToLower(strings.TrimSpace(raw))
	if eco == "" {
		return "go"
	}
	return eco
}

// enrichChangeLicenses resolves license information for each non-removed
// change from the configured package metadata sources (deps.dev, registry
// lookups, or both) and returns the changes with Licenses populated.
//
// It runs before policy evaluation and output conversion, not at render
// time, so policies (e.g. a license allowlist over pkg.licenses), structured
// output, and the rendered report all see the same license data. Lookup
// failures degrade to an empty license list for that package, which policy
// reads as "no license declared" rather than as a license.
func enrichChangeLicenses(ctx context.Context, changes []compare.Change, licenseSource string) []compare.Change {
	if len(changes) == 0 {
		return changes
	}

	useDepsDev := licenseSource == flags.LicenseSourceDepsDev || licenseSource == flags.LicenseSourceBoth
	useScan := licenseSource == flags.LicenseSourceScan || licenseSource == flags.LicenseSourceBoth

	// Unique lookup targets: removed changes have no target version to license.
	targets := make(map[licensePkgKey]struct{})
	for _, c := range changes {
		if c.ChangeType == compare.Removed || c.TargetVersion == "" {
			continue
		}
		targets[licensePkgKey{ecosystem: licenseEcosystem(c.Ecosystem), name: c.Name, version: c.TargetVersion}] = struct{}{}
	}
	if len(targets) == 0 {
		return changes
	}

	// deps.dev lookups (best-effort; failures degrade gracefully).
	depsDevLicenses := map[licensePkgKey][]string{}
	if useDepsDev {
		if client := newDepsDevClient(ctx); client != nil {
			var mu sync.Mutex
			g, gctx := errgroup.WithContext(ctx)
			for pk := range targets {
				g.Go(func() error {
					l := license.FetchLicensesForEcosystem(gctx, depsClient{client}, pk.ecosystem, pk.name, pk.version)
					mu.Lock()
					depsDevLicenses[pk] = l
					mu.Unlock()
					return nil
				})
			}
			_ = g.Wait()
		}
	}

	// Registry lookups for the scan source. Repository-local license files
	// are deliberately not consulted here: they describe the analyzed
	// project, not its dependencies (the SBOM path attaches them to the
	// document root instead).
	remoteLicenses := map[licensePkgKey][]string{}
	if useScan {
		var mu sync.Mutex
		g := new(errgroup.Group)
		g.SetLimit(max(licenseScanConcurrency(len(targets)), 1))
		for pk := range targets {
			g.Go(func() error {
				l := license.LookupLicensesBestEffort(ctx, pk.ecosystem, pk.name, pk.version)
				mu.Lock()
				remoteLicenses[pk] = l
				mu.Unlock()
				return nil
			})
		}
		_ = g.Wait()
	}

	out := make([]compare.Change, len(changes))
	copy(out, changes)
	for i := range out {
		c := &out[i]
		if c.ChangeType == compare.Removed || c.TargetVersion == "" {
			continue
		}
		pk := licensePkgKey{ecosystem: licenseEcosystem(c.Ecosystem), name: c.Name, version: c.TargetVersion}
		licenses := depsDevLicenses[pk]
		if useScan {
			// Only package-specific lookups may populate a dependency's
			// licenses. Licenses discovered in the analyzed repository
			// describe that repository, not the things it depends on, and
			// attaching them here would make every dependency inherit the
			// scanned project's license. That is wrong on its own and, since
			// these values now feed policy evaluation, would let an
			// unknown-license rule pass for a dependency that declares
			// nothing.
			if rl := remoteLicenses[pk]; len(rl) > 0 {
				licenses = license.MergeLicenseSources(licenses, rl)
			}
		}
		c.Licenses = normalizeLicenseList(licenses)
	}
	return out
}

// normalizeLicenseList drops placeholder entries so unknown licenses stay an
// empty list in data (renderers decide how to show "unknown", policies see
// pkg.licenses.size() == 0).
func normalizeLicenseList(licenses []string) []string {
	out := licenses[:0:0]
	for _, l := range licenses {
		if l = strings.TrimSpace(l); l != "" && l != "?" {
			out = append(out, l)
		}
	}
	return out
}

// newDepsDevClient opens a best-effort deps.dev gRPC client tied to ctx.
// Returns nil when the system cert pool or connection setup fails; callers
// treat nil as "deps.dev unavailable".
func newDepsDevClient(ctx context.Context) pb.InsightsClient {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil
	}
	conn, err := grpc.NewClient("api.deps.dev:443", grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(certPool, "")))
	if err != nil {
		return nil
	}
	go func() { <-ctx.Done(); _ = conn.Close() }()
	return pb.NewInsightsClient(conn)
}
