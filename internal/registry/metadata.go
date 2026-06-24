// Package registry fetches registry-sourced metadata about specific package
// versions from deps.dev and exposes it as policy signals.
//
// The metadata it surfaces — when a version was published — is the kind of
// supply-chain signal a known-vulnerability scan cannot see: a freshly published
// version has had no time to be vetted and is a common shape for a malicious
// release, well before any CVE is assigned. Deputy stays self-contained here;
// everything is fetched from the deps.dev Insights API it already depends on.
package registry

import (
	"context"
	"fmt"
	"strings"
	"time"

	pb "deps.dev/api/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	"github.com/temporalio/deputy/internal/cache/memory"
)

const (
	// depsDevEndpoint is the gRPC endpoint for the deps.dev Insights API.
	depsDevEndpoint = "api.deps.dev:443"

	// defaultCacheSize bounds the number of cached version-metadata responses.
	defaultCacheSize = 4096

	// defaultCacheTTL is how long cached responses remain valid. A version's
	// publish date is immutable once released, so a long TTL is safe.
	defaultCacheTTL = 1 * time.Hour
)

// Metadata is the registry-sourced view of a single package version.
type Metadata struct {
	// PublishedAt is when the version was published to its registry. The zero
	// value means deps.dev had no publish date for the version.
	PublishedAt time.Time
	// Registries lists the registries deps.dev reports as hosting the version.
	Registries []string
}

// ToProto converts the metadata to its policy-input proto representation,
// computing age relative to now. It returns nil for a nil receiver so callers
// can pass through "no metadata" without branching.
func (m *Metadata) ToProto(now time.Time) *diffv1.RegistryMetadata {
	if m == nil {
		return nil
	}
	out := &diffv1.RegistryMetadata{
		Registries: m.Registries,
		AgeDays:    -1,
	}
	if !m.PublishedAt.IsZero() {
		out.PublishedAt = timestamppb.New(m.PublishedAt)
		out.AgeDays = now.Sub(m.PublishedAt).Hours() / 24
	}
	return out
}

// Fetcher retrieves version metadata from deps.dev. It is safe for concurrent
// use. Construct it with NewFetcher and Close it when done.
type Fetcher struct {
	client pb.InsightsClient
	conn   *grpc.ClientConn
	cache  *memory.TTLCache[string, *Metadata]
}

// NewFetcher dials deps.dev and returns a ready-to-use Fetcher.
func NewFetcher() (*Fetcher, error) {
	creds := credentials.NewClientTLSFromCert(nil, "")
	conn, err := grpc.NewClient(depsDevEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("connecting to deps.dev: %w", err)
	}
	return &Fetcher{
		client: pb.NewInsightsClient(conn),
		conn:   conn,
		cache:  memory.NewTTLCache[string, *Metadata](defaultCacheSize, defaultCacheTTL),
	}, nil
}

// Close releases the underlying gRPC connection.
func (f *Fetcher) Close() error {
	if f == nil || f.conn == nil {
		return nil
	}
	return f.conn.Close()
}

// Fetch returns registry metadata for the given package version. It returns
// (nil, nil) when the ecosystem is not supported by deps.dev or the coordinates
// are incomplete, so callers can treat "no metadata" uniformly. Network and
// lookup errors are returned so callers can decide whether to degrade.
func (f *Fetcher) Fetch(ctx context.Context, ecosystem, name, version string) (*Metadata, error) {
	system := systemFromEcosystem(ecosystem)
	if system == pb.System_SYSTEM_UNSPECIFIED {
		return nil, nil
	}
	name = strings.TrimSpace(name)
	version = normalizeVersion(system, version)
	if name == "" || version == "" {
		return nil, nil
	}

	cacheKey := fmt.Sprintf("%s/%s@%s", system, name, version)
	if m, ok := f.cache.Get(cacheKey); ok {
		return m, nil
	}

	resp, err := f.client.GetVersion(ctx, &pb.GetVersionRequest{
		VersionKey: &pb.VersionKey{System: system, Name: name, Version: version},
	})
	if err != nil {
		return nil, fmt.Errorf("deps.dev GetVersion %s: %w", cacheKey, err)
	}

	m := metadataFromVersion(resp)
	f.cache.Set(cacheKey, m)
	return m, nil
}

// metadataFromVersion extracts the fields we expose from a deps.dev version
// response. It is pure so it can be unit tested without a network round-trip.
func metadataFromVersion(v *pb.Version) *Metadata {
	if v == nil {
		return nil
	}
	m := &Metadata{Registries: v.GetRegistries()}
	if ts := v.GetPublishedAt(); ts != nil {
		m.PublishedAt = ts.AsTime()
	}
	return m
}

// systemFromEcosystem maps a free-form ecosystem string to a deps.dev system,
// returning SYSTEM_UNSPECIFIED for ecosystems deps.dev does not cover.
func systemFromEcosystem(ecosystem string) pb.System {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "go", "golang":
		return pb.System_GO
	case "npm", "javascript", "node", "nodejs":
		return pb.System_NPM
	case "cargo", "rust", "crates", "crates.io":
		return pb.System_CARGO
	case "maven", "java":
		return pb.System_MAVEN
	case "pypi", "python":
		return pb.System_PYPI
	case "nuget", "dotnet", ".net":
		return pb.System_NUGET
	case "rubygems", "ruby", "gem":
		return pb.System_RUBYGEMS
	default:
		return pb.System_SYSTEM_UNSPECIFIED
	}
}

// normalizeVersion applies the version normalization deps.dev expects, notably
// the leading "v" that Go module versions carry.
func normalizeVersion(system pb.System, version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return ""
	}
	if system == pb.System_GO && !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}
