package providers

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/internal/network"
	"github.com/picatz/deputy/internal/targets"
)

func init() {
	targets.RegisterProvider(containerRegistryProvider{})
}

// priorityContainerRegistry determines detection order relative to other providers.
// Container registries have priority 60, which is:
//   - Lower than specific container images (75) - prefer specific if it has a tag
//   - Higher than directories (50) - prefer registry if scheme matches
const priorityContainerRegistry = 60

// containerRegistryProvider implements [targets.CollectionProvider] for listing
// tags in a container repository.
//
// OCI Terminology:
//   - Registry: The server hosting container images (e.g., docker.io, ghcr.io, gcr.io)
//   - Repository: A named collection of related images within a registry (e.g., library/nginx, myorg/myapp)
//   - Tag: A mutable, human-readable pointer to a specific image manifest (e.g., latest, v1.0.0)
//   - Digest: An immutable, content-addressable identifier (e.g., sha256:abc123...)
//   - Reference: Either a tag or digest used to identify a specific image
//
// URI patterns (trailing slash indicates collection/repository):
//   - docker://gcr.io/project/myapp/     → list tags in repository gcr.io/project/myapp
//   - docker://ghcr.io/owner/repo/       → list tags in repository ghcr.io/owner/repo
//   - oci://registry.example.com/ns/     → list tags in repository registry.example.com/ns
//
// Note: This provider lists TAGS within a single repository, not repositories
// within a registry. The OCI Distribution spec doesn't define a standard API
// for listing repositories, only for listing tags within a repository.
type containerRegistryProvider struct{}

func (containerRegistryProvider) Priority() int { return priorityContainerRegistry }

// Detect returns true if the target looks like a container registry collection.
func (containerRegistryProvider) Detect(ctx context.Context, target string) bool {
	return isContainerRegistryCollection(target)
}

// isContainerRegistryCollection checks if a target is a repository collection URI.
// Collection URIs end with a trailing slash and don't have a tag or digest reference.
func isContainerRegistryCollection(target string) bool {
	// Must have docker:// or oci:// scheme
	scheme, rest, hasScheme := strings.Cut(target, "://")
	if !hasScheme {
		return false
	}
	scheme = strings.ToLower(scheme)
	if scheme != "docker" && scheme != "oci" && scheme != "container" {
		return false
	}

	// Collection URIs end with trailing slash
	if !strings.HasSuffix(rest, "/") {
		return false
	}

	// Remove trailing slash for validation
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		return false
	}

	// Must not have a tag or digest (those are specific targets)
	if strings.Contains(rest, ":") || strings.Contains(rest, "@") {
		return false
	}

	return true
}

// Open is not applicable for repository collections - this provider only lists tags.
// The containerImageProvider handles opening specific image references (tag or digest).
func (containerRegistryProvider) Open(ctx context.Context, target string, opts *targets.OpenOptions) (targets.Materialized, error) {
	return targets.Materialized{}, fmt.Errorf("cannot open registry collection %q directly; use List() to discover images, then Open() each image", target)
}

// IsCollection returns true if the target is a repository collection URI.
func (containerRegistryProvider) IsCollection(ctx context.Context, target string) bool {
	return isContainerRegistryCollection(target)
}

// List enumerates tags in a container repository.
//
// Performance note: This implementation fetches all tags from the registry,
// then applies client-side pagination. For repositories with thousands of tags,
// consider using tag prefix filters or caching the results.
func (p containerRegistryProvider) List(ctx context.Context, target string, opts *targets.ListOptions) (*targets.ListResult, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list registry tags: %w", err)
	}

	// Parse the registry path from the URI
	repoPath, err := parseRegistryCollectionTarget(target)
	if err != nil {
		return nil, fmt.Errorf("parse registry target: %w", err)
	}

	// Build remote options for authentication
	remoteOpts := buildRegistryListOptions(ctx)

	// List tags in the repository
	tags, err := listRepositoryTags(ctx, repoPath, remoteOpts)
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}

	// Sort tags for consistent pagination
	sort.Strings(tags)

	// Apply pagination
	pageSize := int(opts.PageSize)
	if pageSize <= 0 {
		pageSize = 100 // default
	}
	if pageSize > 1000 {
		pageSize = 1000 // max
	}

	// Cursor-based pagination using page token (tag name)
	startIdx := 0
	if opts.PageToken != "" {
		for i, tag := range tags {
			if tag == opts.PageToken {
				startIdx = i + 1
				break
			}
		}
	}

	// Slice the results
	endIdx := startIdx + pageSize
	if endIdx > len(tags) {
		endIdx = len(tags)
	}
	pageTags := tags[startIdx:endIdx]

	// Check context before metadata fetching
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list registry tags: %w", err)
	}

	// Fetch metadata concurrently for better performance
	results := make([]*listv1.DiscoveredTarget, len(pageTags))
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(10) // Limit concurrent requests to avoid overwhelming registries

	for i, tag := range pageTags {
		i, tag := i, tag // capture loop vars
		g.Go(func() error {
			// Check context in each goroutine
			if err := gCtx.Err(); err != nil {
				return err
			}

			imageRef := fmt.Sprintf("%s:%s", repoPath, tag)
			uri := fmt.Sprintf("docker://%s", imageRef)

			dt := &listv1.DiscoveredTarget{
				Uri:  uri,
				Name: tag,
				Metadata: map[string]string{
					"repository": repoPath,
					"tag":        tag,
				},
			}

			// Try to get additional metadata (digest, created time)
			// This is optional and may fail for some registries
			if digest, created, err := getTagMetadata(gCtx, imageRef, remoteOpts); err == nil {
				if digest != "" {
					dt.Metadata["digest"] = digest
				}
				if !created.IsZero() {
					dt.CreatedAt = timestamppb.New(created)
				}
			}

			results[i] = dt
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("fetch tag metadata: %w", err)
	}

	// Calculate next page token
	var nextPageToken string
	if endIdx < len(tags) {
		// Use the last tag in this page as the cursor for the next page
		nextPageToken = pageTags[len(pageTags)-1]
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// parseRegistryCollectionTarget extracts the repository name from a collection URI.
// Returns the fully-qualified repository name (e.g., "gcr.io/project/repo").
func parseRegistryCollectionTarget(target string) (string, error) {
	// Remove scheme
	_, rest, _ := strings.Cut(target, "://")

	// Remove leading slash if present (docker:///path → path)
	rest = strings.TrimPrefix(rest, "/")

	// Remove trailing slash (collection indicator)
	rest = strings.TrimSuffix(rest, "/")

	if rest == "" {
		return "", fmt.Errorf("empty registry path")
	}

	// Validate by parsing as a repository reference
	repo, err := name.NewRepository(rest, name.WeakValidation)
	if err != nil {
		return "", fmt.Errorf("invalid repository %q: %w", rest, err)
	}

	return repo.Name(), nil
}

// buildRegistryListOptions creates remote options for OCI registry API operations.
// Uses the enhanced RegistryKeychain which provides:
//   - Direct AWS ECR authentication (no credential helper needed)
//   - Automatic GITHUB_TOKEN detection for GHCR
//   - Credential caching for improved performance
//   - Fallback to docker config for other registries
func buildRegistryListOptions(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithTransport(network.SafeTransport()),
		remote.WithAuthFromKeychain(GetRegistryKeychain()),
		remote.WithContext(ctx),
		remote.WithRetryBackoff(remote.Backoff{
			Duration: 1 * time.Second,
			Factor:   2.0,
			Jitter:   0.1,
			Steps:    5, // Increased retries for rate-limited registries
		}),
		remote.WithRetryStatusCodes(
			http.StatusRequestTimeout,
			http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout,
		),
	}
}

// listRepositoryTags lists all tags in a repository using the OCI Distribution API.
func listRepositoryTags(ctx context.Context, repoPath string, remoteOpts []remote.Option) ([]string, error) {
	repo, err := name.NewRepository(repoPath, name.WeakValidation)
	if err != nil {
		return nil, fmt.Errorf("parse repository: %w", err)
	}

	tags, err := remote.List(repo, remoteOpts...)
	if err != nil {
		return nil, wrapRegistryListError(err, repoPath)
	}

	return tags, nil
}

// getTagMetadata fetches additional metadata for a tagged image reference.
// Returns the manifest digest and the image creation timestamp (if available).
func getTagMetadata(ctx context.Context, imageRef string, remoteOpts []remote.Option) (string, time.Time, error) {
	ref, err := name.ParseReference(imageRef, name.WeakValidation)
	if err != nil {
		return "", time.Time{}, err
	}

	desc, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return "", time.Time{}, err
	}

	digest := desc.Digest.String()

	// Try to get the created time from the image config
	var created time.Time
	img, err := desc.Image()
	if err == nil {
		if cfg, err := img.ConfigFile(); err == nil && cfg != nil {
			created = cfg.Created.Time
		}
	}

	return digest, created, nil
}

// wrapRegistryListError provides registry-specific error messages with actionable hints.
// Delegates to the enhanced wrapRegistryListErrorWithContext function which detects the
// registry type and provides tailored guidance for ECR, GHCR, Docker Hub, GCR, ACR, etc.
func wrapRegistryListError(err error, repoPath string) error {
	return wrapRegistryListErrorWithContext(err, repoPath)
}

var _ targets.Provider = (*containerRegistryProvider)(nil)
var _ targets.PriorityProvider = (*containerRegistryProvider)(nil)
var _ targets.CollectionProvider = (*containerRegistryProvider)(nil)
