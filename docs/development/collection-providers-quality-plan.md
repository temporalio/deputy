# Collection Providers Quality Plan

This document outlines the quality improvements needed for the container registry and GitHub org collection providers. These providers enable `deputy list` to enumerate targets from external sources (container image tags from registries, repositories from GitHub organizations).

## Current State Assessment

### What's Working Well

**Container Registry Provider (`internal/targets/providers/container_registry.go`)**

1. **Clean URI detection** - Correctly identifies collection URIs with trailing slash (`docker://gcr.io/project/`)
2. **Multi-scheme support** - Handles `docker://`, `oci://`, and `container://` schemes
3. **Authentication** - Uses enhanced `RegistryKeychain` with AWS ECR, GHCR, and Docker config support
4. **Retry logic** - Implements exponential backoff for rate-limited registries with appropriate status codes
5. **Metadata enrichment** - Fetches digest and creation time for each tag
6. **Error wrapping** - Provides registry-specific error messages with actionable hints
7. **Interface compliance** - Correctly implements `Provider`, `PriorityProvider`, and `CollectionProvider`
8. **Test coverage** - Good unit tests for detection and parsing logic

**GitHub Org Provider (`internal/targets/providers/github_org.go`)**

1. **Flexible URI parsing** - Supports `github://org/`, `github.com/org/`, and `https://github.com/org/`
2. **Org/user fallback** - Tries organization API first, falls back to user API on 404
3. **Rich metadata** - Returns comprehensive repo info (language, stars, archived, fork, topics, visibility)
4. **Token authentication** - Uses `GITHUB_TOKEN` environment variable
5. **Error handling** - Provides helpful messages for rate limits, auth failures, and not found
6. **Options structure** - `GitHubListOptions` defines filtering options (forks, archived, type)
7. **Interface compliance** - Correctly implements all required interfaces
8. **Test coverage** - Good unit tests for detection, parsing, and options

### What's Missing or Broken

**Critical Issues**

1. **`next_page_token` never wired in responses** - Both providers calculate pagination internally but never return the token. The `ListPackagesResponse.NextPageToken` field is always empty, making pagination completely broken for API consumers.

2. **`GitHubListOptions` never applied** - The `parseGitHubListOptions()` function exists and is tested, but `List()` never calls it. The `include_forks`, `include_archived`, and `type` options have no effect.

3. **Documentation gaps** - `docs/commands/list.md` has AWS collection examples but no container registry or GitHub org examples.

**Production Readiness Gaps**

4. **No GitHub rate limit headers** - Provider doesn't inspect `X-RateLimit-Remaining` or `X-RateLimit-Reset` headers for proactive backoff

5. **No integration tests** - Only unit tests exist; no tests that actually call registries or GitHub API (even as skippable tests)

6. **Container registry fetches all tags first** - `remote.List()` returns all tags, then provider slices for pagination. Large repositories (1000+ tags) will be slow and memory-intensive.

7. **Sequential metadata fetching** - Container registry fetches digest/created time for each tag sequentially, making large result sets slow

**Nice-to-Have Improvements**

8. **No response caching** - Repeated list calls always hit the API

9. **No progress indicators** - Large collections provide no feedback during enumeration

10. **Duplicate listing calls** - The handler applies CEL filter after provider returns, meaning filtered-out items still consumed API quota

---

## Priority 1: Critical Fixes (Must Have)

### 1. Wire `next_page_token` in responses

**Problem**: Pagination is completely broken. Providers calculate pagination internally but the response `NextPageToken` field is always empty.

**Files to modify**:
- `internal/targets/providers/container_registry.go`
- `internal/targets/providers/github_org.go`
- `internal/targets/targets.go` (potentially add return value)
- `internal/server/list_handler.go`

**Changes needed**:

Option A: Return token from provider (recommended):
```go
// targets.go - Update CollectionProvider interface
type CollectionProvider interface {
    Provider
    IsCollection(ctx context.Context, target string) bool
    // List now returns targets and next page token
    List(ctx context.Context, target string, opts *ListOptions) ([]*listv1.DiscoveredTarget, string, error)
}
```

Option B: Use a result struct:
```go
type ListResult struct {
    Targets       []*listv1.DiscoveredTarget
    NextPageToken string
}
```

For container registry:
```go
// Return next_page_token when there are more results
func (p containerRegistryProvider) List(...) ([]*listv1.DiscoveredTarget, string, error) {
    // ... existing code ...

    // Calculate next page token
    var nextToken string
    if endIdx < len(tags) {
        nextToken = pageTags[len(pageTags)-1] // Last tag as cursor
    }

    return results, nextToken, nil
}
```

For GitHub org:
```go
// Use GitHub's pagination response
func (p githubOrgProvider) List(...) ([]*listv1.DiscoveredTarget, string, error) {
    // ... existing code ...

    var nextToken string
    if resp.NextPage > 0 {
        nextToken = fmt.Sprintf("%d", resp.NextPage)
    }

    return results, nextToken, nil
}
```

**Test requirements**:
- Unit test: Verify next_page_token is set when more results exist
- Unit test: Verify next_page_token is empty on last page
- Integration test: Paginate through a real collection end-to-end

---

### 2. Apply `GitHubListOptions` in List function

**Problem**: `GitHubListOptions` is defined and parsed but never used. Users cannot filter out forks or archived repos.

**File to modify**: `internal/targets/providers/github_org.go`

**Changes needed**:

```go
func (p githubOrgProvider) List(ctx context.Context, target string, opts *targets.ListOptions) ([]*listv1.DiscoveredTarget, error) {
    // ... existing parsing code ...

    // Parse GitHub-specific options
    ghOpts := parseGitHubListOptions(opts)

    // Apply type filter to API call
    listOpts := &github.RepositoryListByOrgOptions{
        Type: ghOpts.Type, // Use parsed type instead of hardcoded "all"
        ListOptions: github.ListOptions{
            PerPage: pageSize,
            Page:    page,
        },
    }

    // ... API call ...

    // Filter results based on options
    results := make([]*listv1.DiscoveredTarget, 0, len(repos))
    for _, repo := range repos {
        if repo == nil {
            continue
        }

        // Skip forks if not included
        if !ghOpts.IncludeForks && repo.GetFork() {
            continue
        }

        // Skip archived if not included
        if !ghOpts.IncludeArchived && repo.GetArchived() {
            continue
        }

        // ... build discovered target ...
    }

    return results, nil
}
```

**Test requirements**:
- Unit test: Verify `include_forks=false` excludes forked repos
- Unit test: Verify `include_archived=false` excludes archived repos
- Unit test: Verify `type=public` only returns public repos

---

### 3. Update documentation with collection provider examples

**Problem**: `docs/commands/list.md` has AWS examples but no container registry or GitHub org examples.

**File to modify**: `docs/commands/list.md`

**Changes needed**: Add new sections after AWS examples:

```markdown
### Container Registry Collections

List tags in a container repository:

```console
# List all tags in a GCR repository
$ deputy list docker://gcr.io/myproject/myapp/

# List tags in GHCR
$ deputy list docker://ghcr.io/myorg/myimage/

# List tags in ECR (uses AWS credentials)
$ deputy list docker://123456789012.dkr.ecr.us-west-2.amazonaws.com/myrepo/

# List with pagination
$ deputy list docker://gcr.io/myproject/myapp/ --page-size 50

# JSON output for scripting
$ deputy list docker://gcr.io/myproject/myapp/ -f json | jq -r '.targets[].uri'
```

Note: The trailing slash indicates a collection (list tags). Without the trailing slash, Deputy treats it as a specific image reference.

### GitHub Organization Collections

List repositories in a GitHub organization or user namespace:

```console
# List repos in an organization
$ deputy list github://kubernetes/

# List repos for a user
$ deputy list github://torvalds/

# Alternative URL formats
$ deputy list github.com/hashicorp/
$ deputy list https://github.com/docker/

# JSON output with metadata
$ deputy list github://golang/ -f json | jq '.targets[] | {name, stars: .metadata.stars}'
```

Authentication: Set `GITHUB_TOKEN` environment variable for higher rate limits and access to private repos.

### Pipeline: Scan All Tags in a Repository

```console
# List tags and scan each one
$ deputy list docker://gcr.io/myproject/myapp/ -f json | \
    jq -r '.targets[].uri' | \
    xargs -I{} deputy scan {}

# Scan latest 5 tags
$ deputy list docker://gcr.io/myproject/myapp/ --page-size 5 -f json | \
    jq -r '.targets[].uri' | \
    xargs -P4 -I{} deputy scan {} --format json
```
```

**Test requirements**:
- Manual verification that examples work
- Consider adding doc tests or example validation

---

## Priority 2: Production Hardening (Should Have)

### 4. GitHub rate limiting improvements

**Problem**: Provider only handles rate limit errors reactively. It should proactively respect rate limit headers.

**File to modify**: `internal/targets/providers/github_org.go`

**Changes needed**:

```go
import "strconv"

// checkRateLimit inspects response headers and waits if approaching limit
func checkRateLimit(resp *github.Response) error {
    if resp == nil {
        return nil
    }

    remaining := resp.Rate.Remaining
    resetTime := resp.Rate.Reset.Time

    // Log rate limit state for observability
    if remaining < 100 {
        slog.Warn("GitHub rate limit low",
            "remaining", remaining,
            "reset", resetTime)
    }

    // If exhausted, return error with reset time
    if remaining == 0 {
        waitDuration := time.Until(resetTime)
        return fmt.Errorf("rate limit exhausted, resets in %v", waitDuration)
    }

    return nil
}

// In List function, after API call:
repos, resp, err := client.Repositories.ListByOrg(ctx, owner, listOpts)
if err != nil {
    // Handle 403 with exponential backoff
    if ghErr, ok := err.(*github.ErrorResponse); ok {
        if ghErr.Response.StatusCode == http.StatusForbidden {
            // Check if it's rate limiting vs other 403
            if strings.Contains(ghErr.Message, "rate limit") {
                // Could implement retry with backoff here
            }
        }
    }
    // ... existing error handling ...
}
if err := checkRateLimit(resp); err != nil {
    return nil, err
}
```

**Test requirements**:
- Unit test: Verify rate limit warning is logged when remaining < 100
- Unit test: Verify error returned when remaining == 0
- Mock test: Verify exponential backoff on 403 rate limit error

---

### 5. Integration tests

**Problem**: No tests verify actual API behavior. Unit tests only cover detection and parsing.

**Files to create**:
- `internal/targets/providers/container_registry_integration_test.go`
- `internal/targets/providers/github_org_integration_test.go`

**Changes needed**:

```go
// container_registry_integration_test.go
//go:build integration

package providers

import (
    "context"
    "os"
    "testing"

    "github.com/picatz/deputy/internal/targets"
)

func TestContainerRegistryProvider_List_Integration(t *testing.T) {
    if os.Getenv("DEPUTY_INTEGRATION_TESTS") == "" {
        t.Skip("Set DEPUTY_INTEGRATION_TESTS=1 to run integration tests")
    }

    ctx := context.Background()
    provider := containerRegistryProvider{}

    // Test with public Docker Hub library
    opts := &targets.ListOptions{PageSize: 10}
    results, err := provider.List(ctx, "docker://library/alpine/", opts)
    if err != nil {
        t.Fatalf("List failed: %v", err)
    }

    if len(results) == 0 {
        t.Error("Expected at least one tag")
    }

    // Verify pagination
    if len(results) > 10 {
        t.Errorf("Expected at most 10 results, got %d", len(results))
    }

    // Verify metadata
    for _, r := range results {
        if r.Uri == "" {
            t.Error("Expected non-empty URI")
        }
        if r.Metadata["tag"] == "" {
            t.Error("Expected tag in metadata")
        }
    }
}

func TestContainerRegistryProvider_Pagination_Integration(t *testing.T) {
    if os.Getenv("DEPUTY_INTEGRATION_TESTS") == "" {
        t.Skip("Set DEPUTY_INTEGRATION_TESTS=1 to run integration tests")
    }

    ctx := context.Background()
    provider := containerRegistryProvider{}

    // First page
    opts := &targets.ListOptions{PageSize: 5}
    page1, token1, err := provider.List(ctx, "docker://library/alpine/", opts)
    if err != nil {
        t.Fatalf("First page failed: %v", err)
    }

    if token1 == "" {
        t.Skip("Only one page of results, cannot test pagination")
    }

    // Second page
    opts.PageToken = token1
    page2, _, err := provider.List(ctx, "docker://library/alpine/", opts)
    if err != nil {
        t.Fatalf("Second page failed: %v", err)
    }

    // Verify no overlap
    page1URIs := make(map[string]bool)
    for _, r := range page1 {
        page1URIs[r.Uri] = true
    }
    for _, r := range page2 {
        if page1URIs[r.Uri] {
            t.Errorf("Duplicate result across pages: %s", r.Uri)
        }
    }
}
```

```go
// github_org_integration_test.go
//go:build integration

package providers

import (
    "context"
    "os"
    "testing"

    "github.com/picatz/deputy/internal/targets"
)

func TestGitHubOrgProvider_List_Integration(t *testing.T) {
    if os.Getenv("DEPUTY_INTEGRATION_TESTS") == "" {
        t.Skip("Set DEPUTY_INTEGRATION_TESTS=1 to run integration tests")
    }

    ctx := context.Background()
    provider := githubOrgProvider{}

    // Test with a known public org
    opts := &targets.ListOptions{PageSize: 5}
    results, err := provider.List(ctx, "github://golang/", opts)
    if err != nil {
        t.Fatalf("List failed: %v", err)
    }

    if len(results) == 0 {
        t.Error("Expected at least one repository")
    }

    // Verify metadata
    for _, r := range results {
        if r.Uri == "" {
            t.Error("Expected non-empty URI")
        }
        if r.Metadata["owner"] != "golang" {
            t.Errorf("Expected owner=golang, got %s", r.Metadata["owner"])
        }
    }
}

func TestGitHubOrgProvider_Filtering_Integration(t *testing.T) {
    if os.Getenv("DEPUTY_INTEGRATION_TESTS") == "" {
        t.Skip("Set DEPUTY_INTEGRATION_TESTS=1 to run integration tests")
    }

    ctx := context.Background()
    provider := githubOrgProvider{}

    // List with fork filtering disabled
    opts := &targets.ListOptions{
        PageSize: 100,
        Context: &targets.ProviderContext{
            Extra: map[string]string{
                "include_forks": "false",
            },
        },
    }

    results, err := provider.List(ctx, "github://golang/", opts)
    if err != nil {
        t.Fatalf("List failed: %v", err)
    }

    // Verify no forks in results
    for _, r := range results {
        if r.Metadata["fork"] == "true" {
            t.Errorf("Found fork in results when include_forks=false: %s", r.Uri)
        }
    }
}
```

**Test requirements**:
- Tests should be skippable without credentials
- Tests should use known public resources (Docker Hub library, golang org)
- Tests should verify both success paths and pagination

---

### 6. Container registry pagination optimization

**Problem**: `remote.List()` fetches all tags at once, then provider slices. For repositories with 1000+ tags, this wastes memory and time.

**File to modify**: `internal/targets/providers/container_registry.go`

**Analysis**: The OCI Distribution API supports pagination via `Link` headers, but `go-containerregistry`'s `remote.List()` doesn't expose this. Options:

1. **Accept current behavior** - Document the limitation; most repos have <1000 tags
2. **Implement custom tag listing** - Use `remote.Catalog` or raw HTTP with pagination
3. **Use `remote.ListWithContext`** - Check if this supports streaming/pagination

**Recommended approach**: For now, document the limitation and add caching (Priority 3). If users report performance issues, implement custom tag listing.

**Changes needed** (documentation):

Add comment to `List` function:
```go
// List enumerates tags in a container repository.
//
// Performance note: This implementation fetches all tags from the registry,
// then applies client-side pagination. For repositories with thousands of tags,
// consider using tag prefix filters or caching the results.
func (p containerRegistryProvider) List(...) { ... }
```

---

## Priority 3: Nice to Have (Could Have)

### 7. Response caching

**Problem**: Repeated list calls always hit the API, wasting quota and adding latency.

**Files to modify**:
- Create `internal/targets/providers/cache.go`
- Modify both provider files

**Changes needed**:

```go
// cache.go
package providers

import (
    "sync"
    "time"

    listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
)

type cacheEntry struct {
    targets   []*listv1.DiscoveredTarget
    nextToken string
    expiresAt time.Time
}

type listCache struct {
    mu      sync.RWMutex
    entries map[string]cacheEntry
    ttl     time.Duration
}

func newListCache(ttl time.Duration) *listCache {
    return &listCache{
        entries: make(map[string]cacheEntry),
        ttl:     ttl,
    }
}

func (c *listCache) Get(key string) ([]*listv1.DiscoveredTarget, string, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    entry, ok := c.entries[key]
    if !ok || time.Now().After(entry.expiresAt) {
        return nil, "", false
    }
    return entry.targets, entry.nextToken, true
}

func (c *listCache) Set(key string, targets []*listv1.DiscoveredTarget, nextToken string) {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.entries[key] = cacheEntry{
        targets:   targets,
        nextToken: nextToken,
        expiresAt: time.Now().Add(c.ttl),
    }
}

// cacheKey generates a cache key from target and options
func cacheKey(target string, opts *targets.ListOptions) string {
    // Include pagination params in key
    return fmt.Sprintf("%s|%d|%s", target, opts.PageSize, opts.PageToken)
}
```

**Test requirements**:
- Unit test: Verify cache hit returns cached data
- Unit test: Verify cache miss calls provider
- Unit test: Verify expired entries are refreshed

---

### 8. Progress indicators

**Problem**: Large collections provide no feedback during enumeration.

**Files to modify**:
- `internal/targets/options.go`
- Both provider files
- `internal/cli/cmd/list.go`

**Changes needed**:

```go
// options.go - Add progress callback
type ListOptions struct {
    // ... existing fields ...

    // OnProgress is called periodically during listing.
    // count is items processed so far, total is -1 if unknown.
    OnProgress func(count, total int)
}
```

```go
// In provider List function:
for i, tag := range pageTags {
    if opts.OnProgress != nil {
        opts.OnProgress(i+1, len(pageTags))
    }
    // ... process tag ...
}
```

**Test requirements**:
- Unit test: Verify callback is invoked with correct counts
- Unit test: Verify nil callback doesn't panic

---

### 9. Concurrent metadata fetching

**Problem**: Container registry fetches digest/created time sequentially for each tag.

**File to modify**: `internal/targets/providers/container_registry.go`

**Changes needed**:

```go
import "golang.org/x/sync/errgroup"

func (p containerRegistryProvider) List(ctx context.Context, target string, opts *targets.ListOptions) ([]*listv1.DiscoveredTarget, error) {
    // ... existing code to get pageTags ...

    // Fetch metadata concurrently
    results := make([]*listv1.DiscoveredTarget, len(pageTags))
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(10) // Limit concurrent requests

    for i, tag := range pageTags {
        i, tag := i, tag // capture loop vars
        g.Go(func() error {
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

            // Fetch metadata (already handles errors gracefully)
            if digest, created, err := getTagMetadata(ctx, imageRef, remoteOpts); err == nil {
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
        return nil, err
    }

    return results, nil
}
```

**Test requirements**:
- Benchmark: Compare sequential vs concurrent performance
- Unit test: Verify all results are populated
- Unit test: Verify context cancellation stops workers

---

## Implementation Order

Recommended implementation sequence:

1. **Week 1**: Priority 1 items (Critical)
   - Wire `next_page_token` (breaks API contract if not fixed)
   - Apply `GitHubListOptions` (feature doesn't work without this)
   - Update documentation (users can't discover features)

2. **Week 2**: Priority 2 items (Production hardening)
   - GitHub rate limiting improvements
   - Integration tests
   - Document container registry pagination limitation

3. **Week 3+**: Priority 3 items (Nice to have)
   - Response caching
   - Progress indicators
   - Concurrent metadata fetching

---

## Related Files Summary

| File | Purpose |
|------|---------|
| `internal/targets/providers/container_registry.go` | Container registry collection provider |
| `internal/targets/providers/container_registry_test.go` | Unit tests |
| `internal/targets/providers/github_org.go` | GitHub org collection provider |
| `internal/targets/providers/github_org_test.go` | Unit tests |
| `internal/targets/targets.go` | `CollectionProvider` interface |
| `internal/targets/registry.go` | Provider registry and `List()` dispatch |
| `internal/targets/options.go` | `ListOptions` and `ProviderContext` |
| `internal/server/list_handler.go` | RPC handler that calls providers |
| `api/deputy/list/v1/service.proto` | Proto definitions including `next_page_token` |
| `docs/commands/list.md` | User documentation |

---

## Testing Checklist

Before merging any changes:

- [ ] All existing unit tests pass (`go test ./internal/targets/providers/...`)
- [ ] New unit tests added for changed behavior
- [ ] Integration tests added (skippable)
- [ ] Documentation updated
- [ ] Proto regenerated if interface changed (`buf generate`)
- [ ] Manual testing with real registries/GitHub orgs
