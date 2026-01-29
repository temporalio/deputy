package providers

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v63/github"
	"google.golang.org/protobuf/types/known/timestamppb"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/internal/targets"
)

func init() {
	targets.RegisterProvider(githubCollectionsProvider{})
}

// priorityGitHubCollections is higher than repo collections (58) to match more specific paths.
const priorityGitHubCollections = 59

// GitHubCollectionType identifies which collection type to list.
type GitHubCollectionType string

const (
	GitHubCollectionReleases       GitHubCollectionType = "releases"
	GitHubCollectionCommits        GitHubCollectionType = "commits"
	GitHubCollectionContributors   GitHubCollectionType = "contributors"
	GitHubCollectionCollaborators  GitHubCollectionType = "collaborators"
	GitHubCollectionForks          GitHubCollectionType = "forks"
	GitHubCollectionPulls          GitHubCollectionType = "pulls"
	GitHubCollectionIssues         GitHubCollectionType = "issues"
	GitHubCollectionWorkflows      GitHubCollectionType = "workflows"
	GitHubCollectionRuns           GitHubCollectionType = "runs"
	GitHubCollectionDependabot     GitHubCollectionType = "dependabot"      // Dependabot alerts
	GitHubCollectionCodeScanning   GitHubCollectionType = "code-scanning"   // CodeQL/SARIF alerts
	GitHubCollectionSecretScanning GitHubCollectionType = "secret-scanning" // Secret scanning alerts
	GitHubCollectionAdvisories     GitHubCollectionType = "advisories"
	GitHubCollectionPackages       GitHubCollectionType = "packages"       // GitHub Packages (org/user level)
	GitHubCollectionReleaseAssets  GitHubCollectionType = "release-assets" // Assets in a specific release
)

// githubCollectionsProvider implements [targets.CollectionProvider] for listing
// various GitHub repository collections beyond branches and tags.
//
// URI patterns (trailing slash indicates collection):
//
// Organization/User level:
//   - github://owner/packages/            → list all packages in org/user
//
// Repository level:
//   - github://owner/repo/packages/       → list packages linked to this repo
//   - github://owner/repo/releases/       → list releases
//   - github://owner/repo/commits/        → list commits
//   - github://owner/repo/contributors/   → list contributors
//   - github://owner/repo/collaborators/  → list collaborators (requires access)
//   - github://owner/repo/forks/          → list forks
//   - github://owner/repo/pulls/          → list pull requests
//   - github://owner/repo/issues/         → list issues
//   - github://owner/repo/actions/        → list workflows
//   - github://owner/repo/actions/runs/   → list workflow runs
//   - github://owner/repo/dependabot/          → list Dependabot alerts
//   - github://owner/repo/code-scanning/       → list code scanning alerts (CodeQL/SARIF)
//   - github://owner/repo/secret-scanning/     → list secret scanning alerts
//   - github://owner/repo/advisories/          → list repository security advisories
//
// The provider uses GITHUB_TOKEN environment variable for authentication.
type githubCollectionsProvider struct{}

func (githubCollectionsProvider) Priority() int { return priorityGitHubCollections }

// Detect returns true if the target looks like a GitHub collection URI.
func (githubCollectionsProvider) Detect(ctx context.Context, target string) bool {
	_, _, collType, ok := parseGitHubCollection(target)
	return ok && collType != ""
}

// parseGitHubCollection extracts owner, repo, and collection type from a collection URI.
func parseGitHubCollection(target string) (owner, repo string, collType GitHubCollectionType, ok bool) {
	target = strings.TrimSpace(target)

	var rest string
	var found bool

	// Handle github:// scheme
	if rest, found = strings.CutPrefix(target, "github://"); found {
		// got it
	} else if rest, found = strings.CutPrefix(target, "https://github.com/"); found {
		// got it
	} else if rest, found = strings.CutPrefix(target, "github.com/"); found {
		// got it
	} else {
		return "", "", "", false
	}

	// Must end with trailing slash for collection
	rest, found = strings.CutSuffix(rest, "/")
	if !found {
		return "", "", "", false
	}

	// Parse the path
	parts := strings.Split(rest, "/")

	// Need at least owner/collection (for org-level) or owner/repo/collection (for repo-level)
	if len(parts) < 2 {
		return "", "", "", false
	}

	owner = parts[0]

	// Handle org-level collections (owner/collection)
	if len(parts) == 2 {
		switch strings.ToLower(parts[1]) {
		case "packages", "package":
			return owner, "", GitHubCollectionPackages, true
		}
		return "", "", "", false
	}

	repo = parts[1]

	// Determine collection type based on path
	switch {
	case len(parts) == 3:
		switch strings.ToLower(parts[2]) {
		case "releases", "release":
			return owner, repo, GitHubCollectionReleases, true
		case "commits", "commit":
			return owner, repo, GitHubCollectionCommits, true
		case "contributors":
			return owner, repo, GitHubCollectionContributors, true
		case "collaborators":
			return owner, repo, GitHubCollectionCollaborators, true
		case "forks", "fork":
			return owner, repo, GitHubCollectionForks, true
		case "pulls", "pull", "prs", "pr":
			return owner, repo, GitHubCollectionPulls, true
		case "issues", "issue":
			return owner, repo, GitHubCollectionIssues, true
		case "actions", "workflows":
			return owner, repo, GitHubCollectionWorkflows, true
		// Security alert types - canonical URIs
		case "dependabot", "dependabot-alerts":
			return owner, repo, GitHubCollectionDependabot, true
		case "code-scanning", "codescanning", "codeql":
			return owner, repo, GitHubCollectionCodeScanning, true
		case "secret-scanning", "secretscanning", "secrets":
			return owner, repo, GitHubCollectionSecretScanning, true
		case "advisories", "advisory", "security-advisories":
			return owner, repo, GitHubCollectionAdvisories, true
		case "packages", "package":
			return owner, repo, GitHubCollectionPackages, true
		}
	case len(parts) == 4:
		// Handle nested paths like actions/runs/, security/alerts/, releases/v1.0.0/
		parent := strings.ToLower(parts[2])
		child := parts[3] // Keep original case for release tags

		if parent == "actions" && (strings.ToLower(child) == "runs" || strings.ToLower(child) == "run") {
			return owner, repo, GitHubCollectionRuns, true
		}
		// releases/tag/ → list assets in that release
		if (parent == "releases" || parent == "release") && child != "" {
			// Store the tag in repo field temporarily, we'll parse it out in listReleaseAssets
			// Format: "repo:tag" to distinguish from regular repo
			return owner, repo + ":" + child, GitHubCollectionReleaseAssets, true
		}
		// Support security/ prefix for backwards compatibility
		if parent == "security" {
			switch strings.ToLower(child) {
			case "dependabot", "alerts", "alert":
				return owner, repo, GitHubCollectionDependabot, true
			case "code-scanning", "codescanning", "codeql":
				return owner, repo, GitHubCollectionCodeScanning, true
			case "secret-scanning", "secretscanning", "secrets":
				return owner, repo, GitHubCollectionSecretScanning, true
			case "advisories", "advisory":
				return owner, repo, GitHubCollectionAdvisories, true
			}
		}
	}

	return "", "", "", false
}

// Open is not applicable for collections.
func (githubCollectionsProvider) Open(ctx context.Context, target string, opts *targets.OpenOptions) (targets.Materialized, error) {
	return targets.Materialized{}, fmt.Errorf("cannot open GitHub collection %q directly; use List() to discover items", target)
}

// IsCollection returns true if the target is a GitHub collection URI.
func (githubCollectionsProvider) IsCollection(ctx context.Context, target string) bool {
	_, _, collType, ok := parseGitHubCollection(target)
	return ok && collType != ""
}

// List enumerates items in a GitHub collection.
func (p githubCollectionsProvider) List(ctx context.Context, target string, opts *targets.ListOptions) (*targets.ListResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list github collection: %w", err)
	}

	owner, repo, collType, ok := parseGitHubCollection(target)
	if !ok || owner == "" || collType == "" {
		return nil, fmt.Errorf("invalid GitHub collection URI: %q", target)
	}

	// Packages can be org-level (repo="") or repo-level (repo set)
	// All other collections require a repo
	if collType != GitHubCollectionPackages && repo == "" {
		return nil, fmt.Errorf("invalid GitHub collection URI (missing repo): %q", target)
	}

	client := newGitHubClient(ctx)

	pageSize := int(opts.PageSize)
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 100 {
		pageSize = 100
	}

	page := 1
	if opts.PageToken != "" {
		if n, err := strconv.Atoi(opts.PageToken); err == nil && n > 0 {
			page = n
		}
	}

	listOpts := github.ListOptions{
		PerPage: pageSize,
		Page:    page,
	}

	switch collType {
	case GitHubCollectionPackages:
		return p.listPackages(ctx, client, owner, repo, listOpts)
	case GitHubCollectionReleases:
		return p.listReleases(ctx, client, owner, repo, listOpts)
	case GitHubCollectionReleaseAssets:
		return p.listReleaseAssets(ctx, client, owner, repo, listOpts)
	case GitHubCollectionCommits:
		return p.listCommits(ctx, client, owner, repo, listOpts)
	case GitHubCollectionContributors:
		return p.listContributors(ctx, client, owner, repo, listOpts)
	case GitHubCollectionCollaborators:
		return p.listCollaborators(ctx, client, owner, repo, listOpts)
	case GitHubCollectionForks:
		return p.listForks(ctx, client, owner, repo, listOpts)
	case GitHubCollectionPulls:
		return p.listPulls(ctx, client, owner, repo, listOpts)
	case GitHubCollectionIssues:
		return p.listIssues(ctx, client, owner, repo, listOpts)
	case GitHubCollectionWorkflows:
		return p.listWorkflows(ctx, client, owner, repo, listOpts)
	case GitHubCollectionRuns:
		return p.listWorkflowRuns(ctx, client, owner, repo, listOpts)
	case GitHubCollectionDependabot:
		return p.listDependabotAlerts(ctx, client, owner, repo, listOpts)
	case GitHubCollectionCodeScanning:
		return p.listCodeScanningAlerts(ctx, client, owner, repo, listOpts)
	case GitHubCollectionSecretScanning:
		return p.listSecretScanningAlerts(ctx, client, owner, repo, listOpts)
	case GitHubCollectionAdvisories:
		return p.listSecurityAdvisories(ctx, client, owner, repo, listOpts)
	default:
		return nil, fmt.Errorf("unknown collection type: %s", collType)
	}
}

// listPackages lists packages in an organization or user namespace.
// If repo is non-empty, filters to packages linked to that repository.
// Supports all GitHub package types: container, npm, maven, rubygems, nuget, docker.
func (p githubCollectionsProvider) listPackages(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	// GitHub Packages API lists by package type, so we query all types
	packageTypes := []string{"container", "npm", "maven", "rubygems", "nuget", "docker"}

	var allPackages []*github.Package
	var lastResp *github.Response

	// Try as organization first
	for _, pkgType := range packageTypes {
		packages, resp, err := client.Organizations.ListPackages(ctx, owner, &github.PackageListOptions{
			PackageType: github.String(pkgType),
			ListOptions: opts,
		})
		if err != nil {
			// If org not found, try as user
			if isGitHubNotFound(err) {
				packages, resp, err = client.Users.ListPackages(ctx, owner, &github.PackageListOptions{
					PackageType: github.String(pkgType),
					ListOptions: opts,
				})
			}
		}
		if err != nil {
			// Skip this package type if not found, continue with others
			if isGitHubNotFound(err) {
				continue
			}
			return nil, wrapGitHubPackageError(err, owner, repo)
		}
		allPackages = append(allPackages, packages...)
		lastResp = resp
	}

	if lastResp != nil {
		checkGitHubRateLimit(ctx, lastResp)
	}

	var results []*listv1.DiscoveredTarget
	for _, pkg := range allPackages {
		if pkg == nil {
			continue
		}

		// Filter by repository if specified
		if repo != "" {
			linkedRepo := ""
			if pkg.Repository != nil {
				linkedRepo = pkg.GetRepository().GetName()
			}
			if linkedRepo != repo {
				continue
			}
		}

		// Build package URI - use package URL if available
		uri := pkg.GetHTMLURL()
		if uri == "" {
			uri = fmt.Sprintf("https://github.com/%s/packages/%s/%s", owner, pkg.GetPackageType(), pkg.GetName())
		}

		dt := &listv1.DiscoveredTarget{
			Uri:  uri,
			Name: pkg.GetName(),
			Metadata: map[string]string{
				"owner":        owner,
				"type":         "package",
				"package_type": pkg.GetPackageType(),
				"visibility":   pkg.GetVisibility(),
			},
		}

		// Add version count if available
		if pkg.VersionCount != nil {
			dt.Metadata["version_count"] = strconv.FormatInt(*pkg.VersionCount, 10)
		}

		// Add repository info if linked
		if pkg.Repository != nil {
			dt.Metadata["repository"] = pkg.GetRepository().GetFullName()
			dt.Description = fmt.Sprintf("%s package from %s", pkg.GetPackageType(), pkg.GetRepository().GetFullName())
		} else {
			dt.Description = fmt.Sprintf("%s package", pkg.GetPackageType())
		}

		// Add owner info
		if pkg.Owner != nil {
			dt.Metadata["owner_login"] = pkg.GetOwner().GetLogin()
			dt.Metadata["owner_type"] = pkg.GetOwner().GetType()
		}

		if !pkg.GetCreatedAt().Time.IsZero() {
			dt.CreatedAt = timestamppb.New(pkg.GetCreatedAt().Time)
		}

		if !pkg.GetUpdatedAt().Time.IsZero() {
			dt.Metadata["updated_at"] = pkg.GetUpdatedAt().Time.Format(time.RFC3339)
		}

		results = append(results, dt)
	}

	// Note: Pagination for packages across multiple types is complex;
	// for now we return all packages from the current page across all types
	var nextPageToken string
	if lastResp != nil && lastResp.NextPage > 0 {
		nextPageToken = strconv.Itoa(lastResp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// wrapGitHubPackageError provides helpful error messages for package API errors.
func wrapGitHubPackageError(err error, owner, repo string) error {
	if err == nil {
		return nil
	}

	var target string
	if repo != "" {
		target = fmt.Sprintf("github://%s/%s/packages/", owner, repo)
	} else {
		target = fmt.Sprintf("github://%s/packages/", owner)
	}

	if ghErr, ok := err.(*github.ErrorResponse); ok {
		switch ghErr.Response.StatusCode {
		case 403:
			if strings.Contains(ghErr.Message, "rate limit") {
				return fmt.Errorf("list %s: rate limit exceeded (hint: set GITHUB_TOKEN for higher limits)", target)
			}
			return fmt.Errorf("list %s: access denied (hint: requires GITHUB_TOKEN with read:packages scope)", target)
		case 401:
			return fmt.Errorf("list %s: authentication failed (hint: check GITHUB_TOKEN is valid)", target)
		case 404:
			return fmt.Errorf("list %s: organization or user not found", target)
		}
	}

	return fmt.Errorf("list %s: %w", target, err)
}

// listReleases lists releases in a repository.
//
// TODO(future): Support hierarchical discovery into release assets:
//   - github://owner/repo/releases/v1.0.0/        → list assets in a specific release
//   - github://owner/repo/releases/v1.0.0/app.zip → scan packages inside the asset
//
// This would enable powerful supply chain auditing:
//   1. Enumerate releases across an org
//   2. Drill into release assets (binaries, archives, SBOMs)
//   3. Scan binaries inside archives (Go/Rust binaries have embedded dependency info)
//   4. Verify release artifacts match expected SBOMs
//   5. Track provenance: source commit → release → deployed artifact
//
// Implementation considerations:
//   - Asset download would need streaming/temp file handling
//   - Archive extraction should be sandboxed (zip bombs, symlink attacks)
//   - Binary scanning reuses existing Go/Rust binary extractors
//   - Could leverage GitHub's attestations API for SLSA provenance
func (p githubCollectionsProvider) listReleases(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	releases, resp, err := client.Repositories.ListReleases(ctx, owner, repo, &opts)
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "releases")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, r := range releases {
		if r == nil {
			continue
		}

		name := r.GetTagName()
		if r.GetName() != "" {
			name = r.GetName()
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         r.GetHTMLURL(),
			Name:        name,
			Description: truncateString(r.GetBody(), 100),
			Metadata: map[string]string{
				"owner":       owner,
				"repo":        repo,
				"tag":         r.GetTagName(),
				"type":        "release",
				"prerelease":  strconv.FormatBool(r.GetPrerelease()),
				"draft":       strconv.FormatBool(r.GetDraft()),
				"author":      r.GetAuthor().GetLogin(),
				"asset_count": strconv.Itoa(len(r.Assets)),
			},
		}

		if !r.GetPublishedAt().Time.IsZero() {
			dt.CreatedAt = timestamppb.New(r.GetPublishedAt().Time)
		} else if !r.GetCreatedAt().Time.IsZero() {
			dt.CreatedAt = timestamppb.New(r.GetCreatedAt().Time)
		}

		if r.GetTarballURL() != "" {
			dt.Metadata["tarball_url"] = r.GetTarballURL()
		}
		if r.GetZipballURL() != "" {
			dt.Metadata["zipball_url"] = r.GetZipballURL()
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listReleaseAssets lists assets in a specific release.
//
// TODO(future): Support scanning assets directly:
//   - github://owner/repo/releases/v1.0.0/app.zip → download and scan binary inside
//
// This would enable complete supply chain tracing - verify that release binaries
// contain expected dependencies and match attached SBOMs.
//
// Implementation considerations:
//   - Asset download needs streaming to temp file with size limits
//   - Archive extraction must be sandboxed (zip bombs, symlink attacks)
//   - Binary scanning reuses existing Go/Rust binary extractors
//   - Could verify against GitHub Attestations API for SLSA provenance
func (p githubCollectionsProvider) listReleaseAssets(ctx context.Context, client *github.Client, owner, repoTag string, opts github.ListOptions) (*targets.ListResult, error) {
	// Parse repo:tag format from the special encoding in parseGitHubCollection
	repo, tag, found := strings.Cut(repoTag, ":")
	if !found || tag == "" {
		return nil, fmt.Errorf("invalid release URI: missing tag (got %q)", repoTag)
	}

	// Get the release by tag to find its ID
	release, resp, err := client.Repositories.GetReleaseByTag(ctx, owner, repo, tag)
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, fmt.Sprintf("releases/%s", tag))
	}
	checkGitHubRateLimit(ctx, resp)

	if release == nil {
		return nil, fmt.Errorf("release %q not found in %s/%s (nil response)", tag, owner, repo)
	}

	// List assets for this release
	assets, resp, err := client.Repositories.ListReleaseAssets(ctx, owner, repo, release.GetID(), &opts)
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, fmt.Sprintf("releases/%s/assets", tag))
	}
	checkGitHubRateLimit(ctx, resp)

	// Initialize results slice (never nil)
	results := make([]*listv1.DiscoveredTarget, 0, len(assets))
	for _, a := range assets {
		if a == nil {
			continue
		}

		// Determine asset type from name/content type
		assetType := classifyAssetType(a.GetName(), a.GetContentType())

		dt := &listv1.DiscoveredTarget{
			Uri:         a.GetBrowserDownloadURL(),
			Name:        a.GetName(),
			Description: fmt.Sprintf("%s (%s)", formatBytes(int64(a.GetSize())), assetType),
			Metadata: map[string]string{
				"owner":        owner,
				"repo":         repo,
				"release_tag":  tag,
				"type":         "release_asset",
				"asset_type":   assetType,
				"content_type": a.GetContentType(),
				"size":         strconv.Itoa(a.GetSize()),
				"download_url": a.GetBrowserDownloadURL(),
				"download_count": strconv.Itoa(a.GetDownloadCount()),
			},
		}

		if a.GetLabel() != "" {
			dt.Metadata["label"] = a.GetLabel()
		}

		if !a.GetCreatedAt().Time.IsZero() {
			dt.CreatedAt = timestamppb.New(a.GetCreatedAt().Time)
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	// If no assets found, return helpful empty result
	// (Some projects like HashiCorp tools don't publish binaries to GitHub Releases)
	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// classifyAssetType determines the type of release asset from its name and content type.
func classifyAssetType(name, contentType string) string {
	nameLower := strings.ToLower(name)

	// Check for common binary patterns
	if strings.HasSuffix(nameLower, ".exe") {
		return "windows-binary"
	}
	if strings.Contains(nameLower, "linux") && !strings.Contains(nameLower, ".") {
		return "linux-binary"
	}
	if strings.Contains(nameLower, "darwin") || strings.Contains(nameLower, "macos") {
		if !strings.HasSuffix(nameLower, ".tar.gz") && !strings.HasSuffix(nameLower, ".zip") {
			return "macos-binary"
		}
	}

	// Check for archives
	if strings.HasSuffix(nameLower, ".tar.gz") || strings.HasSuffix(nameLower, ".tgz") {
		return "tarball"
	}
	if strings.HasSuffix(nameLower, ".zip") {
		return "zip"
	}
	if strings.HasSuffix(nameLower, ".tar.xz") || strings.HasSuffix(nameLower, ".txz") {
		return "tarball"
	}
	if strings.HasSuffix(nameLower, ".tar.bz2") || strings.HasSuffix(nameLower, ".tbz2") {
		return "tarball"
	}

	// Check for checksums/signatures
	if strings.HasSuffix(nameLower, ".sha256") || strings.HasSuffix(nameLower, ".sha256sum") ||
		strings.HasSuffix(nameLower, ".sha512") || strings.HasSuffix(nameLower, ".md5") {
		return "checksum"
	}
	if strings.HasSuffix(nameLower, ".sig") || strings.HasSuffix(nameLower, ".asc") ||
		strings.HasSuffix(nameLower, ".gpg") {
		return "signature"
	}

	// Check for SBOMs
	if strings.Contains(nameLower, "sbom") || strings.Contains(nameLower, "bom") {
		if strings.HasSuffix(nameLower, ".json") || strings.HasSuffix(nameLower, ".xml") {
			return "sbom"
		}
	}
	if strings.HasSuffix(nameLower, ".spdx") || strings.HasSuffix(nameLower, ".spdx.json") {
		return "sbom"
	}
	if strings.HasSuffix(nameLower, ".cdx.json") || strings.HasSuffix(nameLower, ".cyclonedx.json") {
		return "sbom"
	}

	// Check for attestations/provenance
	if strings.Contains(nameLower, "provenance") || strings.Contains(nameLower, "attestation") ||
		strings.HasSuffix(nameLower, ".intoto.jsonl") {
		return "attestation"
	}

	// Check for container images
	if strings.HasSuffix(nameLower, ".tar") && (strings.Contains(nameLower, "image") ||
		strings.Contains(nameLower, "docker") || strings.Contains(nameLower, "container")) {
		return "container-image"
	}

	// Fallback based on content type
	if strings.Contains(contentType, "application/octet-stream") {
		return "binary"
	}
	if strings.Contains(contentType, "application/json") {
		return "json"
	}

	return "file"
}

// formatBytes formats bytes as human-readable size.
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// listCommits lists commits in a repository.
func (p githubCollectionsProvider) listCommits(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	commits, resp, err := client.Repositories.ListCommits(ctx, owner, repo, &github.CommitsListOptions{
		ListOptions: opts,
	})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "commits")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, c := range commits {
		if c == nil {
			continue
		}

		sha := c.GetSHA()
		shortSHA := sha
		if len(sha) > 7 {
			shortSHA = sha[:7]
		}

		message := ""
		if c.GetCommit() != nil {
			message = truncateString(c.GetCommit().GetMessage(), 80)
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         c.GetHTMLURL(),
			Name:        shortSHA,
			Description: message,
			Metadata: map[string]string{
				"owner": owner,
				"repo":  repo,
				"sha":   sha,
				"type":  "commit",
			},
		}

		if c.GetAuthor() != nil {
			dt.Metadata["author"] = c.GetAuthor().GetLogin()
			dt.Metadata["author_avatar"] = c.GetAuthor().GetAvatarURL()
		}
		if c.GetCommitter() != nil {
			dt.Metadata["committer"] = c.GetCommitter().GetLogin()
		}
		if c.GetCommit() != nil && c.GetCommit().GetAuthor() != nil {
			dt.Metadata["author_name"] = c.GetCommit().GetAuthor().GetName()
			dt.Metadata["author_email"] = c.GetCommit().GetAuthor().GetEmail()
			if c.GetCommit().GetAuthor().Date != nil {
				dt.CreatedAt = timestamppb.New(c.GetCommit().GetAuthor().Date.Time)
			}
		}
		if c.GetCommit() != nil && c.GetCommit().GetVerification() != nil {
			dt.Metadata["verified"] = strconv.FormatBool(c.GetCommit().GetVerification().GetVerified())
			dt.Metadata["signature_reason"] = c.GetCommit().GetVerification().GetReason()
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listContributors lists contributors to a repository.
func (p githubCollectionsProvider) listContributors(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	contributors, resp, err := client.Repositories.ListContributors(ctx, owner, repo, &github.ListContributorsOptions{
		ListOptions: opts,
	})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "contributors")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, c := range contributors {
		if c == nil {
			continue
		}

		dt := &listv1.DiscoveredTarget{
			Uri:  c.GetHTMLURL(),
			Name: c.GetLogin(),
			Metadata: map[string]string{
				"owner":        owner,
				"repo":         repo,
				"type":         "contributor",
				"login":        c.GetLogin(),
				"contributions": strconv.Itoa(c.GetContributions()),
				"avatar_url":   c.GetAvatarURL(),
				"user_type":    c.GetType(),
			},
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listCollaborators lists collaborators on a repository.
func (p githubCollectionsProvider) listCollaborators(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	collaborators, resp, err := client.Repositories.ListCollaborators(ctx, owner, repo, &github.ListCollaboratorsOptions{
		ListOptions: opts,
	})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "collaborators")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, c := range collaborators {
		if c == nil {
			continue
		}

		dt := &listv1.DiscoveredTarget{
			Uri:  c.GetHTMLURL(),
			Name: c.GetLogin(),
			Metadata: map[string]string{
				"owner":      owner,
				"repo":       repo,
				"type":       "collaborator",
				"login":      c.GetLogin(),
				"avatar_url": c.GetAvatarURL(),
				"site_admin": strconv.FormatBool(c.GetSiteAdmin()),
			},
		}

		if c.GetPermissions() != nil {
			perms := c.GetPermissions()
			if perms["admin"] {
				dt.Metadata["permission"] = "admin"
			} else if perms["maintain"] {
				dt.Metadata["permission"] = "maintain"
			} else if perms["push"] {
				dt.Metadata["permission"] = "write"
			} else if perms["triage"] {
				dt.Metadata["permission"] = "triage"
			} else if perms["pull"] {
				dt.Metadata["permission"] = "read"
			}
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listForks lists forks of a repository.
func (p githubCollectionsProvider) listForks(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	forks, resp, err := client.Repositories.ListForks(ctx, owner, repo, &github.RepositoryListForksOptions{
		Sort:        "newest",
		ListOptions: opts,
	})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "forks")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, f := range forks {
		if f == nil {
			continue
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         f.GetHTMLURL(),
			Name:        f.GetFullName(),
			Description: truncateString(f.GetDescription(), 100),
			Metadata: map[string]string{
				"owner":          owner,
				"repo":           repo,
				"type":           "fork",
				"fork_owner":     f.GetOwner().GetLogin(),
				"fork_repo":      f.GetName(),
				"default_branch": f.GetDefaultBranch(),
				"stars":          strconv.Itoa(f.GetStargazersCount()),
				"watchers":       strconv.Itoa(f.GetWatchersCount()),
				"forks":          strconv.Itoa(f.GetForksCount()),
				"open_issues":    strconv.Itoa(f.GetOpenIssuesCount()),
				"private":        strconv.FormatBool(f.GetPrivate()),
				"archived":       strconv.FormatBool(f.GetArchived()),
			},
		}

		if f.GetPushedAt().Time.IsZero() == false {
			dt.Metadata["last_push"] = f.GetPushedAt().Time.Format(time.RFC3339)
		}
		if f.GetCreatedAt().Time.IsZero() == false {
			dt.CreatedAt = timestamppb.New(f.GetCreatedAt().Time)
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listPulls lists pull requests in a repository.
func (p githubCollectionsProvider) listPulls(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	pulls, resp, err := client.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{
		State:       "all",
		Sort:        "updated",
		Direction:   "desc",
		ListOptions: opts,
	})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "pulls")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, pr := range pulls {
		if pr == nil {
			continue
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         pr.GetHTMLURL(),
			Name:        fmt.Sprintf("#%d", pr.GetNumber()),
			Description: truncateString(pr.GetTitle(), 80),
			Metadata: map[string]string{
				"owner":    owner,
				"repo":     repo,
				"type":     "pull_request",
				"number":   strconv.Itoa(pr.GetNumber()),
				"state":    pr.GetState(),
				"author":   pr.GetUser().GetLogin(),
				"draft":    strconv.FormatBool(pr.GetDraft()),
				"merged":   strconv.FormatBool(pr.GetMerged()),
				"head_ref": pr.GetHead().GetRef(),
				"base_ref": pr.GetBase().GetRef(),
				"additions": strconv.Itoa(pr.GetAdditions()),
				"deletions": strconv.Itoa(pr.GetDeletions()),
				"commits":   strconv.Itoa(pr.GetCommits()),
				"comments":  strconv.Itoa(pr.GetComments()),
			},
		}

		if pr.GetMergedAt().Time.IsZero() == false {
			dt.Metadata["merged_at"] = pr.GetMergedAt().Format(time.RFC3339)
			dt.Metadata["merged_by"] = pr.GetMergedBy().GetLogin()
		}
		if pr.GetCreatedAt().Time.IsZero() == false {
			dt.CreatedAt = timestamppb.New(pr.GetCreatedAt().Time)
		}

		// Add labels
		var labels []string
		for _, l := range pr.Labels {
			labels = append(labels, l.GetName())
		}
		if len(labels) > 0 {
			dt.Metadata["labels"] = strings.Join(labels, ",")
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listIssues lists issues in a repository.
func (p githubCollectionsProvider) listIssues(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	issues, resp, err := client.Issues.ListByRepo(ctx, owner, repo, &github.IssueListByRepoOptions{
		State:       "all",
		Sort:        "updated",
		Direction:   "desc",
		ListOptions: opts,
	})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "issues")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, issue := range issues {
		if issue == nil {
			continue
		}

		// Skip pull requests (GitHub API returns PRs as issues too)
		if issue.IsPullRequest() {
			continue
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         issue.GetHTMLURL(),
			Name:        fmt.Sprintf("#%d", issue.GetNumber()),
			Description: truncateString(issue.GetTitle(), 80),
			Metadata: map[string]string{
				"owner":    owner,
				"repo":     repo,
				"type":     "issue",
				"number":   strconv.Itoa(issue.GetNumber()),
				"state":    issue.GetState(),
				"author":   issue.GetUser().GetLogin(),
				"comments": strconv.Itoa(issue.GetComments()),
			},
		}

		if issue.GetClosedAt().Time.IsZero() == false {
			dt.Metadata["closed_at"] = issue.GetClosedAt().Format(time.RFC3339)
		}
		if issue.GetCreatedAt().Time.IsZero() == false {
			dt.CreatedAt = timestamppb.New(issue.GetCreatedAt().Time)
		}

		// Add labels
		var labels []string
		for _, l := range issue.Labels {
			labels = append(labels, l.GetName())
		}
		if len(labels) > 0 {
			dt.Metadata["labels"] = strings.Join(labels, ",")
		}

		// Add assignees
		var assignees []string
		for _, a := range issue.Assignees {
			assignees = append(assignees, a.GetLogin())
		}
		if len(assignees) > 0 {
			dt.Metadata["assignees"] = strings.Join(assignees, ",")
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listWorkflows lists GitHub Actions workflows in a repository.
func (p githubCollectionsProvider) listWorkflows(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	workflows, resp, err := client.Actions.ListWorkflows(ctx, owner, repo, &opts)
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "workflows")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, w := range workflows.Workflows {
		if w == nil {
			continue
		}

		dt := &listv1.DiscoveredTarget{
			Uri:  w.GetHTMLURL(),
			Name: w.GetName(),
			Metadata: map[string]string{
				"owner":      owner,
				"repo":       repo,
				"type":       "workflow",
				"id":         strconv.FormatInt(w.GetID(), 10),
				"path":       w.GetPath(),
				"state":      w.GetState(),
				"badge_url":  w.GetBadgeURL(),
			},
		}

		if w.GetCreatedAt().Time.IsZero() == false {
			dt.CreatedAt = timestamppb.New(w.GetCreatedAt().Time)
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listWorkflowRuns lists GitHub Actions workflow runs in a repository.
func (p githubCollectionsProvider) listWorkflowRuns(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	runs, resp, err := client.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo, &github.ListWorkflowRunsOptions{
		ListOptions: opts,
	})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "workflow runs")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, r := range runs.WorkflowRuns {
		if r == nil {
			continue
		}

		dt := &listv1.DiscoveredTarget{
			Uri:  r.GetHTMLURL(),
			Name: fmt.Sprintf("#%d", r.GetRunNumber()),
			Description: truncateString(r.GetDisplayTitle(), 80),
			Metadata: map[string]string{
				"owner":           owner,
				"repo":            repo,
				"type":            "workflow_run",
				"id":              strconv.FormatInt(r.GetID(), 10),
				"run_number":      strconv.Itoa(r.GetRunNumber()),
				"workflow_name":   r.GetName(),
				"status":          r.GetStatus(),
				"conclusion":      r.GetConclusion(),
				"event":           r.GetEvent(),
				"branch":          r.GetHeadBranch(),
				"head_sha":        r.GetHeadSHA()[:7],
				"actor":           r.GetActor().GetLogin(),
				"triggering_actor": r.GetTriggeringActor().GetLogin(),
			},
		}

		if r.GetCreatedAt().Time.IsZero() == false {
			dt.CreatedAt = timestamppb.New(r.GetCreatedAt().Time)
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listDependabotAlerts lists Dependabot security alerts for a repository.
func (p githubCollectionsProvider) listDependabotAlerts(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	alerts, resp, err := client.Dependabot.ListRepoAlerts(ctx, owner, repo, &github.ListAlertsOptions{
		ListOptions: opts,
	})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "dependabot alerts")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, a := range alerts {
		if a == nil {
			continue
		}

		severity := ""
		cve := ""
		summary := ""
		if a.SecurityAdvisory != nil {
			severity = a.SecurityAdvisory.GetSeverity()
			cve = a.SecurityAdvisory.GetCVEID()
			summary = truncateString(a.SecurityAdvisory.GetSummary(), 80)
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         a.GetHTMLURL(),
			Name:        fmt.Sprintf("GHSA-%d", a.GetNumber()),
			Description: summary,
			Metadata: map[string]string{
				"owner":       owner,
				"repo":        repo,
				"type":        "dependabot_alert",
				"number":      strconv.Itoa(a.GetNumber()),
				"state":       a.GetState(),
				"severity":    severity,
				"cve":         cve,
				"package":     a.GetDependency().GetPackage().GetName(),
				"ecosystem":   a.GetDependency().GetPackage().GetEcosystem(),
				"manifest":    a.GetDependency().GetManifestPath(),
			},
		}

		if a.GetCreatedAt().Time.IsZero() == false {
			dt.CreatedAt = timestamppb.New(a.GetCreatedAt().Time)
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listCodeScanningAlerts lists code scanning alerts (CodeQL, SARIF) for a repository.
func (p githubCollectionsProvider) listCodeScanningAlerts(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	alerts, resp, err := client.CodeScanning.ListAlertsForRepo(ctx, owner, repo, &github.AlertListOptions{
		ListOptions: opts,
	})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "code-scanning")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, a := range alerts {
		if a == nil {
			continue
		}

		// Get tool information (e.g., CodeQL, Semgrep, etc.)
		toolName := ""
		toolVersion := ""
		if a.Tool != nil {
			toolName = a.GetTool().GetName()
			toolVersion = a.GetTool().GetVersion()
		}

		// Get rule information
		ruleID := a.GetRuleID()
		ruleSeverity := a.GetRuleSeverity()
		ruleDesc := a.GetRuleDescription()
		if a.Rule != nil {
			if a.Rule.ID != nil {
				ruleID = *a.Rule.ID
			}
			if a.Rule.Severity != nil {
				ruleSeverity = *a.Rule.Severity
			}
			if a.Rule.Description != nil {
				ruleDesc = *a.Rule.Description
			}
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         a.GetHTMLURL(),
			Name:        fmt.Sprintf("#%d", a.GetNumber()),
			Description: truncateString(ruleDesc, 80),
			Metadata: map[string]string{
				"owner":         owner,
				"repo":          repo,
				"type":          "code_scanning_alert",
				"number":        strconv.Itoa(a.GetNumber()),
				"state":         a.GetState(),
				"rule_id":       ruleID,
				"rule_severity": ruleSeverity,
				"tool":          toolName,
				"tool_version":  toolVersion,
			},
		}

		// Add location information if available
		if a.MostRecentInstance != nil {
			if a.MostRecentInstance.Location != nil {
				dt.Metadata["file"] = a.MostRecentInstance.Location.GetPath()
				dt.Metadata["line"] = strconv.Itoa(a.MostRecentInstance.Location.GetStartLine())
			}
			dt.Metadata["ref"] = a.MostRecentInstance.GetRef()
		}

		if !a.GetCreatedAt().Time.IsZero() {
			dt.CreatedAt = timestamppb.New(a.GetCreatedAt().Time)
		}

		// Dismissal info
		if a.DismissedBy != nil {
			dt.Metadata["dismissed_by"] = a.GetDismissedBy().GetLogin()
			dt.Metadata["dismissed_reason"] = a.GetDismissedReason()
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listSecretScanningAlerts lists secret scanning alerts for a repository.
func (p githubCollectionsProvider) listSecretScanningAlerts(ctx context.Context, client *github.Client, owner, repo string, opts github.ListOptions) (*targets.ListResult, error) {
	alerts, resp, err := client.SecretScanning.ListAlertsForRepo(ctx, owner, repo, &github.SecretScanningAlertListOptions{
		ListOptions: opts,
	})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "secret-scanning")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, a := range alerts {
		if a == nil {
			continue
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         a.GetHTMLURL(),
			Name:        fmt.Sprintf("#%d", a.GetNumber()),
			Description: a.GetSecretTypeDisplayName(),
			Metadata: map[string]string{
				"owner":       owner,
				"repo":        repo,
				"type":        "secret_scanning_alert",
				"number":      strconv.Itoa(a.GetNumber()),
				"state":       a.GetState(),
				"secret_type": a.GetSecretType(),
			},
		}

		// Resolution info
		if a.GetResolution() != "" {
			dt.Metadata["resolution"] = a.GetResolution()
		}
		if a.ResolvedBy != nil {
			dt.Metadata["resolved_by"] = a.GetResolvedBy().GetLogin()
		}

		// Push protection bypass info
		if a.GetPushProtectionBypassed() {
			dt.Metadata["push_protection_bypassed"] = "true"
			if a.PushProtectionBypassedBy != nil {
				dt.Metadata["bypassed_by"] = a.GetPushProtectionBypassedBy().GetLogin()
			}
		}

		if !a.GetCreatedAt().Time.IsZero() {
			dt.CreatedAt = timestamppb.New(a.GetCreatedAt().Time)
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// listSecurityAdvisories lists security advisories for a repository.
func (p githubCollectionsProvider) listSecurityAdvisories(ctx context.Context, client *github.Client, owner, repo string, _ github.ListOptions) (*targets.ListResult, error) {
	// Note: GitHub API doesn't support pagination for repository security advisories
	advisories, resp, err := client.SecurityAdvisories.ListRepositorySecurityAdvisories(ctx, owner, repo, &github.ListRepositorySecurityAdvisoriesOptions{})
	if err != nil {
		return nil, wrapGitHubCollectionError(err, owner, repo, "security advisories")
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, a := range advisories {
		if a == nil {
			continue
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         a.GetHTMLURL(),
			Name:        a.GetGHSAID(),
			Description: truncateString(a.GetSummary(), 80),
			Metadata: map[string]string{
				"owner":       owner,
				"repo":        repo,
				"type":        "security_advisory",
				"ghsa_id":     a.GetGHSAID(),
				"cve_id":      a.GetCVEID(),
				"state":       a.GetState(),
				"severity":    a.GetSeverity(),
				"author":      a.GetAuthor().GetLogin(),
			},
		}

		if a.GetPublishedAt().Time.IsZero() == false {
			dt.CreatedAt = timestamppb.New(a.GetPublishedAt().Time)
		} else if a.GetCreatedAt().Time.IsZero() == false {
			dt.CreatedAt = timestamppb.New(a.GetCreatedAt().Time)
		}

		// Add CVSSv3 if available
		if a.GetCVSS() != nil {
			if score := a.GetCVSS().GetScore(); score != nil {
				dt.Metadata["cvss_score"] = fmt.Sprintf("%.1f", *score)
			}
			dt.Metadata["cvss_vector"] = a.GetCVSS().GetVectorString()
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// wrapGitHubCollectionError provides helpful error messages.
func wrapGitHubCollectionError(err error, owner, repo, collection string) error {
	if err == nil {
		return nil
	}

	target := fmt.Sprintf("github://%s/%s/%s/", owner, repo, collection)

	if ghErr, ok := err.(*github.ErrorResponse); ok {
		switch ghErr.Response.StatusCode {
		case 403:
			if strings.Contains(ghErr.Message, "rate limit") {
				return fmt.Errorf("list %s: rate limit exceeded (hint: set GITHUB_TOKEN for higher limits)", target)
			}
			return fmt.Errorf("list %s: access denied (hint: requires GITHUB_TOKEN with appropriate permissions)", target)
		case 401:
			return fmt.Errorf("list %s: authentication failed (hint: check GITHUB_TOKEN is valid)", target)
		case 404:
			return fmt.Errorf("list %s: not found or not accessible", target)
		}
	}

	return fmt.Errorf("list %s: %w", target, err)
}

// truncateString truncates a string to maxLen and adds ellipsis if needed.
func truncateString(s string, maxLen int) string {
	// Remove newlines for single-line display
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.TrimSpace(s)

	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-1] + "…"
}

var _ targets.Provider = (*githubCollectionsProvider)(nil)
var _ targets.PriorityProvider = (*githubCollectionsProvider)(nil)
var _ targets.CollectionProvider = (*githubCollectionsProvider)(nil)
