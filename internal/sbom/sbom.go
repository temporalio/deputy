package sbomx

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	neturl "net/url"

	pb "deps.dev/api/v3"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/compare"
	gitx "github.com/picatz/deputy/internal/gitutil"
	"github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/purlx"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Options configures SBOM generation behavior and enrichment passes.
type Options struct {
	Ref            string
	Ecosystems     []string
	Name           string
	EnrichLicenses bool
	LicenseSource  string // depsdev|scan|both
}

// Result captures the SBOM document alongside contextual metadata that callers
// can surface to users (e.g., --show-context banner in the CLI).
type Result struct {
	Document *sbom.Document
	RepoPath string
	Ref      string
	Commit   string
	Origin   string
	Packages []*extractor.Package
}

// Generate builds an SBOM document for repoPath (local) or a remote reference.
// Generate produces a Protobom SBOM document for the supplied repository path
// (local path or remote reference). Remote repositories are shallow cloned
// (depth 1) to a temporary directory and cleaned up automatically.
func Generate(ctx context.Context, repoRef string, opts Options) (Result, error) {
	if opts.Ref == "" {
		opts.Ref = "HEAD"
	}

	var (
		src *repository.Source
		err error
	)

	result := Result{Ref: opts.Ref}
	repoDisplay := repoRef
	if fi, statErr := os.Stat(repoRef); statErr == nil && fi.IsDir() {
		if abs, absErr := filepath.Abs(repoRef); absErr == nil {
			repoDisplay = abs
		}

		src, err = repository.Open(repoRef)
		if err != nil {
			return Result{}, fmt.Errorf("open repository: %w", err)
		}
	} else {
		url := ToHTTPSGitURL(repoRef)
		if url == "" {
			return Result{}, fmt.Errorf("could not interpret repo %q as local path or remote URL", repoRef)
		}
		auth := AuthForURL(url)
		refName, resolveErr := ResolveReferenceName(ctx, url, auth, opts.Ref)
		if resolveErr == nil && refName.String() != "" {
			opts.Ref = refName.String()
		}
		cloneOpts := &git.CloneOptions{
			URL:          url,
			Depth:        1,
			SingleBranch: true,
			Tags:         git.NoTags,
			Auth:         auth,
		}
		if refName.String() != "" {
			cloneOpts.ReferenceName = refName
		}
		src, err = repository.Clone(ctx, cloneOpts, true)
		if err != nil && cloneOpts.ReferenceName != "" {
			cloneOpts.ReferenceName = ""
			src, err = repository.Clone(ctx, cloneOpts, true)
		}
		if err != nil {
			return Result{}, fmt.Errorf("failed to clone remote repo %s: %w", url, err)
		}
		repoRef = url
		repoDisplay = url
	}
	defer src.Close()
	result.RepoPath = repoDisplay
	result.Ref = opts.Ref

	effRef := opts.Ref
	if strings.EqualFold(effRef, "HEAD") {
		effRef = "HEAD~0"
	}

	pkgs, err := collectInventorySBOM(ctx, src.Repo, src.Workspace, effRef, inventory.ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		return Result{}, err
	}

	var directDeps map[string]bool
	if strings.EqualFold(effRef, "HEAD") || strings.EqualFold(effRef, "HEAD~0") {
		directDeps = compare.CollectGoDirectModulesFromWorkspace(src.Workspace)
	} else {
		if hash, err := gitx.ResolveRevisionEnhanced(src.Repo, effRef); err == nil {
			directDeps, _ = compare.CollectGoDirectModulesFromCommit(src.Repo, *hash)
		}
	}

	doc, err := buildProtobomDocument(ctx, src.Workspace, repoRef, opts.Ref, opts.Name, pkgs, directDeps)
	if err != nil {
		return Result{}, err
	}

	if opts.EnrichLicenses {
		switch strings.ToLower(opts.LicenseSource) {
		case "depsdev", "deps", "dd":
			if err := enrichProtobomLicensesDepsDev(ctx, doc); err != nil {
				return Result{}, err
			}
		case "scan":
			if err := enrichProtobomLicensesScanLocal(ctx, doc, src.Workspace); err != nil {
				return Result{}, err
			}
			fetcher := &remoteFetcher{Timeout: 20 * time.Second}
			if err := enrichProtobomLicensesScanWithFetcher(ctx, doc, fetcher); err != nil {
				return Result{}, err
			}
		case "both":
			if err := enrichProtobomLicensesDepsDev(ctx, doc); err != nil {
				return Result{}, err
			}
			if err := enrichProtobomLicensesScanLocal(ctx, doc, src.Workspace); err != nil {
				return Result{}, err
			}
			fetcher := &remoteFetcher{Timeout: 20 * time.Second}
			if err := enrichProtobomLicensesScanWithFetcher(ctx, doc, fetcher); err != nil {
				return Result{}, err
			}
		default:
			return Result{}, fmt.Errorf("unsupported license source: %s", opts.LicenseSource)
		}
	}

	commit, origin := resolveRepoMetadata(src.Repo, effRef, repoDisplay)
	result.Commit = commit
	result.Origin = origin
	result.Document = doc
	result.Packages = pkgs
	return result, nil
}

// collectInventorySBOM scans the repository at a specific commit snapshot.
func collectInventorySBOM(ctx context.Context, repo *git.Repository, ws workspace.FS, gitRef string, opts inventory.ScanOptions) ([]*extractor.Package, error) {
	if strings.EqualFold(gitRef, "HEAD") || strings.EqualFold(gitRef, "HEAD~0") {
		if ws == nil {
			return nil, fmt.Errorf("workspace is required for working tree scans")
		}
		return inventory.ScanPackagesWorking(ctx, ws, opts)
	}
	if repo == nil {
		return nil, fmt.Errorf("repository is required")
	}
	h, err := repo.ResolveRevision(plumbing.Revision(gitRef))
	if err != nil {
		return nil, err
	}
	return inventory.ScanPackagesAtCommitSnapshot(ctx, repo, *h, opts)
}

func resolveRepoMetadata(repo *git.Repository, ref, fallbackOrigin string) (string, string) {
	if repo == nil {
		return "", fallbackOrigin
	}
	commitHash := ""
	if h, err := gitx.ResolveRevisionEnhanced(repo, ref); err == nil && h != nil {
		commitHash = h.String()
	} else if head, err := repo.Head(); err == nil && head != nil {
		commitHash = head.Hash().String()
	}
	origin := fallbackOrigin
	if remote, err := repo.Remote("origin"); err == nil && remote != nil {
		if cfg := remote.Config(); cfg != nil {
			for _, raw := range cfg.URLs {
				candidate := strings.TrimSpace(raw)
				if candidate == "" {
					continue
				}
				if https := ToHTTPSGitURL(candidate); https != "" {
					origin = https
				} else {
					origin = candidate
				}
				break
			}
		}
	}
	return commitHash, origin
}

// buildProtobomDocument converts the scalibr packages into a Protobom doc.
func buildProtobomDocument(ctx context.Context, ws workspace.FS, repoRef, ref, name string, pkgs []*extractor.Package, directDeps map[string]bool) (*sbom.Document, error) {
	if name == "" {
		name = fmt.Sprintf("%s@%s", repoRef, ref)
	}

	d := sbom.NewDocument()
	d.Metadata.Name = name
	d.Metadata.Date = timestamppb.New(time.Now())

	app := sbom.NewNode()
	app.Id = "application:root"
	app.Type = sbom.Node_PACKAGE
	app.Name = name
	d.NodeList.Nodes = append(d.NodeList.Nodes, app)
	d.NodeList.RootElements = append(d.NodeList.RootElements, app.Id)

	ghaCache := &githubActionsResolutionCache{}

	for _, p := range pkgs {
		if p == nil || p.Name == "" {
			continue
		}
		n := sbom.NewNode()
		var purlStr string
		if purlx.IsGitHubActionsType(p.PURLType) {
			purlStr = purlx.GitHubActionsPURLFromPackage(p)
		} else if pu := p.PURL(); pu != nil {
			purlStr = normalizeGolangPURLString(pu.String(), ws)
		}
		if purlStr != "" {
			n.Id = spdxSafeIDFromPURL(purlStr)
		} else {
			n.Id = fmt.Sprintf("pkg:%s@%s", p.Name, p.Version)
		}
		n.Type = sbom.Node_PACKAGE
		n.Name = deriveDisplayName(p.Name, purlStr)
		n.Version = p.Version
		if purlStr != "" {
			if n.Identifiers == nil {
				n.Identifiers = map[int32]string{}
			}
			n.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purlStr
		}

		if purlx.IsGitHubActionsType(p.PURLType) {
			// Preserve the uses ref as written in the workflow/action file, but
			// also attach a best-effort resolved tag+commit for higher-fidelity SBOMs.
			n.Properties = append(n.Properties, &sbom.Property{
				Name: "deputy:requestedRef",
				Data: strings.TrimSpace(p.Version),
			})
			// GitHub Actions "uses: owner/repo@v2" is effectively a moving tag.
			// We treat it as a direct dependency in Deputy's SCA model.
			n.Properties = append(n.Properties, &sbom.Property{
				Name: "deputy:direct",
				Data: "true",
			})
			if ctx == nil {
				ctx = context.Background()
			}
			res := resolveGitHubActionsRefForSBOM(ctx, ghaCache, p.Name, p.Version)
			if res.ResolvedTag != "" {
				n.Properties = append(n.Properties, &sbom.Property{Name: "deputy:resolvedTag", Data: res.ResolvedTag})
			}
			if res.ResolvedVersion != "" {
				n.Properties = append(n.Properties, &sbom.Property{Name: "deputy:resolvedVersion", Data: res.ResolvedVersion})
			}
			if res.ResolvedCommit != "" {
				n.Properties = append(n.Properties, &sbom.Property{Name: "deputy:resolvedCommit", Data: res.ResolvedCommit})
			}
		}

		// Mark direct dependencies.
		// We use a custom property "deputy:direct" because Protobom's Node struct
		// does not have a native field for dependency directness (unlike CycloneDX's
		// dependency graph or SPDX's relationship types, which are not fully exposed
		// in the flat Node list in a way that persists easily through all formats).
		isDirect := false
		if directDeps != nil {
			nameToCheck := p.Name
			if pu := p.PURL(); pu != nil && pu.Type == purl.TypeGolang {
				info := compare.ParseGoPackage(p)
				nameToCheck = compare.GetModuleRoot(info.CanonicalName)
			}
			if directDeps[nameToCheck] {
				isDirect = true
			}
		}

		if isDirect {
			n.Properties = append(n.Properties, &sbom.Property{
				Name: "deputy:direct",
				Data: "true",
			})
		}

		// Persist location evidence (e.g. "go.mod").
		// Protobom's Node struct does not currently have a dedicated "Evidence" or
		// "Occurrences" field that maps to CycloneDX's component.evidence.occurrences.
		// We use "deputy:location" to preserve this context for remediation commands.
		for _, loc := range p.Locations {
			n.Properties = append(n.Properties, &sbom.Property{
				Name: "deputy:location",
				Data: loc,
			})
		}

		d.NodeList.Nodes = append(d.NodeList.Nodes, n)
		d.NodeList.Edges = append(d.NodeList.Edges, &sbom.Edge{
			Type: sbom.Edge_contains,
			From: app.Id,
			To:   []string{n.Id},
		})
	}
	return d, nil
}

type remoteFetcher struct{ Timeout time.Duration }

// License enrichment helpers.
func enrichProtobomLicensesDepsDev(ctx context.Context, doc *sbom.Document) error {
	if doc == nil || doc.NodeList == nil || len(doc.NodeList.Nodes) == 0 {
		return nil
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("deps.dev trust store: %w", err)
	}
	conn, err := grpc.NewClient("api.deps.dev:443", grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(certPool, "")))
	if err != nil {
		return fmt.Errorf("deps.dev dial: %w", err)
	}
	defer conn.Close()
	client := pb.NewInsightsClient(conn)

	cache := map[string][]string{}
	for _, node := range doc.NodeList.Nodes {
		if node == nil || len(node.GetLicenses()) > 0 {
			continue
		}
		pu := nodePackageURL(node)
		if pu == nil {
			continue
		}
		sys := systemFromPURL(pu)
		if sys == pb.System_SYSTEM_UNSPECIFIED {
			continue
		}
		name := packageNameForSystem(pu, sys)
		version := normalizeVersionForSystem(sys, strings.TrimSpace(pu.Version))
		if name == "" || version == "" {
			continue
		}
		key := fmt.Sprintf("%d|%s|%s", sys, name, version)
		if cached, ok := cache[key]; ok {
			node.Licenses = appendUniqueLicenses(node.Licenses, cached)
			continue
		}
		resp, err := client.GetVersion(ctx, &pb.GetVersionRequest{VersionKey: &pb.VersionKey{System: sys, Name: name, Version: version}})
		if err != nil || resp == nil || len(resp.Licenses) == 0 {
			continue
		}
		cache[key] = resp.Licenses
		node.Licenses = appendUniqueLicenses(node.Licenses, resp.Licenses)
	}
	return nil
}

func enrichProtobomLicensesScanLocal(_ context.Context, doc *sbom.Document, ws workspace.FS) error {
	if doc == nil || ws == nil {
		return nil
	}
	root := rootNode(doc)
	if root == nil {
		return nil
	}
	ids := analysis.LocalRepoLicenseScan(ws)
	if len(ids) == 0 {
		return nil
	}
	root.Licenses = appendUniqueLicenses(root.Licenses, ids)
	return nil
}

func enrichProtobomLicensesScanWithFetcher(ctx context.Context, doc *sbom.Document, fetcher *remoteFetcher) error {
	if doc == nil || fetcher == nil {
		return nil
	}
	if fetcher.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fetcher.Timeout)
		defer cancel()
	}
	for _, node := range doc.NodeList.Nodes {
		if node == nil || len(node.GetLicenses()) > 0 {
			continue
		}
		pu := nodePackageURL(node)
		if pu == nil {
			continue
		}
		eco := strings.ToLower(strings.TrimSpace(pu.Type))
		version := strings.TrimSpace(pu.Version)
		if eco == "" || version == "" {
			continue
		}
		name := packageNameForLicenseLookup(pu)
		if name == "" {
			continue
		}
		if ids := analysis.LookupLicensesBestEffort(ctx, eco, name, version); len(ids) > 0 {
			node.Licenses = appendUniqueLicenses(node.Licenses, ids)
		}
	}
	return nil
}

func nodePackageURL(n *sbom.Node) *purl.PackageURL {
	if n == nil || len(n.Identifiers) == 0 {
		return nil
	}
	val, ok := n.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]
	if !ok || strings.TrimSpace(val) == "" {
		return nil
	}
	pp, err := purlx.ParseLoose(strings.TrimSpace(val))
	if err != nil {
		return nil
	}
	pu := purl.PackageURL{
		Type:       pp.Type,
		Namespace:  pp.Namespace,
		Name:       pp.Name,
		Version:    pp.Version,
		Qualifiers: purl.Qualifiers(pp.Qualifiers),
		Subpath:    pp.Subpath,
	}
	return &pu
}

func systemFromPURL(pu *purl.PackageURL) pb.System {
	if pu == nil {
		return pb.System_SYSTEM_UNSPECIFIED
	}
	switch strings.ToLower(pu.Type) {
	case purl.TypeGolang:
		return pb.System_GO
	case purl.TypeNPM:
		return pb.System_NPM
	case purl.TypeCargo:
		return pb.System_CARGO
	case purl.TypePyPi:
		return pb.System_PYPI
	case purl.TypeGem:
		return pb.System_RUBYGEMS
	case purl.TypeMaven:
		return pb.System_MAVEN
	case purl.TypeNuget:
		return pb.System_NUGET
	default:
		return pb.System_SYSTEM_UNSPECIFIED
	}
}

func packageNameForSystem(pu *purl.PackageURL, sys pb.System) string {
	if pu == nil {
		return ""
	}
	switch sys {
	case pb.System_GO:
		return goModuleFromPURL(pu)
	case pb.System_NPM:
		if pu.Namespace != "" {
			return "@" + pu.Namespace + "/" + pu.Name
		}
	case pb.System_RUBYGEMS, pb.System_CARGO, pb.System_PYPI, pb.System_NUGET:
		if pu.Namespace != "" {
			return pu.Namespace + "/" + pu.Name
		}
	default:
		if pu.Namespace != "" {
			return pu.Namespace + "/" + pu.Name
		}
	}
	return pu.Name
}

func normalizeVersionForSystem(sys pb.System, version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return ""
	}
	if sys == pb.System_GO && !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

func goModuleFromPURL(pu *purl.PackageURL) string {
	if pu == nil {
		return ""
	}
	switch {
	case pu.Namespace != "":
		return strings.TrimSuffix(pu.Namespace, "/") + "/" + pu.Name
	default:
		return pu.Name
	}
}

func appendUniqueLicenses(dst []string, src []string) []string {
	if len(src) == 0 {
		return dst
	}
	seen := map[string]struct{}{}
	for _, existing := range dst {
		seen[existing] = struct{}{}
	}
	for _, candidate := range src {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		dst = append(dst, candidate)
	}
	return dst
}

func packageNameForLicenseLookup(pu *purl.PackageURL) string {
	if pu == nil {
		return ""
	}
	switch strings.ToLower(pu.Type) {
	case purl.TypeGolang:
		return goModuleFromPURL(pu)
	case purl.TypeGithub:
		if pu.Namespace != "" {
			return "github.com/" + pu.Namespace + "/" + pu.Name
		}
		return "github.com/" + pu.Name
	default:
		if pu.Namespace != "" {
			return pu.Namespace + "/" + pu.Name
		}
		return pu.Name
	}
}

func rootNode(doc *sbom.Document) *sbom.Node {
	if doc == nil || doc.NodeList == nil || len(doc.NodeList.RootElements) == 0 {
		return nil
	}
	target := doc.NodeList.RootElements[0]
	for _, node := range doc.NodeList.Nodes {
		if node != nil && node.Id == target {
			return node
		}
	}
	return nil
}

// Git helpers
func ToHTTPSGitURL(ref string) string {
	s := strings.TrimSpace(ref)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if !strings.HasSuffix(s, ".git") {
			s += ".git"
		}
		return s
	}
	if strings.HasPrefix(s, "github.com/") {
		if !strings.HasSuffix(s, ".git") {
			s += ".git"
		}
		return "https://" + s
	}
	return ""
}

func AuthForURL(rawurl string) transport.AuthMethod {
	if u, err := neturl.Parse(rawurl); err == nil && u.Scheme == "https" && u.Host == "github.com" {
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			return &http.BasicAuth{Username: "oauth2", Password: token}
		}
	}
	return nil
}

func ResolveReferenceName(ctx context.Context, remoteURL string, auth transport.AuthMethod, refStr string) (plumbing.ReferenceName, error) {
	r := strings.TrimSpace(refStr)
	if r == "" || strings.EqualFold(r, "HEAD") {
		if br := discoverDefaultBranch(ctx, remoteURL, auth); br != "" {
			return plumbing.ReferenceName(br), nil
		}
		return "", fmt.Errorf("could not discover default branch")
	}
	if strings.HasPrefix(r, "refs/") {
		return plumbing.ReferenceName(r), nil
	}
	if looksLikeTag(r) {
		return plumbing.ReferenceName("refs/tags/" + r), nil
	}
	return plumbing.ReferenceName("refs/heads/" + r), nil
}

func looksLikeTag(r string) bool {
	if strings.HasPrefix(strings.ToLower(r), "v") {
		return true
	}
	for _, c := range r {
		if (c < '0' || c > '9') && c != '.' && c != '-' && c != '_' && c != 'v' {
			return false
		}
	}
	return true
}

func discoverDefaultBranch(ctx context.Context, remoteURL string, auth transport.AuthMethod) string {
	r := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	refs, err := r.ListContext(ctx, &git.ListOptions{Auth: auth})
	if err != nil || len(refs) == 0 {
		// Fallback to common defaults
		return "refs/heads/main"
	}
	// Find HEAD symbolic ref or common branches
	var hasMain, hasMaster bool
	for _, ref := range refs {
		if ref.Name() == plumbing.HEAD && ref.Target().IsBranch() {
			return ref.Target().String()
		}
		if ref.Name() == plumbing.ReferenceName("refs/heads/main") {
			hasMain = true
		}
		if ref.Name() == plumbing.ReferenceName("refs/heads/master") {
			hasMaster = true
		}
	}
	if hasMain {
		return "refs/heads/main"
	}
	if hasMaster {
		return "refs/heads/master"
	}
	return "refs/heads/main"
}

func listRemoteRefs(ctx context.Context, remoteURL string, auth transport.AuthMethod) ([]*plumbing.Reference, error) {
	r := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	return r.ListContext(ctx, &git.ListOptions{Auth: auth})
}

type githubActionsResolution struct {
	ResolvedTag     string
	ResolvedVersion string
	ResolvedCommit  string
}

type githubActionsResolutionCache struct {
	mu    sync.Mutex
	cache map[string]githubActionsResolution
}

func (c *githubActionsResolutionCache) get(key string) (githubActionsResolution, bool) {
	if c == nil {
		return githubActionsResolution{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		return githubActionsResolution{}, false
	}
	v, ok := c.cache[key]
	return v, ok
}

func (c *githubActionsResolutionCache) set(key string, v githubActionsResolution) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[string]githubActionsResolution{}
	}
	c.cache[key] = v
}

var listRemoteRefsForSBOM = listRemoteRefs

// resolveGitHubActionsRefForSBOM resolves a GitHub Actions repository ref (e.g. "v2")
// to a more specific immutable reference when possible (e.g. highest "v2.x.y" tag)
// and includes its commit hash.
//
// Resolution is best-effort: failures return an empty result and should not fail SBOM generation.
func resolveGitHubActionsRefForSBOM(ctx context.Context, cache *githubActionsResolutionCache, repo, ref string) githubActionsResolution {
	repo = strings.TrimSpace(repo)
	ref = strings.TrimSpace(ref)
	if repo == "" || ref == "" {
		return githubActionsResolution{}
	}
	key := repo + "@" + ref
	if v, ok := cache.get(key); ok {
		return v
	}

	remoteURL := ToHTTPSGitURL("github.com/" + repo)
	if remoteURL == "" {
		cache.set(key, githubActionsResolution{})
		return githubActionsResolution{}
	}

	refs, err := listRemoteRefsForSBOM(ctx, remoteURL, AuthForURL(remoteURL))
	if err != nil || len(refs) == 0 {
		cache.set(key, githubActionsResolution{})
		return githubActionsResolution{}
	}

	resolved := resolveGitHubActionsRefFromRefs(refs, ref)
	cache.set(key, resolved)
	return resolved
}

// resolveGitHubActionsRefFromRefs resolves a ref using an already-listed remote ref set.
// It is deterministic and does not perform network calls (used by tests).
func resolveGitHubActionsRefFromRefs(refs []*plumbing.Reference, requested string) githubActionsResolution {
	requested = strings.TrimSpace(requested)
	if requested == "" || len(refs) == 0 {
		return githubActionsResolution{}
	}
	if looksLikeCommitSHA(requested) {
		return githubActionsResolution{ResolvedCommit: requested}
	}

	peeled := map[string]string{}
	raw := map[string]string{}
	for _, r := range refs {
		if r == nil {
			continue
		}
		name := r.Name().String()
		if name == "" {
			continue
		}
		hash := r.Hash().String()
		if strings.HasSuffix(name, "^{}") {
			peeled[strings.TrimSuffix(name, "^{}")] = hash
			continue
		}
		raw[name] = hash
	}
	commitForTag := func(tag string) string {
		if tag == "" {
			return ""
		}
		full := "refs/tags/" + tag
		if h := peeled[full]; h != "" {
			return h
		}
		return raw[full]
	}
	commitForHead := func(branch string) string {
		full := "refs/heads/" + branch
		return raw[full]
	}

	// If this is a rolling major/minor reference, pick the highest matching semver tag.
	if major, minor, ok := parseGHARollingRef(requested); ok {
		best := ""
		for name := range raw {
			if !strings.HasPrefix(name, "refs/tags/") {
				continue
			}
			tag := strings.TrimPrefix(name, "refs/tags/")
			tag = strings.TrimSuffix(tag, "^{}")
			if !strings.HasPrefix(tag, "v") {
				continue
			}
			canon := semver.Canonical(tag)
			if canon == "" {
				continue
			}
			if semver.Major(canon) != fmt.Sprintf("v%d", major) {
				continue
			}
			if minor >= 0 && semver.MajorMinor(canon) != fmt.Sprintf("v%d.%d", major, minor) {
				continue
			}
			if best == "" || semver.Compare(canon, best) > 0 {
				best = canon
			}
		}
		if best != "" {
			tag := best
			commit := commitForTag(tag)
			return githubActionsResolution{ResolvedTag: tag, ResolvedVersion: tag, ResolvedCommit: commit}
		}
		return githubActionsResolution{}
	}

	// Immutable semver tag: resolve to its commit.
	if canon := semver.Canonical(requested); canon != "" && strings.Count(strings.TrimPrefix(canon, "v"), ".") == 2 {
		commit := commitForTag(canon)
		if commit != "" {
			return githubActionsResolution{ResolvedTag: canon, ResolvedVersion: canon, ResolvedCommit: commit}
		}
	}

	// Try tags/branches by name as a best-effort for "master"/"main".
	if h := commitForTag(requested); h != "" {
		return githubActionsResolution{ResolvedTag: requested, ResolvedCommit: h}
	}
	if h := commitForHead(requested); h != "" {
		return githubActionsResolution{ResolvedTag: requested, ResolvedCommit: h}
	}
	return githubActionsResolution{}
}

func looksLikeCommitSHA(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// parseGHARollingRef parses GitHub Actions rolling major/minor refs such as:
// "v2", "2", "v2.3", "2.3".
//
// For major-only refs, minor will be -1.
func parseGHARollingRef(s string) (major int, minor int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}
	if strings.HasPrefix(s, "v") {
		s = strings.TrimPrefix(s, "v")
	}
	if strings.Count(s, ".") == 0 {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			return 0, 0, false
		}
		return n, -1, true
	}
	if strings.Count(s, ".") == 1 {
		parts := strings.SplitN(s, ".", 2)
		maj, err1 := strconv.Atoi(parts[0])
		min, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || maj <= 0 || min < 0 {
			return 0, 0, false
		}
		return maj, min, true
	}
	return 0, 0, false
}

// PURL helpers
func normalizeGolangPURLString(purlStr string, ws workspace.FileReader) string {
	if purlStr == "" {
		return purlStr
	}
	pp, err := purl.FromString(purlStr)
	if err != nil || pp.Type != purl.TypeGolang {
		return purlStr
	}
	full := pp.Name
	if pp.Namespace != "" {
		full = pp.Namespace + "/" + pp.Name
	}
	if full == "." || strings.HasPrefix(full, "./") {
		modPath := readModulePath(ws)
		if modPath == "" {
			return purlStr
		}
		rel := strings.TrimPrefix(full, "./")
		if rel == "." {
			rel = ""
		}
		full = modPath
		if rel != "" {
			full = modPath + "/" + rel
		}
	}
	if idx := strings.LastIndex(full, "/"); idx >= 0 {
		pp.Namespace = full[:idx]
		pp.Name = full[idx+1:]
	} else {
		pp.Namespace = ""
		pp.Name = full
	}
	return pp.String()
}

func readModulePath(ws workspace.FileReader) string {
	if ws == nil {
		return ""
	}
	b, err := ws.ReadFile("go.mod")
	if err != nil {
		return ""
	}
	if mf, err := modfile.Parse("go.mod", b, nil); err == nil && mf != nil && mf.Module != nil {
		return mf.Module.Mod.Path
	}
	return ""
}

func deriveDisplayName(name, purlStr string) string {
	if purlStr != "" {
		if pu, err := purl.FromString(purlStr); err == nil {
			return pu.Name
		}
	}
	return name
}

func spdxSafeIDFromPURL(purlStr string) string {
	if purlStr == "" {
		return ""
	}
	s := strings.TrimPrefix(purlStr, "pkg:")
	if dec, err := neturl.PathUnescape(s); err == nil && dec != "" {
		s = dec
	}
	s = "pkg-" + s
	return sanitizeForSPDXID(s)
}

func sanitizeForSPDXID(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := false
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	return b.String()
}

// shortGitRef removed (unused)

// Writers
func WriteCycloneDXJSON(doc *sbom.Document, w io.Writer) error {
	return writer.New(writer.WithFormat(formats.CDX16JSON)).WriteStream(doc, w)
}

func WriteSPDXJSON(doc *sbom.Document, w io.Writer) error {
	return writer.New(writer.WithFormat(formats.SPDX23JSON)).WriteStream(doc, w)
}

func WriteProtobomJSON(doc *sbom.Document, w io.Writer) error {
	enc := protojson.MarshalOptions{Indent: "  ", UseEnumNumbers: false, EmitUnpopulated: false}
	b, err := enc.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
