package sbomx

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
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
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/temporalio/deputy/internal/auth"
	"github.com/temporalio/deputy/internal/collections"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/dockerfile"
	gitx "github.com/temporalio/deputy/internal/gitutil"
	"github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/license"
	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/otel"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/repository"
	"github.com/temporalio/deputy/internal/repository/workspace"
	"github.com/temporalio/deputy/internal/targets"
	"github.com/temporalio/deputy/internal/version"
)

// HTTP client timeout for remote license scanning during SBOM enrichment.
const remoteLicenseFetchTimeout = 20 * time.Second

// Options configures SBOM generation behavior and enrichment passes.
type Options struct {
	// Ref specifies the git reference (branch, tag, or commit) to generate the SBOM from.
	// Defaults to "HEAD" if empty.
	Ref string
	// Ecosystems filters which package ecosystems to include (e.g., "go", "npm").
	// An empty slice includes all detected ecosystems.
	Ecosystems []string
	// ExcludePaths lists glob patterns for directory paths to skip during the
	// filesystem walk (e.g., ".bin/**"). Matching subtrees are never inventoried.
	ExcludePaths []string
	// Name overrides the SBOM document name. If empty, defaults to "repoRef@ref".
	Name string
	// EnrichLicenses enables license enrichment for packages in the SBOM.
	EnrichLicenses bool
	// LicenseSource specifies where to fetch license data: "depsdev", "scan", or "both".
	LicenseSource string
	// Enrich enables comprehensive SBOM enrichment (CPEs, external refs, suppliers, etc.).
	// When true, calls deps.dev to add CPE identifiers, VCS URLs, homepage links,
	// supplier information, and package publish dates to each component.
	Enrich bool
	// EnrichConcurrency controls how many parallel deps.dev requests are made during enrichment.
	// Defaults to 10 if not set.
	EnrichConcurrency int
}

// Validate checks that Options are valid.
// Returns an error if LicenseSource is set but not a recognized value.
func (o Options) Validate() error {
	if o.EnrichLicenses && o.LicenseSource != "" {
		switch strings.ToLower(o.LicenseSource) {
		case "depsdev", "deps", "dd", "scan", "both":
			// Valid
		default:
			return fmt.Errorf("invalid license source %q: must be one of depsdev, scan, or both", o.LicenseSource)
		}
	}
	if o.EnrichConcurrency < 0 {
		return fmt.Errorf("enrichment concurrency must be non-negative, got %d", o.EnrichConcurrency)
	}
	return nil
}

// Result captures the SBOM document alongside contextual metadata that callers
// can surface to users (e.g., --show-context banner in the CLI).
type Result struct {
	// Document is the generated Protobom SBOM document.
	Document *sbom.Document
	// Target captures the normalized scan target metadata for policies and context output.
	Target inventory.Target
	// RepoPath is the local or remote repository path that was scanned.
	RepoPath string
	// Ref is the git reference that was resolved (may differ from input if normalized).
	Ref string
	// Commit is the resolved commit hash for the scanned reference.
	Commit string
	// Origin is the repository's remote origin URL (if available).
	Origin string
	// Packages is the raw list of packages discovered by the inventory scanner.
	Packages []*extractor.Package
	// Direct marks which of Packages are direct dependencies, keyed the way
	// [protoconv.ExtractorPackageIsDirect] expects (module roots for Go, PURL
	// strings otherwise). It is nil when the target carries no manifest to
	// derive directness from, such as a container image.
	Direct map[string]bool
}

// Generate builds an SBOM document for repoPath (local) or a remote reference.
// Generate produces a Protobom SBOM document for the supplied repository path
// (local path or remote reference). Remote repositories are shallow cloned
// (depth 1) to a temporary directory and cleaned up automatically.
func Generate(ctx context.Context, repoRef string, opts Options) (Result, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.sbom.generate",
		trace.WithAttributes(
			attribute.String("deputy.target.path", repoRef),
			attribute.String("deputy.target.ref", opts.Ref),
			attribute.Bool("deputy.sbom.enrich_licenses", opts.EnrichLicenses),
		))
	defer span.End()

	if opts.Ref == "" {
		opts.Ref = "HEAD"
	}

	var (
		src *repository.Source
		err error
	)

	result := Result{Ref: opts.Ref}
	repoDisplay := repoRef
	cloned := false
	nonGit := false
	if fi, statErr := os.Stat(repoRef); statErr == nil && fi.IsDir() {
		if abs, absErr := filepath.Abs(repoRef); absErr == nil {
			repoDisplay = abs
		}

		src, err = repository.Open(repoRef)
		if err != nil {
			// Not a git repository: fall back to a plain working-tree SBOM. This
			// requires HEAD (the current files on disk); arbitrary git refs are
			// unavailable without a repository.
			if !strings.EqualFold(opts.Ref, "HEAD") {
				return Result{}, fmt.Errorf("cannot resolve ref %q: %q is not a git repository", opts.Ref, repoDisplay)
			}
			src, err = repository.OpenDir(repoRef)
			if err != nil {
				return Result{}, fmt.Errorf("open directory: %w", err)
			}
			nonGit = true
		}
	}
	if src == nil {
		url := gitx.ToHTTPSGitURL(repoRef)
		if url == "" {
			err := fmt.Errorf("could not interpret target %q as local path or remote Git URL", repoRef)
			otel.SetSpanError(span, err)
			return Result{}, err
		}
		// Use the unified auth package for secure, host-aware credential resolution
		gitAuth, _ := auth.GitAuthForURL(ctx, url)
		refName, resolveErr := gitx.ResolveReferenceName(ctx, url, gitAuth, opts.Ref)
		if resolveErr == nil && refName.String() != "" {
			opts.Ref = refName.String()
		}
		cloneOpts := &git.CloneOptions{
			URL:          url,
			Depth:        1,
			SingleBranch: true,
			Tags:         git.NoTags,
			Auth:         gitAuth,
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
		cloned = true
	}
	defer src.Close()
	result.RepoPath = repoDisplay
	result.Ref = opts.Ref

	effRef := opts.Ref
	if strings.EqualFold(effRef, "HEAD") {
		effRef = "HEAD~0"
	}

	pkgs, err := collectInventorySBOM(ctx, src.Repo, src.Workspace(), effRef, inventory.ScanOptions{Ecosystems: opts.Ecosystems, ExcludePaths: opts.ExcludePaths})
	if err != nil {
		otel.SetSpanError(span, err)
		return Result{}, err
	}

	// An SBOM inventories every ecosystem Deputy extracts, so its direct
	// dependency set has to come from every ecosystem's manifests too. The
	// Go-only collectors left each npm, Cargo, and PyPI component marked
	// indirect, which is what a policy scoped to direct dependencies reads.
	var directDeps map[string]bool
	switch {
	case strings.EqualFold(effRef, "HEAD") || strings.EqualFold(effRef, "HEAD~0"):
		directDeps = compare.CollectDirectDependenciesFromWorkspace(src.Workspace())
	default:
		if hash, err := gitx.ResolveRevisionEnhanced(src.Repo, effRef); err == nil {
			directDeps, _ = compare.CollectDirectDependenciesFromCommit(src.Repo, *hash)
		}
	}

	doc, err := buildProtobomDocument(ctx, src.Workspace(), repoRef, opts.Ref, opts.Name, pkgs, directDeps, opts.Ecosystems)
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
			if err := enrichProtobomLicensesScanLocal(ctx, doc, src.Workspace()); err != nil {
				return Result{}, err
			}
			fetcher := &remoteFetcher{Timeout: remoteLicenseFetchTimeout}
			if err := enrichProtobomLicensesScanWithFetcher(ctx, doc, fetcher); err != nil {
				return Result{}, err
			}
		case "both":
			if err := enrichProtobomLicensesDepsDev(ctx, doc); err != nil {
				return Result{}, err
			}
			if err := enrichProtobomLicensesScanLocal(ctx, doc, src.Workspace()); err != nil {
				return Result{}, err
			}
			fetcher := &remoteFetcher{Timeout: remoteLicenseFetchTimeout}
			if err := enrichProtobomLicensesScanWithFetcher(ctx, doc, fetcher); err != nil {
				return Result{}, err
			}
		default:
			return Result{}, fmt.Errorf("unsupported license source: %s", opts.LicenseSource)
		}
	}

	// Comprehensive SBOM enrichment (CPEs, external refs, suppliers, etc.)
	if opts.Enrich {
		concurrency := opts.EnrichConcurrency
		if concurrency <= 0 {
			concurrency = 10
		}
		enrichOpts := EnrichOptions{
			AddCPEs:          true,
			AddSuppliers:     true,
			AddExternalRefs:  true,
			AddPublishedDate: true,
			Concurrency:      concurrency,
		}
		if _, err := Enrich(ctx, doc, enrichOpts); err != nil {
			return Result{}, fmt.Errorf("failed to enrich SBOM: %w", err)
		}
	}

	commit, origin := resolveRepoMetadata(src.Repo, effRef, repoDisplay)
	localPath := src.RootPath()
	result.Commit = commit
	result.Origin = origin
	result.Document = doc
	result.Packages = pkgs
	result.Direct = directDeps
	targetKind := targets.KindGit
	if nonGit {
		targetKind = targets.KindDir
	}
	result.Target = inventory.Target{
		Kind:         targetKind,
		DisplayPath:  repoDisplay,
		LocalPath:    localPath,
		Ref:          opts.Ref,
		EffectiveRef: effRef,
		CommitHash:   commit,
		OriginURL:    origin,
		Cloned:       cloned,
	}

	// Record results on span
	span.SetAttributes(
		attribute.Int("deputy.package.count", len(pkgs)),
		attribute.String("deputy.sbom.commit", commit),
	)

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
				if https := gitx.ToHTTPSGitURL(candidate); https != "" {
					origin = https
				}
				if origin == fallbackOrigin {
					origin = candidate
				}
				break
			}
		}
	}
	return commitHash, origin
}

// buildProtobomDocument converts the scalibr packages into a Protobom doc.
func buildProtobomDocument(ctx context.Context, ws workspace.FS, repoRef, ref, name string, pkgs []*extractor.Package, directDeps map[string]bool, ecosystems []string) (*sbom.Document, error) {
	if name == "" {
		name = fmt.Sprintf("%s@%s", repoRef, ref)
	}

	d := sbom.NewDocument()
	d.Metadata.Name = name
	d.Metadata.Date = timestamppb.New(time.Now())

	// Add SBOM tool metadata for NTIA compliance
	d.Metadata.Tools = append(d.Metadata.Tools, &sbom.Tool{
		Name:    "deputy",
		Version: version.Value,
		Vendor:  "github.com/temporalio/deputy",
	})

	app := sbom.NewNode()
	app.Id = "application:root"
	app.Type = sbom.Node_PACKAGE
	app.Name = name
	d.NodeList.Nodes = append(d.NodeList.Nodes, app)
	d.NodeList.RootElements = append(d.NodeList.RootElements, app.Id)

	ghaCache := &githubActionsResolutionCache{}

	// Node ids must be unique within a protobom document. The same artifact can
	// reach this builder from two producers (a Dockerfile base image arrives
	// from the stage-aware Dockerfile pass and again as the dockerfilex
	// extractor's package), so every append records its id here and later
	// producers skip ids already modeled.
	seenNodeIDs := map[string]struct{}{app.Id: {}}

	if includeDockerfileBaseImages(ecosystems) {
		dockerfiles, _ := discoverAndParseDockerfiles(ws)
		if len(dockerfiles) > 0 {
			addDockerfileBaseImagesToSBOM(d, dockerfiles, app.Id, seenNodeIDs)
		}
	}

	for _, p := range pkgs {
		if p == nil || p.Name == "" {
			continue
		}
		// Skip relative path replace directives (e.g., "../..", "./local").
		// These are local development artifacts from go.mod replace directives.
		if p.PURLType == purl.TypeGolang && compare.IsRelativePathModule(p.Name) {
			continue
		}
		n := sbom.NewNode()
		var purlStr string
		switch {
		case purlx.IsGitHubActionsType(p.PURLType):
			purlStr = purlx.GitHubActionsPURLFromPackage(p)
		case p.PURL() != nil:
			purlStr = normalizeGolangPURLString(p.PURL().String(), ws)
		}
		n.Id = fmt.Sprintf("pkg:%s@%s", p.Name, p.Version)
		if purlStr != "" {
			n.Id = spdxSafeIDFromPURL(purlStr)
		}
		// Skip artifacts an earlier producer already modeled (see seenNodeIDs).
		if _, ok := seenNodeIDs[n.Id]; ok {
			continue
		}
		seenNodeIDs[n.Id] = struct{}{}
		n.Type = sbom.Node_PACKAGE
		n.Name = deriveDisplayName(p.Name, purlStr)
		n.Version = p.Version

		// Copy licenses from SCALIBR extraction (APK, RPM, etc. provide licenses directly).
		// This enables immediate license visibility for OS packages without enrichment.
		if len(p.Licenses) > 0 {
			n.Licenses = append(n.Licenses, p.Licenses...)
		}

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

		// mise-managed tools: attach the exact locked version and per-platform
		// integrity references from a sibling mise.lock, when present.
		if md, ok := p.Metadata.(*mise.Metadata); ok {
			addMiseLockReferences(n, md)
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

		// Persist container image layer details for round-trip SBOM scanning.
		// These properties enable layer-aware vulnerability analysis and policy
		// evaluation when scanning SBOMs generated from container images.
		// Note: p.LayerDetails is extractor.LayerDetails (SCALIBR type) which uses DiffID/ChainID.
		if p.LayerDetails != nil {
			n.Properties = append(n.Properties, &sbom.Property{
				Name: "deputy:layer-index",
				Data: fmt.Sprintf("%d", p.LayerDetails.Index),
			})
			if p.LayerDetails.DiffID != "" {
				n.Properties = append(n.Properties, &sbom.Property{
					Name: "deputy:layer-diffid",
					Data: p.LayerDetails.DiffID,
				})
			}
			if p.LayerDetails.ChainID != "" {
				n.Properties = append(n.Properties, &sbom.Property{
					Name: "deputy:layer-chainid",
					Data: p.LayerDetails.ChainID,
				})
			}
			if p.LayerDetails.Command != "" {
				n.Properties = append(n.Properties, &sbom.Property{
					Name: "deputy:layer-command",
					Data: p.LayerDetails.Command,
				})
			}
			if p.LayerDetails.InBaseImage {
				n.Properties = append(n.Properties, &sbom.Property{
					Name: "deputy:layer-in-base-image",
					Data: "true",
				})
			}
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

// includeDockerfileBaseImages reports whether repository Dockerfile base-image
// discovery should contribute components for the requested ecosystem filter.
func includeDockerfileBaseImages(ecosystems []string) bool {
	if len(ecosystems) == 0 {
		return true
	}
	for _, ecosystem := range ecosystems {
		switch collections.NormalizeLower(ecosystem) {
		case "", "all", "container", "containers", "container-image", "docker", "dockerfile", "containerfile", "oci":
			return true
		}
	}
	return false
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
	ids := license.LocalRepoLicenseScan(ws)
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
		eco := collections.NormalizeLower(pu.Type)
		version := strings.TrimSpace(pu.Version)
		name := packageNameForLicenseLookup(pu)
		if eco == "" || name == "" {
			continue
		}
		// Allow version-less lookups for GitHub-based packages (uses GitHub License API)
		isGitHubBased := eco == "github" || eco == "githubactions" ||
			(eco == "golang" && strings.HasPrefix(name, "github.com/"))
		if version == "" && !isGitHubBased {
			continue
		}
		if ids := license.LookupLicensesBestEffort(ctx, eco, name, version); len(ids) > 0 {
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

// miseHashAlgorithms maps mise.lock checksum algorithm names to protobom hash
// algorithm enum values.
var miseHashAlgorithms = map[string]sbom.HashAlgorithm{
	"sha256": sbom.HashAlgorithm_SHA256,
	"sha512": sbom.HashAlgorithm_SHA512,
	"sha1":   sbom.HashAlgorithm_SHA1,
	"blake3": sbom.HashAlgorithm_BLAKE3,
	"md5":    sbom.HashAlgorithm_MD5,
}

// addMiseLockReferences enriches a package node with the exact locked version
// and per-platform integrity metadata from a sibling mise.lock. Each platform's
// asset is modeled as a DOWNLOAD external reference carrying its URL and
// checksum: a faithful, non-lossy representation, since mise installs a
// distinct artifact per platform. When the lock pins exactly one platform, its
// checksum is also set as the component-level hash for conventional consumers.
func addMiseLockReferences(n *sbom.Node, md *mise.Metadata) {
	if n == nil || md == nil {
		return
	}
	if md.Version != "" && md.Version != n.Version {
		n.Properties = append(n.Properties, &sbom.Property{
			Name: "deputy:requestedVersion",
			Data: md.Version,
		})
	}
	if md.LockedVersion != "" && md.LockedVersion != n.Version {
		n.Properties = append(n.Properties, &sbom.Property{
			Name: "deputy:lockedVersion",
			Data: md.LockedVersion,
		})
	}

	// Deterministic platform order.
	plats := slices.Sorted(maps.Keys(md.Platforms))

	for _, plat := range plats {
		p := md.Platforms[plat]
		if p.Checksum == "" && p.URL == "" {
			continue
		}
		ref := &sbom.ExternalReference{
			Type:    sbom.ExternalReference_DOWNLOAD,
			Url:     p.URL,
			Comment: misePlatformComment(plat, p.Size),
		}
		if algoName, value := mise.ParseChecksum(p.Checksum); value != "" {
			if algo, ok := miseHashAlgorithms[algoName]; ok {
				ref.Hashes = map[int32]string{int32(algo): value}
			}
		}
		n.ExternalReferences = append(n.ExternalReferences, ref)
	}

	// Single unambiguous platform: also expose a component-level hash.
	if len(plats) == 1 {
		if algoName, value := mise.ParseChecksum(md.Platforms[plats[0]].Checksum); value != "" {
			if algo, ok := miseHashAlgorithms[algoName]; ok {
				if n.Hashes == nil {
					n.Hashes = map[int32]string{}
				}
				n.Hashes[int32(algo)] = value
			}
		}
	}
}

// misePlatformComment builds an external-reference comment identifying the
// platform and, when known, the asset size in bytes.
func misePlatformComment(platform string, size int64) string {
	if size > 0 {
		return fmt.Sprintf("mise platform %s (%d bytes)", platform, size)
	}
	return "mise platform " + platform
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
	mu    sync.RWMutex
	cache map[string]githubActionsResolution
}

func (c *githubActionsResolutionCache) get(key string) (githubActionsResolution, bool) {
	if c == nil {
		return githubActionsResolution{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
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

	remoteURL := gitx.ToHTTPSGitURL("github.com/" + repo)
	if remoteURL == "" {
		cache.set(key, githubActionsResolution{})
		return githubActionsResolution{}
	}

	gitAuth, _ := auth.GitAuthForURL(ctx, remoteURL)
	refs, err := listRemoteRefsForSBOM(ctx, remoteURL, gitAuth)
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
		if before, ok := strings.CutSuffix(name, "^{}"); ok {
			peeled[before] = hash
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
	s = strings.TrimPrefix(s, "v")
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
func normalizeGolangPURLString(purlStr string, ws workspace.ReadableFS) string {
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
	pp.Namespace = ""
	pp.Name = full
	if idx := strings.LastIndex(full, "/"); idx >= 0 {
		pp.Namespace = full[:idx]
		pp.Name = full[idx+1:]
	}
	return pp.String()
}

func readModulePath(ws workspace.ReadableFS) string {
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

// discoverAndParseDockerfiles walks the workspace to find all Dockerfiles and parses them.
// Returns parsed Dockerfile info for each discovered file.
func discoverAndParseDockerfiles(ws workspace.FS) ([]*dockerfile.Info, error) {
	if ws == nil {
		return nil, nil
	}

	var dockerfiles []*dockerfile.Info

	// Walk the workspace looking for Dockerfile patterns
	err := fs.WalkDir(ws, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors, continue walking
		}
		if d.IsDir() {
			// Skip common vendor/build directories
			name := d.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" {
				return fs.SkipDir
			}
			return nil
		}

		// Check if this looks like a Dockerfile
		if !isDockerfileFilename(d.Name()) {
			return nil
		}

		// Read and parse the Dockerfile
		content, err := ws.ReadFile(path)
		if err != nil {
			return nil // Skip unreadable files
		}

		info, err := dockerfile.Parse(bytes.NewReader(content))
		if err != nil {
			return nil // Skip unparseable files
		}
		info.Path = path

		dockerfiles = append(dockerfiles, info)
		return nil
	})

	if err != nil {
		return dockerfiles, nil // Return what we found even on walk errors
	}

	return dockerfiles, nil
}

// isDockerfileFilename checks if a filename matches Dockerfile naming patterns.
func isDockerfileFilename(name string) bool {
	lower := strings.ToLower(name)

	// Exact matches
	if lower == "dockerfile" || lower == "containerfile" {
		return true
	}

	// Prefix patterns: Dockerfile.*, Containerfile.*
	if strings.HasPrefix(lower, "dockerfile.") || strings.HasPrefix(lower, "containerfile.") {
		return true
	}

	// Suffix patterns: *.dockerfile, *.containerfile
	if strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile") {
		return true
	}

	// Suffix patterns: *Dockerfile, *Containerfile (case-sensitive check)
	if strings.HasSuffix(name, "Dockerfile") || strings.HasSuffix(name, "Containerfile") {
		return true
	}

	return false
}

// addDockerfileBaseImagesToSBOM adds base image references from Dockerfiles as SBOM nodes.
// Each base image becomes a component with a pkg:docker or pkg:oci PURL.
// addDockerfileBaseImagesToSBOM appends one node per unique Dockerfile base
// image, wired to the root via contains edges. Every appended node id is
// recorded in seenNodeIDs so later producers (the package loop also sees base
// images via the dockerfilex extractor) skip artifacts already modeled here.
func addDockerfileBaseImagesToSBOM(doc *sbom.Document, dockerfiles []*dockerfile.Info, appID string, seenNodeIDs map[string]struct{}) {
	if doc == nil || len(dockerfiles) == 0 {
		return
	}

	seen := make(map[string]bool) // Track unique base images to avoid duplicates

	for _, df := range dockerfiles {
		if df == nil {
			continue
		}

		for i := range df.Stages {
			stage := &df.Stages[i]
			if stage.IsScratch {
				continue // Skip scratch stages
			}

			baseImage := stage.BaseImage
			if baseImage == "" {
				continue
			}

			// Create a unique key for deduplication
			key := baseImage
			if seen[key] {
				continue
			}
			seen[key] = true

			// Create the SBOM node for this base image
			node := createBaseImageNode(stage, df.Path)
			if node == nil {
				continue
			}

			doc.NodeList.Nodes = append(doc.NodeList.Nodes, node)
			if seenNodeIDs != nil {
				seenNodeIDs[node.Id] = struct{}{}
			}

			// Add edge from root to this base image
			doc.NodeList.Edges = append(doc.NodeList.Edges, &sbom.Edge{
				Type: sbom.Edge_contains,
				From: appID,
				To:   []string{node.Id},
			})
		}
	}
}

// createBaseImageNode creates an SBOM node for a container base image.
func createBaseImageNode(stage *dockerfile.Stage, dockerfilePath string) *sbom.Node {
	if stage == nil || stage.BaseImage == "" {
		return nil
	}

	node := sbom.NewNode()
	node.Type = sbom.Node_PACKAGE

	// Parse the image reference to extract components
	ref := stage.BaseImageResolved
	if ref == nil {
		// Fallback: use base image string as-is
		node.Name = stage.BaseImage
		node.Id = sanitizeForSPDXID("pkg-docker-" + stage.BaseImage)
		return node
	}

	// Build the PURL for the container image
	purlStr := buildContainerPURL(ref)
	if purlStr != "" {
		node.Id = spdxSafeIDFromPURL(purlStr)
		if node.Identifiers == nil {
			node.Identifiers = map[int32]string{}
		}
		node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purlStr
	} else {
		node.Id = sanitizeForSPDXID("pkg-docker-" + stage.BaseImage)
	}

	// Set display name
	node.Name = ref.Repository
	if ref.Registry != "" && ref.Registry != "index.docker.io" {
		node.Name = ref.Registry + "/" + ref.Repository
	}

	// Set version from tag or digest
	if ref.Digest != "" {
		node.Version = ref.Digest
	} else if ref.Tag != "" {
		node.Version = ref.Tag
	}

	// Add properties for additional context
	node.Properties = append(node.Properties, &sbom.Property{
		Name: "deputy:type",
		Data: "container-base-image",
	})

	node.Properties = append(node.Properties, &sbom.Property{
		Name: "deputy:location",
		Data: dockerfilePath,
	})

	if stage.Name != "" {
		node.Properties = append(node.Properties, &sbom.Property{
			Name: "deputy:dockerfile-stage",
			Data: stage.Name,
		})
	}

	if stage.Platform != "" {
		node.Properties = append(node.Properties, &sbom.Property{
			Name: "deputy:platform",
			Data: stage.Platform,
		})
	}

	// Mark as direct dependency (base images are always direct)
	node.Properties = append(node.Properties, &sbom.Property{
		Name: "deputy:direct",
		Data: "true",
	})

	return node
}

// buildContainerPURL constructs a PURL for a container image reference.
// Uses pkg:docker for Docker Hub images, pkg:oci for other registries.
//
// PURL format for containers:
// - pkg:docker/namespace/name@version (Docker Hub)
// - pkg:oci/registry/namespace/name@version (other registries)
func buildContainerPURL(ref *dockerfile.ImageRef) string {
	if ref == nil || ref.Repository == "" {
		return ""
	}

	// Determine PURL type based on registry
	purlType := "docker"
	registry := ref.Registry

	// Docker Hub uses index.docker.io internally
	if registry == "index.docker.io" || registry == "docker.io" || registry == "" {
		purlType = "docker"
		registry = "" // Omit for Docker Hub (implicit)
	} else {
		purlType = "oci"
	}

	// Build the PURL string
	// Note: PURL spec says namespace/name segments use "/" literally, not escaped
	var sb strings.Builder
	sb.WriteString("pkg:")
	sb.WriteString(purlType)
	sb.WriteString("/")

	// Add registry as namespace for non-Docker Hub
	if registry != "" {
		sb.WriteString(registry)
		sb.WriteString("/")
	}

	// Add repository name (may contain "/" for namespace/name)
	sb.WriteString(ref.Repository)

	// Add version (prefer digest, then tag)
	if ref.Digest != "" {
		sb.WriteString("@")
		sb.WriteString(ref.Digest)
	} else if ref.Tag != "" {
		sb.WriteString("@")
		sb.WriteString(ref.Tag)
	}

	return sb.String()
}

// DefaultGenerator returns a function that generates SBOMs using the default logic.
// This adapter allows the sbom package to satisfy the service.SBOMGenerator interface.
func DefaultGenerator() func(ctx context.Context, target string, ref string, ecosystems []string) (*sbom.Document, error) {
	return func(ctx context.Context, target string, ref string, ecosystems []string) (*sbom.Document, error) {
		result, err := Generate(ctx, target, Options{
			Ref:        ref,
			Ecosystems: ecosystems,
		})
		if err != nil {
			return nil, err
		}
		return result.Document, nil
	}
}
