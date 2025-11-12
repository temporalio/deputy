package sbomx

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	gitx "github.com/picatz/deputy/internal/gitutil"
	"github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"golang.org/x/mod/modfile"
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

	doc, err := buildProtobomDocument(src.Workspace, repoRef, opts.Ref, opts.Name, pkgs)
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
// buildProtobomDocument converts the scalibr packages into a Protobom doc.
func buildProtobomDocument(ws workspace.FS, repoRef, ref, name string, pkgs []*extractor.Package) (*sbom.Document, error) {
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

	for _, p := range pkgs {
		if p == nil || p.Name == "" {
			continue
		}
		n := sbom.NewNode()
		var purlStr string
		if pu := p.PURL(); pu != nil {
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
		if pu == nil || pu.Type != purl.TypeGolang {
			continue
		}
		module := goModuleFromPURL(pu)
		version := strings.TrimSpace(pu.Version)
		if module == "" || version == "" {
			continue
		}
		if ids := analysis.RemoteModuleLicenseScan(ctx, module, version); len(ids) > 0 {
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
	pu, err := purl.FromString(strings.TrimSpace(val))
	if err != nil {
		return nil
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
