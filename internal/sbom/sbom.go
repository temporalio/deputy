package sbomx

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	neturl "net/url"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	pl "github.com/google/osv-scalibr/plugin/list"
	scalpurl "github.com/google/osv-scalibr/purl"
	gitx "github.com/picatz/deputy/internal/git"
	"github.com/protobom/protobom/pkg/formats"
	pbsbom "github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"golang.org/x/mod/modfile"
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

// Generate builds an SBOM document for repoPath (local) or a remote reference.
// Generate produces a Protobom SBOM document for the supplied repository path
// (local path or remote reference). Remote repositories are shallow cloned
// (depth 1) to a temporary directory and cleaned up automatically.
func Generate(ctx context.Context, repoPath string, opts Options) (*pbsbom.Document, error) {
	if opts.Ref == "" {
		opts.Ref = "HEAD"
	}

	localRepoPath := repoPath
	var cleanup func()

	// If repoPath is not a local directory, treat it as a remote and clone
	if fi, err := os.Stat(repoPath); err != nil || !fi.IsDir() {
		url := ToHTTPSGitURL(repoPath)
		if url == "" {
			return nil, fmt.Errorf("could not interpret repo %q as local path or remote URL", repoPath)
		}
		auth := AuthForURL(url)
		rn, _ := ResolveReferenceName(ctx, url, auth, opts.Ref)
		if rn.String() != "" {
			opts.Ref = rn.String()
		}
		path, cf, cerr := CloneRepoToTemp(ctx, url, auth, rn)
		if cerr != nil {
			return nil, fmt.Errorf("failed to clone remote repo %s: %w", url, cerr)
		}
		localRepoPath = path
		cleanup = cf
		defer func() {
			if cleanup != nil {
				_ = os.RemoveAll(localRepoPath)
				cleanup = nil
			}
		}()
	}

	// Resolve effective ref for inventory collection
	effRef := opts.Ref
	if strings.EqualFold(effRef, "HEAD") {
		// Use exact last commit rather than working tree
		effRef = "HEAD~0"
	}

	pkgs, err := collectInventorySBOM(ctx, localRepoPath, effRef, opts.Ecosystems)
	if err != nil {
		return nil, err
	}

	doc, err := buildProtobomDocument(localRepoPath, opts.Ref, opts.Name, pkgs)
	if err != nil {
		return nil, err
	}

	if opts.EnrichLicenses {
		switch strings.ToLower(opts.LicenseSource) {
		case "depsdev", "deps", "dd":
			if err := enrichProtobomLicensesDepsDev(ctx, doc); err != nil {
				return nil, err
			}
		case "scan":
			if err := enrichProtobomLicensesScanLocal(ctx, doc, localRepoPath); err != nil {
				return nil, err
			}
			fetcher := &remoteFetcher{Timeout: 20 * time.Second}
			if err := enrichProtobomLicensesScanWithFetcher(ctx, doc, fetcher); err != nil {
				return nil, err
			}
		case "both":
			if err := enrichProtobomLicensesDepsDev(ctx, doc); err != nil {
				return nil, err
			}
			if err := enrichProtobomLicensesScanLocal(ctx, doc, localRepoPath); err != nil {
				return nil, err
			}
			fetcher := &remoteFetcher{Timeout: 20 * time.Second}
			if err := enrichProtobomLicensesScanWithFetcher(ctx, doc, fetcher); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported license source: %s", opts.LicenseSource)
		}
	}

	return doc, nil
}

// collectInventorySBOM scans the repository at a specific commit snapshot.
func collectInventorySBOM(ctx context.Context, repoPath, gitRef string, _ []string) ([]*extractor.Package, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}
	h, err := repo.ResolveRevision(plumbing.Revision(gitRef))
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(*h)
	if err != nil {
		return nil, err
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}

	// Materialize the commit tree into a temp directory to let scalibr scan it
	dir, err := os.MkdirTemp("", "deputy-sbom-commit-*")
	if err != nil {
		return nil, err
	}

	err = tree.Files().ForEach(func(f *object.File) error {
		if f.Name == ".git" || strings.HasPrefix(f.Name, ".git/") {
			return nil
		}
		target := filepath.Join(dir, f.Name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		r, err := f.Blob.Reader()
		if err != nil {
			return err
		}
		defer r.Close()
		b, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	plugins, err := pl.FromNames([]string{"go"})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	cfg := &scalibr.ScanConfig{
		ScanRoots: scalibrfs.RealFSScanRoots(dir),
		Plugins:   plugins,
	}
	res := scalibr.New().Scan(ctx, cfg)
	_ = os.RemoveAll(dir)
	return res.Inventory.Packages, nil
}

// buildProtobomDocument converts the scalibr packages into a Protobom doc.
func buildProtobomDocument(repoPath, ref, name string, pkgs []*extractor.Package) (*pbsbom.Document, error) {
	if name == "" {
		name = fmt.Sprintf("%s@%s", repoPath, ref)
	}

	d := pbsbom.NewDocument()
	d.Metadata.Name = name
	d.Metadata.Date = timestamppb.New(time.Now())

	app := pbsbom.NewNode()
	app.Id = "application:root"
	app.Type = pbsbom.Node_PACKAGE
	app.Name = name
	d.NodeList.Nodes = append(d.NodeList.Nodes, app)
	d.NodeList.RootElements = append(d.NodeList.RootElements, app.Id)

	for _, p := range pkgs {
		if p == nil || p.Name == "" {
			continue
		}
		n := pbsbom.NewNode()
		var purlStr string
		if pu := p.PURL(); pu != nil {
			purlStr = normalizeGolangPURLString(pu.String(), repoPath)
		}
		if purlStr != "" {
			n.Id = spdxSafeIDFromPURL(purlStr)
		} else {
			n.Id = fmt.Sprintf("pkg:%s@%s", p.Name, p.Version)
		}
		n.Type = pbsbom.Node_PACKAGE
		n.Name = deriveDisplayName(p.Name, purlStr)
		n.Version = p.Version
		if purlStr != "" {
			if n.Identifiers == nil {
				n.Identifiers = map[int32]string{}
			}
			n.Identifiers[int32(pbsbom.SoftwareIdentifierType_PURL)] = purlStr
		}
		d.NodeList.Nodes = append(d.NodeList.Nodes, n)
		d.NodeList.Edges = append(d.NodeList.Edges, &pbsbom.Edge{
			Type: pbsbom.Edge_contains,
			From: app.Id,
			To:   []string{n.Id},
		})
	}
	return d, nil
}

// License enrichment helpers — currently stubs.
func enrichProtobomLicensesDepsDev(_ context.Context, _ *pbsbom.Document) error { return nil }
func enrichProtobomLicensesScanLocal(_ context.Context, _ *pbsbom.Document, _ string) error {
	return nil
}

type remoteFetcher struct{ Timeout time.Duration }

func enrichProtobomLicensesScanWithFetcher(_ context.Context, _ *pbsbom.Document, _ *remoteFetcher) error {
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

// CloneRepoToTemp clones a remote to a temporary directory, returning its path
// and a cleanup function to remove it when done.
func CloneRepoToTemp(ctx context.Context, remoteURL string, auth transport.AuthMethod, ref plumbing.ReferenceName) (string, func(), error) {
	dir, err := os.MkdirTemp("", "deputy-sbom-*")
	if err != nil {
		return "", nil, err
	}
	cloneOpts := &git.CloneOptions{
		URL:          remoteURL,
		Depth:        1,
		SingleBranch: true,
		Tags:         git.NoTags,
		Auth:         auth,
	}
	if ref.String() != "" {
		cloneOpts.ReferenceName = ref
	}
	var closeStorer func()
	if _, closeStorer, err = gitx.CloneContext(ctx, dir, cloneOpts); err != nil {
		// If the specified ref failed, retry without ReferenceName to let server default
		if ref.String() != "" {
			cloneOpts.ReferenceName = ""
			if _, closeStorer, err = gitx.CloneContext(ctx, dir, cloneOpts); err != nil {
				_ = os.RemoveAll(dir)
				return "", nil, err // return original error for clarity
			}
		} else {
			_ = os.RemoveAll(dir)
			return "", nil, err
		}
	}
	return dir, func() {
		if closeStorer != nil {
			closeStorer()
		}
		_ = os.RemoveAll(dir)
	}, nil
}

// PURL helpers
func normalizeGolangPURLString(purlStr, repoPath string) string {
	if purlStr == "" {
		return purlStr
	}
	pp, err := scalpurl.FromString(purlStr)
	if err != nil || pp.Type != scalpurl.TypeGolang {
		return purlStr
	}
	full := pp.Name
	if pp.Namespace != "" {
		full = pp.Namespace + "/" + pp.Name
	}
	if full == "." || strings.HasPrefix(full, "./") {
		modPath := readModulePath(repoPath)
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

func readModulePath(repoPath string) string {
	b, err := os.ReadFile(filepath.Join(repoPath, "go.mod"))
	if err != nil {
		return ""
	}
	if mf, err := modfile.Parse("go.mod", b, nil); err == nil && mf != nil && mf.Module != nil {
		return mf.Module.Mod.Path
	}
	return ""
}

func deriveDisplayName(name, purl string) string {
	if purl != "" {
		if pu, err := scalpurl.FromString(purl); err == nil {
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
func WriteCycloneDXJSON(doc *pbsbom.Document, w io.Writer) error {
	return writer.New(writer.WithFormat(formats.CDX16JSON)).WriteStream(doc, w)
}

func WriteSPDXJSON(doc *pbsbom.Document, w io.Writer) error {
	return writer.New(writer.WithFormat(formats.SPDX23JSON)).WriteStream(doc, w)
}

func WriteProtobomJSON(doc *pbsbom.Document, w io.Writer) error {
	enc := protojson.MarshalOptions{Indent: "  ", UseEnumNumbers: false, EmitUnpopulated: false}
	b, err := enc.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
