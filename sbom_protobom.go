package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"crypto/x509"
	neturl "net/url"

	billy "github.com/go-git/go-billy/v5"
	memfs "github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	transportclient "github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	scalplugin "github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"
	retryhttp "github.com/hashicorp/go-retryablehttp"
	"github.com/spf13/cobra"

	pb "deps.dev/api/v3"
	"github.com/google/licensecheck"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"golang.org/x/mod/modfile"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// addSBOMSubcommand registers the sbom subcommand with Protobom-backed writers.
func addSBOMSubcommand(root *cobra.Command) {
	var (
		repoPath       string
		ref            string
		format         string
		outPath        string
		ecos           []string
		name           string
		enrichLicenses bool
		licenseSource  string
		showContext    bool
	)

	cmd := &cobra.Command{
		Use:   "sbom [repo]",
		Short: "Generate an SBOM (Protobom intermediary) for a given ref",
		Long:  "Generate an SBOM for the repository at the specified Git ref using Protobom as the intermediary representation. Supports CycloneDX JSON, SPDX 2.3 JSON, and Protobom JSON.",
		Args:  cobra.MaximumNArgs(1),
		Example: strings.TrimSpace(`
          # Quick start (stdout)
          deputy sbom --format spdx-json
          deputy sbom -f spdx-json

          # Local repository at CWD, tag ref, write SPDX JSON to a file
          deputy sbom --ref=v1.16.0 --format=spdx-json --output=sbom.spdx.json

          # Explicit local repository path
          deputy sbom ./path/to/repo --ref=main --format=cyclonedx-json

          # Remote GitHub repository by shorthand or URL
          deputy sbom github.com/hashicorp/vault --ref=v1.16.0 --format=spdx-json
          deputy sbom https://github.com/hashicorp/vault --ref=main --format=cyclonedx-json

          # Limit to specific ecosystems (auto-detects by default)
          deputy sbom --ref=HEAD --ecosystems=go,npm --format=spdx-json

          # Notes:
          # - Without --ref, HEAD uses the working tree (includes uncommitted changes)
          # - Use --ref=HEAD to capture the exact last commit

          # Enrich licenses via deps.dev, local scan, or both
		  deputy sbom --ref=v1.16.0 --enrich-licenses --license-source=depsdev --format=spdx-json
		  deputy sbom --ref=v1.16.0 --enrich-licenses --license-source=scan    --format=spdx-json
		  deputy sbom --ref=v1.16.0 --enrich-licenses --license-source=both    --format=spdx-json

		  # Write Protobom (intermediary) JSON
		  deputy sbom --ref=v1.16.0 --format=protobom-json --output=sbom.protobom.json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Optional positional argument [repo] overrides --repo if provided
			if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
				repoPath = args[0]
			}
			if repoPath == "" {
				var err error
				repoPath, err = os.Getwd()
				if err != nil {
					return err
				}
			}
			if ref == "" {
				ref = "HEAD"
			}

			// Resolve local vs remote repo input; support friendly remote refs like github.com/owner/repo or https URLs.
			localRepoPath := repoPath
			var cleanup func()
			if !isExistingDir(repoPath) {
				// Treat as remote repo reference
				u := toHTTPSGitURL(repoPath)
				if u == "" {
					fmt.Printf("Warning: could not interpret repo %q as local path or remote URL\n", repoPath)
				} else {
					// Resolve auth and ref name
					auth := authForURL(u)
					rn, derr := resolveReferenceName(cmd.Context(), u, auth, ref)
					if derr != nil {
						fmt.Printf("Warning: could not resolve reference %q for %s: %v. Attempting default HEAD.\n", ref, u, derr)
					} else {
						ref = rn.String()
					}
					// Clone shallow into temp dir
					path, cf, cerr := cloneRepoToTemp(cmd.Context(), u, auth, rn)
					if cerr != nil {
						return fmt.Errorf("failed to clone remote repo %s: %w", u, cerr)
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
			}

			// Inventory packages using a non-destructive strategy:
			// - For HEAD on a local repo, scan the working tree (includes uncommitted changes)
			// - For other refs or remotes, scan a read-only snapshot of the commit
			// Decide effective ref for inventory: if user explicitly set --ref=HEAD, honor exact commit via HEAD~0; otherwise use working tree for HEAD
			effRef := refOrHEAD(ref)
			if strings.EqualFold(effRef, "HEAD") {
				if cmd.Flags().Changed("ref") {
					effRef = "HEAD~0"
				}
			}
			pkgs, err := collectInventorySBOM(cmd.Context(), localRepoPath, effRef, ecos)
			if err != nil {
				return err
			}

			// Build Protobom document
			// Use localRepoPath so we can read go.mod for module path and fix relative PURLs.
			doc, err := buildProtobomDocument(localRepoPath, ref, name, pkgs)
			if err != nil {
				return err
			}

			// Optional license enrichment
			if enrichLicenses {
				switch strings.ToLower(licenseSource) {
				case "depsdev", "deps", "dd":
					if err := enrichProtobomLicensesDepsDev(cmd.Context(), doc); err != nil {
						return err
					}
				case "scan":
					// Local repo license(s) -> app root
					if err := enrichProtobomLicensesScanLocal(cmd.Context(), doc, localRepoPath); err != nil {
						return err
					}
					// Attempt to scan dependency repos via go-git
					fetcher := &remoteFetcher{Timeout: 20 * time.Second}
					if err := enrichProtobomLicensesScanWithFetcher(cmd.Context(), doc, fetcher); err != nil {
						return err
					}
				case "both":
					if err := enrichProtobomLicensesDepsDev(cmd.Context(), doc); err != nil {
						return err
					}
					if err := enrichProtobomLicensesScanLocal(cmd.Context(), doc, localRepoPath); err != nil {
						return err
					}
					fetcher := &remoteFetcher{Timeout: 20 * time.Second}
					if err := enrichProtobomLicensesScanWithFetcher(cmd.Context(), doc, fetcher); err != nil {
						return err
					}
				default:
					return fmt.Errorf("unsupported --license-source %q (use depsdev|scan|both)", licenseSource)
				}
			}

			// Optional context header (to stderr) for human-friendly context
			if showContext {
				// Resolve commit hash for the selected ref
				shortRef := shortGitRef(ref)
				shortHash := ""
				if repo, err := git.PlainOpen(localRepoPath); err == nil {
					if h, herr := resolveRevisionEnhanced(repo, ref); herr == nil && h != nil {
						sh := h.String()
						if len(sh) > 7 {
							shortHash = sh[:7]
						} else {
							shortHash = sh
						}
					}
					// If scanning the working tree at HEAD with local changes, reflect that in the display
					if strings.EqualFold(refOrHEAD(ref), "HEAD") {
						if wt, werr := repo.Worktree(); werr == nil {
							if st, serr := wt.Status(); serr == nil && !st.IsClean() {
								shortRef = "WORKING"
							}
						}
					}
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "\nGenerated SBOM for %s @ %s (%s) → %s\n\n", repoPath, shortRef, shortHash, strings.ToUpper(format))
			}

			// Choose output
			var w io.Writer = os.Stdout
			if outPath != "" && outPath != "-" {
				f, err := os.Create(outPath)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}

			switch strings.ToLower(format) {
			case "cyclonedx-json", "cyclonedx":
				return writer.New(writer.WithFormat(formats.CDX16JSON)).WriteStream(doc, w)
			case "spdx-json", "spdx":
				return writer.New(writer.WithFormat(formats.SPDX23JSON)).WriteStream(doc, w)
			case "protobom-json", "protobom":
				enc := protojson.MarshalOptions{Indent: "  ", UseEnumNumbers: false, EmitUnpopulated: false}
				b, err := enc.Marshal(doc)
				if err != nil {
					return err
				}
				_, err = w.Write(b)
				return err
			default:
				return fmt.Errorf("unsupported format %q (use cyclonedx-json | spdx-json | protobom-json)", format)
			}
		},
	}

	cmd.Flags().StringVar(&ref, "ref", "HEAD", "Git reference (commit, tag, branch)")
	cmd.Flags().StringVarP(&format, "format", "f", "cyclonedx-json", "SBOM format: cyclonedx-json | spdx-json | protobom-json")
	cmd.Flags().StringVarP(&outPath, "output", "o", "-", "Output file path or '-' for stdout")
	cmd.Flags().StringSliceVar(&ecos, "ecosystems", nil, "Limit to specific ecosystems (e.g., go,npm,pip). Defaults to auto-detect.")
	cmd.Flags().StringVar(&name, "name", "", "Optional document name (defaults to repo@ref)")
	cmd.Flags().BoolVar(&enrichLicenses, "enrich-licenses", false, "Enrich SBOM nodes with licenses (optional)")
	cmd.Flags().StringVar(&licenseSource, "license-source", "depsdev", "License enrichment source: depsdev | scan | both")
	cmd.Flags().BoolVar(&showContext, "show-context", false, "Print a context header to stderr with repo, ref, and commit hash")

	root.AddCommand(cmd)
}

// isExistingDir returns true if path exists and is a directory
func isExistingDir(p string) bool {
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		return true
	}
	return false
}

// toHTTPSGitURL converts a friendly repo ref into an HTTPS git URL.
// Accepts forms like:
// - https://github.com/owner/repo(.git)
// - github.com/owner/repo(.git)
func toHTTPSGitURL(ref string) string {
	s := strings.TrimSpace(ref)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		// Ensure .git suffix for consistency
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

// authForURL returns BasicAuth for github.com when GITHUB_TOKEN is present, otherwise nil.
func authForURL(rawurl string) transport.AuthMethod {
	if u, err := neturl.Parse(rawurl); err == nil && u.Scheme == "https" && u.Host == "github.com" {
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			return &http.BasicAuth{Username: "oauth2", Password: token}
		}
	}
	return nil
}

// resolveReferenceName determines the reference name to use for cloning.
// If refStr is empty, attempts to discover the default branch.
func resolveReferenceName(ctx context.Context, remoteURL string, auth transport.AuthMethod, refStr string) (plumbing.ReferenceName, error) {
	r := strings.TrimSpace(refStr)
	// Treat empty or HEAD as: use remote default branch
	if r == "" || strings.EqualFold(r, "HEAD") {
		if br := discoverDefaultBranch(ctx, remoteURL, auth); br != "" {
			return plumbing.ReferenceName(br), nil
		}
		return "", fmt.Errorf("could not discover default branch")
	}
	if strings.HasPrefix(r, "refs/") {
		return plumbing.ReferenceName(r), nil
	}
	// Heuristic: version-like tokens are tags (e.g., v1.2.3). Otherwise treat as branch.
	if looksLikeTag(r) {
		return plumbing.ReferenceName("refs/tags/" + r), nil
	}
	return plumbing.ReferenceName("refs/heads/" + r), nil
}

// looksLikeTag returns true for common tag names such as v1.2.3
func looksLikeTag(s string) bool {
	if s == "" {
		return false
	}
	// Very light heuristic: starts with 'v' followed by a digit, or contains two dots and digits
	if (s[0] == 'v' || s[0] == 'V') && len(s) > 1 && s[1] >= '0' && s[1] <= '9' {
		return true
	}
	dot := 0
	digit := false
	for _, r := range s {
		if r == '.' {
			dot++
		}
		if r >= '0' && r <= '9' {
			digit = true
		}
	}
	return dot >= 1 && digit
}

// cloneRepoToTemp clones a repository shallowly into a temporary directory.
func cloneRepoToTemp(ctx context.Context, url string, auth transport.AuthMethod, ref plumbing.ReferenceName) (string, func(), error) {
	dir, err := os.MkdirTemp("", "deputy-sbom-*")
	if err != nil {
		return "", nil, err
	}
	opts := &git.CloneOptions{
		URL:          url,
		Depth:        1,
		SingleBranch: true,
		Tags:         git.NoTags,
		Auth:         auth,
	}
	if ref != "" {
		opts.ReferenceName = ref
	}
	if _, err := git.PlainCloneContext(ctx, dir, false, opts); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

func buildProtobomDocument(repoPath, ref, name string, pkgs []*extractor.Package) (*sbom.Document, error) {
	// Resolve display name
	if name == "" {
		// Prefer Go module path when available (gives github.com/org/repo)
		modPath := readModulePath(repoPath)
		repoID := modPath
		if repoID == "" {
			// Fall back to directory name
			base := repoPath
			if i := strings.LastIndex(base, string(os.PathSeparator)); i >= 0 && i < len(base)-1 {
				base = base[i+1:]
			}
			repoID = base
		}
		name = fmt.Sprintf("%s@%s", repoID, shortGitRef(ref))
	}

	d := sbom.NewDocument()
	d.Metadata.Name = name
	d.Metadata.Date = timestamppb.New(time.Now())

	// Root element: virtual application node referencing all packages
	app := sbom.NewNode()
	app.Id = "application:root"
	app.Type = sbom.Node_PACKAGE
	app.Name = name
	d.NodeList.Nodes = append(d.NodeList.Nodes, app)
	d.NodeList.RootElements = append(d.NodeList.RootElements, app.Id)

	// Add packages as nodes
	for _, p := range pkgs {
		if p == nil || p.Name == "" {
			continue
		}
		n := sbom.NewNode()
		// Prefer PURL as stable node ID; fallback to name@version
		var purlStr string
		if pu := p.PURL(); pu != nil {
			purlStr = normalizeGolangPURLString(pu.String(), repoPath)
		}
		if purlStr != "" {
			// Use a safe, deterministic ID derived from the PURL
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
		// Link app -> package
		d.NodeList.Edges = append(d.NodeList.Edges, &sbom.Edge{
			Type: sbom.Edge_contains,
			From: app.Id,
			To:   []string{n.Id},
		})
	}

	return d, nil
}

// normalizeGolangPURLString fixes relative Golang PURLs like pkg:golang/./api@v1.2.3
// by prefixing the module path from go.mod in repoPath.
func normalizeGolangPURLString(purlStr, repoPath string) string {
	if purlStr == "" || !strings.HasPrefix(purlStr, "pkg:golang/") {
		return purlStr
	}
	rest := strings.TrimPrefix(purlStr, "pkg:golang/")
	namePart := rest
	verPart := ""
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		namePart = rest[:i]
		verPart = rest[i+1:]
	}
	if namePart == "." || strings.HasPrefix(namePart, "./") {
		modPath := readModulePath(repoPath)
		if modPath == "" {
			return purlStr
		}
		rel := strings.TrimPrefix(namePart, "./")
		if rel == "." {
			rel = ""
		}
		full := modPath
		if rel != "" {
			full = modPath + "/" + rel
		}
		if verPart != "" {
			return "pkg:golang/" + full + "@" + verPart
		}
		return "pkg:golang/" + full
	}
	return purlStr
}

// shortGitRef converts full refs (e.g., refs/tags/v1.2.3, refs/heads/main)
// into a human-friendly short form (v1.2.3, main). Otherwise returns ref as-is.
func shortGitRef(ref string) string {
	r := strings.TrimSpace(ref)
	if r == "" {
		return r
	}
	if strings.HasPrefix(r, "refs/tags/") {
		return strings.TrimPrefix(r, "refs/tags/")
	}
	if strings.HasPrefix(r, "refs/heads/") {
		return strings.TrimPrefix(r, "refs/heads/")
	}
	if strings.HasPrefix(r, "refs/") {
		// Fallback: take last path element
		if i := strings.LastIndex(r, "/"); i >= 0 && i < len(r)-1 {
			return r[i+1:]
		}
	}
	return r
}

// spdxSafeIDFromPURL converts a PURL string into a deterministic, SPDX-safe identifier
// with a limited character set [A-Za-z0-9._-]. It keeps type/name@version semantics
// but replaces disallowed characters with '-', and decodes any percent-encoding.
func spdxSafeIDFromPURL(purlStr string) string {
	if purlStr == "" {
		return ""
	}
	s := strings.TrimPrefix(purlStr, "pkg:")
	if dec, err := neturl.PathUnescape(s); err == nil && dec != "" {
		s = dec
	}
	// Ensure a stable, readable prefix
	s = "pkg-" + s
	return sanitizeForSPDXID(s)
}

// sanitizeForSPDXID maps any rune not in [A-Za-z0-9._-] to '-', and collapses repeats.
func sanitizeForSPDXID(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
			prevDash = false
		} else {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := b.String()
	out = strings.Trim(out, "-")
	if out == "" {
		return "pkg"
	}
	return out
}

// readModulePath returns module path from repoPath/go.mod
func readModulePath(repoPath string) string {
	data, err := os.ReadFile(filepath.Join(repoPath, "go.mod"))
	if err != nil {
		return ""
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil || mf == nil || mf.Module == nil {
		return ""
	}
	return mf.Module.Mod.Path
}

// deriveDisplayName prefers the PURL name for nicer display when available.
func deriveDisplayName(origName, purlStr string) string {
	if purlStr == "" {
		return origName
	}
	// purl: pkg:type/name@ver
	p := strings.TrimPrefix(purlStr, "pkg:")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[i+1:] // drop type/
	}
	if j := strings.IndexByte(p, '@'); j >= 0 {
		p = p[:j]
	}
	if p != "" {
		// PURL encodes special chars; prefer human-friendly decoded name
		if dec, err := neturl.PathUnescape(p); err == nil && dec != "" {
			return dec
		}
		return p
	}
	return origName
}

// collectInventoryAtRef redefined here to avoid build tag issues linking stub.
func collectInventorySBOM(ctx context.Context, repoPath, gitRef string, ecos []string) ([]*extractor.Package, error) {
	// Plugin selection honors --ecosystems; default to "all", then fallback to "go".
	var (
		plugins []scalplugin.Plugin
		err     error
	)
	if len(ecos) == 0 {
		plugins, err = pl.FromNames([]string{"all"})
		if err != nil {
			plugins, err = pl.FromNames([]string{"go"})
			if err != nil {
				return nil, fmt.Errorf("load plugins: %w", err)
			}
		}
	} else {
		plugins, err = pl.FromNames(ecos)
		if err != nil {
			return nil, fmt.Errorf("load plugins for %v: %w", ecos, err)
		}
	}

	// Treat empty as HEAD
	ref := refOrHEAD(gitRef)

	// If HEAD on a local repo, scan the working tree (non-destructive, includes uncommitted changes)
	if strings.EqualFold(ref, "HEAD") {
		if _, err := git.PlainOpen(repoPath); err == nil {
			cfg := &scalibr.ScanConfig{ScanRoots: scalibrfs.RealFSScanRoots(repoPath), Plugins: plugins}
			results := scalibr.New().Scan(ctx, cfg)
			return results.Inventory.Packages, nil
		}
		// If not a git repo (shouldn't happen for cloned remotes), still scan filesystem
		cfg := &scalibr.ScanConfig{ScanRoots: scalibrfs.RealFSScanRoots(repoPath), Plugins: plugins}
		results := scalibr.New().Scan(ctx, cfg)
		return results.Inventory.Packages, nil
	}

	// For other refs, create a read-only snapshot of the commit into a temp dir and scan it
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("open repo: %w", err)
	}
	h, err := resolveRevisionEnhanced(repo, ref)
	if err != nil {
		return nil, fmt.Errorf("resolve ref %q: %w", ref, err)
	}
	commit, err := repo.CommitObject(*h)
	if err != nil {
		return nil, fmt.Errorf("get commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("get tree: %w", err)
	}
	dir, err := os.MkdirTemp("", "deputy-sbom-snap-*")
	if err != nil {
		return nil, err
	}
	// Materialize tree files into temp dir
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
	// Scan the snapshot dir
	cfg := &scalibr.ScanConfig{ScanRoots: scalibrfs.RealFSScanRoots(dir), Plugins: plugins}
	results := scalibr.New().Scan(ctx, cfg)
	_ = os.RemoveAll(dir)
	return results.Inventory.Packages, nil
}

// enrichProtobomLicensesDepsDev connects to deps.dev and populates licenses on nodes with PURLs.
func enrichProtobomLicensesDepsDev(ctx context.Context, doc *sbom.Document) error {
	if doc == nil || doc.NodeList == nil {
		return nil
	}

	// Create deps.dev client using existing adapter interface
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("deps.dev cert pool: %w", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	conn, err := grpc.NewClient("api.deps.dev:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("deps.dev connect: %w", err)
	}
	defer conn.Close()
	client := &pbInsightsAdapter{client: pb.NewInsightsClient(conn)}

	return enrichProtobomLicensesDepsDevWithClient(ctx, doc, client)
}

// enrichProtobomLicensesDepsDevWithClient enriches using a provided depsClient (for tests).
func enrichProtobomLicensesDepsDevWithClient(ctx context.Context, doc *sbom.Document, client depsClient) error {
	if doc == nil || doc.NodeList == nil || client == nil {
		return nil
	}
	for _, n := range doc.NodeList.Nodes {
		if n == nil || n.Type != sbom.Node_PACKAGE {
			continue
		}
		if len(n.Licenses) > 0 {
			continue
		}
		purlStr := n.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]
		if purlStr == "" {
			continue
		}
		p, err := packageurl.FromString(purlStr)
		if err != nil {
			continue
		}
		system, name, version := mapPURLToDepsDev(p)
		if system == 0 || name == "" || version == "" {
			continue
		}
		resp, err := client.GetVersion(ctx, &pb.GetVersionRequest{VersionKey: &pb.VersionKey{System: system, Name: name, Version: version}})
		if err != nil || resp == nil {
			continue
		}
		if len(resp.Licenses) == 0 {
			continue
		}
		// Deduplicate
		seen := map[string]struct{}{}
		var out []string
		for _, l := range resp.Licenses {
			if l == "" {
				continue
			}
			if _, ok := seen[l]; ok {
				continue
			}
			seen[l] = struct{}{}
			out = append(out, l)
		}
		if len(out) > 0 {
			n.Licenses = out
		}
	}
	return nil
}

// mapPURLToDepsDev maps a packageurl to deps.dev system, name and version
func mapPURLToDepsDev(p packageurl.PackageURL) (pb.System, string, string) {
	t := strings.ToLower(p.Type)
	name := p.Name
	if p.Namespace != "" {
		// npm scopes should be like @scope/name for deps.dev
		switch t {
		case "npm":
			ns := p.Namespace
			if strings.HasPrefix(ns, "@") {
				name = ns + "/" + p.Name
			} else {
				name = "@" + ns + "/" + p.Name
			}
		case "maven":
			// maven expects groupId:artifactId
			name = p.Namespace + ":" + p.Name
		default:
			name = p.Namespace + "/" + p.Name
		}
	}
	ver := p.Version
	switch t {
	case "golang", "go":
		if ver != "" && !strings.HasPrefix(ver, "v") {
			ver = "v" + ver
		}
		return pb.System_GO, name, ver
	case "npm":
		return pb.System_NPM, name, ver
	case "pypi":
		return pb.System_PYPI, name, ver
	case "maven":
		return pb.System_MAVEN, name, ver
	case "nuget":
		return pb.System_NUGET, name, ver
	case "cargo":
		return pb.System_CARGO, name, ver
	default:
		return 0, "", ""
	}
}

// RepoFetcher abstracts fetching a repository FS for a given PURL (used in tests).
type RepoFetcher interface {
	Fetch(ctx context.Context, p packageurl.PackageURL) (billy.Filesystem, string, error)
}

// remoteFetcher clones public repositories into an in-memory filesystem.
//
// It supports GitHub via a GITHUB_TOKEN env var, applied only to github.com
// to avoid sending credentials to untrusted hosts (confused deputy problem).
type remoteFetcher struct {
	Timeout time.Duration
}

// Fetch retrieves the repository filesystem and root path for a given PURL.
func (f *remoteFetcher) Fetch(ctx context.Context, p packageurl.PackageURL) (billy.Filesystem, string, error) {
	configureGoGitHTTPOnce()
	url, ref, subdir := deriveGitURLAndRef(p)
	if url == "" {
		return nil, "", fmt.Errorf("unsupported purl for fetch: %s", p.String())
	}

	if f.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.Timeout)
		defer cancel()
	}

	st := memory.NewStorage()
	fs := memfs.New()

	opts := &git.CloneOptions{
		URL:          url,
		Depth:        1,          // shallow clone
		SingleBranch: true,       // limit to one branch/tag
		Tags:         git.NoTags, // avoid fetching all tags by default
	}
	// If host is github.com and a GitHub token is present, use it as an OAuth token.
	if u, perr := neturl.Parse(url); perr == nil && u.Host == "github.com" && u.Scheme == "https" {
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			// Use "oauth2" as username per Git over HTTPS convention
			opts.Auth = &http.BasicAuth{Username: "oauth2", Password: token}
		}
	}
	// Build candidate refs to try
	var candidates []plumbing.ReferenceName
	if ref != "" {
		if strings.HasPrefix(ref, "refs/") {
			candidates = append(candidates, plumbing.ReferenceName(ref))
		} else {
			candidates = append(candidates, plumbing.ReferenceName("refs/tags/"+ref))
			candidates = append(candidates, plumbing.ReferenceName("refs/heads/"+ref))
		}
	} else {
		// Resolve the remote's default branch precisely; if unavailable, return an error
		if br := discoverDefaultBranch(ctx, url, opts.Auth); br != "" {
			candidates = append(candidates, plumbing.ReferenceName(br))
		} else {
			return nil, "", fmt.Errorf("could not discover default branch for %s", url)
		}
	}

	for _, cand := range candidates {
		opts.ReferenceName = cand
		if _, err := git.CloneContext(ctx, st, fs, opts); err == nil {
			root := "/"
			if subdir != "" {
				root = "/" + subdir
			}
			return fs, root, nil
		}
	}

	// No viable ref worked
	return nil, "", fmt.Errorf("failed to clone any candidate ref for %s", url)
}

// discoverDefaultBranch tries to get the remote HEAD target or falls back to main/master presence
func discoverDefaultBranch(ctx context.Context, remoteURL string, auth transport.AuthMethod) string {
	r := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	refs, err := r.ListContext(ctx, &git.ListOptions{Auth: auth})
	if err != nil {
		return ""
	}
	for _, ref := range refs {
		name := ref.Name()
		if name == plumbing.HEAD && ref.Type() == plumbing.SymbolicReference {
			return ref.Target().String()
		}
	}
	return ""
}

// one-time installer of retrying HTTP client for go-git (concurrency-safe)
var httpInstallOnce sync.Once

func configureGoGitHTTPOnce() {
	httpInstallOnce.Do(func() {
		rc := retryhttp.NewClient()
		rc.Logger = nil
		rc.RetryWaitMin = 200 * time.Millisecond
		rc.RetryWaitMax = 2 * time.Second
		rc.RetryMax = 5
		stdc := rc.StandardClient()
		// stdc.Timeout = 30 * time.Second
		transportclient.InstallProtocol("http", http.NewClient(stdc))
		transportclient.InstallProtocol("https", http.NewClient(stdc))
	})
}

// deriveGitURLAndRef maps a PURL to a git URL, ref (tag or #hash) and subdir.
func deriveGitURLAndRef(p packageurl.PackageURL) (gitURL, ref, subdir string) {
	t := strings.ToLower(p.Type)
	switch t {
	case "github":
		if p.Namespace == "" || p.Name == "" {
			return "", "", ""
		}
		gitURL = "https://github.com/" + p.Namespace + "/" + p.Name + ".git"
		if p.Version != "" {
			ref = "refs/tags/" + p.Version
		}
		return
	case "golang", "go":
		// Heuristic for Github-hosted modules: github.com/<org>/<repo>[/subpaths]
		full := p.Name
		if p.Namespace != "" {
			full = p.Namespace + "/" + p.Name
		}
		if strings.HasPrefix(full, "github.com/") {
			parts := strings.Split(full, "/")
			if len(parts) >= 3 {
				host, org, repo := parts[0], parts[1], parts[2]
				gitURL = "https://" + host + "/" + org + "/" + repo + ".git"
				if len(parts) > 3 {
					subdir = strings.Join(parts[3:], "/")
				}
				ver := p.Version
				if ver != "" && !strings.HasPrefix(ver, "v") {
					ver = "v" + ver
				}
				if ver != "" {
					ref = "refs/tags/" + ver
				}
				return
			}
		}
		return "", "", ""
	default:
		return "", "", ""
	}
}

// enrichProtobomLicensesScanWithFetcher uses a provided fetcher to scan licenses for each node.
func enrichProtobomLicensesScanWithFetcher(ctx context.Context, doc *sbom.Document, fetcher RepoFetcher) error {
	if doc == nil || doc.NodeList == nil || fetcher == nil {
		return nil
	}
	for _, n := range doc.NodeList.Nodes {
		if n == nil || n.Type != sbom.Node_PACKAGE || len(n.Licenses) > 0 {
			continue
		}
		purlStr := n.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]
		if purlStr == "" {
			continue
		}
		p, err := packageurl.FromString(purlStr)
		if err != nil {
			continue
		}
		fsys, root, err := fetcher.Fetch(ctx, p)
		if err != nil || fsys == nil {
			continue
		}
		ids := scanBillyForLicenseIDs(fsys, root)
		if len(ids) > 0 {
			n.Licenses = ids
		}
	}
	return nil
}

// enrichProtobomLicensesScanLocal scans the local repoPath for license files and applies to root node.
func enrichProtobomLicensesScanLocal(_ context.Context, doc *sbom.Document, repoPath string) error {
	if doc == nil || doc.NodeList == nil {
		return nil
	}
	if repoPath == "" {
		return nil
	}
	// Find root node
	var root *sbom.Node
	if len(doc.NodeList.RootElements) > 0 {
		rootID := doc.NodeList.RootElements[0]
		for _, n := range doc.NodeList.Nodes {
			if n.Id == rootID {
				root = n
				break
			}
		}
	}
	if root == nil {
		return nil
	}
	if len(root.Licenses) > 0 {
		return nil
	}
	ids := scanLocalForLicenseIDs(repoPath)
	if len(ids) > 0 {
		root.Licenses = ids
	}
	return nil
}

// scanLocalForLicenseIDs scans standard license files in a local path.
func scanLocalForLicenseIDs(dir string) []string {
	candidates := []string{
		"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt", "COPYRIGHT",
	}
	seen := map[string]struct{}{}
	var out []string
	for _, name := range candidates {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		ids := detectLicenseIDs(data)
		for _, id := range ids {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

// scanBillyForLicenseIDs scans a billy FS for license files under root directory.
func scanBillyForLicenseIDs(fs billy.Filesystem, root string) []string {
	candidates := []string{
		"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt", "COPYRIGHT",
	}
	seen := map[string]struct{}{}
	var out []string
	for _, name := range candidates {
		f, err := fs.Open(filepath.Join(root, name))
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(f)
		_ = f.Close()
		if len(data) == 0 {
			continue
		}
		ids := detectLicenseIDs(data)
		for _, id := range ids {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

// detectLicenseIDs classifies license text and returns all matched SPDX IDs, de-duplicated.
func detectLicenseIDs(b []byte) []string {
	r := licensecheck.Scan(b)
	if len(r.Match) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, m := range r.Match {
		id := m.ID
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
