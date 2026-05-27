package inventory

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/container/image"
	"github.com/temporalio/deputy/internal/dockerfile"
	"github.com/temporalio/deputy/internal/otel"
	"github.com/temporalio/deputy/internal/repository/workspace"
	"github.com/temporalio/deputy/internal/targets"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
)

// workspaceProvider is implemented by types that provide a workspace.FS.
// This interface allows collector.go to work with repository.Source without
// importing the repository package, avoiding import cycles.
type workspaceProvider interface {
	// Workspace returns the filesystem workspace for scanning.
	Workspace() workspace.FS
}

// v1ImageProvider is implemented by container image data types that provide
// access to a v1.Image for config extraction. This interface allows collector.go
// to work with providers.ContainerImageData without importing the providers package.
type v1ImageProvider interface {
	scalibrimage.Image
	V1() v1.Image
}

// dockerfileDataProvider is implemented by dockerfile data types that provide
// access to parsed Dockerfile info. This interface allows collector.go to work
// with providers.DockerfileData without importing the providers package.
type dockerfileDataProvider interface {
	DockerfileInfo() *dockerfile.Info
	DockerfileAnalysis() *dockerfile.Analysis
}

// Result is the output of inventory collection.
// It contains discovered packages and metadata about the target.
type Result struct {
	// Target describes what was scanned.
	Target Target

	// GeneratedAt is when the inventory was collected.
	GeneratedAt time.Time

	// Packages are the discovered dependencies.
	Packages []*extractor.Package

	// Direct maps package keys to whether they are direct dependencies.
	// For Go, this is derived from go.mod. For other ecosystems, heuristics apply.
	Direct map[string]bool

	// ImageInfo contains container image configuration (for image targets).
	ImageInfo *image.Info

	// DockerfileInfo contains parsed Dockerfile data (for dockerfile targets).
	DockerfileInfo *dockerfile.Info

	// DockerfileAnalysis contains static analysis results (for dockerfile targets).
	DockerfileAnalysis *dockerfile.Analysis
}

// Target describes the source of the inventory.
type Target struct {
	Kind         targets.Kind
	DisplayPath  string
	LocalPath    string
	Ref          string
	EffectiveRef string
	CommitHash   string
	OriginURL    string
	Cloned       bool
	Provenance   map[string]string
}

// TargetHint provides explicit target type hints when auto-detection is insufficient.
type TargetHint struct {
	// Kind explicitly specifies the target type.
	// Zero value means auto-detect.
	Kind targets.Kind

	// ImageTransport specifies how to fetch container images.
	// Values: "remote" (default), "daemon", "tarball", "oci-archive", "oci-layout".
	ImageTransport string
}

// Execution wraps an inventory result and cleanup function.
// Always call Close() when done to release temporary resources.
type Execution struct {
	Result    Result
	Workspace workspace.FS // Optional: file access for graph edge resolution
	cleanup   func()
}

// Close releases any temporary resources (e.g., cloned repos).
func (e *Execution) Close() error {
	if e != nil && e.cleanup != nil {
		e.cleanup()
	}
	return nil
}

// Options configures inventory collection.
type Options struct {
	// Ecosystems limits extraction to specific package ecosystems.
	// Empty means all supported ecosystems.
	Ecosystems []string

	// Platform specifies container image platform (e.g., "linux/amd64").
	Platform string

	// DetectBaseImage enables base image detection for container image scans.
	// When true, the baseimage enricher queries deps.dev to determine if layers
	// belong to known base images, populating LayerDetails.InBaseImage.
	// This requires network access and adds latency to the scan.
	DetectBaseImage bool
}

// Collect extracts package inventory from any supported target type.
// It auto-detects the target kind and routes to the appropriate collector.
//
// Supported targets:
//   - Local directories (e.g., ".", "/path/to/project")
//   - Git repositories (local or remote URLs)
//   - Container images (e.g., "docker://nginx:1.25", "ghcr.io/owner/app:v1")
//   - Git refs (use CollectRepository for explicit ref control)
//
// Example:
//
//	exec, err := inventory.Collect(ctx, ".", inventory.Options{})
//	if err != nil { return err }
//	defer exec.Close()
//	for _, pkg := range exec.Result.Packages {
//	    fmt.Println(pkg.Name, pkg.Version)
//	}
func Collect(ctx context.Context, target string, opts Options) (*Execution, error) {
	kind := targets.DetectKind(target)

	switch kind {
	case targets.KindContainerImage:
		targetOpts := map[string]string{}
		if opts.Platform != "" {
			targetOpts["platform"] = opts.Platform
		}
		return CollectContainerImage(ctx, target, targetOpts, opts)

	case targets.KindDockerfile:
		return CollectDockerfile(ctx, target, opts)

	case targets.KindDir:
		return CollectDirectory(ctx, target, opts)

	default:
		// Default: treat as repository (handles local dirs, remote repos, git URLs)
		return CollectRepository(ctx, target, "HEAD", false, opts)
	}
}

// CollectRepository extracts inventory from a git repository.
// The target can be a local path or remote URL.
//
// Parameters:
//   - target: local path or git URL
//   - ref: git reference (branch, tag, commit hash), or "HEAD"
//   - refProvided: true if the caller explicitly provided ref
//   - opts: collection options
func CollectRepository(ctx context.Context, target, ref string, refProvided bool, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.inventory.repository",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
			attribute.String("deputy.target.ref", ref),
		))
	defer span.End()

	resolved, err := resolveRepositoryTarget(ctx, target, ref)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}
	span.SetAttributes(attribute.Bool("deputy.target.remote", resolved.cloned))

	effectiveRef := refOrHEAD(ref)
	if effectiveRef == "HEAD" && refProvided {
		effectiveRef = "HEAD~0"
	}

	// Scan packages
	pkgs, err := ScanPackagesWorking(ctx, resolved.workspace, ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		resolved.cleanup()
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("failed to scan packages: %w", err)
	}
	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	// Resolve direct dependencies (multi-ecosystem: Go, npm, Cargo, PyPI)
	direct := compare.CollectDirectDependenciesFromWorkspace(resolved.workspace)

	result := Result{
		Target: Target{
			Kind:         resolved.kind,
			DisplayPath:  resolved.displayPath,
			LocalPath:    resolved.localPath,
			Ref:          ref,
			EffectiveRef: effectiveRef,
			Cloned:       resolved.cloned,
			Provenance:   resolved.provenance,
		},
		GeneratedAt: time.Now().UTC(),
		Packages:    pkgs,
		Direct:      direct,
	}

	// Get commit metadata if available
	result.Target.CommitHash, result.Target.OriginURL = getRepoMetadata(resolved.localPath, ref)

	return &Execution{Result: result, Workspace: resolved.workspace, cleanup: resolved.cleanup}, nil
}

// CollectDirectory extracts inventory from a local directory (no git context).
func CollectDirectory(ctx context.Context, path string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.inventory.directory",
		trace.WithAttributes(
			attribute.String("deputy.target.path", path),
		))
	defer span.End()

	ws, err := workspace.NewDir(path)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("failed to open directory: %w", err)
	}

	pkgs, err := ScanPackagesWorking(ctx, ws, ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		_ = ws.Close()
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("failed to scan packages: %w", err)
	}
	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	// Resolve direct dependencies (multi-ecosystem: Go, npm, Cargo, PyPI)
	direct := compare.CollectDirectDependenciesFromWorkspace(ws)

	result := Result{
		Target: Target{
			Kind:        targets.KindDir,
			DisplayPath: path,
			LocalPath:   path,
		},
		GeneratedAt: time.Now().UTC(),
		Packages:    pkgs,
		Direct:      direct,
	}

	return &Execution{
		Result:    result,
		Workspace: ws,
		cleanup:   func() { _ = ws.Close() },
	}, nil
}

// CollectContainerImage extracts inventory from a container image.
//
// The target can be:
//   - Remote registry: "docker://nginx:1.25", "ghcr.io/owner/app:v1"
//   - Docker daemon: "docker-daemon://myapp:latest"
//   - Tarball: "tarball:///path/to/image.tar"
//   - OCI archive: "oci-archive:///path/to/image.tar"
//   - OCI layout: "oci-layout:///path/to/layout"
//
// targetOpts supports:
//   - "platform": target platform (e.g., "linux/amd64")
//   - "transport": override auto-detected transport
func CollectContainerImage(ctx context.Context, target string, targetOpts map[string]string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.inventory.container_image",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
		))
	defer span.End()

	mat, err := targets.Open(ctx, target, targetOpts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}

	cleanup := func() {}
	if mat.Cleanup != nil {
		cleanup = mat.Cleanup
	}

	// Extract scalibr image and optional v1.Image for config access
	var img scalibrimage.Image
	var imageInfo *image.Info

	switch data := mat.Data.(type) {
	case v1ImageProvider:
		img = data
		if v1img := data.V1(); v1img != nil {
			info, err := image.Extract(v1img)
			if err != nil {
				slog.Debug("failed to extract image config", "target", target, "error", err)
			} else {
				imageInfo = info
			}
		}
	case scalibrimage.Image:
		img = data
	default:
		cleanup()
		err := fmt.Errorf("target %q did not resolve to a container image", target)
		otel.SetSpanError(span, err)
		return nil, err
	}

	pkgs, err := ScanPackagesContainerImage(ctx, img, ScanOptions{
		Ecosystems:      opts.Ecosystems,
		DetectBaseImage: opts.DetectBaseImage,
	})
	if err != nil {
		cleanup()
		otel.SetSpanError(span, err)
		return nil, err
	}
	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	displayPath := target
	if mat.Meta.Target != "" {
		displayPath = mat.Meta.Target
	}

	result := Result{
		Target: Target{
			Kind:        mat.Meta.Kind,
			DisplayPath: displayPath,
			LocalPath:   mat.Path,
			Provenance:  mat.Meta.Provenance,
		},
		GeneratedAt: time.Now().UTC(),
		Packages:    pkgs,
		Direct:      nil, // Container images don't have direct/transitive distinction
		ImageInfo:   imageInfo,
	}

	return &Execution{Result: result, cleanup: cleanup}, nil
}

// CollectVMImage scans a VM disk image or rootfs image for packages.
// Supported formats: qcow2, vmdk, vhd, vhdx, vdi, raw, and ext4 rootfs images.
func CollectVMImage(ctx context.Context, target string, targetOpts map[string]string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.inventory.vm_image",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
		))
	defer span.End()

	mat, err := targets.Open(ctx, target, targetOpts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}

	cleanup := func() {}
	if mat.Cleanup != nil {
		cleanup = mat.Cleanup
	}

	// Verify we got a filesystem
	if mat.FS == nil {
		cleanup()
		err := fmt.Errorf("target %q did not provide a filesystem", target)
		otel.SetSpanError(span, err)
		return nil, err
	}

	// Cast to scalibrfs.FS (requires fs.FS, fs.ReadDirFS, fs.StatFS)
	scalibrFS, ok := mat.FS.(scalibrfs.FS)
	if !ok {
		cleanup()
		err := fmt.Errorf("VM image filesystem does not implement required interfaces")
		otel.SetSpanError(span, err)
		return nil, err
	}

	pkgs, scanErr := ScanPackagesVMImage(ctx, scalibrFS, ScanOptions{
		Ecosystems: opts.Ecosystems,
	})
	// Continue even if there were plugin failures, as long as we found packages
	if scanErr != nil && len(pkgs) == 0 {
		cleanup()
		otel.SetSpanError(span, scanErr)
		return nil, scanErr
	}
	if scanErr != nil {
		// Log warning but continue with found packages
		slog.WarnContext(ctx, "VM image scan had partial failures", "error", scanErr, "packages_found", len(pkgs))
	}
	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	displayPath := target
	if mat.Meta.Target != "" {
		displayPath = mat.Meta.Target
	}

	result := Result{
		Target: Target{
			Kind:        mat.Meta.Kind,
			DisplayPath: displayPath,
			LocalPath:   mat.Path,
			Provenance:  mat.Meta.Provenance,
		},
		GeneratedAt: time.Now().UTC(),
		Packages:    pkgs,
		Direct:      nil, // VM images don't have direct/transitive distinction
	}

	return &Execution{Result: result, cleanup: cleanup}, nil
}

// CollectDockerfile parses a Dockerfile without scanning packages.
// Use CollectContainerImage to scan packages in referenced images.
func CollectDockerfile(ctx context.Context, target string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.inventory.dockerfile",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
		))
	defer span.End()

	mat, err := targets.Open(ctx, target, nil)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}

	cleanup := func() {}
	if mat.Cleanup != nil {
		cleanup = mat.Cleanup
	}

	data, ok := mat.Data.(dockerfileDataProvider)
	if !ok {
		cleanup()
		err := fmt.Errorf("target %q did not resolve to a dockerfile", target)
		otel.SetSpanError(span, err)
		return nil, err
	}

	displayPath := target
	if mat.Meta.Target != "" {
		displayPath = mat.Meta.Target
	}

	result := Result{
		Target: Target{
			Kind:        targets.KindDockerfile,
			DisplayPath: displayPath,
			LocalPath:   mat.Path,
		},
		GeneratedAt:        time.Now().UTC(),
		DockerfileInfo:     data.DockerfileInfo(),
		DockerfileAnalysis: data.DockerfileAnalysis(),
	}

	return &Execution{Result: result, cleanup: cleanup}, nil
}

// CollectAtCommit extracts inventory from a specific git commit.
func CollectAtCommit(ctx context.Context, repo *git.Repository, commitHash plumbing.Hash, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.inventory.commit",
		trace.WithAttributes(
			attribute.String("deputy.target.commit", commitHash.String()),
		))
	defer span.End()

	pkgs, err := ScanPackagesAtCommitSnapshot(ctx, repo, commitHash, ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}
	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	// Try to get direct dependencies from the commit snapshot
	direct, _ := compare.CollectGoDirectModulesFromCommit(repo, commitHash)

	result := Result{
		Target: Target{
			Kind:       targets.KindGit,
			CommitHash: commitHash.String(),
		},
		GeneratedAt: time.Now().UTC(),
		Packages:    pkgs,
		Direct:      direct,
	}

	return &Execution{Result: result}, nil
}

// CollectRepositoryAtRef extracts inventory from a git repository at a specific reference.
// Unlike CollectRepository which scans the working tree, this function materializes
// the tree at the specified ref into memory and scans that snapshot.
//
// This provides consistent behavior with `deputy diff` which properly scans at refs.
func CollectRepositoryAtRef(ctx context.Context, target, ref string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.inventory.repository_at_ref",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
			attribute.String("deputy.target.ref", ref),
		))
	defer span.End()

	// Resolve target to get repo path
	resolved, err := resolveRepositoryTarget(ctx, target, ref)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}
	defer resolved.cleanup()

	// Open the git repository
	repo, err := git.PlainOpen(resolved.localPath)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("failed to open git repository: %w", err)
	}

	// Resolve the ref to a commit hash
	hash, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("failed to resolve ref %q: %w", ref, err)
	}
	span.SetAttributes(attribute.String("deputy.target.commit", hash.String()))

	// Scan at the specific commit
	pkgs, err := ScanPackagesAtCommitSnapshot(ctx, repo, *hash, ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("failed to scan packages at ref %q: %w", ref, err)
	}
	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	// Get direct dependencies from the commit
	direct, _ := compare.CollectGoDirectModulesFromCommit(repo, *hash)

	// Get origin URL
	originURL := ""
	if remote, err := repo.Remote("origin"); err == nil && remote != nil {
		if urls := remote.Config().URLs; len(urls) > 0 {
			originURL = urls[0]
		}
	}

	result := Result{
		Target: Target{
			Kind:         targets.KindGit,
			DisplayPath:  resolved.displayPath,
			LocalPath:    resolved.localPath,
			Ref:          ref,
			EffectiveRef: ref,
			CommitHash:   hash.String(),
			OriginURL:    originURL,
			Cloned:       resolved.cloned,
			Provenance:   resolved.provenance,
		},
		GeneratedAt: time.Now().UTC(),
		Packages:    pkgs,
		Direct:      direct,
	}

	return &Execution{Result: result}, nil
}

// CollectBinary extracts inventory from a Go or Rust binary file.
// It uses SCALIBR's gobinary and cargoauditable extractors.
//
// For Go binaries, this extracts the embedded buildinfo which includes:
//   - The main module path and version
//   - All dependency module paths and versions
//
// For Rust binaries built with cargo-auditable, this extracts:
//   - All crate dependencies with versions
//
// Note: Standard Rust binaries without cargo-auditable metadata will return
// an empty inventory, not an error.
func CollectBinary(ctx context.Context, path string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.inventory.binary",
		trace.WithAttributes(
			attribute.String("deputy.target.path", path),
		))
	defer span.End()

	// Detect binary type
	binType := targets.DetectBinaryType(path)
	span.SetAttributes(attribute.String("deputy.binary.type", binType.String()))

	var pkgs []*extractor.Package
	var err error

	switch binType {
	case targets.BinaryTypeGo:
		pkgs, err = scanGoBinary(ctx, path)
	default:
		// Try SCALIBR scan for any binary (handles Rust and unknown types)
		pkgs, err = scanBinaryWithSCALIBR(ctx, path, opts)
	}

	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}

	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	result := Result{
		Target: Target{
			Kind:        targets.KindBinary,
			DisplayPath: path,
			LocalPath:   path,
		},
		GeneratedAt: time.Now().UTC(),
		Packages:    pkgs,
		Direct:      make(map[string]bool), // Binary deps are all "direct" in the sense they're compiled in
	}

	return &Execution{Result: result}, nil
}

// scanGoBinary extracts dependencies from a Go binary using debug/buildinfo.
// This is more efficient than SCALIBR for Go binaries since it uses the stdlib directly.
func scanGoBinary(ctx context.Context, path string) ([]*extractor.Package, error) {
	info, err := targets.ReadGoBinaryInfo(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Go binary info: %w", err)
	}

	// Count: main module + all deps
	pkgs := make([]*extractor.Package, 0, 1+len(info.Deps))

	// Add main module if present
	if info.Main.Path != "" {
		pkgs = append(pkgs, &extractor.Package{
			Name:      info.Main.Path,
			Version:   info.Main.Version,
			PURLType:  "golang",
			Locations: []string{path},
		})
	}

	// Add all dependencies
	for _, dep := range info.Deps {
		if dep.Path == "" {
			continue
		}
		// Skip replaced modules - use the replacement instead
		if dep.Replace != nil {
			dep = dep.Replace
		}
		pkgs = append(pkgs, &extractor.Package{
			Name:      dep.Path,
			Version:   dep.Version,
			PURLType:  "golang",
			Locations: []string{path},
		})
	}

	return pkgs, nil
}

// scanBinaryWithSCALIBR scans a binary file using SCALIBR extractors.
// This handles Rust binaries with cargo-auditable and serves as a fallback.
func scanBinaryWithSCALIBR(ctx context.Context, path string, opts Options) ([]*extractor.Package, error) {
	// Create a workspace containing just the binary's parent directory
	// This allows SCALIBR's FileRequired to properly filter
	ws, err := workspace.NewDir(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}
	defer ws.Close()

	// Use specific binary extractors
	return ScanPackagesWorking(ctx, ws, ScanOptions{
		Ecosystems: []string{"go/binary", "rust/cargoauditable"},
	})
}

// CollectPURL extracts inventory for a single PURL.
// This creates a minimal inventory with just the one package.
func CollectPURL(ctx context.Context, purlStr string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.inventory.purl",
		trace.WithAttributes(
			attribute.String("deputy.target.purl", purlStr),
		))
	defer span.End()

	pu, err := parsePURL(purlStr)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}

	// Create a single package entry
	pkg := &extractor.Package{
		Name:     purlDisplayName(pu),
		Version:  pu.Version,
		PURLType: pu.Type,
	}

	result := Result{
		Target: Target{
			Kind:        targets.KindPURL,
			DisplayPath: purlStr,
		},
		GeneratedAt: time.Now().UTC(),
		Packages:    []*extractor.Package{pkg},
		Direct:      map[string]bool{purlStr: true}, // PURLs are always direct
	}

	span.SetAttributes(attribute.Int("deputy.package.count", 1))

	return &Execution{Result: result}, nil
}

// parsePURL parses a PURL string into a PackageURL.
func parsePURL(purlStr string) (packageurl.PackageURL, error) {
	// Handle pkg: prefix
	if strings.HasPrefix(purlStr, "pkg:") {
		return packageurl.FromString(purlStr)
	}
	// Try with pkg: prefix if not already present
	return packageurl.FromString("pkg:" + purlStr)
}

// purlDisplayName returns a human-readable display name for a package URL.
func purlDisplayName(pu packageurl.PackageURL) string {
	name := pu.Name
	if pu.Namespace != "" {
		name = pu.Namespace + "/" + pu.Name
	}
	return name
}

// CollectSBOM extracts inventory from an SBOM file or stdin.
// Supports protobom-json, cyclonedx-json, and spdx-json formats.
func CollectSBOM(ctx context.Context, target string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.inventory.sbom",
		trace.WithAttributes(
			attribute.String("deputy.target.sbom", target),
		))
	defer span.End()

	var data []byte
	var err error
	var displayPath string

	if target == "-" {
		// Read from stdin
		data, err = io.ReadAll(os.Stdin)
		displayPath = "<stdin>"
	} else {
		data, err = os.ReadFile(target)
		displayPath = target
	}
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("failed to read SBOM: %w", err)
	}

	doc, err := parseSBOMDocument(data)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("failed to parse SBOM: %w", err)
	}

	pkgs := sbomDocToPackages(doc)

	result := Result{
		Target: Target{
			Kind:        targets.KindSBOM,
			DisplayPath: displayPath,
		},
		GeneratedAt: time.Now().UTC(),
		Packages:    pkgs,
		Direct:      make(map[string]bool), // SBOM doesn't distinguish direct/transitive
	}

	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	return &Execution{Result: result}, nil
}

// parseSBOMDocument parses SBOM data into a protobom Document.
// Supports protobom-json, cyclonedx-json, and spdx-json formats.
func parseSBOMDocument(data []byte) (*sbom.Document, error) {
	// Try protobom format first
	doc := &sbom.Document{}
	if err := protojson.Unmarshal(data, doc); err == nil && doc.NodeList != nil {
		return doc, nil
	}
	// For other formats, we'd need additional parsing
	// For now, only support protobom-json to avoid import cycle with sbomx
	return nil, fmt.Errorf("unsupported SBOM format (only protobom-json supported in inventory collector)")
}

// sbomDocToPackages converts a protobom Document to extractor.Package slice.
func sbomDocToPackages(doc *sbom.Document) []*extractor.Package {
	if doc == nil || doc.NodeList == nil {
		return nil
	}

	pkgs := make([]*extractor.Package, 0, len(doc.NodeList.Nodes))
	for _, node := range doc.NodeList.Nodes {
		if node == nil {
			continue
		}

		pkg := &extractor.Package{
			Name:     node.Name,
			Version:  node.Version,
			Licenses: node.Licenses,
		}

		// Extract PURL if available
		if node.Identifiers != nil {
			if purl, ok := node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]; ok {
				if pu, err := packageurl.FromString(purl); err == nil {
					pkg.PURLType = pu.Type
				}
			}
		}

		pkgs = append(pkgs, pkg)
	}

	return pkgs
}

// resolvedTarget holds the result of target resolution.
type resolvedTarget struct {
	kind        targets.Kind
	displayPath string
	localPath   string
	cloned      bool
	provenance  map[string]string
	workspace   workspace.FS
	cleanup     func()
}

// resolveRepositoryTarget resolves a target string to a local path.
func resolveRepositoryTarget(ctx context.Context, target, ref string) (*resolvedTarget, error) {
	// Try to open as git repository
	mat, err := targets.Open(ctx, target, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target %q: %w", target, err)
	}

	cleanup := func() {}
	if mat.Cleanup != nil {
		cleanup = mat.Cleanup
	}

	var ws workspace.FS
	switch data := mat.Data.(type) {
	case workspaceProvider:
		ws = data.Workspace()
	case workspace.FS:
		ws = data
	default:
		// Not a git/directory target - try workspace adapter
		dirWs, err := workspace.NewDir(mat.Path)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("unsupported target type for %q", target)
		}
		ws = dirWs
	}

	displayPath := target
	if mat.Meta.Target != "" {
		displayPath = mat.Meta.Target
	}

	return &resolvedTarget{
		kind:        mat.Meta.Kind,
		displayPath: displayPath,
		localPath:   mat.Path,
		cloned:      mat.Meta.Kind == targets.KindGit && mat.Meta.Provenance != nil && mat.Meta.Provenance["origin"] != "",
		provenance:  mat.Meta.Provenance,
		workspace:   ws,
		cleanup:     cleanup,
	}, nil
}

// refOrHEAD returns ref if non-empty, otherwise "HEAD".
func refOrHEAD(ref string) string {
	if ref == "" {
		return "HEAD"
	}
	return ref
}

// getRepoMetadata extracts commit hash and origin URL from a git repository.
func getRepoMetadata(repoPath, ref string) (commitHash, originURL string) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return "", ""
	}

	// Get commit hash - try HEAD first, then resolve ref
	head, err := repo.Head()
	if err == nil {
		commitHash = head.Hash().String()
	} else if ref != "" && ref != "HEAD" {
		// Try to resolve the ref directly
		hash, err := repo.ResolveRevision(plumbing.Revision(ref))
		if err == nil {
			commitHash = hash.String()
		}
	}

	// Get origin URL
	remote, err := repo.Remote("origin")
	if err == nil && remote != nil {
		urls := remote.Config().URLs
		if len(urls) > 0 {
			originURL = urls[0]
		}
	}

	return commitHash, originURL
}
