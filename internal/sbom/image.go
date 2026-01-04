package sbomx

import (
	"context"
	"fmt"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	"github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/picatz/deputy/internal/scan"
	"github.com/picatz/deputy/internal/targets"
	"github.com/picatz/deputy/internal/targets/providers"
	"github.com/protobom/protobom/pkg/sbom"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// GenerateImage builds an SBOM document for a container image target.
func GenerateImage(ctx context.Context, target string, targetOpts map[string]string, opts Options) (Result, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.sbom.generate_image",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
			attribute.Bool("deputy.sbom.enrich_licenses", opts.EnrichLicenses),
		))
	defer span.End()

	target = strings.TrimSpace(target)
	if target == "" {
		return Result{}, fmt.Errorf("image target is required")
	}

	mat, err := targets.Open(ctx, target, targetOpts)
	if err != nil {
		otel.SetSpanError(span, err)
		return Result{}, err
	}

	cleanup := func() {}
	if mat.Cleanup != nil {
		cleanup = mat.Cleanup
	}
	defer cleanup()

	img, ok := mat.Data.(scalibrimage.Image)
	if !ok {
		err := fmt.Errorf("target %q did not resolve to a container image", target)
		otel.SetSpanError(span, err)
		return Result{}, err
	}

	pkgs, err := inventory.ScanPackagesContainerImage(ctx, img, inventory.ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		otel.SetSpanError(span, err)
		return Result{}, err
	}
	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	display := target
	if mat.Meta.Target != "" {
		display = mat.Meta.Target
	}
	docName := opts.Name
	if docName == "" {
		docName = display
	}

	// Wrap the image filesystem in a workspace adapter for license scanning.
	// The ReadOnlyFS wrapper provides the workspace.FS interface needed by
	// buildProtobomDocument and license enrichment functions.
	var ws workspace.FS
	if mat.FS != nil {
		ws = workspace.NewReadOnlyFS(mat.FS)
	}
	doc, err := buildProtobomDocument(ctx, ws, display, "", docName, pkgs, nil)
	if err != nil {
		otel.SetSpanError(span, err)
		return Result{}, err
	}

	if opts.EnrichLicenses {
		switch strings.ToLower(opts.LicenseSource) {
		case "depsdev", "deps", "dd":
			if err := enrichProtobomLicensesDepsDev(ctx, doc); err != nil {
				return Result{}, err
			}
		case "scan":
			if err := enrichProtobomLicensesScanLocal(ctx, doc, ws); err != nil {
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
			if err := enrichProtobomLicensesScanLocal(ctx, doc, ws); err != nil {
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

	targetMeta := scan.Target{
		Kind:        targets.KindContainerImage,
		DisplayPath: display,
		LocalPath:   mat.Path,
		Provenance:  mat.Meta.Provenance,
	}
	if registry := strings.TrimSpace(mat.Meta.Provenance["registry"]); registry != "" {
		targetMeta.OriginURL = registry
	}

	// Extract and apply OCI label licenses to the root SBOM node.
	// This provides license information from the image's org.opencontainers.image.licenses label,
	// which is the standard OCI annotation for declaring image licenses.
	if v1Img := extractV1Image(mat.Data); v1Img != nil {
		if licenses := extractOCILabelLicenses(v1Img); len(licenses) > 0 {
			if root := rootNode(doc); root != nil {
				root.Licenses = appendUniqueLicenses(root.Licenses, licenses)
			}
		}
	}

	result := Result{
		Document: doc,
		Target:   targetMeta,
		RepoPath: display,
		Packages: pkgs,
	}

	return result, nil
}

// OCI annotation key for image licenses per the OCI image spec.
// See: https://github.com/opencontainers/image-spec/blob/main/annotations.md
const ociLicensesAnnotation = "org.opencontainers.image.licenses"

// extractV1Image attempts to extract the underlying v1.Image from materialized target data.
// Returns nil if the data does not contain a v1.Image (e.g., for tarball sources).
func extractV1Image(data any) v1.Image {
	switch d := data.(type) {
	case *providers.ContainerImageData:
		return d.V1Image
	case v1.Image:
		return d
	default:
		return nil
	}
}

// extractOCILabelLicenses extracts license identifiers from the OCI image labels.
// The org.opencontainers.image.licenses annotation should contain SPDX license expression(s).
// Returns nil if no license label is present or the image config cannot be read.
func extractOCILabelLicenses(img v1.Image) []string {
	if img == nil {
		return nil
	}

	cf, err := img.ConfigFile()
	if err != nil || cf == nil {
		return nil
	}

	licenseValue := cf.Config.Labels[ociLicensesAnnotation]
	if licenseValue == "" {
		return nil
	}

	return parseOCILicenseExpression(licenseValue)
}

// parseOCILicenseExpression parses an SPDX license expression into individual license identifiers.
// The OCI spec recommends SPDX expressions like "Apache-2.0" or "MIT OR Apache-2.0".
// This function splits compound expressions into individual licenses.
func parseOCILicenseExpression(expr string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}

	// Split on common SPDX expression operators and separators
	// Handle: "MIT", "MIT OR Apache-2.0", "MIT AND GPL-2.0", "MIT, Apache-2.0"
	var licenses []string
	seen := make(map[string]bool)

	// Split on OR, AND, comma, semicolon while preserving license IDs
	parts := strings.FieldsFunc(expr, func(r rune) bool {
		return r == ',' || r == ';'
	})

	for _, part := range parts {
		// Further split on " OR " and " AND " (with spaces to avoid splitting license names)
		subparts := splitOnOperators(part)
		for _, license := range subparts {
			license = strings.TrimSpace(license)
			// Remove SPDX expression syntax artifacts
			license = strings.TrimPrefix(license, "(")
			license = strings.TrimSuffix(license, ")")
			license = strings.TrimSpace(license)

			if license == "" || license == "OR" || license == "AND" || license == "WITH" {
				continue
			}

			// Normalize and deduplicate
			if !seen[license] {
				seen[license] = true
				licenses = append(licenses, license)
			}
		}
	}

	if len(licenses) == 0 {
		return nil
	}
	slices.Sort(licenses)
	return licenses
}

// splitOnOperators splits a string on SPDX operators (OR, AND) while preserving license identifiers.
func splitOnOperators(s string) []string {
	var result []string
	// Replace operators with a delimiter we can split on
	s = strings.ReplaceAll(s, " OR ", "\x00")
	s = strings.ReplaceAll(s, " AND ", "\x00")
	s = strings.ReplaceAll(s, " or ", "\x00")
	s = strings.ReplaceAll(s, " and ", "\x00")
	for _, part := range strings.Split(s, "\x00") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// enrichProtobomLicensesFromOCILabels adds licenses from OCI image labels to the SBOM root node.
// This is called during license enrichment to capture image-level license declarations.
func enrichProtobomLicensesFromOCILabels(doc *sbom.Document, img v1.Image) {
	if doc == nil || img == nil {
		return
	}
	licenses := extractOCILabelLicenses(img)
	if len(licenses) == 0 {
		return
	}
	root := rootNode(doc)
	if root == nil {
		return
	}
	root.Licenses = appendUniqueLicenses(root.Licenses, licenses)
}
