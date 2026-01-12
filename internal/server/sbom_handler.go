package server

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/writer"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	sbomv1 "github.com/picatz/deputy/gen/deputy/sbom/v1"
	"github.com/picatz/deputy/gen/deputy/sbom/v1/sbomv1connect"
	"github.com/picatz/deputy/internal/otel"
	internalproto "github.com/picatz/deputy/internal/proto"
	sbomx "github.com/picatz/deputy/internal/sbom"
	sbomdiff "github.com/picatz/deputy/internal/sbom/diff"
	"github.com/picatz/deputy/internal/targets"
)

// SBOMHandler implements the SBOMService gRPC handler.
type SBOMHandler struct {
	localMode bool // Skip remote target validation for in-process usage
}

// Ensure SBOMHandler implements the SBOMServiceHandler interface.
var _ sbomv1connect.SBOMServiceHandler = (*SBOMHandler)(nil)

// SBOMHandlerOption configures a SBOMHandler.
type SBOMHandlerOption func(*SBOMHandler)

// WithSBOMLocalMode enables local mode which skips remote target validation.
// Use this for in-process clients that need to access local filesystems.
func WithSBOMLocalMode() SBOMHandlerOption {
	return func(h *SBOMHandler) {
		h.localMode = true
	}
}

// NewSBOMHandler creates a new SBOM service handler.
func NewSBOMHandler(opts ...SBOMHandlerOption) *SBOMHandler {
	h := &SBOMHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Generate creates an SBOM for a target.
func (h *SBOMHandler) Generate(
	ctx context.Context,
	req *connect.Request[sbomv1.GenerateRequest],
) (*connect.Response[sbomv1.GenerateResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.GetTarget()
	if target == "" {
		target = "."
	}

	// Add business attributes to the otelconnect span
	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target is accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTarget(target); err != nil {
			otel.SetSpanError(span, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	opts := sbomx.Options{}

	if req.Msg.GetOptions() != nil {
		opts.EnrichLicenses = req.Msg.Options.GetIncludeLicenses()
		opts.Ref = req.Msg.Options.GetRef()
	}

	result, err := sbomx.Generate(ctx, target, opts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Convert document to requested format
	format := protoFormatToProtobom(req.Msg.GetFormat())
	var buf bytes.Buffer
	w := writer.New(writer.WithFormat(format))
	if err := w.WriteStream(result.Document, &buf); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("serialize SBOM: %w", err))
	}

	// Calculate stats from document
	stats := &sbomv1.Stats{
		TotalComponents: int32(len(result.Document.GetNodeList().GetNodes())),
		Ecosystems:      make(map[string]int32),
	}

	// Count packages by ecosystem
	for _, pkg := range result.Packages {
		eco := pkg.Ecosystem().String()
		if eco != "" {
			stats.Ecosystems[eco]++
		}
	}

	// Record component count on the span
	span.SetAttributes(otel.AttrPackageCount.Int(int(stats.TotalComponents)))

	resp := &sbomv1.GenerateResponse{
		Sbom:        buf.Bytes(),
		Format:      req.Msg.GetFormat(),
		GeneratedAt: timestamppb.New(time.Now()),
		Stats:       stats,
	}

	return connect.NewResponse(resp), nil
}

// Diff compares two SBOMs.
func (h *SBOMHandler) Diff(
	ctx context.Context,
	req *connect.Request[sbomv1.DiffRequest],
) (*connect.Response[sbomv1.DiffResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if len(req.Msg.GetBase()) == 0 {
		err := fmt.Errorf("base SBOM is required")
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if len(req.Msg.GetTarget()) == 0 {
		err := fmt.Errorf("target SBOM is required")
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Parse both SBOMs
	baseSBOM, err := sbomx.Read(req.Msg.GetBase())
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("parse base SBOM: %w", err))
	}

	targetSBOM, err := sbomx.Read(req.Msg.GetTarget())
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("parse target SBOM: %w", err))
	}

	// Compute the diff
	result, err := sbomdiff.Compare(baseSBOM, targetSBOM)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("compare SBOMs: %w", err))
	}

	// Convert to proto response
	resp := sbomDiffToProto(result)

	// Record stats on span
	stats := result.Stats()
	span.SetAttributes(
		otel.AttrPackageCount.Int(stats.Added + stats.Removed + stats.Changed),
	)

	return connect.NewResponse(resp), nil
}

// sbomDiffToProto converts internal diff result to proto response.
func sbomDiffToProto(d *sbomdiff.Diff) *sbomv1.DiffResponse {
	if d == nil {
		return &sbomv1.DiffResponse{}
	}

	resp := &sbomv1.DiffResponse{
		Added:    make([]*dependencyv1.Package, 0, len(d.Added)),
		Removed:  make([]*dependencyv1.Package, 0, len(d.Removed)),
		Modified: make([]*sbomv1.PackageChange, 0, len(d.Changed)),
	}

	// Convert added packages
	for _, pkg := range d.Added {
		resp.Added = append(resp.Added, &dependencyv1.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
			Purl:      pkg.PURL,
			Licenses:  pkg.Licenses,
		})
	}

	// Convert removed packages
	for _, pkg := range d.Removed {
		resp.Removed = append(resp.Removed, &dependencyv1.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
			Purl:      pkg.PURL,
			Licenses:  pkg.Licenses,
		})
	}

	// Convert changed packages
	for _, change := range d.Changed {
		protoChange := &sbomv1.PackageChange{
			Package: &dependencyv1.Package{
				Name:      change.Name,
				Ecosystem: extractEcosystemFromPURL(change.PURL),
				Purl:      change.PURL,
			},
			PreviousVersion: change.OldVersion,
			NewVersion:      change.NewVersion,
			Kind:            changeKindToProto(change.Kind),
		}
		if change.Licenses.HasChange() {
			protoChange.LicenseChange = &sbomv1.LicenseChange{
				Added:   change.Licenses.Added,
				Removed: change.Licenses.Removed,
			}
		}
		resp.Modified = append(resp.Modified, protoChange)
	}

	// Add stats
	stats := d.Stats()
	resp.Stats = &sbomv1.DiffStats{
		AddedCount:     int32(stats.Added),
		RemovedCount:   int32(stats.Removed),
		ModifiedCount:  int32(stats.Changed),
		BreakingCount:  int32(stats.Breaking),
		DowngradeCount: int32(stats.Downgrades),
	}

	return resp
}

// changeKindToProto converts internal ChangeKind to proto ChangeKind.
func changeKindToProto(k sbomdiff.ChangeKind) sbomv1.ChangeKind {
	switch k {
	case sbomdiff.ChangeKindMajor:
		return sbomv1.ChangeKind_CHANGE_KIND_MAJOR
	case sbomdiff.ChangeKindMinor:
		return sbomv1.ChangeKind_CHANGE_KIND_MINOR
	case sbomdiff.ChangeKindPatch:
		return sbomv1.ChangeKind_CHANGE_KIND_PATCH
	case sbomdiff.ChangeKindDowngrade:
		return sbomv1.ChangeKind_CHANGE_KIND_DOWNGRADE
	default:
		return sbomv1.ChangeKind_CHANGE_KIND_UNSPECIFIED
	}
}

// extractEcosystemFromPURL extracts the ecosystem from a PURL string.
func extractEcosystemFromPURL(purl string) string {
	// PURL format: pkg:type/namespace/name@version
	if len(purl) < 5 || purl[:4] != "pkg:" {
		return ""
	}
	rest := purl[4:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[:i]
		}
	}
	return ""
}

// protoFormatToProtobom converts proto SBOM format to protobom format.
func protoFormatToProtobom(f sbomv1.Format) formats.Format {
	switch f {
	case sbomv1.Format_FORMAT_CYCLONEDX_JSON, sbomv1.Format_FORMAT_CYCLONEDX_XML:
		return formats.CDX16JSON
	case sbomv1.Format_FORMAT_SPDX_JSON, sbomv1.Format_FORMAT_SPDX_TV:
		return formats.SPDX23JSON
	default:
		return formats.CDX16JSON
	}
}
