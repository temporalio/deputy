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

	sbomv1 "github.com/picatz/deputy/gen/deputy/sbom/v1"
	"github.com/picatz/deputy/gen/deputy/sbom/v1/sbomv1connect"
	"github.com/picatz/deputy/internal/otel"
	internalproto "github.com/picatz/deputy/internal/proto"
	sbomx "github.com/picatz/deputy/internal/sbom"
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
		eco := pkg.Ecosystem()
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

	// TODO: Implement SBOM diff using internal/sbom package
	err := fmt.Errorf("SBOM diff not yet implemented")
	otel.SetSpanError(span, err)
	return nil, connect.NewError(connect.CodeUnimplemented, err)
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
