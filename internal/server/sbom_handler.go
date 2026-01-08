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
	sbomx "github.com/picatz/deputy/internal/sbom"
	"github.com/picatz/deputy/internal/targets"
)

// SBOMHandler implements the SBOMService gRPC handler.
type SBOMHandler struct{}

// Ensure SBOMHandler implements the SBOMServiceHandler interface.
var _ sbomv1connect.SBOMServiceHandler = (*SBOMHandler)(nil)

// NewSBOMHandler creates a new SBOM service handler.
func NewSBOMHandler() *SBOMHandler {
	return &SBOMHandler{}
}

// Generate creates an SBOM for a target.
func (h *SBOMHandler) Generate(
	ctx context.Context,
	req *connect.Request[sbomv1.GenerateRequest],
) (*connect.Response[sbomv1.GenerateResponse], error) {
	if req.Msg.GetTarget() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target is required"))
	}

	// Security: Validate target is accessible from remote server
	if err := targets.ValidateRemoteTarget(req.Msg.GetTarget()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	opts := sbomx.Options{}

	if req.Msg.GetOptions() != nil {
		opts.EnrichLicenses = req.Msg.Options.GetIncludeLicenses()
		opts.Ref = req.Msg.Options.GetRef()
	}

	result, err := sbomx.Generate(ctx, req.Msg.GetTarget(), opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Convert document to requested format
	format := protoFormatToProtobom(req.Msg.GetFormat())
	var buf bytes.Buffer
	w := writer.New(writer.WithFormat(format))
	if err := w.WriteStream(result.Document, &buf); err != nil {
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
	if len(req.Msg.GetBase()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("base SBOM is required"))
	}
	if len(req.Msg.GetTarget()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target SBOM is required"))
	}

	// TODO: Implement SBOM diff using internal/sbom package
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("SBOM diff not yet implemented"))
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
