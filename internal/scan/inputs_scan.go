package scan

import (
	"context"

	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/analysis/osv"
)

// ScanInputs queries OSV using precomputed inputs and returns a populated scan result.
// Note: Graph resolution is not supported for this method since there's no
// filesystem context. Use ScanRepository or ScanDirectory for graph support.
func (s *Service) ScanInputs(ctx context.Context, target Target, pkgs []*extractor.Package, direct map[string]bool, inputs []osv.PkgInput, opts Options) Result {
	svc := s
	if svc == nil {
		svc = NewService()
	}
	findings, advisories, queryErr := svc.queryOSV(ctx, inputs)
	return buildResult(buildResultInput{
		target:     target,
		pkgs:       pkgs,
		direct:     direct,
		findings:   findings,
		advisories: advisories,
		queryErr:   queryErr,
		opts:       opts,
		graph:      nil,
	})
}
