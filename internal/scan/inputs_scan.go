package scan

import (
	"context"

	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/analysis/osv"
)

// ScanInputs queries OSV using precomputed inputs and returns a populated scan result.
func (s *Service) ScanInputs(ctx context.Context, target Target, pkgs []*extractor.Package, direct map[string]bool, inputs []osv.PkgInput, opts Options) Result {
	svc := s
	if svc == nil {
		svc = NewService()
	}
	findings, advisories, queryErr := svc.queryOSV(ctx, inputs)
	return buildResult(target, pkgs, direct, findings, advisories, queryErr, opts)
}
