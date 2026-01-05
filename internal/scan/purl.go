package scan

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/picatz/deputy/internal/analysis/osv"
	"github.com/picatz/deputy/internal/ecosystem"
	"github.com/picatz/deputy/internal/logs"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/purlx"
	"github.com/picatz/deputy/internal/targets"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ScanPURL scans a single PURL by querying OSV directly.
func (s *Service) ScanPURL(ctx context.Context, purlStr string, opts Options) (*Execution, error) {
	startTime := time.Now()
	ctx, span := otel.StartSpan(ctx, "deputy.scan.purl",
		trace.WithAttributes(
			attribute.String("deputy.target.purl", purlStr),
		))
	defer span.End()

	purlStr = strings.TrimSpace(purlStr)
	if purlStr == "" {
		err := fmt.Errorf("purl is required")
		otel.SetSpanError(span, err)
		return nil, err
	}
	pu, err := purlx.ParseLoose(purlStr)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}
	pu.Type = strings.TrimSpace(pu.Type)
	pu.Namespace = strings.TrimSpace(pu.Namespace)
	pu.Name = strings.TrimSpace(pu.Name)
	pu.Version = strings.TrimSpace(pu.Version)
	if pu.Name == "" {
		err := fmt.Errorf("purl %q is missing a name", purlStr)
		otel.SetSpanError(span, err)
		return nil, err
	}
	if pu.Version == "" {
		err := fmt.Errorf("purl %q is missing a version", purlStr)
		otel.SetSpanError(span, err)
		return nil, err
	}
	canonical := pu.String()

	logs.Info(ctx, "starting purl scan", "purl", canonical)

	name := purlDisplayName(pu)
	ecos := purlEcosystem(pu)
	inputs := []osv.PkgInput{
		{
			QueryKey: osv.QueryKey{
				Name:      name,
				Version:   pu.Version,
				Ecosystem: ecos,
				PURL:      canonical,
			},
			PackageContext: osv.PackageContext{
				IsDirect: true,
			},
		},
	}
	pkgs := []*extractor.Package{
		{
			Name:     name,
			Version:  pu.Version,
			PURLType: pu.Type,
		},
	}
	direct := map[string]bool{}
	if canonical != "" {
		direct[canonical] = true
	}

	findings, advisories, queryErr := s.queryOSV(ctx, inputs)
	result := buildResult(
		Target{
			Kind:        targets.KindPURL,
			DisplayPath: canonical,
		},
		pkgs,
		direct,
		findings,
		advisories,
		queryErr,
		opts,
	)

	otel.RecordScanCompletion(ctx, otel.ScanCompletion{
		Span:         span,
		Duration:     time.Since(startTime).Seconds(),
		Ecosystem:    string(targets.KindPURL),
		PackageCount: result.PackagesScanned,
		Severity: otel.SeverityCounts{
			Critical: result.Stats.CriticalSev,
			High:     result.Stats.HighSeverity,
			Medium:   result.Stats.MedSeverity,
			Low:      result.Stats.LowSeverity,
		},
	})

	return &Execution{Result: result}, nil
}

func purlDisplayName(pu packageurl.PackageURL) string {
	if pu.Name == "" {
		return ""
	}
	if pu.Namespace == "" {
		return pu.Name
	}
	if strings.EqualFold(pu.Type, "maven") {
		return pu.Namespace + ":" + pu.Name
	}
	return path.Join(pu.Namespace, pu.Name)
}

func purlEcosystem(pu packageurl.PackageURL) string {
	if purlx.IsGitHubActionsType(pu.Type) {
		return "GitHub Actions"
	}
	eco := ecosystem.Parse(pu.Type)
	if eco != ecosystem.Unknown {
		return eco.OSVName()
	}
	return strings.TrimSpace(pu.Type)
}
