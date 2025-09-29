package sast

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// Engine wires dialect discovery, IR construction, and reachability evaluation
// into a cohesive workflow.
type Engine struct {
	dialects *DialectRegistry
	symbols  *SymbolRegistry
}

// EngineOption customises the reachability engine at construction time.
type EngineOption func(*Engine)

// WithDialect registers a dialect with the engine's internal registry.
func WithDialect(d Dialect) EngineOption {
	return func(e *Engine) {
		e.dialects.Register(d)
	}
}

// WithSymbolRegistry swaps the default symbol registry with a caller provided
// instance.
func WithSymbolRegistry(r *SymbolRegistry) EngineOption {
	return func(e *Engine) {
		e.symbols = r
	}
}

// NewEngine constructs an Engine configured via options.
func NewEngine(opts ...EngineOption) *Engine {
	e := &Engine{
		dialects: NewDialectRegistry(),
		symbols:  NewSymbolRegistry(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// ReachabilityFinding represents the result for a specific vulnerability hint.
type ReachabilityFinding struct {
	Vulnerability string
	Hint          SymbolHint
	Symbol        Symbol
	Reachable     bool
	Path          []SymbolID
	Message       string
}

// ReachabilityReport is the top level result returned by the engine.
type ReachabilityReport struct {
	Target      TargetDescriptor
	DialectName string
	Findings    []ReachabilityFinding
	Entrypoints []SymbolID
}

// AnalyzeReachability builds the IR for the target and evaluates the provided
// vulnerabilities (identified by OSV IDs or aliases) for reachability.
func (e *Engine) AnalyzeReachability(ctx context.Context, target *Target, vulnerabilities []string) (*ReachabilityReport, error) {
	if target == nil {
		return nil, errors.New("sast: nil target")
	}
	dialect := e.dialects.Resolve(target)
	if dialect == nil {
		return nil, fmt.Errorf("%w: no dialect available", ErrUnsupportedTarget)
	}

	units, err := dialect.DiscoverUnits(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("discover units: %w", err)
	}
	if len(units) == 0 {
		return nil, fmt.Errorf("%w: dialect %s returned no units", ErrUnsupportedTarget, dialect.Name())
	}

	var packages []*IRPackage
	for _, unit := range units {
		if err := dialect.Prepare(ctx, unit); err != nil {
			return nil, fmt.Errorf("prepare unit %s: %w", unit.Path, err)
		}
		pkg, err := dialect.LowerToIR(ctx, unit)
		if err != nil {
			return nil, fmt.Errorf("lower unit %s: %w", unit.Path, err)
		}
		if pkg != nil {
			unit.IR = pkg
			packages = append(packages, pkg)
		}
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("dialect %s produced no IR packages", dialect.Name())
	}

	graph := NewGraph()
	for _, pkg := range packages {
		graph.Merge(pkg.Graph)
	}
	snapshot := graph.Snapshot()
	entrypoints := collectEntrypoints(packages, snapshot)

	report := &ReachabilityReport{
		Target:      target.Descriptor,
		DialectName: dialect.Name(),
		Entrypoints: entrypoints,
	}

	cfg := ReachabilityConfig{
		Snapshot:   snapshot,
		Edge:       EdgeKindCall,
		Entrypoint: entrypoints,
	}

	for _, vuln := range vulnerabilities {
		if e.symbols == nil {
			report.Findings = append(report.Findings, ReachabilityFinding{
				Vulnerability: vuln,
				Message:       "no symbol registry configured",
			})
			continue
		}
		hints := e.symbols.HintsForVulnerability(vuln)
		if len(hints) == 0 {
			report.Findings = append(report.Findings, ReachabilityFinding{
				Vulnerability: vuln,
				Message:       "no symbol hints registered",
			})
			continue
		}
		for _, hint := range hints {
			id := hint.SymbolID()
			sym, ok := snapshot.Symbol(id)
			if !ok {
				report.Findings = append(report.Findings, ReachabilityFinding{
					Vulnerability: vuln,
					Hint:          hint,
					Message:       "symbol not observed in graph",
				})
				continue
			}
			res := Reachability(cfg, id)
			report.Findings = append(report.Findings, ReachabilityFinding{
				Vulnerability: vuln,
				Hint:          hint,
				Symbol:        sym,
				Reachable:     res.Reachable,
				Path:          res.Path,
				Message:       outcomeMessage(res.Reachable),
			})
		}
	}

	return report, nil
}

// AnalyzeTaint builds the IR for the target and executes taint/dataflow
// analyses described by configs. The returned slice aggregates flows from all
// configs.
func (e *Engine) AnalyzeTaint(ctx context.Context, target *Target, configs []TaintConfig) ([]TaintFlow, error) {
	if target == nil {
		return nil, errors.New("sast: nil target")
	}
	dialect := e.dialects.Resolve(target)
	if dialect == nil {
		return nil, fmt.Errorf("%w: no dialect available", ErrUnsupportedTarget)
	}

	units, err := dialect.DiscoverUnits(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("discover units: %w", err)
	}
	if len(units) == 0 {
		return nil, fmt.Errorf("%w: dialect %s returned no units", ErrUnsupportedTarget, dialect.Name())
	}

	var packages []*IRPackage
	for _, unit := range units {
		if err := dialect.Prepare(ctx, unit); err != nil {
			return nil, fmt.Errorf("prepare unit %s: %w", unit.Path, err)
		}
		pkg, err := dialect.LowerToIR(ctx, unit)
		if err != nil {
			return nil, fmt.Errorf("lower unit %s: %w", unit.Path, err)
		}
		if pkg != nil {
			packages = append(packages, pkg)
		}
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("dialect %s produced no IR packages", dialect.Name())
	}

	graph := NewGraph()
	for _, pkg := range packages {
		graph.Merge(pkg.Graph)
	}
	snapshot := graph.Snapshot()
	engine := NewTaintEngine(snapshot)
	var flows []TaintFlow
	for _, cfg := range configs {
		flows = append(flows, engine.Analyze(cfg)...)
	}
	return flows, nil
}

func outcomeMessage(reachable bool) string {
	if reachable {
		return "reachable"
	}
	return "unreachable"
}

func collectEntrypoints(pkgs []*IRPackage, snapshot Snapshot) []SymbolID {
	recorded := map[string]SymbolID{}
	for _, pkg := range pkgs {
		for _, id := range pkg.Entrypoints {
			if key := id.String(); key != "" {
				recorded[key] = id
			}
		}
		if len(pkg.Entrypoints) == 0 {
			pkgSnapshot := pkg.Graph.Snapshot()
			for _, sym := range pkgSnapshot.Symbols() {
				if sym.Attributes != nil {
					if val, ok := sym.Attributes["entrypoint"].(bool); ok && val {
						recorded[sym.ID.String()] = sym.ID
					}
				}
			}
		}
	}
	if len(recorded) == 0 {
		// Last resort: look for canonical main functions.
		for _, sym := range snapshot.Symbols() {
			if sym.Kind == SymbolKindFunction && sym.ID.Name == "main" {
				recorded[sym.ID.String()] = sym.ID
			}
		}
	}
	out := make([]SymbolID, 0, len(recorded))
	for _, id := range recorded {
		if _, ok := snapshot.Symbol(id); !ok {
			continue
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out
}
