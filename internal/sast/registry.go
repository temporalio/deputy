package sast

import "sync"

// SymbolHint links a vulnerability identifier (primary or alias) to a dialect
// aware symbol. It can represent data sourced from OSV directly as well as
// Deputy specific augmentations.
type SymbolHint struct {
	Vulnerability string
	Alias         string
	Dialect       string
	Package       string
	Name          string
	Receiver      string
	Kind          SymbolKind
	Metadata      map[string]any
}

// SymbolID returns the canonical ID derived from the hint.
func (h SymbolHint) SymbolID() SymbolID {
	return SymbolID{
		Dialect: h.Dialect,
		Package: h.Package,
		Name:    h.Name,
		Recv:    h.Receiver,
	}
}

// SymbolRegistry stores hints keyed by vulnerability ID and symbol ID enabling
// bidirectional lookups during reachability checks.
type SymbolRegistry struct {
	mu       sync.RWMutex
	byVuln   map[string][]SymbolHint
	bySymbol map[string][]SymbolHint
}

// NewSymbolRegistry initialises an empty registry.
func NewSymbolRegistry() *SymbolRegistry {
	return &SymbolRegistry{
		byVuln:   make(map[string][]SymbolHint),
		bySymbol: make(map[string][]SymbolHint),
	}
}

// Register inserts a hint for a vulnerability. Duplicate hints are ignored if
// they have the same canonical symbol ID.
func (r *SymbolRegistry) Register(hint SymbolHint) {
	id := hint.SymbolID().String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byVuln[hint.Vulnerability]; !ok {
		r.byVuln[hint.Vulnerability] = []SymbolHint{}
	}
	if _, ok := r.bySymbol[id]; !ok {
		r.bySymbol[id] = []SymbolHint{}
	}
	if r.contains(r.byVuln[hint.Vulnerability], id) {
		return
	}
	r.byVuln[hint.Vulnerability] = append(r.byVuln[hint.Vulnerability], hint)
	r.bySymbol[id] = append(r.bySymbol[id], hint)
	if hint.Alias != "" {
		r.byVuln[hint.Alias] = append(r.byVuln[hint.Alias], hint)
	}
}

// contains reports whether any hint in the slice matches the symbol ID string.
func (r *SymbolRegistry) contains(hints []SymbolHint, symbolID string) bool {
	for _, h := range hints {
		if h.SymbolID().String() == symbolID {
			return true
		}
	}
	return false
}

// HintsForVulnerability returns all symbol hints registered for an OSV ID or
// alias. The slice is a copy and safe for modification by the caller.
func (r *SymbolRegistry) HintsForVulnerability(vulnID string) []SymbolHint {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hints := r.byVuln[vulnID]
	out := make([]SymbolHint, len(hints))
	copy(out, hints)
	return out
}

// HintsForSymbol returns all vulnerabilities associated with the provided
// symbol ID.
func (r *SymbolRegistry) HintsForSymbol(id SymbolID) []SymbolHint {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hints := r.bySymbol[id.String()]
	out := make([]SymbolHint, len(hints))
	copy(out, hints)
	return out
}

// RegisterOSVImport expands OSV ecosystem specific symbol entries into a hint.
func (r *SymbolRegistry) RegisterOSVImport(vulnID, alias, dialect, pkgPath string, symbol string) {
	r.Register(SymbolHint{
		Vulnerability: vulnID,
		Alias:         alias,
		Dialect:       dialect,
		Package:       pkgPath,
		Name:          symbol,
		Kind:          SymbolKindFunction,
	})
}
