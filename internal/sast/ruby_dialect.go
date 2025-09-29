package sast

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// RubyDialect implements the Dialect interface for Ruby ecosystems. It delegates
// lexing and parsing to the specialised lexer/parser in ruby_parser.go and then
// lowers the resulting symbols into the shared IR graph.
type RubyDialect struct{}

// NewRubyDialect constructs a RubyDialect instance ready for registration.
func NewRubyDialect() *RubyDialect { return &RubyDialect{} }

func (d *RubyDialect) Name() string { return "ruby" }

func (d *RubyDialect) Supports(target *Target) bool {
	if target == nil || target.FS == nil {
		return false
	}
	found := false
	fs.WalkDir(target.FS, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil || found {
			return err
		}
		if entry.IsDir() {
			if shouldSkipRubyDir(p) {
				return fs.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rb") || name == "Gemfile" || strings.HasSuffix(name, ".gemspec") {
			found = true
			return fs.SkipDir
		}
		return nil
	})
	return found
}

func (d *RubyDialect) DiscoverUnits(ctx context.Context, target *Target) ([]*CompilationUnit, error) {
	if target == nil || target.FS == nil {
		return nil, fmt.Errorf("nil target or filesystem")
	}
	packages := make(map[string][]string)
	err := fs.WalkDir(target.FS, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if shouldSkipRubyDir(p) {
				return fs.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".rb") && name != "Gemfile" && !strings.HasSuffix(name, ".gemspec") {
			return nil
		}
		dir := path.Dir(p)
		packages[dir] = append(packages[dir], p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("no Ruby sources discovered")
	}
	units := make([]*CompilationUnit, 0, len(packages))
	for dir, files := range packages {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		sort.Strings(files)
		units = append(units, &CompilationUnit{
			Segment: TargetSegment{Path: dir, FS: target.FS},
			Path:    dir,
			Files:   files,
		})
	}
	sort.Slice(units, func(i, j int) bool { return units[i].Path < units[j].Path })
	return units, nil
}

func (d *RubyDialect) Prepare(ctx context.Context, unit *CompilationUnit) error {
	if unit == nil {
		return fmt.Errorf("nil compilation unit")
	}
	if len(unit.Files) == 0 {
		return fmt.Errorf("unit %s has no files", unit.Path)
	}
	agg := &rubyUnit{types: make(map[string]*rubyType)}
	var tokens []Token
	for _, file := range unit.Files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		src, err := fs.ReadFile(unit.Segment.FS, file)
		if err != nil {
			return fmt.Errorf("read %s: %w", file, err)
		}
		lex := lexRuby(file, src)
		tokens = append(tokens, lex.genericTokens...)
		fileUnit := parseRubyFile(file, lex)
		agg.methods = append(agg.methods, fileUnit.methods...)
		agg.aliases = append(agg.aliases, fileUnit.aliases...)
		agg.requires = append(agg.requires, fileUnit.requires...)
		mergeRubyTypes(agg.types, fileUnit.types)
	}
	unit.Tokens = tokens
	unit.AST = agg
	return nil
}

func mergeRubyTypes(dst map[string]*rubyType, src map[string]*rubyType) {
	if len(src) == 0 {
		return
	}
	for name, typ := range src {
		if typ == nil {
			continue
		}
		if existing, ok := dst[name]; ok {
			if existing.Kind == "" {
				existing.Kind = typ.Kind
			}
			if existing.Super == "" {
				existing.Super = typ.Super
			}
			existing.Includes = appendUnique(existing.Includes, typ.Includes...)
			existing.Extends = appendUnique(existing.Extends, typ.Extends...)
			existing.Prepends = appendUnique(existing.Prepends, typ.Prepends...)
			if len(typ.Visibility) > 0 {
				if existing.Visibility == nil {
					existing.Visibility = make(map[string]rubyVisibility, len(typ.Visibility))
				}
				for k, v := range typ.Visibility {
					existing.Visibility[k] = v
				}
			}
			if len(typ.ModuleFunctions) > 0 {
				if existing.ModuleFunctions == nil {
					existing.ModuleFunctions = make(map[string]struct{}, len(typ.ModuleFunctions))
				}
				for k := range typ.ModuleFunctions {
					existing.ModuleFunctions[k] = struct{}{}
				}
			}
			if typ.ModuleFnDefault {
				existing.ModuleFnDefault = true
			}
			continue
		}
		dst[name] = cloneRubyType(typ)
	}
}

func cloneRubyType(typ *rubyType) *rubyType {
	if typ == nil {
		return nil
	}
	clone := &rubyType{
		Name:            typ.Name,
		Kind:            typ.Kind,
		Super:           typ.Super,
		Includes:        append([]string(nil), typ.Includes...),
		Extends:         append([]string(nil), typ.Extends...),
		Prepends:        append([]string(nil), typ.Prepends...),
		ModuleFnDefault: typ.ModuleFnDefault,
	}
	if len(typ.Visibility) > 0 {
		clone.Visibility = make(map[string]rubyVisibility, len(typ.Visibility))
		for k, v := range typ.Visibility {
			clone.Visibility[k] = v
		}
	}
	if len(typ.ModuleFunctions) > 0 {
		clone.ModuleFunctions = make(map[string]struct{}, len(typ.ModuleFunctions))
		for k := range typ.ModuleFunctions {
			clone.ModuleFunctions[k] = struct{}{}
		}
	}
	return clone
}

func (d *RubyDialect) LowerToIR(ctx context.Context, unit *CompilationUnit) (*IRPackage, error) {
	data, ok := unit.AST.(*rubyUnit)
	if !ok {
		return nil, fmt.Errorf("unexpected AST payload for Ruby unit")
	}
	graph := NewGraph()
	canonicalIndex := make(map[string]SymbolID)
	methodByKey := make(map[string]*rubyMethod)
	methodsByReceiver := make(map[string][]*rubyMethod)
	if data.types == nil {
		data.types = make(map[string]*rubyType)
	}

	var symbols []Symbol
	var entrypoints []SymbolID
	seenPlaceholders := make(map[string]struct{})

	for _, method := range data.methods {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		receiver := receiverOrDefault(method.receiver)
		typeInfo := data.types[receiver]
		if typeInfo == nil {
			typeInfo = &rubyType{Name: receiver}
			data.types[receiver] = typeInfo
		}

		id := rubyMethodSymbolID(unit.Path, method)
		key := canonicalMethodKey(method)
		canonicalIndex[key] = id
		methodByKey[key] = method
		methodsByReceiver[receiver] = append(methodsByReceiver[receiver], method)

		kind := SymbolKindMethod
		if method.typ == rubyMethodTopLevel {
			kind = SymbolKindFunction
		}

		attrs := map[string]any{}
		for k, v := range method.attributes {
			attrs[k] = v
		}
		if typeInfo != nil {
			if vis := typeInfo.Visibility; vis != nil {
				if visibility, ok := vis[method.name]; ok {
					attrs["visibility"] = string(visibility)
				}
			}
			if typeInfo.ModuleFnDefault {
				attrs["module_function_default"] = true
			}
			if _, ok := typeInfo.ModuleFunctions[method.name]; ok {
				attrs["module_function"] = true
			}
		}
		if method.typ == rubyMethodClass {
			attrs["class_method"] = true
		}
		sym := Symbol{
			ID:        id,
			Kind:      kind,
			Display:   methodDisplayName(method),
			Locations: []Location{method.location},
		}
		if len(attrs) > 0 {
			sym.Attributes = attrs
		}
		graph.AddSymbol(sym)
		symbols = append(symbols, sym)
		if val, ok := attrs["entrypoint"].(bool); ok && val {
			entrypoints = append(entrypoints, id)
		}
	}

	for _, method := range data.methods {
		if len(method.params) > 0 {
			for idx := range method.params {
				paramID := rubyParamSymbolID(unit.Path, method, idx)
				paramSym := Symbol{
					ID:      paramID,
					Kind:    SymbolKindField,
					Display: rubyParamDisplay(method, idx),
					Attributes: map[string]any{
						"parameter": method.params[idx].name,
						"index":     idx,
						"kind":      method.params[idx].kind.String(),
					},
				}
				graph.AddSymbol(paramSym)
				symbols = append(symbols, paramSym)
				graph.AddEdgeWithAttributes(EdgeKindCall, paramID, rubyMethodSymbolID(unit.Path, method), EdgeAttributes{Confidence: EdgeConfidenceCertain, Metadata: map[string]any{"direction": "param_to_body"}})
			}
		}
		if method.hasBlock || method.blockParam != "" || method.yields {
			blockID := rubyBlockSymbolID(unit.Path, method)
			if blockID.String() != "" {
				attrs := map[string]any{"block": true}
				if method.blockParam != "" {
					attrs["block_param"] = method.blockParam
				}
				if method.yields {
					attrs["yields"] = true
				}
				blockSym := Symbol{ID: blockID, Kind: SymbolKindCallsite, Display: fmt.Sprintf("%s block", methodDisplayName(method)), Attributes: attrs}
				graph.AddSymbol(blockSym)
				symbols = append(symbols, blockSym)
				graph.AddEdgeWithAttributes(EdgeKindCall, blockID, rubyMethodSymbolID(unit.Path, method), EdgeAttributes{Confidence: EdgeConfidenceCertain, Metadata: map[string]any{"direction": "block_to_body"}})
			}
		}
	}

	applyModuleFunctions(graph, canonicalIndex, &symbols, unit.Path, data.types, methodsByReceiver, methodByKey)
	applyMixins(graph, canonicalIndex, &symbols, unit.Path, data.types, methodsByReceiver, methodByKey)
	applyInheritance(graph, canonicalIndex, &symbols, unit.Path, data.types, methodsByReceiver, methodByKey)
	applyAliases(graph, canonicalIndex, &symbols, unit.Path, data.aliases)

	for _, method := range data.methods {
		fromID := rubyMethodSymbolID(unit.Path, method)
		for _, call := range method.calls {
			key := canonicalCallKey(call.receiver, call.name, call.typ)
			targetID, ok := canonicalIndex[key]
			if !ok {
				targetID = SymbolID{Dialect: d.Name(), Package: unit.Path, Name: call.name, Recv: receiverOrDefault(call.receiver)}
				canonicalIndex[key] = targetID
				if _, seen := seenPlaceholders[targetID.String()]; !seen {
					placeholder := Symbol{ID: targetID, Kind: SymbolKindMethod, Display: methodDisplayFromCall(call), Attributes: map[string]any{"placeholder": true}}
					graph.AddSymbol(placeholder)
					symbols = append(symbols, placeholder)
					seenPlaceholders[targetID.String()] = struct{}{}
				}
			}
			if call.yieldCall {
				blockID := rubyBlockSymbolID(unit.Path, method)
				if blockID.String() != "" {
					graph.AddEdgeWithAttributes(EdgeKindCall, fromID, blockID, edgeAttributesFromCall(call))
					limit := call.argCount
					if limit <= 0 || limit > len(method.params) {
						limit = len(method.params)
					}
					for i := 0; i < limit; i++ {
						paramID := rubyParamSymbolID(unit.Path, method, i)
						graph.AddEdgeWithAttributes(EdgeKindCall, paramID, blockID, EdgeAttributes{Confidence: call.confidence, Metadata: map[string]any{"yield_arg": i}})
					}
				}
				continue
			}
			attrs := edgeAttributesFromCall(call)
			graph.AddEdgeWithAttributes(EdgeKindCall, fromID, targetID, attrs)
			if calleeMethod, ok := methodByKey[key]; ok {
				argMap := buildArgMapping(method, calleeMethod, call)
				for _, pair := range argMap {
					callerParamID := rubyParamSymbolID(unit.Path, method, pair.from)
					calleeParamID := rubyParamSymbolID(unit.Path, calleeMethod, pair.to)
					if callerParamID.String() == "" || calleeParamID.String() == "" {
						continue
					}
					metadata := map[string]any{"arg_flow": true, "from_index": pair.from, "to_index": pair.to}
					graph.AddEdgeWithAttributes(EdgeKindCall, callerParamID, calleeParamID, EdgeAttributes{Confidence: attrs.Confidence, Metadata: metadata})
				}
				if call.hasBlock {
					callerBlock := rubyBlockSymbolID(unit.Path, method)
					calleeBlock := rubyBlockSymbolID(unit.Path, calleeMethod)
					if callerBlock.String() != "" && calleeBlock.String() != "" {
						graph.AddEdgeWithAttributes(EdgeKindCall, callerBlock, calleeBlock, EdgeAttributes{Confidence: attrs.Confidence, Metadata: map[string]any{"block_flow": true}})
					}
				}
			}
			graph.AddEdgeWithAttributes(EdgeKindCall, targetID, fromID, EdgeAttributes{Confidence: attrs.Confidence, Metadata: map[string]any{"return_flow": true}})
		}
	}

	return &IRPackage{
		Dialect:     d.Name(),
		Unit:        unit,
		Graph:       graph,
		Symbols:     symbols,
		Entrypoints: uniqueSymbolIDs(entrypoints),
	}, nil
}

func edgeAttributesFromCall(call rubyCall) EdgeAttributes {
	attrs := EdgeAttributes{Confidence: call.confidence}
	if attrs.Confidence == EdgeConfidenceUnknown {
		attrs.Confidence = EdgeConfidenceCertain
	}
	meta := make(map[string]any)
	if call.dynamic {
		meta["dynamic"] = true
	}
	if call.source != "" && call.source != "direct" {
		meta["source"] = call.source
	}
	if len(call.symbolArgs) > 0 {
		copyArgs := append([]string(nil), call.symbolArgs...)
		meta["symbol_args"] = copyArgs
	}
	for k, v := range call.metadata {
		meta[k] = v
	}
	if call.argCount > 0 {
		meta["arg_count"] = call.argCount
	}
	if call.hasBlock {
		meta["has_block"] = true
	}
	if call.yieldCall {
		meta["yield"] = true
	}
	if len(meta) > 0 {
		attrs.Metadata = meta
	}
	return attrs
}

func ensureAliasSymbol(graph *Graph, canonicalIndex map[string]SymbolID, symbols *[]Symbol, unitPath string, targetID SymbolID, receiver, name string, typ rubyMethodType, reason string, extra map[string]any) SymbolID {
	aliasKey := canonicalCallKey(receiver, name, typ)
	if existing, ok := canonicalIndex[aliasKey]; ok {
		return existing
	}
	aliasID := SymbolID{Dialect: "ruby", Package: unitPath, Name: name, Recv: receiverOrDefault(receiver)}
	kind := SymbolKindMethod
	if typ == rubyMethodTopLevel {
		kind = SymbolKindFunction
	}
	display := methodDisplayFromCall(rubyCall{receiver: receiver, name: name, typ: typ})
	attrs := make(map[string]any, 2)
	attrs["alias_of"] = targetID.String()
	attrs["relationship"] = reason
	if typ == rubyMethodClass {
		attrs["class_method"] = true
	}
	for k, v := range extra {
		attrs[k] = v
	}
	aliasSym := Symbol{ID: aliasID, Kind: kind, Display: display, Attributes: attrs}
	graph.AddSymbol(aliasSym)
	*symbols = append(*symbols, aliasSym)
	graph.AddEdgeWithAttributes(EdgeKindCall, aliasID, targetID, EdgeAttributes{Confidence: EdgeConfidenceCertain, Metadata: map[string]any{"alias": true, "relationship": reason}})
	canonicalIndex[aliasKey] = aliasID
	return aliasID
}

func applyModuleFunctions(graph *Graph, canonicalIndex map[string]SymbolID, symbols *[]Symbol, unitPath string, types map[string]*rubyType, methodsByReceiver map[string][]*rubyMethod, methodByKey map[string]*rubyMethod) {
	for name, typ := range types {
		if typ == nil || typ.Kind != rubyTypeModule {
			continue
		}
		methods := methodsByReceiver[name]
		if len(methods) == 0 {
			continue
		}
		for _, method := range methods {
			if method.typ != rubyMethodInstance && method.typ != rubyMethodTopLevel {
				continue
			}
			moduleFunc := typ.ModuleFnDefault
			if method.attributes != nil {
				if val, ok := method.attributes["module_function"].(bool); ok && val {
					moduleFunc = true
				}
			}
			if _, ok := typ.ModuleFunctions[method.name]; ok {
				moduleFunc = true
			}
			if !moduleFunc {
				continue
			}
			targetKey := canonicalMethodKey(method)
			targetID, ok := canonicalIndex[targetKey]
			if !ok {
				continue
			}
			extra := map[string]any{"module_function": true}
			ensureAliasSymbol(graph, canonicalIndex, symbols, unitPath, targetID, name, method.name, rubyMethodClass, "module_function", extra)
		}
	}
}

func applyMixins(graph *Graph, canonicalIndex map[string]SymbolID, symbols *[]Symbol, unitPath string, types map[string]*rubyType, methodsByReceiver map[string][]*rubyMethod, methodByKey map[string]*rubyMethod) {
	for name, typ := range types {
		if typ == nil {
			continue
		}
		if len(typ.Includes) > 0 {
			for _, mod := range typ.Includes {
				for _, modMethod := range methodsByReceiver[mod] {
					if modMethod.typ == rubyMethodClass {
						continue
					}
					targetKey := canonicalMethodKey(modMethod)
					targetID, ok := canonicalIndex[targetKey]
					if !ok {
						continue
					}
					ensureAliasSymbol(graph, canonicalIndex, symbols, unitPath, targetID, name, modMethod.name, rubyMethodInstance, "include", nil)
				}
			}
		}
		if len(typ.Prepends) > 0 {
			for _, mod := range typ.Prepends {
				for _, modMethod := range methodsByReceiver[mod] {
					if modMethod.typ == rubyMethodClass {
						continue
					}
					targetKey := canonicalMethodKey(modMethod)
					targetID, ok := canonicalIndex[targetKey]
					if !ok {
						continue
					}
					extra := map[string]any{"prepend": true}
					ensureAliasSymbol(graph, canonicalIndex, symbols, unitPath, targetID, name, modMethod.name, rubyMethodInstance, "prepend", extra)
				}
			}
		}
		if len(typ.Extends) > 0 {
			for _, mod := range typ.Extends {
				for _, modMethod := range methodsByReceiver[mod] {
					targetKey := canonicalMethodKey(modMethod)
					targetID, ok := canonicalIndex[targetKey]
					if !ok {
						continue
					}
					ensureAliasSymbol(graph, canonicalIndex, symbols, unitPath, targetID, name, modMethod.name, rubyMethodClass, "extend", nil)
				}
			}
		}
	}
}

func applyInheritance(graph *Graph, canonicalIndex map[string]SymbolID, symbols *[]Symbol, unitPath string, types map[string]*rubyType, methodsByReceiver map[string][]*rubyMethod, methodByKey map[string]*rubyMethod) {
	for name, typ := range types {
		if typ == nil || typ.Kind != rubyTypeClass {
			continue
		}
		parent := typ.Super
		visited := make(map[string]struct{})
		for parent != "" {
			if _, seen := visited[parent]; seen {
				break
			}
			visited[parent] = struct{}{}
			for _, parentMethod := range methodsByReceiver[parent] {
				targetKey := canonicalMethodKey(parentMethod)
				targetID, ok := canonicalIndex[targetKey]
				if !ok {
					continue
				}
				aliasType := parentMethod.typ
				if aliasType == rubyMethodTopLevel {
					aliasType = rubyMethodInstance
				}
				extra := map[string]any{"from": parent}
				ensureAliasSymbol(graph, canonicalIndex, symbols, unitPath, targetID, name, parentMethod.name, aliasType, "inheritance", extra)
			}
			parentType := types[parent]
			if parentType == nil {
				break
			}
			parent = parentType.Super
		}
	}
}

func applyAliases(graph *Graph, canonicalIndex map[string]SymbolID, symbols *[]Symbol, unitPath string, aliases []rubyAlias) {
	for _, alias := range aliases {
		targetKey := canonicalCallKey(alias.owner, alias.old, alias.typ)
		targetID, ok := canonicalIndex[targetKey]
		if !ok {
			continue
		}
		ensureAliasSymbol(graph, canonicalIndex, symbols, unitPath, targetID, alias.owner, alias.new, alias.typ, "alias", nil)
	}
}

type argMapEntry struct {
	from int
	to   int
}

func buildArgMapping(caller *rubyMethod, callee *rubyMethod, call rubyCall) []argMapEntry {
	if caller == nil || callee == nil {
		return nil
	}
	callerCount := len(caller.params)
	calleeCount := len(callee.params)
	if callerCount == 0 || calleeCount == 0 {
		return nil
	}
	entries := []argMapEntry{}
	if len(call.argDescriptors) > 0 {
		calleeIndex := 0
		for _, arg := range call.argDescriptors {
			if calleeIndex >= calleeCount {
				break
			}
			switch arg.kind {
			case rubyArgParameter:
				if arg.paramIndex >= 0 && arg.paramIndex < callerCount {
					entries = append(entries, argMapEntry{from: arg.paramIndex, to: calleeIndex})
				}
			case rubyArgIdentifier:
				if idx := paramIndexByName(caller, arg.name); idx >= 0 {
					entries = append(entries, argMapEntry{from: idx, to: calleeIndex})
				}
			}
			calleeIndex++
		}
	}
	if len(entries) == 0 {
		count := call.argCount
		if count <= 0 {
			count = calleeCount
		}
		count = minInt(count, callerCount)
		count = minInt(count, calleeCount)
		for i := 0; i < count; i++ {
			entries = append(entries, argMapEntry{from: i, to: i})
		}
	}
	return entries
}

func rubyParamSymbolID(pkg string, method *rubyMethod, index int) SymbolID {
	if method == nil || index < 0 || index >= len(method.params) {
		return SymbolID{}
	}
	name := method.name + "#param:" + fmt.Sprint(index)
	if method.params[index].name != "" {
		name = method.name + "#param:" + method.params[index].name
	}
	return SymbolID{Dialect: "ruby", Package: pkg, Name: name, Recv: receiverOrDefault(method.receiver)}
}

func rubyParamDisplay(method *rubyMethod, index int) string {
	if method == nil || index < 0 || index >= len(method.params) {
		return "param"
	}
	param := method.params[index]
	label := param.name
	if label == "" {
		label = fmt.Sprintf("param%d", index)
	}
	return fmt.Sprintf("%s %s", methodDisplayName(method), label)
}

func rubyBlockSymbolID(pkg string, method *rubyMethod) SymbolID {
	if method == nil {
		return SymbolID{}
	}
	if !method.hasBlock && !method.yields && method.blockParam == "" {
		return SymbolID{}
	}
	name := method.name + "#block"
	return SymbolID{Dialect: "ruby", Package: pkg, Name: name, Recv: receiverOrDefault(method.receiver)}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func shouldSkipRubyDir(name string) bool {
	if name == "" || name == "." {
		return false
	}
	base := path.Base(name)
	if base == "vendor" || base == "bundle" || base == "tmp" || base == "log" || base == "node_modules" || strings.HasPrefix(base, ".") {
		return true
	}
	return false
}

func uniqueSymbolIDs(ids []SymbolID) []SymbolID {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]SymbolID)
	for _, id := range ids {
		if id.String() == "" {
			continue
		}
		seen[id.String()] = id
	}
	out := make([]SymbolID, 0, len(seen))
	for _, id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
