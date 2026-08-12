package lsp

import (
	"strings"

	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	protocol "github.com/sourcegraph/go-lsp"
	"github.com/temporalio/deputy/internal/policy"
)

var (
	yamlTopKeys = []string{"policies", "metadata"}
	policyKeys  = []string{"name", "description", "ecosystems", "entrypoints", "commands", "mode", "vars", "rules"}
	actions     = []string{"allow", "deny", "warn"}
)

// celVariables are the common identifiers injected into CEL environments.
var celVariables = append([]string{}, policy.DefaultVariableNames()...)

// completionItems returns completion items based on the current line text and cursor.
func completionItems(line string, cursor int) []protocol.CompletionItem {
	linePrefix := strings.TrimLeft(line[:min(cursor, len(line))], " \t")
	if strings.HasPrefix(linePrefix, "- ") {
		linePrefix = strings.TrimSpace(strings.TrimPrefix(linePrefix, "-"))
	}
	if strings.Contains(line, "when") { // be permissive; YAML may have spaces before colon
		return celCompletion(line, cursor)
	}
	// Top-level keys
	if !strings.Contains(linePrefix, ":") {
		items := make([]protocol.CompletionItem, 0, len(policyKeys))
		for _, k := range yamlTopKeys {
			items = append(items, protocol.CompletionItem{
				Label: k,
				Kind:  protocol.CIKVariable,
			})
		}
		for _, k := range policyKeys {
			items = append(items, protocol.CompletionItem{
				Label: k + ": ",
				Kind:  protocol.CIKField,
			})
		}
		return items
	}
	if strings.Contains(linePrefix, "action") {
		items := make([]protocol.CompletionItem, 0, len(actions))
		for _, a := range actions {
			items = append(items, protocol.CompletionItem{Label: a, Kind: protocol.CIKEnum})
		}
		return items
	}
	if strings.Contains(linePrefix, "mode") {
		modes := policy.Modes()
		items := make([]protocol.CompletionItem, 0, len(modes))
		for _, m := range modes {
			items = append(items, protocol.CompletionItem{Label: m.String(), Kind: protocol.CIKEnum})
		}
		return items
	}
	if strings.Contains(linePrefix, "commands") {
		commands := policy.CanonicalCommands()
		items := make([]protocol.CompletionItem, 0, len(commands)+1)
		for _, command := range commands {
			items = append(items, protocol.CompletionItem{
				Label:  command,
				Kind:   protocol.CIKEnum,
				Detail: "Canonical Deputy policy command",
			})
		}
		items = append(items, protocol.CompletionItem{
			Label:  "exec",
			Kind:   protocol.CIKEnum,
			Detail: "Legacy alias for sandbox",
		})
		return items
	}
	if strings.Contains(linePrefix, "entrypoints") {
		items := make([]protocol.CompletionItem, 0, len(policy.AllEntrypoints))
		for _, entrypoint := range policy.AllEntrypoints {
			items = append(items, protocol.CompletionItem{
				Label:  entrypoint.String(),
				Kind:   protocol.CIKEnum,
				Detail: entrypoint.Category(),
			})
		}
		return items
	}
	return nil
}

// celCompletion suggests identifiers, fields, and helper functions when editing a CEL expression.
func celCompletion(line string, cursor int) []protocol.CompletionItem {
	items := []protocol.CompletionItem{}
	expr := strings.TrimSpace(strings.TrimPrefix(line, "when:"))
	base, partial := celContextFromAST(expr, cursor-len("when: "))
	if base == "" {
		// fallback to heuristic
		base, partial = celContextToken(line, cursor)
	}
	if base != "" {
		for _, field := range celFieldCompletions(base) {
			if partial != "" && !strings.HasPrefix(field, partial) {
				continue
			}
			items = append(items, protocol.CompletionItem{
				Label:  field,
				Kind:   protocol.CIKField,
				Detail: base + "." + field,
			})
		}
	}
	for _, v := range celVariables {
		if partial == "" || strings.HasPrefix(v, partial) {
			items = append(items, protocol.CompletionItem{
				Label:  v,
				Kind:   protocol.CIKVariable,
				Detail: "CEL variable",
			})
		}
	}
	for _, fn := range celFunctionCatalog() {
		items = append(items, protocol.CompletionItem{
			Label:         fn.Name,
			Kind:          protocol.CIKFunction,
			Detail:        fn.Signature,
			Documentation: fn.Doc,
		})
	}
	return items
}

// celContextToken extracts the identifier chain before the cursor and any partial field.
// It scans backward from the cursor to collect [identifier(.identifier)*] tokens.
func celContextToken(line string, cursor int) (base string, partial string) {
	if cursor > len(line) {
		cursor = len(line)
	}
	fragment := line[:cursor]
	// walk backward to find last token containing dots
	if idx := strings.LastIndexAny(fragment, " \t(["); idx >= 0 {
		fragment = fragment[idx+1:]
	}
	if idx := strings.LastIndex(fragment, "."); idx >= 0 {
		base = strings.TrimLeft(fragment[:idx], "(!")
		partial = fragment[idx+1:]
		return base, partial
	}
	return "", ""
}

// celContextFromAST uses cel-go parser source info to find the identifier at the cursor.
func celContextFromAST(expr string, offset int) (string, string) {
	if offset < 0 {
		offset = len(expr)
	}
	src := common.NewTextSource(expr)
	parsed, errors := celParser.Parse(src)
	if len(errors.GetErrors()) > 0 {
		return "", ""
	}
	info := parsed.SourceInfo()
	var match string
	var matchSelect ast.Expr
	walkExpr(parsed.Expr(), func(e ast.Expr) {
		if e.Kind() == ast.IdentKind {
			if rng, ok := info.GetOffsetRange(e.ID()); ok {
				if offset >= int(rng.Start) && offset <= int(rng.Stop) {
					match = e.AsIdent()
				}
			}
		}
		if e.Kind() == ast.SelectKind {
			if rng, ok := info.GetOffsetRange(e.ID()); ok {
				if offset >= int(rng.Start) && offset <= int(rng.Stop) {
					matchSelect = e
				}
			}
		}
	})
	if match == "" && matchSelect == nil {
		return "", ""
	}
	var base, partial string
	if matchSelect != nil {
		e := matchSelect
		field := e.AsSelect().FieldName()
		op := e.AsSelect().Operand()
		switch op.Kind() {
		case ast.IdentKind:
			base = op.AsIdent()
		case ast.SelectKind:
			inner := op.AsSelect()
			if inner.Operand().Kind() == ast.IdentKind {
				base = inner.Operand().AsIdent() + "." + inner.FieldName()
			}
		}
		partial = field
	}
	if base == "" {
		// fallback: first ident hit
		base = match
	}
	if base == "" {
		base = match
	}
	return base, partial
}

// celFieldCompletions lists known fields for common CEL base identifiers.
// Proto-typed variables (pkg, vulnerability, target, env, …) are derived from
// their proto descriptors via policy.VariableFieldCompletions, so completions
// use the proto field names (snake_case, the CEL contract) and can never drift
// from the messages. The hand-maintained lists below cover only object-typed
// variables and helper constants that have no proto shape.
func celFieldCompletions(base string) []string {
	if fields, ok := policy.VariableFieldCompletions(base); ok {
		return fields
	}
	switch base {
	case "request":
		return []string{"ecosystem", "module", "package", "version", "raw_version", "has_version", "fileType", "operation", "client", "licenses", "registry", "repository", "reference", "tag", "digest", "image", "path"}
	case "request.client":
		return []string{"ip", "userAgent", "principal"}
	case "severity":
		// Derived from the runtime constants map so completions offer exactly
		// the members that evaluate (severity.critical, not severity.CRITICAL).
		return policy.SeverityConstantNames()
	case "scope":
		return []string{"RUNTIME", "DEV", "TEST", "BUILD", "OPTIONAL", "UNSPECIFIED"}
	case "repo":
		return []string{"name", "ref", "commit", "path"}
	case "target.provenance":
		// target resolves via proto, but provenance is a map<string,string>;
		// these are its conventional keys, not proto fields.
		return []string{"registry", "repository", "tag", "digest", "reference", "image", "image_input", "transport", "platform", "path"}
	case "image", "image_info":
		return []string{"registry", "repository", "tag", "digest", "reference", "image", "config", "metadata", "history"}
	case "image.config", "image_info.config":
		return []string{"user", "is_root", "env", "sensitive_env", "entrypoint", "cmd", "exposed_ports", "volumes", "labels", "working_dir", "healthcheck", "shell", "stop_signal", "on_build"}
	case "image.config.healthcheck", "image_info.config.healthcheck":
		return []string{"test", "interval", "timeout", "retries"}
	case "image.metadata", "image_info.metadata":
		return []string{"architecture", "os", "os_version", "variant", "layer_count", "size", "created", "author", "docker_version", "digest"}
	default:
		return nil
	}
}

// walkExpr performs a depth-first traversal of the CEL AST.
func walkExpr(e ast.Expr, fn func(ast.Expr)) {
	if e == nil {
		return
	}
	fn(e)
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		if call.IsMemberFunction() && call.Target() != nil {
			walkExpr(call.Target(), fn)
		}
		for _, arg := range call.Args() {
			walkExpr(arg, fn)
		}
	case ast.SelectKind:
		walkExpr(e.AsSelect().Operand(), fn)
	case ast.ListKind:
		for _, elem := range e.AsList().Elements() {
			walkExpr(elem, fn)
		}
	case ast.MapKind:
		for _, entry := range e.AsMap().Entries() {
			me := entry.AsMapEntry()
			walkExpr(me.Key(), fn)
			walkExpr(me.Value(), fn)
		}
	case ast.StructKind:
		for _, entry := range e.AsStruct().Fields() {
			sf := entry.AsStructField()
			walkExpr(sf.Value(), fn)
		}
	case ast.ComprehensionKind:
		comp := e.AsComprehension()
		walkExpr(comp.IterRange(), fn)
		walkExpr(comp.AccuInit(), fn)
		walkExpr(comp.LoopCondition(), fn)
		walkExpr(comp.LoopStep(), fn)
		walkExpr(comp.Result(), fn)
	}
}
