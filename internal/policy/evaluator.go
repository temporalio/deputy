package policy

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	anyType = reflect.TypeOf((*any)(nil)).Elem()

	defaultVariableNames = []string{
		"pkg",
		"request",
		"target",
		"image",
		"image_info", // Container image config, metadata, and build history
		"vulnerabilities",
		"vulnerability",
		"jwt", // JWT claims from authenticated proxy requests
		"changes",
		"packages",
		"sbom",
		"config",
		"env",
		"dependency",
		"plan",
		"step",
		"repo",
		"cluster",
		"component",
		"findings",
		"change",
		// Container diff specific variables
		"base_image",
		"target_image",
		"package_changes",
		"vulnerability_changes",
		"config_changes",
		"layer_analysis",
		"summary",
		"layer",
		// Dockerfile specific variables
		"dockerfile",
		"dockerfile_analysis",
		"stage",
		// Secrets specific variables
		"secret",
		"secrets",
		"report",
		// Graph specific variables
		"graph",       // Full graph data (stats, nodes, edges)
		"node",        // Current node in graph_node entrypoint
		"edge",        // Current edge in graph_edge entrypoint
		"from_node",   // Source node for edge
		"to_node",     // Target node for edge
		"nodes",       // All nodes in graph
		"edges",       // All edges in graph
		"stats",       // Graph statistics
		"roots",       // Root (direct) dependencies
		"ancestors",   // Ancestor nodes for current node
		"descendants", // Descendant nodes for current node
		// Constants for policy authoring
		"severity", // Severity constants: severity.CRITICAL, severity.HIGH, etc.
		"scope",    // Dependency scope constants: scope.RUNTIME, scope.DEV, etc.
	}

	// severityConstants provides named severity levels for cleaner policy expressions.
	// Instead of: vulnerability.severity == "CRITICAL"
	// Authors can write: vulnerability.severity == severity.CRITICAL
	severityConstants = map[string]any{
		"CRITICAL":    "CRITICAL",
		"HIGH":        "HIGH",
		"MEDIUM":      "MEDIUM",
		"LOW":         "LOW",
		"UNSPECIFIED": "UNSPECIFIED",
	}

	// scopeConstants provides named dependency scopes for graph policies.
	// Instead of: edgeScope(edge) == "runtime"
	// Authors can write: edgeScope(edge) == scope.RUNTIME
	scopeConstants = map[string]any{
		"RUNTIME":     "runtime",
		"DEV":         "dev",
		"TEST":        "test",
		"BUILD":       "build",
		"OPTIONAL":    "optional",
		"UNSPECIFIED": "unspecified",
	}
)

// DefaultVariableNames returns the identifiers that Deputy injects into CEL
// environments for policies. Tooling (e.g., LSP) uses this to stay aligned with
// the runtime without duplicating the list.
func DefaultVariableNames() []string {
	return slices.Clone(defaultVariableNames)
}

// Evaluate compiles the provided CEL source and evaluates it against the input
// document. Input keys are exposed to the CEL program as top-level identifiers.
func Evaluate(ctx context.Context, source string, input map[string]any) (any, error) {
	// Clone input to avoid side effects on the caller's map.
	input = maps.Clone(input)
	if input == nil {
		input = map[string]any{}
	}
	seedDefaultVariables(input)
	env, err := envForInput(input)
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(source)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	out, _, err := prog.ContextEval(ctx, input)
	if err != nil {
		return nil, err
	}
	return convertRefVal(out)
}

// Compile verifies that the CEL source parses and type-checks using the
// provided extra variable names (in addition to the default policy variables).
func Compile(source string, extraVars []string) error {
	env, err := envWithNames(extraVars)
	if err != nil {
		return err
	}
	_, iss := env.Compile(source)
	if iss != nil && iss.Err() != nil {
		return iss.Err()
	}
	return nil
}

// envForInput creates a CEL environment configured with variables derived from the input map keys.
func envForInput(input map[string]any) (*cel.Env, error) {
	return envWithNames(slices.Collect(maps.Keys(input)))
}

// envWithNames creates a CEL environment with the default variables plus any extra variables provided.
func envWithNames(extra []string) (*cel.Env, error) {
	names := slices.Concat(defaultVariableNames, extra)
	slices.Sort(names)
	names = slices.Compact(names)

	// Filter out empty strings and create declarations
	declSlice := make([]*exprpb.Decl, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		declSlice = append(declSlice, decls.NewVar(name, decls.Dyn))
	}
	opts := []cel.EnvOption{
		cel.OptionalTypes(),
		cel.Declarations(declSlice...),
		// Register proto types for native proto support in CEL expressions.
		// This enables policies to work directly with proto messages, providing:
		// - Type-safe field access (e.g., finding.advisory.severity.level)
		// - Proto enum support (e.g., SeverityLevel_SEVERITY_LEVEL_HIGH)
		// - Proper nested message handling
		cel.Types(
			// Core domain types
			&vulnerabilityv1.Finding{},
			&vulnerabilityv1.Advisory{},
			&vulnerabilityv1.Severity{},
			&vulnerabilityv1.Stats{},
			&dependencyv1.Package{},
			&targetv1.Target{},
			// Policy evaluation context types (proto-first)
			&policyv1.Environment{},
			&policyv1.JWTClaims{},
			&policyv1.ProxyRequest{},
			&policyv1.ScanVulnerabilityContext{},
			&policyv1.ScanReportContext{},
			&policyv1.ProxyRequestContext{},
		),
		// Standard extensions
		ext.Strings(),
		ext.Lists(),
		ext.Sets(),
		ext.Regex(),
		// Additional extensions for richer policy expressions
		ext.Bindings(), // cel.bind() for local variables
		ext.Encoders(), // base64.encode/decode
		ext.Math(),     // math functions (abs, ceil, floor, etc.)
	}
	opts = append(opts, customHelperFunctions()...)
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}
	return env, nil
}

// buildPkgHelper synthesizes a unified package view from common input shapes.
// It always returns a map with sensible defaults for optional fields so that
// policy authors can write simpler expressions without excessive ?.orValue() usage:
//   - name defaults to "" (empty string)
//   - licenses defaults to [] (empty list)
//   - version defaults to "" (empty string)
//   - ecosystem defaults to "" (empty string)
//
// This allows policies like `pkg.licenses.exists(l, l == "GPL-3.0")` to work
// without needing `pkg.?licenses.orValue([]).exists(...)`.
//
// Policies that need to guard against "no package data" can check `pkg.name == ""`
// or use entrypoint filtering to only run when package data is expected.
func buildPkgHelper(input map[string]any) map[string]any {
	// Initialize with sensible defaults for all fields.
	// This simplifies policy expressions by eliminating ?.orValue() boilerplate.
	pkg := map[string]any{
		"name":      "",
		"licenses":  []any{},
		"version":   "",
		"ecosystem": "",
	}

	// Prefer component (sbom/diff) then request (proxy)
	var src map[string]any
	if comp, ok := input["component"].(map[string]any); ok {
		src = comp
	}
	if src == nil {
		if req, ok := input["request"].(map[string]any); ok {
			src = req
		}
	}
	if src == nil {
		return pkg
	}

	// Try various keys for the package name
	if name, ok := src["package"]; ok {
		pkg["name"] = name
	}
	if pkg["name"] == "" {
		if name, ok := src["module"]; ok {
			pkg["name"] = name
		}
	}
	if pkg["name"] == "" {
		if name, ok := src["name"]; ok {
			pkg["name"] = name
		}
	}

	// Override defaults with actual values if present
	if ver, ok := src["version"]; ok {
		pkg["version"] = ver
	}
	if eco, ok := src["ecosystem"]; ok {
		pkg["ecosystem"] = eco
	}
	if lic, ok := src["licenses"]; ok {
		pkg["licenses"] = lic
	}
	return pkg
}

// buildTargetHelper synthesizes a normalized target view with safe defaults.
// It mirrors the scan/proxy target metadata when available and falls back to
// repo/ref/commit fields when target metadata is absent.
func buildTargetHelper(input map[string]any) map[string]any {
	target := map[string]any{
		"kind":          "",
		"display":       "",
		"ref":           "",
		"effective_ref": "",
		"commit":        "",
		"origin":        "",
		"local":         "",
		"cloned":        false,
		"provenance":    map[string]any{},
	}
	if input == nil {
		return target
	}
	if src, ok := input["target"].(map[string]any); ok {
		maps.Copy(target, src)
	} else {
		if repo, ok := input["repo"]; ok {
			target["display"] = repo
		}
		if ref, ok := input["ref"]; ok {
			target["ref"] = ref
		}
		if commit, ok := input["commit"]; ok {
			target["commit"] = commit
		}
	}
	target["provenance"] = normalizeStringMap(target["provenance"])
	return target
}

// buildImageHelper derives normalized image metadata from request/target inputs.
// It returns nil when no image-related data is available.
//
// When image_info is present (from container image scans), the helper merges
// configuration and metadata into the image object for policy evaluation:
//   - image.config.user - user to run as (empty = root)
//   - image.config.is_root - true if running as root
//   - image.config.env - environment variables
//   - image.config.sensitive_env - env vars that may contain secrets
//   - image.config.entrypoint - container entrypoint
//   - image.config.cmd - default command arguments
//   - image.config.exposed_ports - exposed ports
//   - image.config.labels - image labels
//   - image.metadata.architecture - CPU architecture
//   - image.metadata.os - operating system
//   - image.metadata.layer_count - number of layers
//   - image.metadata.size - total size in bytes
//   - image.history - build history entries
func buildImageHelper(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	src, _ := input["image"].(map[string]any)
	req, _ := input["request"].(map[string]any)
	tgt, _ := input["target"].(map[string]any)
	imgInfo, _ := input["image_info"].(map[string]any)
	var prov map[string]any
	if tgt != nil {
		prov, _ = tgt["provenance"].(map[string]any)
	}

	hasImage := len(src) > 0 || hasImageKeys(req) || hasImageKeys(prov) || len(imgInfo) > 0
	if !hasImage {
		return nil
	}

	image := map[string]any{
		"registry":   "",
		"repository": "",
		"tag":        "",
		"digest":     "",
		"reference":  "",
		"image":      "",
	}
	maps.Copy(image, src)
	mergeImageMap(image, req)
	mergeImageMap(image, prov)

	if image["reference"] == "" {
		if digest := stringValue(image["digest"]); digest != "" {
			image["reference"] = digest
		} else if tag := stringValue(image["tag"]); tag != "" {
			image["reference"] = tag
		}
	}
	if image["image"] == "" {
		reg := stringValue(image["registry"])
		repo := stringValue(image["repository"])
		tag := stringValue(image["tag"])
		digest := stringValue(image["digest"])
		// Build full image reference: registry/repo:tag or registry/repo@digest
		var base string
		if reg != "" && repo != "" {
			base = reg + "/" + repo
		} else if repo != "" {
			base = repo
		}
		if base != "" {
			if digest != "" {
				image["image"] = base + "@" + digest
			} else if tag != "" {
				image["image"] = base + ":" + tag
			} else {
				image["image"] = base
			}
		}
	}

	// Merge image_info (config, metadata, history) from container image scans
	if len(imgInfo) > 0 {
		if cfg, ok := imgInfo["config"].(map[string]any); ok {
			image["config"] = cfg
		}
		if meta, ok := imgInfo["metadata"].(map[string]any); ok {
			image["metadata"] = meta
		}
		if hist, ok := imgInfo["history"].([]any); ok {
			image["history"] = hist
		}
	}

	return image
}

func mergeImageMap(dst, src map[string]any) {
	if dst == nil || src == nil {
		return
	}
	setIfEmpty(dst, "registry", src["registry"])
	setIfEmpty(dst, "repository", src["repository"])
	setIfEmpty(dst, "tag", src["tag"])
	setIfEmpty(dst, "digest", src["digest"])
	setIfEmpty(dst, "reference", src["reference"])
	setIfEmpty(dst, "image", src["image"])
}

func hasImageKeys(src map[string]any) bool {
	if src == nil {
		return false
	}
	for _, key := range []string{"registry", "repository", "tag", "digest", "reference", "image"} {
		if stringValue(src[key]) != "" {
			return true
		}
	}
	return false
}

func setIfEmpty(dst map[string]any, key string, val any) {
	if dst == nil {
		return
	}
	if stringValue(dst[key]) != "" {
		return
	}
	if v := stringValue(val); v != "" {
		dst[key] = v
	}
}

func stringValue(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func normalizeStringMap(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case map[string]string:
		out := make(map[string]any, len(t))
		for k, v := range t {
			out[k] = v
		}
		return out
	default:
		return map[string]any{}
	}
}

// convertRefVal converts a CEL ref.Val to a native Go value.
// The path parameter tracks the location in nested structures for error context.
func convertRefVal(val ref.Val) (any, error) {
	return convertRefValWithPath(val, "")
}

// convertRefValWithPath converts a CEL ref.Val with path tracking for better error messages.
func convertRefValWithPath(val ref.Val, path string) (any, error) {
	if val == nil {
		return nil, nil
	}
	switch v := val.Value().(type) {
	case []ref.Val:
		out := make([]any, len(v))
		for i, elem := range v {
			elemPath := fmt.Sprintf("%s[%d]", path, i)
			if path == "" {
				elemPath = fmt.Sprintf("[%d]", i)
			}
			converted, err := convertRefValWithPath(elem, elemPath)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case map[ref.Val]ref.Val:
		out := make(map[string]any, len(v))
		for mk, mv := range v {
			keyVal, err := convertRefValWithPath(mk, path+".key")
			if err != nil {
				return nil, fmt.Errorf("at %s: %w", path, err)
			}
			keyStr, ok := keyVal.(string)
			if !ok {
				location := path
				if location == "" {
					location = "root"
				}
				return nil, fmt.Errorf("at %s: map keys must be strings, got %T", location, keyVal)
			}
			valPath := path + "." + keyStr
			if path == "" {
				valPath = keyStr
			}
			valVal, err := convertRefValWithPath(mv, valPath)
			if err != nil {
				return nil, err
			}
			out[keyStr] = valVal
		}
		return out, nil
	default:
		if native, err := val.ConvertToNative(anyType); err == nil {
			return native, nil
		}
		location := path
		if location == "" {
			location = "root"
		}
		return nil, fmt.Errorf("at %s: unable to convert CEL value of type %T", location, val.Value())
	}
}

// levenshtein computes the Levenshtein distance between a and b with an optional
// maxLen cap (rejects if either input exceeds cap by returning -1) and an early
// exit limit (stop when distance already exceeds limit; pass -1 for no early exit).
func levenshtein(a, b string, maxLen int, limit int64) int64 {
	if maxLen > 0 && (len(a) > maxLen || len(b) > maxLen) {
		return -1
	}
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return int64(len(b))
	}
	if len(b) == 0 {
		return int64(len(a))
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	// Pre-allocate two rows and swap them to avoid allocations per iteration
	prev := make([]int64, len(a)+1)
	curr := make([]int64, len(a)+1)
	for i := range prev {
		prev[i] = int64(i)
	}
	for j := 1; j <= len(b); j++ {
		curr[0] = int64(j)
		minRow := curr[0]
		bc := b[j-1]
		for i := 1; i <= len(a); i++ {
			cost := int64(0)
			if a[i-1] != bc {
				cost = 1
			}
			del := prev[i] + 1
			ins := curr[i-1] + 1
			sub := prev[i-1] + cost
			curr[i] = min(del, ins, sub)
			if curr[i] < minRow {
				minRow = curr[i]
			}
		}
		if limit >= 0 && minRow > limit {
			return minRow
		}
		prev, curr = curr, prev
	}
	if limit >= 0 && prev[len(a)] > limit {
		return prev[len(a)]
	}
	return prev[len(a)]
}

// toString safely converts a CEL ref.Val to a string.
func toString(v ref.Val) string {
	if v == nil {
		return ""
	}
	switch t := v.Value().(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

// toInt64 safely converts a CEL ref.Val to an int64.
func toInt64(v ref.Val) int64 {
	if v == nil {
		return 0
	}
	switch t := v.Value().(type) {
	case int64:
		return t
	case int32:
		return int64(t)
	case int:
		return int64(t)
	case uint64:
		return int64(t)
	case uint32:
		return int64(t)
	case float64:
		return int64(t)
	case float32:
		return int64(t)
	default:
		return 0
	}
}
