// Package terraform extracts Terraform version requirements from configuration files.
//
// It inventories:
//   - terraform.required_version (Terraform core constraint)
//   - terraform.required_providers entries (provider version constraints)
//
// The extractor is offline and does not invoke Terraform or resolve modules.
package terraform

import (
	"context"
	"io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/mod/semver"

	"github.com/picatz/deputy/internal/purlx"
)

const (
	// Name is the internal plugin identifier.
	Name = "terraform/requirements"
)

// RequirementKind identifies the Terraform requirement type.
type RequirementKind string

const (
	RequirementTerraformCore     RequirementKind = "terraform_core"
	RequirementTerraformProvider RequirementKind = "terraform_provider"
	RequirementLockedProvider    RequirementKind = "locked_provider"
	RequirementModule            RequirementKind = "module"
)

// Requirement captures a Terraform requirement discovered in config.
type Requirement struct {
	Kind    RequirementKind
	Name    string
	Version string
	Path    string

	// Lock file fields (for RequirementLockedProvider)
	Constraints string   // Original version constraints
	Hashes      []string // Provider hashes (h1:, zh:)

	// Module fields (for RequirementModule)
	Source     string // Module source (registry, git, local)
	ModuleType string // "registry", "git", "local"
}

// Extractor implements an OSV-Scalibr filesystem extractor for Terraform requirements.
type Extractor struct {
	mu   sync.Mutex
	seen map[string]bool
}

// New returns a new Terraform requirements extractor.
func New() filesystem.Extractor {
	return &Extractor{seen: make(map[string]bool)}
}

// Name returns the plugin name as understood by Deputy.
func (Extractor) Name() string { return Name }

// Version returns the plugin version; Deputy uses 0 for internal plugins.
func (Extractor) Version() int { return 0 }

// Requirements declares required capabilities; Terraform scanning is filesystem-only.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired limits extraction to Terraform config files.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	if api == nil {
		return false
	}
	return isTerraformConfigPath(api.Path())
}

// Extract parses Terraform configuration files in the containing directory and
// returns discovered requirements. The directory is processed once per scan to
// avoid duplicate results when multiple .tf files exist.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input == nil || input.FS == nil {
		return inventory.Inventory{}, nil
	}

	dir := path.Dir(input.Path)

	e.mu.Lock()
	if e.seen[dir] {
		e.mu.Unlock()
		return inventory.Inventory{}, nil
	}
	e.seen[dir] = true
	e.mu.Unlock()

	reqs, err := ParseDir(ctx, input.FS, dir)
	if err != nil {
		slog.WarnContext(ctx, "terraform: parse failed", "path", dir, "error", err)
		return inventory.Inventory{}, nil
	}
	pkgs := requirementsToPackages(reqs)
	if len(pkgs) == 0 {
		return inventory.Inventory{}, nil
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

func isTerraformConfigPath(p string) bool {
	if p == "" {
		return false
	}
	clean := path.Clean(filepath.ToSlash(p))
	if clean == "." {
		return false
	}
	// Skip Terraform state/config cache directory (but allow lock file)
	base := path.Base(clean)
	lower := strings.ToLower(base)

	// Lock file is always processed
	if lower == ".terraform.lock.hcl" {
		return true
	}

	// Skip .terraform directory
	if strings.Contains(clean, "/.terraform/") || strings.HasPrefix(clean, ".terraform/") {
		return false
	}

	return strings.HasSuffix(lower, ".tf") || strings.HasSuffix(lower, ".tf.json")
}

// isLockFile returns true if the path is a Terraform lock file.
func isLockFile(p string) bool {
	return strings.ToLower(path.Base(p)) == ".terraform.lock.hcl"
}

// ParseDir parses Terraform configuration files in dir and returns any requirements found.
func ParseDir(ctx context.Context, fsys fs.ReadDirFS, dir string) ([]Requirement, error) {
	readDir := dir
	if readDir == "" {
		readDir = "."
	}
	entries, err := fs.ReadDir(fsys, readDir)
	if err != nil {
		return nil, err
	}
	parser := hclparse.NewParser()
	var reqs []Requirement
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isTerraformConfigPath(name) {
			continue
		}
		filePath := name
		if dir != "" && dir != "." {
			filePath = path.Join(dir, name)
		}
		data, err := fs.ReadFile(fsys, filePath)
		if err != nil {
			slog.WarnContext(ctx, "terraform: read file failed", "path", filePath, "error", err)
			continue
		}

		// Handle lock file separately
		if isLockFile(filePath) {
			lockReqs, err := parseLockFile(ctx, parser, filePath, data)
			if err != nil {
				slog.WarnContext(ctx, "terraform: lock file parse failed", "path", filePath, "error", err)
				continue
			}
			reqs = append(reqs, lockReqs...)
			continue
		}

		file, diags := parseTerraformFile(parser, filePath, data)
		if diags.HasErrors() {
			slog.WarnContext(ctx, "terraform: parse error", "path", filePath, "diagnostics", diags.Error())
		}
		if file == nil {
			continue
		}
		reqs = append(reqs, extractRequirements(file.Body, filePath)...)
	}
	return reqs, nil
}

func parseTerraformFile(parser *hclparse.Parser, filename string, data []byte) (*hcl.File, hcl.Diagnostics) {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".tf.json") {
		return parser.ParseJSON(data, filename)
	}
	return parser.ParseHCL(data, filename)
}

// parseLockFile parses a .terraform.lock.hcl file and returns locked provider requirements.
func parseLockFile(ctx context.Context, parser *hclparse.Parser, filePath string, data []byte) ([]Requirement, error) {
	file, diags := parser.ParseHCL(data, filePath)
	if diags.HasErrors() {
		return nil, diags
	}
	if file == nil || file.Body == nil {
		return nil, nil
	}

	content, diags := file.Body.Content(lockFileSchema)
	if diags.HasErrors() {
		slog.WarnContext(ctx, "terraform: lock file schema error", "path", filePath, "diagnostics", diags.Error())
	}

	var reqs []Requirement
	for _, block := range content.Blocks {
		if block.Type != "provider" || len(block.Labels) == 0 {
			continue
		}

		// Label is the full source like "registry.terraform.io/hashicorp/aws"
		fullSource := block.Labels[0]

		// Parse provider block attributes
		attrs, _ := block.Body.JustAttributes()

		var version, constraints string
		var hashes []string

		if attr, ok := attrs["version"]; ok {
			version = stringValueOrEmpty(attr.Expr)
		}
		if attr, ok := attrs["constraints"]; ok {
			constraints = stringValueOrEmpty(attr.Expr)
		}
		if attr, ok := attrs["hashes"]; ok {
			hashes = stringListValue(attr.Expr)
		}

		// Convert full source to short source (e.g., "registry.terraform.io/hashicorp/aws" -> "hashicorp/aws")
		source := normalizeProviderSource(fullSource)

		reqs = append(reqs, Requirement{
			Kind:        RequirementLockedProvider,
			Name:        source,
			Version:     version,
			Path:        filePath,
			Constraints: constraints,
			Hashes:      hashes,
		})
	}

	return reqs, nil
}

// normalizeProviderSource converts a full provider source to short form.
// "registry.terraform.io/hashicorp/aws" -> "hashicorp/aws"
func normalizeProviderSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return source
	}
	// Remove registry prefix if present
	if strings.HasPrefix(source, "registry.terraform.io/") {
		return strings.TrimPrefix(source, "registry.terraform.io/")
	}
	return source
}

// stringListValue extracts a list of strings from an HCL expression.
func stringListValue(expr hcl.Expression) []string {
	if expr == nil {
		return nil
	}
	val, diags := expr.Value(nil)
	if diags.HasErrors() || !val.IsKnown() {
		return nil
	}
	if !val.Type().IsTupleType() && !val.Type().IsListType() && !val.Type().IsSetType() {
		return nil
	}
	var result []string
	for _, elem := range val.AsValueSlice() {
		if elem.IsKnown() && elem.Type() == cty.String {
			result = append(result, elem.AsString())
		}
	}
	return result
}

var rootSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "terraform"},
		{Type: "module", LabelNames: []string{"name"}},
	},
}

var terraformSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "required_version"},
	},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "required_providers"},
	},
}

// Lock file schema for .terraform.lock.hcl
var lockFileSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "provider", LabelNames: []string{"source"}},
	},
}

var lockProviderSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "version"},
		{Name: "constraints"},
		{Name: "hashes"},
	},
}

// Module block schema
var moduleSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "source"},
		{Name: "version"},
	},
}

func extractRequirements(body hcl.Body, filePath string) []Requirement {
	if body == nil {
		return nil
	}
	content, _ := body.Content(rootSchema)
	var reqs []Requirement
	for _, block := range content.Blocks {
		switch block.Type {
		case "terraform":
			reqs = append(reqs, extractTerraformBlock(block, filePath)...)
		case "module":
			if req := extractModuleBlock(block, filePath); req != nil {
				reqs = append(reqs, *req)
			}
		}
	}
	return reqs
}

func extractModuleBlock(block *hcl.Block, filePath string) *Requirement {
	if block == nil || len(block.Labels) == 0 {
		return nil
	}
	moduleName := block.Labels[0]

	attrs, _ := block.Body.JustAttributes()
	if len(attrs) == 0 {
		return nil
	}

	var source, version string
	if attr, ok := attrs["source"]; ok {
		source = stringValueOrEmpty(attr.Expr)
	}
	if attr, ok := attrs["version"]; ok {
		version = stringValueOrEmpty(attr.Expr)
	}

	// Skip modules without a source attribute
	if source == "" {
		return nil
	}

	modType := classifyModuleSource(source)

	return &Requirement{
		Kind:       RequirementModule,
		Name:       moduleName,
		Version:    version,
		Path:       filePath,
		Source:     source,
		ModuleType: modType,
	}
}

// classifyModuleSource determines the module type from its source string.
func classifyModuleSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}

	// Local modules: start with ./ or ../
	if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
		return "local"
	}

	// Git modules: git::, github.com/, bitbucket.org/, or contain .git
	if strings.HasPrefix(source, "git::") ||
		strings.HasPrefix(source, "github.com/") ||
		strings.HasPrefix(source, "bitbucket.org/") ||
		strings.Contains(source, ".git") {
		return "git"
	}

	// HTTP/S modules
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return "http"
	}

	// S3 modules
	if strings.HasPrefix(source, "s3::") {
		return "s3"
	}

	// GCS modules
	if strings.HasPrefix(source, "gcs::") {
		return "gcs"
	}

	// Mercurial modules
	if strings.HasPrefix(source, "hg::") {
		return "mercurial"
	}

	// Default to registry module (namespace/name/provider format)
	// e.g., "terraform-aws-modules/vpc/aws"
	return "registry"
}

func extractTerraformBlock(block *hcl.Block, filePath string) []Requirement {
	if block == nil {
		return nil
	}
	var reqs []Requirement
	attrs, _ := block.Body.JustAttributes()
	if attr, ok := attrs["required_version"]; ok {
		reqs = append(reqs, Requirement{
			Kind:    RequirementTerraformCore,
			Name:    "terraform",
			Version: stringValueOrEmpty(attr.Expr),
			Path:    filePath,
		})
	}
	content, _ := block.Body.Content(terraformSchema)
	for _, rpBlock := range content.Blocks {
		reqs = append(reqs, extractRequiredProviders(rpBlock, filePath)...)
	}
	return reqs
}

func extractRequiredProviders(block *hcl.Block, filePath string) []Requirement {
	if block == nil {
		return nil
	}
	attrs, _ := block.Body.JustAttributes()
	if len(attrs) == 0 {
		return nil
	}
	var reqs []Requirement
	for name, attr := range attrs {
		source, version := parseProviderRequirement(name, attr.Expr)
		reqs = append(reqs, Requirement{
			Kind:    RequirementTerraformProvider,
			Name:    source,
			Version: version,
			Path:    filePath,
		})
	}
	return reqs
}

func parseProviderRequirement(name string, expr hcl.Expression) (string, string) {
	source := defaultProviderSource(name)
	if expr == nil {
		return source, ""
	}
	if v, ok := stringValue(expr); ok {
		return source, strings.TrimSpace(v)
	}
	obj := objectStringMap(expr)
	if obj == nil {
		return source, ""
	}
	if src, ok := obj["source"]; ok {
		if src != "" {
			source = strings.TrimSpace(src)
		}
	}
	if ver, ok := obj["version"]; ok {
		return source, strings.TrimSpace(ver)
	}
	return source, ""
}

func defaultProviderSource(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return ""
	}
	return "hashicorp/" + n
}

func stringValueOrEmpty(expr hcl.Expression) string {
	if expr == nil {
		return ""
	}
	if v, ok := stringValue(expr); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func stringValue(expr hcl.Expression) (string, bool) {
	if expr == nil {
		return "", false
	}
	switch t := expr.(type) {
	case *hclsyntax.TemplateExpr:
		if t.IsStringLiteral() {
			val, _ := t.Value(nil)
			if val.IsKnown() && val.Type() == cty.String {
				return val.AsString(), true
			}
		}
	case *hclsyntax.LiteralValueExpr:
		if t.Val.IsKnown() && t.Val.Type() == cty.String {
			return t.Val.AsString(), true
		}
	case *hclsyntax.ObjectConsKeyExpr:
		// Object keys like source = "hashicorp/aws" appear here
		return stringValue(t.Wrapped)
	}
	val, diags := expr.Value(nil)
	if diags.HasErrors() || !val.IsKnown() || val.Type() != cty.String {
		return "", false
	}
	return val.AsString(), true
}

func objectStringMap(expr hcl.Expression) map[string]string {
	if expr == nil {
		return nil
	}
	val, diags := expr.Value(nil)
	if !diags.HasErrors() && val.IsKnown() && val.Type().IsObjectType() {
		out := make(map[string]string)
		for k, v := range val.AsValueMap() {
			if v.IsKnown() && v.Type() == cty.String {
				out[k] = v.AsString()
			}
		}
		return out
	}
	obj, ok := expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		return nil
	}
	out := make(map[string]string)
	for _, item := range obj.Items {
		key, ok := stringValue(item.KeyExpr)
		if !ok || key == "" {
			continue
		}
		val, ok := stringValue(item.ValueExpr)
		if !ok {
			continue
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func requirementsToPackages(reqs []Requirement) []*extractor.Package {
	if len(reqs) == 0 {
		return nil
	}
	type pkgKey struct {
		kind    RequirementKind
		name    string
		version string
	}
	seen := make(map[pkgKey]*extractor.Package)
	for _, req := range reqs {
		// Determine package name based on requirement kind
		pkgName := req.Name
		switch req.Kind {
		case RequirementModule:
			// For modules, use the source as the package name (not the module label)
			pkgName = req.Source
			if pkgName == "" {
				continue
			}
		default:
			if pkgName == "" {
				continue
			}
		}

		key := pkgKey{kind: req.Kind, name: pkgName, version: req.Version}
		pkg := seen[key]
		if pkg == nil {
			pkg = &extractor.Package{
				Name:      pkgName,
				Version:   req.Version,
				PURLType:  purlTypeForRequirement(req.Kind),
				Locations: nil,
				Metadata:  requirementMetadata(req),
			}
			seen[key] = pkg
		}
		if req.Path != "" {
			pkg.Locations = appendUnique(pkg.Locations, req.Path)
		}
	}
	out := make([]*extractor.Package, 0, len(seen))
	for _, pkg := range seen {
		out = append(out, pkg)
	}
	return out
}

func purlTypeForRequirement(kind RequirementKind) string {
	switch kind {
	case RequirementTerraformProvider, RequirementLockedProvider:
		return purlx.TypeTerraformProvider
	case RequirementModule:
		return purlx.TypeTerraformModule
	default:
		return purlx.TypeTerraform
	}
}

func requirementMetadata(req Requirement) map[string]any {
	meta := map[string]any{
		"kind": string(req.Kind),
	}

	switch req.Kind {
	case RequirementTerraformProvider:
		meta["source"] = strings.TrimSpace(req.Name)
		meta["constraint"] = strings.TrimSpace(req.Version)

	case RequirementLockedProvider:
		meta["source"] = strings.TrimSpace(req.Name)
		meta["resolved"] = true
		if req.Constraints != "" {
			meta["constraint"] = strings.TrimSpace(req.Constraints)
		}
		if len(req.Hashes) > 0 {
			meta["hashes"] = req.Hashes
		}
		// For locked providers, the version is exact, so we parse it directly
		if req.Version != "" {
			if major, minor, patch, ok := parseSemverParts(req.Version); ok {
				meta["version_major"] = major
				meta["version_minor"] = minor
				meta["version_patch"] = patch
			}
		}
		return meta // Skip constraint parsing for locked providers

	case RequirementModule:
		meta["source"] = strings.TrimSpace(req.Source)
		meta["module_type"] = req.ModuleType
		if req.Version != "" {
			meta["constraint"] = strings.TrimSpace(req.Version)
		}

	case RequirementTerraformCore:
		meta["constraint"] = strings.TrimSpace(req.Version)
	}

	// Parse version constraints for non-locked requirements
	if req.Version == "" {
		return meta
	}
	summary := summarizeConstraint(req.Version)
	if summary.min != "" {
		meta["min_version"] = summary.min
		meta["min_inclusive"] = summary.minInclusive
		if summary.minMajor >= 0 {
			meta["min_major"] = summary.minMajor
		}
		if summary.minMinor >= 0 {
			meta["min_minor"] = summary.minMinor
		}
		if summary.minPatch >= 0 {
			meta["min_patch"] = summary.minPatch
		}
	}
	if summary.max != "" {
		meta["max_version"] = summary.max
		meta["max_inclusive"] = summary.maxInclusive
		if summary.maxMajor >= 0 {
			meta["max_major"] = summary.maxMajor
		}
		if summary.maxMinor >= 0 {
			meta["max_minor"] = summary.maxMinor
		}
		if summary.maxPatch >= 0 {
			meta["max_patch"] = summary.maxPatch
		}
	}
	if len(summary.excludes) > 0 {
		meta["excludes"] = summary.excludes
	}
	return meta
}

func appendUnique(list []string, val string) []string {
	for _, item := range list {
		if item == val {
			return list
		}
	}
	return append(list, val)
}

type constraintSummary struct {
	min          string
	max          string
	minInclusive bool
	maxInclusive bool
	excludes     []string
	minMajor     int
	minMinor     int
	minPatch     int
	maxMajor     int
	maxMinor     int
	maxPatch     int
}

func summarizeConstraint(raw string) constraintSummary {
	out := constraintSummary{
		minMajor: -1, minMinor: -1, minPatch: -1,
		maxMajor: -1, maxMinor: -1, maxPatch: -1,
	}
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		op, ver := splitConstraint(part)
		if ver == "" {
			continue
		}
		switch op {
		case "!=":
			out.excludes = append(out.excludes, ver)
		case ">":
			out.applyMin(ver, false)
		case ">=":
			out.applyMin(ver, true)
		case "<":
			out.applyMax(ver, false)
		case "<=":
			out.applyMax(ver, true)
		case "~>":
			out.applyMin(ver, true)
			if upper, ok := pessimisticUpper(ver); ok {
				out.applyMax(upper, false)
			}
		default:
			// Treat bare versions as exact matches.
			out.applyMin(ver, true)
			out.applyMax(ver, true)
		}
	}
	return out
}

func splitConstraint(part string) (string, string) {
	for _, op := range []string{"~>", ">=", "<=", "!=", ">", "<", "="} {
		if strings.HasPrefix(part, op) {
			return op, strings.TrimSpace(strings.TrimPrefix(part, op))
		}
	}
	return "", strings.TrimSpace(part)
}

func (c *constraintSummary) applyMin(ver string, inclusive bool) {
	norm, ok := normalizeSemver(ver)
	if !ok {
		return
	}
	if c.min == "" {
		c.min = trimV(norm)
		c.minInclusive = inclusive
		c.setMinParts(ver)
		return
	}
	currNorm, currOK := normalizeSemver(c.min)
	if !currOK || semver.Compare(norm, currNorm) > 0 {
		c.min = trimV(norm)
		c.minInclusive = inclusive
		c.setMinParts(ver)
	} else if c.min == trimV(norm) {
		c.minInclusive = c.minInclusive && inclusive
	}
}

func (c *constraintSummary) applyMax(ver string, inclusive bool) {
	norm, ok := normalizeSemver(ver)
	if !ok {
		return
	}
	if c.max == "" {
		c.max = trimV(norm)
		c.maxInclusive = inclusive
		c.setMaxParts(ver)
		return
	}
	currNorm, currOK := normalizeSemver(c.max)
	if !currOK || semver.Compare(norm, currNorm) < 0 {
		c.max = trimV(norm)
		c.maxInclusive = inclusive
		c.setMaxParts(ver)
	} else if c.max == trimV(norm) {
		c.maxInclusive = c.maxInclusive && inclusive
	}
}

func (c *constraintSummary) setMinParts(ver string) {
	major, minor, patch, ok := parseSemverParts(ver)
	if !ok {
		return
	}
	c.minMajor, c.minMinor, c.minPatch = major, minor, patch
}

func (c *constraintSummary) setMaxParts(ver string) {
	major, minor, patch, ok := parseSemverParts(ver)
	if !ok {
		return
	}
	c.maxMajor, c.maxMinor, c.maxPatch = major, minor, patch
}

func normalizeSemver(ver string) (string, bool) {
	ver = strings.TrimSpace(ver)
	if ver == "" {
		return "", false
	}
	ver = strings.TrimPrefix(ver, "v")
	main, suffix := splitVersionSuffix(ver)
	parts := strings.Split(main, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	for i, p := range parts {
		if p == "" {
			parts[i] = "0"
		}
	}
	main = strings.Join(parts, ".")
	norm := "v" + main + suffix
	if !semver.IsValid(norm) {
		return "", false
	}
	return semver.Canonical(norm), true
}

func trimV(ver string) string {
	return strings.TrimPrefix(ver, "v")
}

func splitVersionSuffix(ver string) (string, string) {
	idx := strings.IndexAny(ver, "+-")
	if idx == -1 {
		return ver, ""
	}
	return ver[:idx], ver[idx:]
}

func parseSemverParts(ver string) (int, int, int, bool) {
	ver = strings.TrimSpace(strings.TrimPrefix(ver, "v"))
	main, _ := splitVersionSuffix(ver)
	if main == "" {
		return 0, 0, 0, false
	}
	rawParts := strings.Split(main, ".")
	for len(rawParts) < 3 {
		rawParts = append(rawParts, "0")
	}
	parts := make([]int, 3)
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(rawParts[i])
		if err != nil {
			return 0, 0, 0, false
		}
		parts[i] = n
	}
	return parts[0], parts[1], parts[2], true
}

func pessimisticUpper(ver string) (string, bool) {
	ver = strings.TrimSpace(strings.TrimPrefix(ver, "v"))
	main, _ := splitVersionSuffix(ver)
	if main == "" {
		return "", false
	}
	rawParts := strings.Split(main, ".")
	precision := len(rawParts)
	for len(rawParts) < 3 {
		rawParts = append(rawParts, "0")
	}
	parts := make([]int, 3)
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(rawParts[i])
		if err != nil {
			return "", false
		}
		parts[i] = n
	}
	switch {
	case precision <= 1:
		parts[0]++
		parts[1], parts[2] = 0, 0
	case precision == 2:
		parts[0]++
		parts[1], parts[2] = 0, 0
	default:
		parts[1]++
		parts[2] = 0
	}
	return strconv.Itoa(parts[0]) + "." + strconv.Itoa(parts[1]) + "." + strconv.Itoa(parts[2]), true
}
