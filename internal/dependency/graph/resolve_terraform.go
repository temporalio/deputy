package graph

import (
	"context"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/purl"
	"github.com/picatz/deputy/internal/inventory/plugins/terraform"
	"github.com/picatz/deputy/internal/logs"
	"github.com/picatz/deputy/internal/purlx"
)

// TerraformResolver resolves dependency edges for Terraform requirements.
type TerraformResolver struct{}

// NewTerraformResolver creates a new Terraform edge resolver.
func NewTerraformResolver() *TerraformResolver {
	return &TerraformResolver{}
}

// Ecosystem returns "Terraform" as the ecosystem identifier.
func (r *TerraformResolver) Ecosystem() string {
	return "Terraform"
}

// ResolveEdges parses Terraform configuration files to add dependency edges.
func (r *TerraformResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	if g == nil || files == nil {
		return nil
	}
	fsReader, ok := files.(fs.FS)
	if !ok {
		return nil
	}
	readDirFS, ok := files.(fs.ReadDirFS)
	if !ok {
		return nil
	}

	dirs := findTerraformDirs(fsReader)
	if len(dirs) == 0 {
		return nil
	}

	edgeSet := make(map[string]bool)
	for _, dir := range dirs {
		reqs, err := terraform.ParseDir(ctx, readDirFS, dir)
		if err != nil {
			logs.Debug(ctx, "terraform graph: parse dir failed", "dir", dir, "error", err)
			continue
		}
		if len(reqs) == 0 {
			continue
		}
		module := ensureTerraformModuleNode(g, dir, reqs)
		for _, req := range reqs {
			reqNode := ensureTerraformRequirementNode(g, req)
			if reqNode == nil {
				continue
			}
			key := module.Purl + "->" + reqNode.Purl
			if edgeSet[key] {
				continue
			}
			edgeSet[key] = true
			g.AddEdge(&Edge{
				From:  module.Purl,
				To:    reqNode.Purl,
				Scope: ScopeRuntime,
			})
		}
	}

	g.UpdateDepths()
	return nil
}

func findTerraformDirs(fsys fs.FS) []string {
	dirs := make(map[string]bool)
	_ = fs.WalkDir(fsys, ".", func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipTerraformDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !isTerraformConfigFile(filePath) {
			return nil
		}
		dir := path.Dir(filePath)
		if dir == "." || dir == "" {
			dir = "."
		}
		dirs[dir] = true
		return nil
	})

	list := make([]string, 0, len(dirs))
	for dir := range dirs {
		list = append(list, dir)
	}
	slices.Sort(list)
	return list
}

func shouldSkipTerraformDir(name string) bool {
	switch name {
	case ".git", ".terraform", "node_modules", "vendor", "testdata":
		return true
	default:
		return false
	}
}

func isTerraformConfigFile(filePath string) bool {
	if filePath == "" {
		return false
	}
	clean := path.Clean(filePath)
	if strings.Contains(clean, "/.terraform/") || strings.HasPrefix(clean, ".terraform/") {
		return false
	}
	base := strings.ToLower(path.Base(clean))
	return strings.HasSuffix(base, ".tf") || strings.HasSuffix(base, ".tf.json")
}

func ensureTerraformModuleNode(g *Graph, dir string, reqs []terraform.Requirement) *Node {
	purlStr := terraformModulePURL(dir)
	name := terraformModuleDisplayName(dir)
	if purlStr == "" || name == "" {
		return nil
	}

	node := g.Node(purlStr)
	if node == nil {
		node = &Node{
			Purl:      purlStr,
			Name:      name,
			Ecosystem: "Terraform",
			Direct:    true,
			Depth:     DepthSyntheticRoot,
		}
	}

	if node.Ecosystem == "" {
		node.Ecosystem = "Terraform"
	}
	node.Direct = true
	node.Depth = DepthSyntheticRoot
	for _, req := range reqs {
		if req.Path != "" {
			node.Locations = appendUniqueStrings(node.Locations, req.Path)
		}
	}

	g.AddNode(node)
	return node
}

func ensureTerraformRequirementNode(g *Graph, req terraform.Requirement) *Node {
	purlStr := terraformRequirementPURL(req)
	if purlStr == "" {
		return nil
	}
	name := strings.TrimSpace(req.Name)
	version := strings.TrimSpace(req.Version)

	node := g.Node(purlStr)
	if node == nil {
		node = &Node{
			Purl:      purlStr,
			Name:      name,
			Version:   version,
			Ecosystem: "Terraform",
			Direct:    true,
			Depth:     0,
		}
	}
	if node.Ecosystem == "" {
		node.Ecosystem = "Terraform"
	}
	if !node.Direct {
		node.Direct = true
		if node.Depth > 0 {
			node.Depth = 0
		}
	}
	if req.Path != "" {
		node.Locations = appendUniqueStrings(node.Locations, req.Path)
	}
	g.AddNode(node)
	return node
}

func terraformRequirementPURL(req terraform.Requirement) string {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return ""
	}
	purlType := purlx.TypeTerraform
	if req.Kind == terraform.RequirementTerraformProvider {
		purlType = purlx.TypeTerraformProvider
	}
	return purl.PackageURL{
		Type:    purlType,
		Name:    name,
		Version: strings.TrimSpace(req.Version),
	}.String()
}

func terraformModulePURL(dir string) string {
	key := terraformModuleKey(dir)
	if key == "" {
		return ""
	}
	return purl.PackageURL{
		Type: purlx.TypeTerraformModule,
		Name: key,
	}.String()
}

func terraformModuleKey(dir string) string {
	clean := strings.TrimSpace(path.Clean(dir))
	if clean == "." || clean == "/" || clean == "" {
		return "root"
	}
	clean = strings.TrimPrefix(clean, "./")
	return clean
}

func terraformModuleDisplayName(dir string) string {
	key := terraformModuleKey(dir)
	if key == "" {
		return ""
	}
	return "module:" + key
}

func appendUniqueStrings(list []string, val string) []string {
	for _, item := range list {
		if item == val {
			return list
		}
	}
	return append(list, val)
}
