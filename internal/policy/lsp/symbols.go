package lsp

import (
	protocol "github.com/sourcegraph/go-lsp"
	"gopkg.in/yaml.v3"
)

// parseDocumentSymbols extracts top-level policy names as document symbols.
func parseDocumentSymbols(text string, uri protocol.DocumentURI) ([]protocol.SymbolInformation, error) {
	root := &yaml.Node{}
	if err := yaml.Unmarshal([]byte(text), root); err != nil {
		return nil, err
	}
	if len(root.Content) == 0 {
		return nil, nil
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil, nil
	}
	policies := findMapValue(doc, "policies")
	if policies == nil || policies.Kind != yaml.SequenceNode {
		return nil, nil
	}
	var out []protocol.SymbolInformation
	for _, item := range policies.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		nameNode := findMapValue(item, "name")
		name := "policy"
		if nameNode != nil && nameNode.Kind == yaml.ScalarNode && nameNode.Value != "" {
			name = nameNode.Value
		}
		r := nodeRange(nameNode)
		out = append(out, protocol.SymbolInformation{
			Name: name,
			Kind: protocol.SKStruct,
			Location: protocol.Location{
				URI:   uri,
				Range: r,
			},
		})
	}
	return out, nil
}

// nodeRange converts a YAML node's line/column information into an LSP Range.
// It handles nil nodes gracefully by returning a zero range.
func nodeRange(n *yaml.Node) protocol.Range {
	if n == nil {
		return protocol.Range{}
	}
	start := protocol.Position{Line: n.Line - 1, Character: n.Column - 1}
	end := protocol.Position{Line: n.Line - 1, Character: n.Column - 1 + len(n.Value)}
	return protocol.Range{Start: start, End: end}
}
