package graph

import (
	"fmt"
	"testing"
)

// buildTestGraph creates a graph with the specified number of nodes and edges.
// Structure: n direct deps, each with depth transitive deps forming a chain.
func buildTestGraph(directCount, depth int) *Graph {
	g := New()

	// Create direct dependencies
	for i := range directCount {
		rootPURL := fmt.Sprintf("pkg:test/direct-%d@1.0.0", i)
		g.AddNode(&Node{
			Purl:   rootPURL,
			Name:   fmt.Sprintf("direct-%d", i),
			Direct: true,
			Depth:  0,
		})

		// Create chain of transitive deps
		parentPURL := rootPURL
		for d := 1; d <= depth; d++ {
			childPURL := fmt.Sprintf("pkg:test/trans-%d-%d@1.0.0", i, d)
			g.AddNode(&Node{
				Purl:  childPURL,
				Name:  fmt.Sprintf("trans-%d-%d", i, d),
				Depth: int32(d),
			})
			g.AddEdge(&Edge{From: parentPURL, To: childPURL})
			parentPURL = childPURL
		}
	}

	return g
}

// buildDiamondGraph creates a graph with diamond dependency patterns.
// This is common in real-world dependency graphs where multiple packages
// depend on the same transitive dependency.
func buildDiamondGraph(width, depth int) *Graph {
	g := New()

	// Root node
	rootPURL := "pkg:test/root@1.0.0"
	g.AddNode(&Node{Purl: rootPURL, Name: "root", Direct: true, Depth: 0})

	// Create diamond pattern: root -> [a, b, c, ...] -> shared
	for i := range width {
		midPURL := fmt.Sprintf("pkg:test/mid-%d@1.0.0", i)
		g.AddNode(&Node{Purl: midPURL, Name: fmt.Sprintf("mid-%d", i), Depth: 1})
		g.AddEdge(&Edge{From: rootPURL, To: midPURL})

		// Each mid node points to the same shared node
		sharedPURL := "pkg:test/shared@1.0.0"
		if g.Node(sharedPURL) == nil {
			g.AddNode(&Node{Purl: sharedPURL, Name: "shared", Depth: 2})
		}
		g.AddEdge(&Edge{From: midPURL, To: sharedPURL})
	}

	// Add more depth after shared
	parentPURL := "pkg:test/shared@1.0.0"
	for d := 3; d <= depth; d++ {
		childPURL := fmt.Sprintf("pkg:test/deep-%d@1.0.0", d)
		g.AddNode(&Node{Purl: childPURL, Name: fmt.Sprintf("deep-%d", d), Depth: int32(d)})
		g.AddEdge(&Edge{From: parentPURL, To: childPURL})
		parentPURL = childPURL
	}

	return g
}

func BenchmarkChildren(b *testing.B) {
	sizes := []struct {
		direct, depth int
	}{
		{10, 5},
		{50, 10},
		{100, 20},
		{200, 30},
	}

	for _, size := range sizes {
		name := fmt.Sprintf("direct=%d,depth=%d", size.direct, size.depth)
		g := buildTestGraph(size.direct, size.depth)

		b.Run(name, func(b *testing.B) {
			purl := "pkg:test/direct-0@1.0.0"
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				count := 0
				for range g.Children(purl) {
					count++
				}
			}
		})
	}
}

func BenchmarkParents(b *testing.B) {
	sizes := []struct {
		direct, depth int
	}{
		{10, 5},
		{50, 10},
		{100, 20},
	}

	for _, size := range sizes {
		name := fmt.Sprintf("direct=%d,depth=%d", size.direct, size.depth)
		g := buildTestGraph(size.direct, size.depth)

		b.Run(name, func(b *testing.B) {
			// Look up parents of a transitive dep
			purl := fmt.Sprintf("pkg:test/trans-0-%d@1.0.0", size.depth)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				count := 0
				for range g.Parents(purl) {
					count++
				}
			}
		})
	}
}

func BenchmarkPathsTo(b *testing.B) {
	sizes := []struct {
		direct, depth int
	}{
		{10, 5},
		{50, 10},
		{100, 15},
	}

	for _, size := range sizes {
		name := fmt.Sprintf("direct=%d,depth=%d", size.direct, size.depth)
		g := buildTestGraph(size.direct, size.depth)

		b.Run(name, func(b *testing.B) {
			// Find paths to deepest node
			target := fmt.Sprintf("pkg:test/trans-0-%d@1.0.0", size.depth)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				paths := g.PathsTo(target)
				_ = paths
			}
		})
	}
}

func BenchmarkPathsToDiamond(b *testing.B) {
	sizes := []struct {
		width, depth int
	}{
		{5, 5},
		{10, 10},
		{20, 15},
		{50, 10},
	}

	for _, size := range sizes {
		name := fmt.Sprintf("width=%d,depth=%d", size.width, size.depth)
		g := buildDiamondGraph(size.width, size.depth)

		b.Run(name, func(b *testing.B) {
			// Find paths to the deepest node
			target := fmt.Sprintf("pkg:test/deep-%d@1.0.0", size.depth)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				paths := g.PathsTo(target)
				_ = paths
			}
		})
	}
}

func BenchmarkDescendants(b *testing.B) {
	g := buildTestGraph(50, 20)

	b.Run("from_root", func(b *testing.B) {
		purl := "pkg:test/direct-0@1.0.0"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			count := 0
			for range g.Descendants(purl) {
				count++
			}
		}
	})
}

func BenchmarkAncestors(b *testing.B) {
	g := buildTestGraph(50, 20)

	b.Run("from_leaf", func(b *testing.B) {
		purl := "pkg:test/trans-0-20@1.0.0"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			count := 0
			for range g.Ancestors(purl) {
				count++
			}
		}
	})
}

func BenchmarkUpdateDepths(b *testing.B) {
	sizes := []struct {
		direct, depth int
	}{
		{50, 10},
		{100, 20},
		{200, 30},
	}

	for _, size := range sizes {
		name := fmt.Sprintf("direct=%d,depth=%d", size.direct, size.depth)
		g := buildTestGraph(size.direct, size.depth)

		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				g.UpdateDepths()
			}
		})
	}
}

func BenchmarkVulnerablePaths(b *testing.B) {
	g := buildDiamondGraph(20, 10)

	// Mark a few nodes as vulnerable
	if n := g.Node("pkg:test/shared@1.0.0"); n != nil {
		n.VulnerabilityCount = &VulnerabilityCount{Total: 2, Critical: 1}
	}
	if n := g.Node("pkg:test/deep-10@1.0.0"); n != nil {
		n.VulnerabilityCount = &VulnerabilityCount{Total: 1, High: 1}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		paths := g.VulnerablePaths()
		_ = paths
	}
}
