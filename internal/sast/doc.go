// Package sast implements Deputy's static analysis and reachability engine.
//
// Architecture Overview
//
//  1. Targets describe the artifact under analysis (repository, container,
//     archive, etc.) and abstract filesystem access and configuration.
//  2. Dialects provide language or ecosystem specific capabilities, including
//     lexing, parsing, and IR lowering rules.
//  3. Pipelines coordinate dialects, producing intermediate representations
//     (IR) composed of property graphs over canonical symbols.
//  4. Reachability engines evaluate vulnerability symbol hints against IR and
//     answer whether a symbol is reachable from well defined entry points.
//  5. Registries provide extensible catalogs for augmenting OSV symbol data
//     and mapping ecosystem identifiers to canonical symbol IDs.
//
// The package favors composable abstractions so Deputy can mix generic analysis
// infrastructure with ecosystem specific overrides when needed. Call graph
// computations operate on a shared property graph interface which enables the
// engine to reason across languages as long as a dialect can lower artifacts
// into the shared IR. Dialects can implement advanced semantics (SSA, type
// resolution, etc.) while the engine remains agnostic to the underlying
// language details.
package sast
