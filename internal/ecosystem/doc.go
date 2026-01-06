// Package ecosystem provides types and utilities for working with package ecosystems.
//
// An ecosystem represents a software packaging system like Go modules, npm, PyPI, etc.
// This package provides:
//
//   - [Ecosystem] type for representing ecosystems with compile-time safety
//   - [Parse] function for normalizing ecosystem strings from various sources
//   - [Capability] flags for describing what Deputy can do with each ecosystem
//   - [Registry] for discovering ecosystem capabilities at runtime
//
// # Ecosystem Types
//
// Ecosystems are represented as typed string constants:
//
//	eco := ecosystem.Go       // Go modules
//	eco := ecosystem.NPM      // npm packages
//	eco := ecosystem.PyPI     // Python packages
//	eco := ecosystem.Maven    // Java/Maven packages
//	eco := ecosystem.RubyGems // Ruby gems
//
// # Parsing Ecosystem Strings
//
// The [Parse] function normalizes various ecosystem names:
//
//	ecosystem.Parse("golang")   // Returns ecosystem.Go
//	ecosystem.Parse("python")   // Returns ecosystem.PyPI
//	ecosystem.Parse("node")     // Returns ecosystem.NPM
//
// # Capabilities
//
// Each ecosystem has different capabilities depending on implementation status:
//
//	caps := ecosystem.DefaultRegistry.Capabilities(ecosystem.Go)
//	if caps.Has(ecosystem.CapInventory) {
//	    // Can scan for dependencies
//	}
//	if caps.Has(ecosystem.CapProxy) {
//	    // Can proxy package requests
//	}
//
// # Registry
//
// The [DefaultRegistry] provides access to ecosystem metadata:
//
//	for _, eco := range ecosystem.DefaultRegistry.All() {
//	    fmt.Printf("%s: %s\n", eco.Name, eco.Description)
//	}
package ecosystem
