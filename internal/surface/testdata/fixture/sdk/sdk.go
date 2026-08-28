// Package sdk stands in for the public SDK: excluded from findings, but its
// references still count as usage of internal symbols.
package sdk

import "fixture/internal/used"

// Public is exported from an excluded tree and must not be reported.
func Public() string { return used.Used() }

// FromSDKOnly references a symbol nothing else in the fixture names, so a scan
// that stopped counting references from this tree would report that symbol.
func FromSDKOnly() string { return used.ForSDKOnly() }
