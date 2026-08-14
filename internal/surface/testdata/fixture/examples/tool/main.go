// Command tool stands in for examples/: excluded from findings, and its
// references still count as usage of internal symbols.
package main

import (
	"fmt"

	"fixture/internal/used"
)

// ForExampleOnly is named here and nowhere else, so a scan that stopped counting
// references from this tree would report it.
func main() { fmt.Println(used.Used(), used.ForExampleOnly()) }
