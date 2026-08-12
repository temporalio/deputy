// Command tool stands in for examples/: excluded from findings, and its
// references still count as usage of internal symbols.
package main

import (
	"fmt"

	"fixture/internal/used"
)

func main() { fmt.Println(used.Used()) }
