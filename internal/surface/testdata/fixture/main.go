package main

import (
	"fmt"

	"fixture/internal/ifaces"
	_ "fixture/internal/registered"
	"fixture/internal/used"
)

func main() {
	fmt.Println(used.Used(), ifaces.Run(nil, nil), ifaces.Make())
}
