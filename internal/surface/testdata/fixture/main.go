package main

import (
	"fmt"

	"fixture/internal/ifaces"
	"fixture/internal/used"
)

func main() {
	fmt.Println(used.Used(), ifaces.Run(nil, nil), ifaces.Make())
}
