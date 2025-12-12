package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/picatz/deputy/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := cli.Run(ctx); err != nil {
		os.Exit(1)
	}
}
