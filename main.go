package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/picatz/deputy/internal/cli"
	"github.com/picatz/deputy/internal/errors"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cli.Run(ctx); err != nil {
		// Use exit code from error if available, otherwise default to 1
		os.Exit(errors.ExitCode(err))
	}
}
