// Command deskweaver is the advisor-only conversion CLI.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/luel-4013/deskweaver/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(cli.RunContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
