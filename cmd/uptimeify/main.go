package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/uptimeify/cli/internal/clierr"
)

// version is set by the release build: -ldflags "-X main.version=1.2.3".
var version = "dev"

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "uptimeify",
		Short:         "Uptimeify from your terminal",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return root
}

func main() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(clierr.ExitCode(err))
	}
}
