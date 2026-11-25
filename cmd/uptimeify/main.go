package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/uptimeify/cli/internal/client"
	"github.com/uptimeify/cli/internal/clierr"
	"github.com/uptimeify/cli/internal/commands"
)

// version is set by the release build: -ldflags "-X main.version=1.2.3".
var version = "dev"

const defaultAPIURL = "https://uptimeify.io"

func apiURL(env func(string) string) string {
	if u := env("UPTIMEIFY_API_URL"); u != "" {
		return u
	}
	return defaultAPIURL
}

// newRoot reads configuration only from env (the process environment in main), never from files.
func newRoot(env func(string) string, out, errOut io.Writer, in io.Reader, stdinTTY, stdoutTTY func() bool) *cobra.Command {
	root := &cobra.Command{
		Use:           "uptimeify",
		Short:         "Uptimeify from your terminal",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(out)
	root.SetErr(errOut)
	root.PersistentFlags().Bool("json", false, "print the raw JSON response")

	newClient := func() (commands.Doer, error) {
		o := client.Options{
			BaseURL:               apiURL(env),
			Token:                 env("UPTIMEIFY_TOKEN"),
			Version:               version,
			AllowInsecureLoopback: env("UPTIMEIFY_ALLOW_INSECURE_LOOPBACK") == "1",
		}
		if env("UPTIMEIFY_DEBUG") == "1" {
			o.Debug = errOut
		}
		return client.New(o)
	}

	ops, err := commands.Ops()
	if err != nil {
		// The manifest is embedded at build time; a broken one is a build defect.
		panic(fmt.Sprintf("embedded command manifest is invalid: %v", err))
	}
	commands.Register(root, ops, commands.Deps{
		NewClient: newClient, Out: out, Err: errOut, In: in, IsTTY: stdinTTY, StdoutIsTTY: stdoutTTY,
	})

	auth := &cobra.Command{Use: "auth", Short: "Sign-in state"}
	auth.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show where requests go and whether a token is configured",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			state := "not set"
			if env("UPTIMEIFY_TOKEN") != "" {
				state = "set (from UPTIMEIFY_TOKEN)"
			}
			fmt.Fprintf(out, "API:   %s\nToken: %s\n", apiURL(env), state)
			return nil
		},
	})
	root.AddCommand(auth)

	root.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Check configuration and connectivity",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cl, err := newClient()
			if err != nil {
				return err
			}
			// GET /api/organization: read-only and identifies the caller's organisation.
			if _, err := cl.Do(c.Context(), "GET", "/api/organization", nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(out, "ok: signed in at %s\n", apiURL(env))
			return nil
		},
	})
	return root
}

func exitCode(err error) int {
	var ae *client.APIError
	if errors.As(err, &ae) {
		return ae.ExitCode()
	}
	return clierr.ExitCode(err)
}

func main() {
	stdinTTY := func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	stdoutTTY := func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
	err := newRoot(os.Getenv, os.Stdout, os.Stderr, os.Stdin, stdinTTY, stdoutTTY).Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
	}
	os.Exit(exitCode(err))
}
