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
	"github.com/uptimeify/cli/internal/output"
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
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return clierr.New(clierr.Usage, "%v", err) })
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
			allowLoop := env("UPTIMEIFY_ALLOW_INSECURE_LOOPBACK") == "1"
			urlErr := client.CheckBaseURL(apiURL(env), allowLoop)
			apiLine := apiURL(env)
			if urlErr != nil {
				apiLine = "invalid (" + urlErr.Error() + ")"
			}
			state := "not set"
			if env("UPTIMEIFY_TOKEN") != "" {
				state = "set (from UPTIMEIFY_TOKEN)"
			}
			fmt.Fprintf(out, "API:   %s\nToken: %s\n", apiLine, state)
			return urlErr
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
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	requireKnownSubcommands(root)
	return root
}

// requireKnownSubcommands makes every pure group (subcommands, no action of its own) print help
// when bare and reject any extra word as a usage error. Cobra would otherwise print help and exit 0.
func requireKnownSubcommands(c *cobra.Command) {
	for _, s := range c.Commands() {
		requireKnownSubcommands(s)
	}
	if len(c.Commands()) == 0 || c.Runnable() {
		return
	}
	c.Args = func(c *cobra.Command, args []string) error {
		if len(args) > 0 {
			return clierr.New(clierr.Usage, "unknown command %q for %q", args[0], c.CommandPath())
		}
		return nil
	}
	c.RunE = func(c *cobra.Command, _ []string) error { return c.Help() }
}

func exitCode(err error) int {
	var ae *client.APIError
	if errors.As(err, &ae) {
		return ae.ExitCode()
	}
	return clierr.ExitCode(err)
}

// printError writes err as one sanitised line, so control characters cannot act on the terminal.
func printError(w io.Writer, err error) {
	if err != nil {
		fmt.Fprintln(w, "Error:", output.Sanitize(err.Error()))
	}
}

func main() {
	stdinTTY := func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	stdoutTTY := func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
	err := newRoot(os.Getenv, os.Stdout, os.Stderr, os.Stdin, stdinTTY, stdoutTTY).Execute()
	printError(os.Stderr, err)
	os.Exit(exitCode(err))
}
