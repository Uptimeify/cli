package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/uptimeify/cli/internal/auth"
	"github.com/uptimeify/cli/internal/client"
	"github.com/uptimeify/cli/internal/clierr"
	"github.com/uptimeify/cli/internal/commands"
	"github.com/uptimeify/cli/internal/sanitize"
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

// system is what main takes from the operating system; tests replace it.
type system struct {
	store    auth.Store
	lockDir  string
	hostname func() (string, error)
	browser  func(string) error
}

// newManager builds the sign-in manager for the host in UPTIMEIFY_API_URL. The host is the
// profile: another host has its own keyring entries and needs its own sign-in.
func newManager(env func(string) string, sys system, debug io.Writer) (*auth.Manager, error) {
	base, err := client.BaseURL(apiURL(env), env("UPTIMEIFY_ALLOW_INSECURE_LOOPBACK") == "1")
	if err != nil {
		return nil, err
	}
	origin := auth.Origin(base)
	return &auth.Manager{
		Origin:   origin,
		Store:    sys.store,
		OAuth:    &auth.OAuth{Origin: origin, UserAgent: client.UserAgent(version), Debug: debug},
		LockDir:  sys.lockDir,
		Hostname: sys.hostname,
	}, nil
}

// scopeList drops offline_access, which every browser sign-in has, and sanitises the rest.
func scopeList(scope string) string {
	var keep []string
	for _, s := range strings.Fields(scope) {
		if s != "offline_access" {
			keep = append(keep, s)
		}
	}
	return sanitize.Line(strings.Join(keep, " "))
}

// organizationName asks the API which organisation the sign-in belongs to. Only auth status uses
// it; a failure is shown, not returned.
func organizationName(ctx context.Context, newClient func() (commands.Doer, error)) string {
	unavailable := func(err error) string { return "unavailable (" + sanitize.Line(err.Error()) + ")" }
	cl, err := newClient()
	if err != nil {
		return unavailable(err)
	}
	res, err := cl.Do(ctx, "GET", "/api/organization", nil, nil)
	if err != nil {
		return unavailable(err)
	}
	var org struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(res.Body, &org); err != nil {
		return unavailable(err)
	}
	return sanitize.Line(org.Name)
}

// newRoot reads configuration only from env (the process environment in main), never from files.
// Stored browser sign-ins come from sys.store, the system keyring in main.
func newRoot(env func(string) string, out, errOut io.Writer, in io.Reader, stdinTTY, stdoutTTY func() bool, sys system) *cobra.Command {
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
		if o.Token == "" {
			// UPTIMEIFY_TOKEN takes precedence. The keyring is read only without it, so CI jobs and
			// containers without a keyring behave exactly as before.
			m, err := newManager(env, sys, o.Debug)
			if err != nil {
				return nil, err
			}
			signed, err := m.SignedIn()
			if errors.Is(err, auth.ErrNoKeyring) {
				return nil, clierr.New(clierr.Auth, "not signed in: %v; set UPTIMEIFY_TOKEN to an API token", err)
			}
			if err != nil {
				return nil, err
			}
			if !signed {
				return nil, clierr.New(clierr.Auth, "not signed in: run `uptimeify auth login`, or set UPTIMEIFY_TOKEN to an API token")
			}
			o.Source = m
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

	// authCmd, not auth: the variable would hide the imported package auth.
	authCmd := &cobra.Command{Use: "auth", Short: "Sign-in state"}
	authCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show where requests go and which sign-in they use",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			allowLoop := env("UPTIMEIFY_ALLOW_INSECURE_LOOPBACK") == "1"
			urlErr := client.CheckBaseURL(apiURL(env), allowLoop)
			apiLine := apiURL(env)
			if urlErr != nil {
				apiLine = "invalid (" + urlErr.Error() + ")"
			}
			envToken := env("UPTIMEIFY_TOKEN") != ""

			// The keyring is read only for a valid URL: the URL names the keyring entry.
			var m *auth.Manager
			var st *auth.Status
			var keyErr error
			if urlErr == nil {
				if m, keyErr = newManager(env, sys, nil); keyErr == nil {
					st, keyErr = m.Status()
				}
			}
			signedIn := keyErr == nil && st != nil && st.SignedIn

			var state string
			switch {
			case envToken && signedIn:
				state = "set (from UPTIMEIFY_TOKEN, which takes precedence over the browser sign-in)"
			case envToken:
				state = "set (from UPTIMEIFY_TOKEN)"
			case signedIn:
				state = "browser sign-in (stored in the system keyring)"
			case keyErr != nil:
				state = "not set (no system keyring available: " + sanitize.Line(keyErr.Error()) + ")"
			default:
				state = "not set"
			}
			asJSON, _ := c.Flags().GetBool("json")
			report := map[string]any{"api": apiLine, "token": state}
			source := "none"
			switch {
			case envToken:
				source = "env"
			case signedIn:
				source = "browser"
			}
			report["source"] = source
			if !asJSON {
				fmt.Fprintf(out, "API:   %s\nToken: %s\n", apiLine, state)
			}
			if envToken || !signedIn {
				if asJSON {
					writeJSON(out, report)
				}
				return urlErr
			}

			org := organizationName(c.Context(), newClient)
			if fresh, err := m.Status(); err == nil && fresh != nil && fresh.SignedIn {
				st = fresh // the request above may have renewed the access token
			}
			when := func(t time.Time) string { return t.Local().Format("2006-01-02 15:04 MST") }
			line := func(label, value string) { fmt.Fprintf(out, "  %-14s %s\n", label+":", value) }
			userID := sanitize.Line(st.UserID)
			if userID == "" {
				userID = "unknown until the next request"
			}
			access := "expired, renewed on the next request"
			if st.AccessExpiresAt.After(time.Now()) {
				access = "valid until " + when(st.AccessExpiresAt)
			}
			grantEnd, idleEnd := st.GrantStartedAt.Add(auth.GrantMaxAge), st.RefreshedAt.Add(auth.IdleLimit)
			if asJSON {
				report["deviceName"] = sanitize.Line(st.DeviceName)
				report["userId"] = userID
				report["organization"] = org
				report["scopes"] = strings.Fields(scopeList(st.Scope))
				report["accessExpiresAt"] = st.AccessExpiresAt.UTC().Format(time.RFC3339)
				report["grantEndsAt"] = grantEnd.UTC().Format(time.RFC3339)
				report["idleEndsAt"] = idleEnd.UTC().Format(time.RFC3339)
				writeJSON(out, report)
				return nil
			}
			line("Device", sanitize.Line(st.DeviceName))
			line("User ID", userID)
			line("Organization", org)
			line("Scopes", scopeList(st.Scope))
			line("Access token", access)
			line("Sign-in ends", fmt.Sprintf("at the latest %s (30 days), or after 7 days without use (%s)", when(grantEnd), when(idleEnd)))
			return nil
		},
	})
	authCmd.AddCommand(newLoginCmd(env, out, errOut, sys), newLogoutCmd(env, out, errOut, sys))
	root.AddCommand(authCmd)

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

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// printError writes err as one sanitised line, so control characters cannot act on the terminal.
// An API error with a hint (missing scope, path closed to browser sign-ins) gets a second line.
func printError(w io.Writer, err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(w, "Error:", sanitize.Line(err.Error()))
	var ae *client.APIError
	if errors.As(err, &ae) && ae.Hint != "" {
		fmt.Fprintln(w, "Hint:", sanitize.Line(ae.Hint))
		if ae.Code == "cliScopeForbidden" && isAreaWriteScope(ae.RequiredScope) {
			fmt.Fprintln(w, "Hint: `uptimeify auth login --write` asks for the write scopes of all areas at once")
		}
	}
}

func main() {
	stdinTTY := func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	stdoutTTY := func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
	// Without a user cache directory lockDir is "", and renewing a browser sign-in fails with a
	// clear error. main is the only place that uses the real system keyring.
	lockDir, _ := os.UserCacheDir()
	sys := system{store: auth.Keyring{}, lockDir: lockDir, hostname: os.Hostname, browser: auth.OpenBrowser}
	err := newRoot(os.Getenv, os.Stdout, os.Stderr, os.Stdin, stdinTTY, stdoutTTY, sys).Execute()
	printError(os.Stderr, err)
	os.Exit(exitCode(err))
}

func isAreaWriteScope(s string) bool {
	for _, w := range auth.WriteScopes() {
		if w == s {
			return true
		}
	}
	return false
}
