package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/uptimeify/cli/internal/auth"
	"github.com/uptimeify/cli/internal/clierr"
	"github.com/uptimeify/cli/internal/sanitize"
)

func loginLong() string {
	return "Sign in with the browser (OAuth with PKCE). The CLI prints the address on stderr and opens\n" +
		"it in your browser. The browser must run on this computer: it returns to http://127.0.0.1 on a\n" +
		"random port.\n\n" +
		"The sign-in is kept in the system keyring (macOS Keychain, Windows Credential Manager, Secret\n" +
		"Service on Linux). Without a keyring there is no browser sign-in: set UPTIMEIFY_TOKEN to an API\n" +
		"token instead. While UPTIMEIFY_TOKEN is set, it takes precedence over the browser sign-in.\n\n" +
		"By default the CLI asks for read access only (the :read scopes, without users, billing, audit and\n" +
		"status page subscribers). --write adds the :write scopes of the same areas. --scope <scope>, which\n" +
		"may be repeated, adds single scopes, including the separate ones such as api:users:read or\n" +
		"api:billing:write. The consent page in the browser can grant fewer than requested.\n\n" +
		"Scopes:\n  " + strings.Join(auth.AllScopes, "\n  ")
}

func newLoginCmd(env func(string) string, out, errOut io.Writer, sys system) *cobra.Command {
	var scopes []string
	var write, noBrowser bool
	var deviceName string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in with the browser and keep the sign-in in the system keyring",
		Long:  loginLong(),
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if env("UPTIMEIFY_TOKEN") != "" {
				// UPTIMEIFY_TOKEN wins everywhere and the keyring is then neither read nor written.
				return clierr.New(clierr.Usage, "UPTIMEIFY_TOKEN is set and takes precedence over the browser sign-in; unset it to sign in with the browser")
			}
			var debug io.Writer
			if env("UPTIMEIFY_DEBUG") == "1" {
				debug = errOut
			}
			m, err := newManager(env, sys, debug, errOut)
			if err != nil {
				return err
			}
			all := append([]string(nil), scopes...)
			if write {
				all = append(all, auth.WriteScopes()...)
			}
			o := auth.LoginOptions{Scopes: all, DeviceName: deviceName, Out: errOut}
			if !noBrowser {
				o.OpenBrowser = sys.browser
			}
			cred, err := m.Login(c.Context(), o)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Signed in to %s as device \"%s\".\n", m.Origin, sanitize.Line(cred.DeviceName))
			fmt.Fprintf(out, "Scopes: %s\n", scopeList(cred.Scope))
			return nil
		},
	}
	cmd.Flags().BoolVar(&write, "write", false, "also ask for the write scopes of every area (default: read only)")
	cmd.Flags().StringSliceVar(&scopes, "scope", nil, "extra scope to request, repeatable (also the separate ones: users, billing, audit, status page subscribers)")
	cmd.Flags().StringVar(&deviceName, "device-name", "", "name of this device in Connected apps (default: uptimeify CLI on <hostname>)")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not open a browser, only print the address to open on this computer")
	return cmd
}

func newLogoutCmd(env func(string) string, out, errOut io.Writer, sys system) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Sign out on this computer and revoke the sign-in on the server",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			var debug io.Writer
			if env("UPTIMEIFY_DEBUG") == "1" {
				debug = errOut
			}
			m, err := newManager(env, sys, debug, errOut)
			if err != nil {
				return err
			}
			res, err := m.Logout(c.Context())
			if err != nil {
				return err
			}
			switch {
			case res.Revoked:
				fmt.Fprintf(out, "Signed out of %s. The server revoked the sign-in.\n", m.Origin)
			case res.WasSignedIn && res.RevokeErr != nil:
				fmt.Fprintf(out, "Signed out of %s on this computer. The server did not confirm the revocation (%s). To end the sign-in there too, disconnect the device \"%s\" in the dashboard under Connected apps.\n",
					m.Origin, sanitize.Line(res.RevokeErr.Error()), sanitize.Line(res.DeviceName))
			default:
				// Nothing stored, or only a registration whose sign-in never completed: there was no
				// sign-in to revoke. Logout has removed the leftover registration anyway.
				fmt.Fprintf(out, "Not signed in to %s.\n", m.Origin)
			}
			return nil
		},
	}
}
