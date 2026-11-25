package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/uptimeify/cli/internal/clierr"
)

func runCLI(t *testing.T, env map[string]string, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	no := func() bool { return false }
	root := newRoot(func(k string) string { return env[k] }, &out, &errOut, strings.NewReader(""), no, no)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), errOut.String(), err
}

func walk(c *cobra.Command, f func(*cobra.Command)) {
	f(c)
	for _, s := range c.Commands() {
		walk(s, f)
	}
}

func testRoot() *cobra.Command {
	no := func() bool { return false }
	return newRoot(func(string) string { return "" }, &bytes.Buffer{}, &bytes.Buffer{}, strings.NewReader(""), no, no)
}

func TestNoSiblingCommandsShareAName(t *testing.T) {
	walk(testRoot(), func(c *cobra.Command) {
		seen := map[string]bool{}
		for _, s := range c.Commands() {
			if seen[s.Name()] {
				t.Errorf("duplicate command %q under %q", s.Name(), c.CommandPath())
			}
			seen[s.Name()] = true
		}
	})
}

func TestNoSecretFlagExistsAnywhere(t *testing.T) {
	walk(testRoot(), func(c *cobra.Command) {
		for _, name := range []string{"token", "insecure", "api-url"} {
			if c.Flags().Lookup(name) != nil || c.PersistentFlags().Lookup(name) != nil {
				t.Errorf("%s: flag --%s must not exist", c.CommandPath(), name)
			}
		}
	})
}

func TestMissingTokenIsAuthError(t *testing.T) {
	_, _, err := runCLI(t, nil, "websites", "list")
	if exitCode(err) != clierr.Auth {
		t.Errorf("err = %v, exit %d", err, exitCode(err))
	}
}

func TestHelpWorksWithoutToken(t *testing.T) {
	out, _, err := runCLI(t, nil, "websites", "--help")
	if err != nil || !strings.Contains(out, "list") {
		t.Errorf("help failed: %v, %q", err, out)
	}
}

func apiServer(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wsm_x" {
			w.WriteHeader(401)
			w.Write([]byte(`{"message":"bad token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"items":[{"id":5,"name":"Shop"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEndToEndAgainstLocalServer(t *testing.T) {
	srv := apiServer(t)
	env := map[string]string{"UPTIMEIFY_TOKEN": "wsm_x", "UPTIMEIFY_API_URL": srv.URL, "UPTIMEIFY_ALLOW_INSECURE_LOOPBACK": "1", "UPTIMEIFY_DEBUG": "1"}
	out, errOut, err := runCLI(t, env, "websites", "list", "--json")
	if err != nil || out != `{"items":[{"id":5,"name":"Shop"}]}`+"\n" {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	if !strings.Contains(errOut, "GET") || strings.Contains(errOut, "wsm_x") {
		t.Errorf("debug output = %q", errOut)
	}
	out, _, err = runCLI(t, env, "doctor")
	if err != nil || !strings.Contains(out, "ok") {
		t.Errorf("doctor: %q, %v", out, err)
	}

	env["UPTIMEIFY_TOKEN"] = "wrong"
	_, _, err = runCLI(t, env, "websites", "list")
	if exitCode(err) != clierr.Auth {
		t.Errorf("401 mapped to exit %d", exitCode(err))
	}
}

func hasSixCharSubstring(haystack, secret string) bool {
	for i := 0; i+6 <= len(secret); i++ {
		if strings.Contains(haystack, secret[i:i+6]) {
			return true
		}
	}
	return false
}

func TestTokenNeverLeaks(t *testing.T) {
	const token = "wsm_Zq8xKd3LmN7pRt"
	srv := apiServer(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	cases := map[string][]string{
		"auth status": {"auth", "status"},
		"401":         {"websites", "list"},
		"refused":     {"websites", "list"},
	}
	urls := map[string]string{"auth status": srv.URL, "401": srv.URL, "refused": deadURL}
	for name, args := range cases {
		env := map[string]string{"UPTIMEIFY_TOKEN": token, "UPTIMEIFY_API_URL": urls[name], "UPTIMEIFY_ALLOW_INSECURE_LOOPBACK": "1", "UPTIMEIFY_DEBUG": "1"}
		out, errOut, err := runCLI(t, env, args...)
		all := out + errOut
		if err != nil {
			all += err.Error()
		}
		if hasSixCharSubstring(all, token) {
			t.Errorf("%s: token fragment leaked: %q", name, all)
		}
	}
}

func TestAuthStatus(t *testing.T) {
	out, _, err := runCLI(t, map[string]string{"UPTIMEIFY_TOKEN": "wsm_supersecret"}, "auth", "status")
	if err != nil || !strings.Contains(out, "https://uptimeify.io") || !strings.Contains(out, "set") {
		t.Errorf("out = %q, err = %v", out, err)
	}
}

func TestAPIURLPolicy(t *testing.T) {
	srv := apiServer(t)
	base := map[string]string{"UPTIMEIFY_TOKEN": "wsm_x"}
	with := func(url string, loop bool) map[string]string {
		e := map[string]string{"UPTIMEIFY_TOKEN": base["UPTIMEIFY_TOKEN"], "UPTIMEIFY_API_URL": url}
		if loop {
			e["UPTIMEIFY_ALLOW_INSECURE_LOOPBACK"] = "1"
		}
		return e
	}
	if _, _, err := runCLI(t, with("http://example.com", false), "websites", "list"); exitCode(err) != clierr.Usage {
		t.Errorf("plain http to example.com: %v", err)
	}
	if _, _, err := runCLI(t, with(srv.URL, false), "websites", "list"); exitCode(err) != clierr.Usage {
		t.Errorf("loopback without opt-in: %v", err)
	}
	if _, _, err := runCLI(t, with(srv.URL, true), "websites", "list"); err != nil {
		t.Errorf("loopback with opt-in: %v", err)
	}
}

func TestConfigFilesInWorkingDirectoryAreIgnored(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{".uptimeify", ".uptimeify.json", "uptimeify.json", ".env"} {
		body := "UPTIMEIFY_API_URL=https://evil.example\nUPTIMEIFY_TOKEN=evil\n{\"apiUrl\":\"https://evil.example\",\"token\":\"evil\"}"
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	out, _, err := runCLI(t, nil, "auth", "status")
	if err != nil || !strings.Contains(out, "https://uptimeify.io") || strings.Contains(out, "evil") || !strings.Contains(out, "not set") {
		t.Errorf("out = %q, err = %v", out, err)
	}
}
