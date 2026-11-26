package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/uptimeify/cli/internal/auth"
	"github.com/uptimeify/cli/internal/client"
	"github.com/uptimeify/cli/internal/clierr"
)

func runCLI(t *testing.T, env map[string]string, args ...string) (string, string, error) {
	t.Helper()
	return runCLIWith(t, env, testSystem(t), args...)
}

func runCLIWith(t *testing.T, env map[string]string, sys system, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	no := func() bool { return false }
	root := newRoot(func(k string) string { return env[k] }, &out, &errOut, strings.NewReader(""), no, no, sys)
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

func testRoot(t *testing.T) *cobra.Command {
	no := func() bool { return false }
	root := newRoot(func(string) string { return "" }, &bytes.Buffer{}, &bytes.Buffer{}, strings.NewReader(""), no, no, testSystem(t))
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	return root
}

func TestNoSiblingCommandsShareAName(t *testing.T) {
	walk(testRoot(t), func(c *cobra.Command) {
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
	walk(testRoot(t), func(c *cobra.Command) {
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

func TestUsageErrorsExitTwoWithoutRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	env := map[string]string{"UPTIMEIFY_TOKEN": "wsm_x", "UPTIMEIFY_API_URL": srv.URL, "UPTIMEIFY_ALLOW_INSECURE_LOOPBACK": "1"}
	cases := []struct {
		args []string
		word string
	}{
		{[]string{"bogus"}, "bogus"},
		{[]string{"websites", "bogus"}, "bogus"},
		{[]string{"im", "teams", "bogus"}, "bogus"},
		{[]string{"websites", "list", "--nope"}, "nope"},
		{[]string{"organization", "get", "--nope"}, "nope"},
	}
	for _, c := range cases {
		_, _, err := runCLI(t, env, c.args...)
		if exitCode(err) != clierr.Usage || err == nil || !strings.Contains(err.Error(), c.word) {
			t.Errorf("%v: err = %v, exit %d", c.args, err, exitCode(err))
		}
	}
	if hits.Load() != 0 {
		t.Errorf("server got %d requests", hits.Load())
	}
}

func TestBareGroupPrintsHelpAndExitsZero(t *testing.T) {
	out, _, err := runCLI(t, nil, "websites")
	if err != nil || !strings.Contains(out, "list") {
		t.Errorf("out = %q, err = %v", out, err)
	}
	srv := apiServer(t)
	env := map[string]string{"UPTIMEIFY_TOKEN": "wsm_x", "UPTIMEIFY_API_URL": srv.URL, "UPTIMEIFY_ALLOW_INSECURE_LOOPBACK": "1"}
	if _, _, err := runCLI(t, env, "websites", "list"); err != nil {
		t.Errorf("websites list: %v", err)
	}
}

func TestPrintErrorSanitises(t *testing.T) {
	_, _, err := runCLI(t, nil, "\x1b[31mbogus")
	var b bytes.Buffer
	printError(&b, err)
	if strings.ContainsRune(b.String(), 0x1b) || strings.Count(b.String(), "\n") != 1 || !strings.HasPrefix(b.String(), "Error: ") {
		t.Errorf("printed %q", b.String())
	}
}

func TestAuthStatusInvalidURL(t *testing.T) {
	out, _, err := runCLI(t, map[string]string{"UPTIMEIFY_API_URL": "http://example.com"}, "auth", "status")
	if exitCode(err) != clierr.Usage || !strings.Contains(out, "API:   invalid (") || strings.Contains(out, "API:   http") {
		t.Errorf("out = %q, err = %v", out, err)
	}
	out, _, err = runCLI(t, nil, "auth", "status")
	if err != nil || !strings.Contains(out, "API:   https://uptimeify.io") {
		t.Errorf("valid: out = %q, err = %v", out, err)
	}
}

// memStore is an in-memory auth.Store. Tests never touch the real system keyring.
type memStore struct {
	mu     sync.Mutex
	m      map[string]string
	getErr error
}

func (s *memStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return "", s.getErr
	}
	v, ok := s.m[key]
	if !ok {
		return "", auth.ErrNotFound
	}
	return v, nil
}

func (s *memStore) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[key] = value
	return nil
}

func (s *memStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

func (s *memStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

func testSystem(t *testing.T) system {
	return system{
		store:    &memStore{},
		lockDir:  t.TempDir(),
		hostname: func() (string, error) { return "testhost", nil },
		browser:  func(string) error { return errors.New("no browser in tests") },
	}
}

func testClientID() string { return "ucli_" + strings.Repeat("c", 32) }

// fakeAccess builds a JWT-shaped access token at run time, so no token literal is in the repo.
func fakeAccess(sub string, n int) string {
	enc := base64.RawURLEncoding
	claims, _ := json.Marshal(map[string]any{"sub": sub, "scope": "api:monitors:read", "n": n})
	return enc.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`)) + "." + enc.EncodeToString(claims) + ".sig"
}

// seedSignIn stores a browser sign-in for origin the way internal/auth does (keys origin and
// origin + " access", JSON of auth.Credentials and auth.Access).
func seedSignIn(t *testing.T, st auth.Store, origin, access string, expires time.Time) {
	t.Helper()
	now := time.Now()
	cred, err := json.Marshal(auth.Credentials{
		ClientID:       testClientID(),
		RegisteredAt:   now.Add(-time.Hour),
		DeviceName:     "uptimeify CLI on testhost",
		RefreshToken:   fmt.Sprintf("rt-%d", 1),
		Scope:          "offline_access api:monitors:read api:organization:read",
		GrantStartedAt: now.Add(-time.Hour),
		RefreshedAt:    now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	acc, err := json.Marshal(auth.Access{Token: access, ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Set(origin, string(cred)); err != nil {
		t.Fatal(err)
	}
	if err := st.Set(origin+" access", string(acc)); err != nil {
		t.Fatal(err)
	}
}

// storedRefresh returns the refresh token stored for origin, or "" when there is none.
func storedRefresh(t *testing.T, st auth.Store, origin string) string {
	t.Helper()
	raw, err := st.Get(origin)
	if errors.Is(err, auth.ErrNotFound) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	var c auth.Credentials
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	return c.RefreshToken
}

func loopEnv(url string) map[string]string {
	return map[string]string{"UPTIMEIFY_API_URL": url, "UPTIMEIFY_ALLOW_INSECURE_LOOPBACK": "1"}
}

func TestEnvTokenTakesPrecedence(t *testing.T) {
	srv := apiServer(t)
	sys := testSystem(t)
	seedSignIn(t, sys.store, srv.URL, fakeAccess("user-1", 1), time.Now().Add(10*time.Minute))
	env := loopEnv(srv.URL)
	env["UPTIMEIFY_TOKEN"] = "wsm_x"
	if _, _, err := runCLIWith(t, env, sys, "websites", "list"); err != nil {
		t.Fatalf("the stored sign-in won over UPTIMEIFY_TOKEN: %v", err)
	}
	// With the variable set the keyring is not read at all: a broken keyring changes nothing.
	sys.store.(*memStore).getErr = fmt.Errorf("%w: dbus", auth.ErrNoKeyring)
	if _, _, err := runCLIWith(t, env, sys, "websites", "list"); err != nil {
		t.Fatalf("keyring was read although UPTIMEIFY_TOKEN is set: %v", err)
	}
}

func TestStoredSignInIsUsed(t *testing.T) {
	access := fakeAccess("user-1", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+access {
			w.WriteHeader(401)
			w.Write([]byte(`{"message":"bad token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"items":[]}`))
	}))
	t.Cleanup(srv.Close)
	sys := testSystem(t)
	seedSignIn(t, sys.store, srv.URL, access, time.Now().Add(10*time.Minute))
	if _, _, err := runCLIWith(t, loopEnv(srv.URL), sys, "websites", "list"); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestNotSignedInMessage(t *testing.T) {
	_, _, err := runCLI(t, nil, "websites", "list")
	if exitCode(err) != clierr.Auth || err == nil || !strings.Contains(err.Error(), "uptimeify auth login") || !strings.Contains(err.Error(), "UPTIMEIFY_TOKEN") {
		t.Errorf("err = %v, exit %d", err, exitCode(err))
	}
}

func TestNoKeyringMessage(t *testing.T) {
	sys := testSystem(t)
	sys.store.(*memStore).getErr = fmt.Errorf("%w: dbus", auth.ErrNoKeyring)
	_, _, err := runCLIWith(t, nil, sys, "websites", "list")
	if exitCode(err) != clierr.Auth || err == nil || !strings.Contains(err.Error(), "UPTIMEIFY_TOKEN") {
		t.Errorf("err = %v, exit %d", err, exitCode(err))
	}
}

func TestRenewalThroughMain(t *testing.T) {
	oldAccess, newAccess := fakeAccess("user-1", 1), fakeAccess("user-1", 2)
	var refreshes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/auth/oauth2/token" {
			refreshes.Add(1)
			if r.PostFormValue("grant_type") != "refresh_token" || r.PostFormValue("refresh_token") != fmt.Sprintf("rt-%d", 1) {
				t.Errorf("token request form = %v", r.PostForm)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  newAccess,
				"token_type":    "Bearer",
				"expires_in":    900,
				"refresh_token": fmt.Sprintf("rt-%d", 2),
				"scope":         "offline_access api:monitors:read",
			})
			return
		}
		switch r.Header.Get("Authorization") {
		case "Bearer " + newAccess:
			w.Write([]byte(`{"items":[]}`))
		case "Bearer " + oldAccess:
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			w.WriteHeader(401)
			w.Write([]byte(`{"message":"expired","data":{"code":"unauthorized"}}`))
		default:
			w.WriteHeader(401)
		}
	}))
	t.Cleanup(srv.Close)
	sys := testSystem(t)
	seedSignIn(t, sys.store, srv.URL, oldAccess, time.Now().Add(10*time.Minute))
	if _, _, err := runCLIWith(t, loopEnv(srv.URL), sys, "websites", "list", "--json"); err != nil {
		t.Fatalf("err = %v", err)
	}
	if refreshes.Load() != 1 {
		t.Errorf("refreshes = %d, want 1", refreshes.Load())
	}
	if got := storedRefresh(t, sys.store, srv.URL); got != fmt.Sprintf("rt-%d", 2) {
		t.Errorf("stored refresh token = %q, want the rotated one", got)
	}
}

func TestAuthStatusBrowserSignIn(t *testing.T) {
	access := fakeAccess("user-1", 1)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/api/organization" || r.Header.Get("Authorization") != "Bearer "+access {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":1,"name":"Acme\u001b[31m"}`))
	}))
	t.Cleanup(srv.Close)
	sys := testSystem(t)
	seedSignIn(t, sys.store, srv.URL, access, time.Now().Add(10*time.Minute))
	out, _, err := runCLIWith(t, loopEnv(srv.URL), sys, "auth", "status")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"Token: browser sign-in (stored in the system keyring)", "Organization:  Acme[31m", "user-1", "Scopes:", "api:monitors:read", "Access token:", "Sign-in ends:", "30 days", "7 days"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	if strings.ContainsRune(out, 0x1b) || strings.Contains(out, "offline_access") {
		t.Errorf("unsanitised or unfiltered output: %q", out)
	}
	if hasSixCharSubstring(out, access) {
		t.Errorf("token fragment in %q", out)
	}
	if hits.Load() != 1 {
		t.Errorf("server hits = %d, want 1", hits.Load())
	}
}

func TestAuthStatusBothSources(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	sys := testSystem(t)
	seedSignIn(t, sys.store, srv.URL, fakeAccess("user-1", 1), time.Now().Add(10*time.Minute))
	env := loopEnv(srv.URL)
	env["UPTIMEIFY_TOKEN"] = "wsm_x"
	out, _, err := runCLIWith(t, env, sys, "auth", "status")
	if err != nil || !strings.Contains(out, "takes precedence") || strings.Contains(out, "Organization") {
		t.Errorf("out = %q, err = %v", out, err)
	}
	if hits.Load() != 0 {
		t.Errorf("server hits = %d, want 0", hits.Load())
	}
}

func TestAuthStatusNoKeyring(t *testing.T) {
	sys := testSystem(t)
	sys.store.(*memStore).getErr = fmt.Errorf("%w: dbus", auth.ErrNoKeyring)
	out, _, err := runCLIWith(t, nil, sys, "auth", "status")
	if err != nil || !strings.Contains(out, "Token: not set (no system keyring available") {
		t.Errorf("out = %q, err = %v", out, err)
	}
}

func TestPrintErrorHint(t *testing.T) {
	var b bytes.Buffer
	printError(&b, &client.APIError{Status: 403, Code: "cliScopeForbidden", Hint: "h\x1b"})
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "Error: ") || lines[1] != "Hint: h" {
		t.Errorf("printed %q", b.String())
	}
}

func TestHintPrintedForScopeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		w.Write([]byte(`{"message":"This CLI sign-in lacks the scope api:monitors:write. Sign in again and grant it.","data":{"code":"cliScopeForbidden","requiredScope":"api:monitors:write"}}`))
	}))
	t.Cleanup(srv.Close)
	env := loopEnv(srv.URL)
	env["UPTIMEIFY_TOKEN"] = "wsm_x"
	_, _, err := runCLI(t, env, "websites", "list")
	if exitCode(err) != clierr.Auth {
		t.Fatalf("err = %v, exit %d", err, exitCode(err))
	}
	var b bytes.Buffer
	printError(&b, err)
	if !strings.Contains(b.String(), "Hint: ") || !strings.Contains(b.String(), "uptimeify auth login --scope api:monitors:write") {
		t.Errorf("printed %q", b.String())
	}
}

func TestAuthStatusJSONHasNoSecrets(t *testing.T) {
	access := fakeAccess("user-1", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":1,"name":"Acme"}`))
	}))
	t.Cleanup(srv.Close)
	sys := testSystem(t)
	seedSignIn(t, sys.store, srv.URL, access, time.Now().Add(10*time.Minute))
	for _, args := range [][]string{{"auth", "status", "--json"}, {"auth", "status"}} {
		out, _, err := runCLIWith(t, loopEnv(srv.URL), sys, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		for _, secret := range []string{access, "rt-1"} {
			if hasSixCharSubstring(out, secret) {
				t.Errorf("%v: secret fragment in %q", args, out)
			}
		}
	}
	out, _, _ := runCLIWith(t, loopEnv(srv.URL), sys, "auth", "status", "--json")
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got["source"] != "browser" || got["organization"] != "Acme" || got["deviceName"] == "" {
		t.Errorf("json = %v", got)
	}
}

func TestPrintErrorWriteScopeHint(t *testing.T) {
	var b bytes.Buffer
	printError(&b, &client.APIError{Status: 403, Code: "cliScopeForbidden", RequiredScope: "api:monitors:write", Hint: "run auth login --scope api:monitors:write"})
	if !strings.Contains(b.String(), "auth login --write") {
		t.Errorf("printed %q", b.String())
	}
	b.Reset()
	printError(&b, &client.APIError{Status: 403, Code: "cliScopeForbidden", RequiredScope: "api:users:write", Hint: "x"})
	if strings.Contains(b.String(), "--write") {
		t.Errorf("separate scope got the --write hint: %q", b.String())
	}
}
