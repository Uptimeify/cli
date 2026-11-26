package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptimeify/cli/internal/auth"
	"github.com/uptimeify/cli/internal/clierr"
)

// testCode is the authorization code the fake server accepts.
var testCode = "code-" + "1"

// syncBuffer is a bytes.Buffer that the command and the test may use at the same time.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// loginServer is a slim stand-in for the OAuth endpoints of the server. The full fake with
// rotation lives in internal/auth; test helpers cannot be shared across packages.
type loginServer struct {
	srv          *httptest.Server
	hits         atomic.Int32
	revokes      atomic.Int32
	revokeStatus atomic.Int32
}

func newLoginServer(t *testing.T) *loginServer {
	s := &loginServer{}
	s.revokeStatus.Store(http.StatusOK)
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/oauth/cli/clients":
			if r.Method != http.MethodPost || r.Header.Get("Origin") != "" {
				t.Errorf("registration: method %s, Origin %q", r.Method, r.Header.Get("Origin"))
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"client_id":        testClientID(),
				"redirect_uri":     "http://127.0.0.1/callback",
				"resource":         "http://" + r.Host + "/api/cli",
				"scopes_supported": auth.AllScopes,
			})
		case "/api/auth/oauth2/token":
			if r.PostFormValue("grant_type") != "authorization_code" || r.PostFormValue("code") != testCode {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_grant","error_description":"invalid authorization code"}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  fakeAccess("user-1", 1),
				"token_type":    "Bearer",
				"expires_in":    900,
				"refresh_token": fmt.Sprintf("rt-%d", 2),
				"scope":         "offline_access api:monitors:read",
			})
		case "/api/auth/oauth2/revoke":
			s.revokes.Add(1)
			if r.PostFormValue("token") != fmt.Sprintf("rt-%d", 1) || r.PostFormValue("token_type_hint") != "refresh_token" || r.PostFormValue("client_id") != testClientID() {
				t.Errorf("revoke form = %v", r.PostForm)
			}
			w.WriteHeader(int(s.revokeStatus.Load()))
			w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

var authorizeAddress = regexp.MustCompile(`http\S+/api/auth/oauth2/authorize\?\S+`)

// loginAndComplete runs `auth login --no-browser` and plays the browser: it reads the address from
// stderr and calls the redirect URI with the code, as the consent page would.
func loginAndComplete(t *testing.T, env map[string]string, sys system, args ...string) (string, string, error) {
	t.Helper()
	var out bytes.Buffer
	var errOut syncBuffer
	no := func() bool { return false }
	root := newRoot(func(k string) string { return env[k] }, &out, &errOut, strings.NewReader(""), no, no, sys)
	root.SetArgs(append([]string{"auth", "login", "--no-browser"}, args...))
	done := make(chan error, 1)
	go func() { done <- root.Execute() }()

	deadline := time.Now().Add(10 * time.Second)
	addr := ""
	for addr == "" {
		select {
		case err := <-done:
			return out.String(), errOut.String(), err
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no authorize address on stderr: %q", errOut.String())
		}
		addr = authorizeAddress.FindString(errOut.String())
		time.Sleep(10 * time.Millisecond)
	}
	u, err := url.Parse(addr)
	if err != nil {
		t.Fatalf("address %q: %v", addr, err)
	}
	q := u.Query()
	redirect := q.Get("redirect_uri")
	if !regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]+/callback$`).MatchString(redirect) {
		t.Fatalf("redirect_uri = %q", redirect)
	}
	res, err := http.Get(redirect + "?code=" + url.QueryEscape(testCode) + "&state=" + url.QueryEscape(q.Get("state")))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	res.Body.Close()
	select {
	case err := <-done:
		return out.String(), errOut.String(), err
	case <-time.After(10 * time.Second):
		t.Fatal("auth login did not finish after the callback")
		return "", "", nil
	}
}

func TestLoginCommandNoBrowser(t *testing.T) {
	ls := newLoginServer(t)
	sys := testSystem(t)
	out, errOut, err := loginAndComplete(t, loopEnv(ls.srv.URL), sys)
	if err != nil {
		t.Fatalf("err = %v, stderr %q", err, errOut)
	}
	if !strings.Contains(out, "Signed in to "+ls.srv.URL+` as device "uptimeify CLI on testhost".`) || !strings.Contains(out, "Scopes: api:monitors:read") {
		t.Errorf("out = %q", out)
	}
	if strings.Contains(out, "offline_access") {
		t.Errorf("offline_access printed: %q", out)
	}
	if !strings.Contains(errOut, "Open this address") || strings.Contains(errOut, testCode) {
		t.Errorf("stderr = %q", errOut)
	}
	if got := storedRefresh(t, sys.store, ls.srv.URL); got != fmt.Sprintf("rt-%d", 2) {
		t.Errorf("stored refresh token = %q", got)
	}
	if strings.Contains(errOut, "UPTIMEIFY_TOKEN is set") {
		t.Errorf("note printed without UPTIMEIFY_TOKEN: %q", errOut)
	}
}

func TestLoginCommandUnknownScope(t *testing.T) {
	ls := newLoginServer(t)
	_, _, err := runCLI(t, loopEnv(ls.srv.URL), "auth", "login", "--no-browser", "--scope", "api:nope:read")
	if exitCode(err) != clierr.Usage || err == nil || !strings.Contains(err.Error(), "api:nope:read") {
		t.Errorf("err = %v, exit %d", err, exitCode(err))
	}
	if ls.hits.Load() != 0 {
		t.Errorf("server hits = %d, want 0", ls.hits.Load())
	}
}

func TestLoginCommandRefusesWithEnvToken(t *testing.T) {
	ls := newLoginServer(t)
	env := loopEnv(ls.srv.URL)
	env["UPTIMEIFY_TOKEN"] = "wsm_x"
	sys := testSystem(t)
	_, _, err := runCLIWith(t, env, sys, "auth", "login", "--no-browser")
	if exitCode(err) != clierr.Usage || err == nil || !strings.Contains(err.Error(), "UPTIMEIFY_TOKEN is set") {
		t.Errorf("err = %v, exit %d", err, exitCode(err))
	}
	if ls.hits.Load() != 0 || sys.store.(*memStore).count() != 0 {
		t.Errorf("hits = %d, store entries = %d, want 0 and 0", ls.hits.Load(), sys.store.(*memStore).count())
	}
}

func authorizeScopes(t *testing.T, errOut string) []string {
	t.Helper()
	u, err := url.Parse(authorizeAddress.FindString(errOut))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(u.Query().Get("scope"))
}

func TestLoginScopesInAuthorizeAddress(t *testing.T) {
	has := func(l []string, s string) bool {
		for _, x := range l {
			if x == s {
				return true
			}
		}
		return false
	}
	ls := newLoginServer(t)
	_, errOut, err := loginAndComplete(t, loopEnv(ls.srv.URL), testSystem(t))
	if err != nil {
		t.Fatal(err)
	}
	def := authorizeScopes(t, errOut)
	if !has(def, "offline_access") || !has(def, "api:monitors:read") || has(def, "api:monitors:write") || has(def, "api:users:read") {
		t.Errorf("default scopes = %v", def)
	}
	_, errOut, err = loginAndComplete(t, loopEnv(ls.srv.URL), testSystem(t), "--write", "--scope", "api:users:read", "--scope", "api:billing:write", "--device-name", "my laptop")
	if err != nil {
		t.Fatal(err)
	}
	got := authorizeScopes(t, errOut)
	for _, want := range []string{"offline_access", "api:monitors:read", "api:monitors:write", "api:users:read", "api:billing:write"} {
		if !has(got, want) {
			t.Errorf("scopes %v lack %s", got, want)
		}
	}
	if has(got, "api:users:write") || has(got, "api:audit:read") {
		t.Errorf("unrequested scope in %v", got)
	}
}

func TestLoginBadDeviceNameSendsNothing(t *testing.T) {
	ls := newLoginServer(t)
	for _, name := range []string{strings.Repeat("a", 65), "bad\x1bname", "   "} {
		_, _, err := runCLI(t, loopEnv(ls.srv.URL), "auth", "login", "--no-browser", "--device-name", name)
		if exitCode(err) != clierr.Usage || err == nil {
			t.Errorf("name %q: err = %v, exit %d", name, err, exitCode(err))
		}
	}
	if ls.hits.Load() != 0 {
		t.Errorf("server hits = %d, want 0", ls.hits.Load())
	}
}

func TestLoginCustomDeviceName(t *testing.T) {
	ls := newLoginServer(t)
	out, _, err := loginAndComplete(t, loopEnv(ls.srv.URL), testSystem(t), "--device-name", "build box")
	if err != nil || !strings.Contains(out, `as device "build box"`) {
		t.Errorf("out = %q, err = %v", out, err)
	}
}

func TestLogoutCommand(t *testing.T) {
	ls := newLoginServer(t)
	env := loopEnv(ls.srv.URL)
	sys := testSystem(t)
	st := sys.store.(*memStore)

	seedSignIn(t, st, ls.srv.URL, fakeAccess("user-1", 1), time.Now().Add(10*time.Minute))
	out, _, err := runCLIWith(t, env, sys, "auth", "logout")
	if err != nil || out != "Signed out of "+ls.srv.URL+". The server revoked the sign-in.\n" || st.count() != 0 {
		t.Errorf("revoked: out = %q, err = %v, entries %d", out, err, st.count())
	}

	ls.revokeStatus.Store(http.StatusBadRequest)
	seedSignIn(t, st, ls.srv.URL, fakeAccess("user-1", 1), time.Now().Add(10*time.Minute))
	out, _, err = runCLIWith(t, env, sys, "auth", "logout")
	if err != nil || !strings.Contains(out, "did not confirm the revocation") || !strings.Contains(out, `disconnect the device "uptimeify CLI on testhost"`) || st.count() != 0 {
		t.Errorf("not revoked: out = %q, err = %v, entries %d", out, err, st.count())
	}

	out, _, err = runCLIWith(t, env, sys, "auth", "logout")
	if err != nil || out != "Not signed in to "+ls.srv.URL+".\n" {
		t.Errorf("empty: out = %q, err = %v", out, err)
	}
	if ls.revokes.Load() != 2 {
		t.Errorf("revocations = %d, want 2", ls.revokes.Load())
	}
}

func TestLoginHelpListsScopes(t *testing.T) {
	out, _, err := runCLI(t, nil, "auth", "login", "--help")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"api:billing:write", "api:statuspage-subscribers:read", "--no-browser", "--scope", "--write", "--device-name", "consent page"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q: %q", want, out)
		}
	}
}

// The generator reserves "auth"; /api/auth/* becomes "api-auth". Neither the top level nor the
// auth group may hold a name twice, and the group holds exactly the hand-written commands.
func TestAuthGroupHasNoGeneratedCollision(t *testing.T) {
	root := testRoot(t)
	seen := map[string]bool{}
	for _, c := range root.Commands() {
		if seen[c.Name()] {
			t.Errorf("duplicate top-level command %q", c.Name())
		}
		seen[c.Name()] = true
	}
	var authKids []string
	for _, c := range root.Commands() {
		if c.Name() == "auth" {
			for _, k := range c.Commands() {
				authKids = append(authKids, k.Name())
			}
		}
	}
	if got := strings.Join(authKids, ","); got != "login,logout,status" {
		t.Errorf("auth commands = %s", got)
	}
}
