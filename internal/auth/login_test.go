package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
)

// fakeJWT builds an unsigned access token with the given claims. It is put together at run time,
// so no token-shaped literal sits in the repository.
func fakeJWT(claims map[string]any) string {
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "none", "typ": "at+jwt"})
	payload, _ := json.Marshal(claims)
	return enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + "." + "sig"
}

// fakeOAuthServer imitates the server side of the browser sign-in: device registration, code
// exchange with PKCE, refresh rotation without grace (a second use of a rotated refresh token
// kills the whole family, like cli-oauth-token.ts) and revocation.
type fakeOAuthServer struct {
	srv *httptest.Server
	mu  sync.Mutex

	registrations, exchanges, refreshes, revokes int
	refresh                                      string          // the one valid refresh token; "" when the family is dead
	rotated                                      map[string]bool // refresh tokens that were used once
	clientID                                     string
	// failRefresh sees every refresh request first; returning true means it has answered.
	failRefresh func(w http.ResponseWriter) bool

	requests, invalidGrants int
	counter                 int
	challenge, redirectURI  string
	code                    string
	authorizeScope          string
	tokenScope              string // scope in token answers; "" echoes the authorize scope
	omitScope               bool   // token answers carry no scope at all
	failExchange            bool   // the code exchange answers invalid_grant
	refreshDelay            time.Duration
	revokeStatus            int // 0 means 200
	revokeForm              url.Values
}

type fakeStats struct {
	requests, registrations, exchanges, refreshes, revokes, invalidGrants int
}

func newFakeOAuthServer(t *testing.T) *fakeOAuthServer {
	t.Helper()
	fs := &fakeOAuthServer{rotated: map[string]bool{}}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		fs.requests++
		fs.mu.Unlock()
		if r.Method != http.MethodPost {
			t.Errorf("fake OAuth server: unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case registerPath:
			fs.register(w)
		case tokenPath:
			fs.token(t, w, r)
		case revokePath:
			fs.revoke(w, r)
		default:
			t.Errorf("fake OAuth server: unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *fakeOAuthServer) stats() fakeStats {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fakeStats{
		requests:      fs.requests,
		registrations: fs.registrations,
		exchanges:     fs.exchanges,
		refreshes:     fs.refreshes,
		revokes:       fs.revokes,
		invalidGrants: fs.invalidGrants,
	}
}

func fakeWriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func fakeOAuthError(w http.ResponseWriter, code, description string) {
	fakeWriteJSON(w, http.StatusBadRequest, map[string]string{"error": code, "error_description": description})
}

func (fs *fakeOAuthServer) register(w http.ResponseWriter) {
	fs.mu.Lock()
	fs.registrations++
	fs.clientID = "ucli_" + strings.Repeat("c", 32)
	id := fs.clientID
	fs.mu.Unlock()
	fakeWriteJSON(w, http.StatusCreated, map[string]any{
		"client_id":        id,
		"redirect_uri":     RegisteredRedirectURI,
		"resource":         fs.srv.URL + ResourcePath,
		"scopes_supported": AllScopes,
	})
}

// issueLocked hands out a new token pair. fs.mu must be held.
func (fs *fakeOAuthServer) issueLocked() map[string]any {
	fs.counter++
	fs.refresh = fmt.Sprintf("rt-%d", fs.counter)
	body := map[string]any{
		"access_token":  fakeJWT(map[string]any{"sub": "user-1", "scope": "api:monitors:read", "n": fs.counter}),
		"token_type":    "Bearer",
		"expires_in":    900,
		"refresh_token": fs.refresh,
	}
	if !fs.omitScope {
		scope := fs.tokenScope
		if scope == "" {
			scope = fs.authorizeScope
		}
		body["scope"] = scope
	}
	return body
}

func (fs *fakeOAuthServer) token(t *testing.T, w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		t.Errorf("fake OAuth server: form: %v", err)
		fakeOAuthError(w, "invalid_request", "bad form")
		return
	}
	form := r.PostForm
	fs.mu.Lock()
	if form.Get("client_id") != fs.clientID || form.Get("resource") != fs.srv.URL+ResourcePath {
		fs.mu.Unlock()
		t.Errorf("fake OAuth server: token request for client %q, resource %q", form.Get("client_id"), form.Get("resource"))
		fakeOAuthError(w, "invalid_client", "unknown client")
		return
	}
	switch form.Get("grant_type") {
	case "authorization_code":
		fs.exchanges++
		sum := sha256.Sum256([]byte(form.Get("code_verifier")))
		ok := !fs.failExchange && fs.code != "" && form.Get("code") == fs.code &&
			form.Get("redirect_uri") == fs.redirectURI &&
			base64.RawURLEncoding.EncodeToString(sum[:]) == fs.challenge
		fs.code = "" // a code is good for one exchange
		if !ok {
			fs.mu.Unlock()
			fakeOAuthError(w, "invalid_grant", "invalid authorization code")
			return
		}
		body := fs.issueLocked()
		fs.mu.Unlock()
		fakeWriteJSON(w, http.StatusOK, body)
	case "refresh_token":
		fs.refreshes++
		fail, delay := fs.failRefresh, fs.refreshDelay
		fs.mu.Unlock()
		if fail != nil && fail(w) {
			return
		}
		fs.mu.Lock()
		presented := form.Get("refresh_token")
		if presented == "" || presented != fs.refresh {
			if fs.rotated[presented] {
				fs.refresh = "" // second use of a rotated token: the whole family dies
			}
			fs.invalidGrants++
			fs.mu.Unlock()
			fakeOAuthError(w, "invalid_grant", "invalid refresh token")
			return
		}
		fs.rotated[presented] = true
		body := fs.issueLocked()
		fs.mu.Unlock()
		time.Sleep(delay)
		fakeWriteJSON(w, http.StatusOK, body)
	default:
		fs.mu.Unlock()
		t.Errorf("fake OAuth server: unexpected grant_type %q", form.Get("grant_type"))
		fakeOAuthError(w, "unsupported_grant_type", "")
	}
}

func (fs *fakeOAuthServer) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	fs.mu.Lock()
	fs.revokes++
	fs.revokeForm = r.PostForm
	status := fs.revokeStatus
	if status == 0 {
		status = http.StatusOK
	}
	if status == http.StatusOK {
		fs.refresh = ""
	}
	fs.mu.Unlock()
	w.WriteHeader(status)
}

var fakeRedirectPattern = regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]+/callback$`)

// authorize plays the browser and the consent page: it checks the address the CLI built,
// remembers the PKCE challenge like the server and returns where the browser would be sent.
func (fs *fakeOAuthServer) authorize(t *testing.T, addr string) (redirectURI, code, state string) {
	t.Helper()
	u, err := url.Parse(addr)
	if err != nil {
		t.Errorf("authorize address: %v", err)
		return "", "", ""
	}
	q := u.Query()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if u.Path != authorizePath {
		t.Errorf("authorize path = %q", u.Path)
	}
	if q.Get("client_id") != fs.clientID {
		t.Errorf("client_id = %q, want %q", q.Get("client_id"), fs.clientID)
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("response_type %q, code_challenge_method %q", q.Get("response_type"), q.Get("code_challenge_method"))
	}
	if q.Get("resource") != fs.srv.URL+ResourcePath {
		t.Errorf("resource = %q", q.Get("resource"))
	}
	if !fakeRedirectPattern.MatchString(q.Get("redirect_uri")) {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if !strings.HasPrefix(q.Get("scope"), "offline_access ") {
		t.Errorf("scope = %q", q.Get("scope"))
	}
	if q.Get("state") == "" || q.Get("code_challenge") == "" {
		t.Error("state or code_challenge missing")
	}
	fs.challenge = q.Get("code_challenge")
	fs.redirectURI = q.Get("redirect_uri")
	fs.authorizeScope = q.Get("scope")
	fs.counter++
	fs.code = fmt.Sprintf("code-%d", fs.counter)
	return fs.redirectURI, fs.code, q.Get("state")
}

// hitCallback is the browser following the redirect to the loopback receiver.
func hitCallback(u string) {
	c := &http.Client{Timeout: 5 * time.Second}
	res, err := c.Get(u)
	if err == nil {
		_ = res.Body.Close()
	}
}

// browserFor approves every sign-in at once, like a user who clicks "Allow".
func browserFor(t *testing.T, srv *fakeOAuthServer) func(string) error {
	return func(addr string) error {
		redirect, code, state := srv.authorize(t, addr)
		go hitCallback(redirect + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state))
		return nil
	}
}

func testManager(t *testing.T, srv *fakeOAuthServer, st Store) *Manager {
	t.Helper()
	return &Manager{
		Origin:   srv.srv.URL,
		Store:    st,
		OAuth:    &OAuth{Origin: srv.srv.URL, UserAgent: "test"},
		LockDir:  t.TempDir(),
		Hostname: func() (string, error) { return "testhost", nil },
	}
}

func mustCredentials(t *testing.T, st Store, origin string) *Credentials {
	t.Helper()
	c, err := loadCredentials(st, origin)
	if err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}
	return c
}

func mustAccess(t *testing.T, st Store, origin string) *Access {
	t.Helper()
	a, err := loadAccess(st, origin)
	if err != nil {
		t.Fatalf("loadAccess: %v", err)
	}
	return a
}

// loginBuffer is an Out that the test can read while Login writes to it.
type loginBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *loginBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *loginBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var loginAddressLine = regexp.MustCompile(`(?m)^  (http://\S+)$`)

func waitForAuthorizeURL(t *testing.T, out *loginBuffer) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := loginAddressLine.FindStringSubmatch(out.String()); m != nil {
			return m[1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the authorize address never appeared on Out")
	return ""
}

func TestLoginStoresSignIn(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	m := testManager(t, fs, st)
	cred, err := m.Login(context.Background(), LoginOptions{OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	got := mustCredentials(t, st, m.Origin)
	if got.ClientID != "ucli_"+strings.Repeat("c", 32) || got.ClientID != cred.ClientID {
		t.Errorf("ClientID = %q", got.ClientID)
	}
	if got.RefreshToken == "" || got.GrantStartedAt.IsZero() || got.RefreshedAt.IsZero() {
		t.Errorf("stored sign-in incomplete: refresh set %v, grant %v, refreshed %v", got.RefreshToken != "", got.GrantStartedAt, got.RefreshedAt)
	}
	if got.DeviceName != "uptimeify CLI on testhost" {
		t.Errorf("DeviceName = %q", got.DeviceName)
	}
	a := mustAccess(t, st, m.Origin)
	if a.Token == "" || !a.ExpiresAt.After(time.Now().Add(14*time.Minute)) {
		t.Errorf("access entry: token set %v, expires %v", a.Token != "", a.ExpiresAt)
	}
	s := fs.stats()
	if s.registrations != 1 || s.exchanges != 1 {
		t.Errorf("registrations %d, exchanges %d, want 1 and 1", s.registrations, s.exchanges)
	}
	fs.mu.Lock()
	scope := fs.authorizeScope
	fs.mu.Unlock()
	if want := "offline_access " + strings.Join(DefaultScopes(), " "); scope != want {
		t.Errorf("authorize scope = %q, want %q", scope, want)
	}
}

func TestLoginAddsRequestedScopes(t *testing.T) {
	fs := newFakeOAuthServer(t)
	m := testManager(t, fs, &memStore{})
	_, err := m.Login(context.Background(), LoginOptions{Scopes: []string{"api:billing:write"}, OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	fs.mu.Lock()
	scope := fs.authorizeScope
	fs.mu.Unlock()
	if !strings.Contains(" "+scope+" ", " api:billing:write ") {
		t.Errorf("authorize scope = %q, want api:billing:write in it", scope)
	}
}

func TestLoginUnknownScopeSendsNothing(t *testing.T) {
	fs := newFakeOAuthServer(t)
	m := testManager(t, fs, &memStore{})
	_, err := m.Login(context.Background(), LoginOptions{Scopes: []string{"api:bogus:read"}, OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second})
	if clierr.ExitCode(err) != clierr.Usage {
		t.Fatalf("err = %v, exit %d, want 2", err, clierr.ExitCode(err))
	}
	if got := fs.stats().requests; got != 0 {
		t.Errorf("server saw %d requests, want 0", got)
	}
}

func TestLoginWithoutKeyring(t *testing.T) {
	fs := newFakeOAuthServer(t)
	m := testManager(t, fs, &memStore{getErr: fmt.Errorf("%w: dbus", ErrNoKeyring)})
	_, err := m.Login(context.Background(), LoginOptions{OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second})
	if clierr.ExitCode(err) != clierr.Auth {
		t.Fatalf("err = %v, exit %d, want 3", err, clierr.ExitCode(err))
	}
	if !strings.Contains(err.Error(), "UPTIMEIFY_TOKEN") {
		t.Errorf("err = %v, want a pointer to UPTIMEIFY_TOKEN", err)
	}
	if got := fs.stats().requests; got != 0 {
		t.Errorf("server saw %d requests, want 0", got)
	}
}

func TestLoginReusesBoundClient(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	m := testManager(t, fs, st)
	opts := LoginOptions{OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second}
	if _, err := m.Login(context.Background(), opts); err != nil {
		t.Fatalf("first Login: %v", err)
	}
	first := mustCredentials(t, st, m.Origin)
	if _, err := m.Login(context.Background(), opts); err != nil {
		t.Fatalf("second Login: %v", err)
	}
	second := mustCredentials(t, st, m.Origin)
	if s := fs.stats(); s.registrations != 1 || s.exchanges != 2 {
		t.Errorf("registrations %d, exchanges %d, want 1 and 2", s.registrations, s.exchanges)
	}
	if second.ClientID != first.ClientID {
		t.Errorf("client id changed")
	}
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Errorf("second Login did not store a new refresh token")
	}
}

func TestLoginReusesFreshUnboundRegistration(t *testing.T) {
	cases := []struct {
		name         string
		age          time.Duration
		wantRegister int
	}{
		{"registered 10 minutes ago", 10 * time.Minute, 0},
		{"registered 15 minutes ago", 15 * time.Minute, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := newFakeOAuthServer(t)
			st := &memStore{}
			m := testManager(t, fs, st)
			old := "ucli_" + strings.Repeat("o", 32)
			fs.mu.Lock()
			fs.clientID = old
			fs.mu.Unlock()
			seed := &Credentials{ClientID: old, RegisteredAt: time.Now().Add(-c.age), DeviceName: "uptimeify CLI on testhost"}
			if err := saveCredentials(st, m.Origin, seed); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Login(context.Background(), LoginOptions{OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second}); err != nil {
				t.Fatalf("Login: %v", err)
			}
			if got := fs.stats().registrations; got != c.wantRegister {
				t.Errorf("registrations = %d, want %d", got, c.wantRegister)
			}
			want := old
			if c.wantRegister == 1 {
				want = "ucli_" + strings.Repeat("c", 32)
			}
			if got := mustCredentials(t, st, m.Origin); got.ClientID != want || got.RefreshToken == "" {
				t.Errorf("stored client id %q (refresh set %v), want %q", got.ClientID, got.RefreshToken != "", want)
			}
		})
	}
}

func TestLoginWithoutBrowserPrintsAddress(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	m := testManager(t, fs, st)
	out := &loginBuffer{}
	done := make(chan error, 1)
	go func() {
		_, err := m.Login(context.Background(), LoginOptions{Out: out, Timeout: 10 * time.Second})
		done <- err
	}()
	addr := waitForAuthorizeURL(t, out)
	redirect, code, state := fs.authorize(t, addr)
	hitCallback(redirect + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state))
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Login did not return")
	}
	text := out.String()
	if !strings.Contains(text, "Open this address in a browser on this computer:") {
		t.Errorf("Out = %q, want the address prompt", text)
	}
	if strings.Contains(text, "Your browser should open") {
		t.Errorf("Out promises a browser although none was asked for")
	}
	if strings.Contains(text, code) {
		t.Errorf("Out contains the authorization code")
	}
	if a := mustAccess(t, st, m.Origin); strings.Contains(text, a.Token) {
		t.Errorf("Out contains the access token")
	}
	if c := mustCredentials(t, st, m.Origin); strings.Contains(text, c.RefreshToken) {
		t.Errorf("Out contains the refresh token")
	}
}

func TestLoginBrowserFailureStillWaits(t *testing.T) {
	fs := newFakeOAuthServer(t)
	m := testManager(t, fs, &memStore{})
	out := &loginBuffer{}
	approve := browserFor(t, fs)
	opener := func(addr string) error {
		_ = approve(addr)
		return errors.New("no display")
	}
	if _, err := m.Login(context.Background(), LoginOptions{OpenBrowser: opener, Out: out, Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !strings.Contains(out.String(), "Could not open a browser (no display). Open the address above yourself.") {
		t.Errorf("Out = %q", out.String())
	}
}

func TestLoginDeclined(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	m := testManager(t, fs, st)
	opener := func(addr string) error {
		redirect, _, state := fs.authorize(t, addr)
		go hitCallback(redirect + "?error=access_denied&state=" + url.QueryEscape(state))
		return nil
	}
	_, err := m.Login(context.Background(), LoginOptions{OpenBrowser: opener, Timeout: 10 * time.Second})
	if clierr.ExitCode(err) != clierr.Auth {
		t.Fatalf("err = %v, exit %d, want 3", err, clierr.ExitCode(err))
	}
	got := mustCredentials(t, st, m.Origin)
	if got.ClientID == "" || got.RefreshToken != "" {
		t.Errorf("stored client id %q, refresh set %v; want the client id kept and no refresh token", got.ClientID, got.RefreshToken != "")
	}
	if n := fs.stats().exchanges; n != 0 {
		t.Errorf("exchanges = %d, want 0", n)
	}
}

func TestLoginExchangeRefused(t *testing.T) {
	fs := newFakeOAuthServer(t)
	fs.failExchange = true
	st := &memStore{}
	m := testManager(t, fs, st)
	_, err := m.Login(context.Background(), LoginOptions{OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second})
	if clierr.ExitCode(err) != clierr.Auth || !strings.Contains(err.Error(), "auth login") {
		t.Fatalf("err = %v, exit %d, want 3 with a pointer to auth login", err, clierr.ExitCode(err))
	}
	if got := mustCredentials(t, st, m.Origin); got.RefreshToken != "" {
		t.Errorf("a refresh token was stored after a refused exchange")
	}
}

func TestLoginTimeout(t *testing.T) {
	fs := newFakeOAuthServer(t)
	m := testManager(t, fs, &memStore{})
	_, err := m.Login(context.Background(), LoginOptions{OpenBrowser: func(string) error { return nil }, Timeout: 100 * time.Millisecond})
	if clierr.ExitCode(err) != clierr.Auth || !strings.Contains(err.Error(), "within 5 minutes") {
		t.Fatalf("err = %v, exit %d, want 3 and 'within 5 minutes'", err, clierr.ExitCode(err))
	}
}

func TestLoginKeepsServerScope(t *testing.T) {
	fs := newFakeOAuthServer(t)
	fs.tokenScope = "offline_access api:monitors:read"
	st := &memStore{}
	m := testManager(t, fs, st)
	if _, err := m.Login(context.Background(), LoginOptions{OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got := mustCredentials(t, st, m.Origin).Scope; got != "offline_access api:monitors:read" {
		t.Errorf("Scope = %q", got)
	}

	// Without scope in the token answer the scope claim of the access token is kept.
	fs2 := newFakeOAuthServer(t)
	fs2.omitScope = true
	st2 := &memStore{}
	m2 := testManager(t, fs2, st2)
	if _, err := m2.Login(context.Background(), LoginOptions{OpenBrowser: browserFor(t, fs2), Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got := mustCredentials(t, st2, m2.Origin).Scope; got != "api:monitors:read" {
		t.Errorf("Scope from the JWT = %q", got)
	}
}

func TestStatus(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	m := testManager(t, fs, st)

	signed, err := m.SignedIn()
	if err != nil || signed {
		t.Fatalf("empty store: SignedIn = %v, %v; want false, nil", signed, err)
	}
	s, err := m.Status()
	if err != nil || s.SignedIn {
		t.Fatalf("empty store: Status = %+v, %v", s, err)
	}

	if _, err := m.Login(context.Background(), LoginOptions{OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	signed, err = m.SignedIn()
	if err != nil || !signed {
		t.Fatalf("after Login: SignedIn = %v, %v", signed, err)
	}
	s, err = m.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !s.SignedIn || s.UserID != "user-1" || s.DeviceName != "uptimeify CLI on testhost" {
		t.Errorf("Status = %+v", s)
	}
	if s.AccessExpiresAt.IsZero() || s.GrantStartedAt.IsZero() || s.RefreshedAt.IsZero() || s.Scope == "" {
		t.Errorf("Status lacks times or scope: %+v", s)
	}
}

func TestStatusWithoutKeyring(t *testing.T) {
	fs := newFakeOAuthServer(t)
	m := testManager(t, fs, &memStore{getErr: fmt.Errorf("%w: dbus", ErrNoKeyring)})
	if _, err := m.SignedIn(); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("SignedIn err = %v, want ErrNoKeyring", err)
	}
	if _, err := m.Status(); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("Status err = %v, want ErrNoKeyring", err)
	}
}

func TestJWTClaimsNeverPanics(t *testing.T) {
	notJSON := "a." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c"
	for _, tok := range []string{"", "a.b", "a.%%%.c", notJSON} {
		if sub, scope := jwtClaims(tok); sub != "" || scope != "" {
			t.Errorf("jwtClaims(%q) = %q, %q; want empty", tok, sub, scope)
		}
	}
	sub, scope := jwtClaims(fakeJWT(map[string]any{"sub": "user-1", "scope": "api:monitors:read"}))
	if sub != "user-1" || scope != "api:monitors:read" {
		t.Errorf("jwtClaims = %q, %q", sub, scope)
	}
}

func TestLoginInvalidDeviceNameSendsNothing(t *testing.T) {
	fs := newFakeOAuthServer(t)
	m := testManager(t, fs, &memStore{})
	for _, name := range []string{strings.Repeat("n", 65), "bad‮name", "  "} {
		_, err := m.Login(context.Background(), LoginOptions{DeviceName: name, OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second})
		if clierr.ExitCode(err) != clierr.Usage {
			t.Fatalf("%q: err = %v, exit %d, want 2", name, err, clierr.ExitCode(err))
		}
	}
	if got := fs.stats().requests; got != 0 {
		t.Errorf("server saw %d requests, want 0", got)
	}
}

func TestLoginUsesGivenDeviceName(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	m := testManager(t, fs, st)
	if _, err := m.Login(context.Background(), LoginOptions{DeviceName: "my laptop", OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if got := mustCredentials(t, st, m.Origin).DeviceName; got != "my laptop" {
		t.Errorf("device name = %q", got)
	}
}

func TestLoginLockFailureSendsNothing(t *testing.T) {
	fs := newFakeOAuthServer(t)
	m := testManager(t, fs, &memStore{})
	// A file where the cache directory should be: creating the lock directory fails.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m.LockDir = blocker
	if _, err := m.Login(context.Background(), LoginOptions{OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second}); err == nil {
		t.Fatal("login succeeded without a lock")
	}
	m.LockDir = ""
	if _, err := m.Login(context.Background(), LoginOptions{OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second}); err == nil {
		t.Fatal("login succeeded without a cache directory")
	}
	if got := fs.stats().requests; got != 0 {
		t.Errorf("server saw %d requests, want 0", got)
	}
}
