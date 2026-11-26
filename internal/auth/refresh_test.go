package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
)

func init() { helpers["refresh"] = refreshHelper }

// refreshHelper runs in a child process and is one CLI invocation that needs a token.
func refreshHelper() int {
	origin := os.Getenv("UPTIMEIFY_AUTH_TEST_ORIGIN")
	m := &Manager{
		Origin:  origin,
		Store:   &fileStore{dir: os.Getenv("UPTIMEIFY_AUTH_TEST_STORE")},
		OAuth:   &OAuth{Origin: origin, UserAgent: "test"},
		LockDir: os.Getenv("UPTIMEIFY_AUTH_TEST_LOCKDIR"),
	}
	tok, err := m.Token(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(tok)
	return 0
}

// seedCredentials is a bound sign-in as Login leaves it, one hour old.
func seedCredentials(now time.Time) *Credentials {
	return &Credentials{
		ClientID:       "ucli_" + strings.Repeat("s", 32),
		RegisteredAt:   now.Add(-time.Hour),
		DeviceName:     "uptimeify CLI on testhost",
		RefreshToken:   fmt.Sprintf("rt-seed-%d", 0),
		Scope:          "offline_access api:monitors:read",
		GrantStartedAt: now.Add(-time.Hour),
		RefreshedAt:    now.Add(-time.Hour),
	}
}

// signedIn stores a sign-in that fs accepts, with an access token valid until accessUntil, and
// returns a Manager whose clock stands still at now.
func signedIn(t *testing.T, fs *fakeOAuthServer, st Store, now, accessUntil time.Time) (*Manager, *Credentials) {
	t.Helper()
	m := testManager(t, fs, st)
	m.Now = func() time.Time { return now }
	cred := seedCredentials(now)
	if err := saveCredentials(st, m.Origin, cred); err != nil {
		t.Fatal(err)
	}
	if err := saveAccess(st, m.Origin, &Access{Token: fakeJWT(map[string]any{"sub": "user-1", "n": 0}), ExpiresAt: accessUntil}); err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	fs.clientID = cred.ClientID
	fs.refresh = cred.RefreshToken
	fs.mu.Unlock()
	return m, cred
}

// setOrderStore records the order of Set calls.
type setOrderStore struct {
	*memStore
	logMu sync.Mutex
	sets  []string
}

func (s *setOrderStore) Set(key, value string) error {
	s.logMu.Lock()
	s.sets = append(s.sets, key)
	s.logMu.Unlock()
	return s.memStore.Set(key, value)
}

func TestTokenUsesCachedAccess(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	now := time.Now()
	m, _ := signedIn(t, fs, st, now, now.Add(10*time.Minute))
	tok, err := m.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != mustAccess(t, st, m.Origin).Token {
		t.Error("Token did not return the stored access token")
	}
	if n := fs.stats().requests; n != 0 {
		t.Errorf("server saw %d requests, want 0", n)
	}
}

func TestTokenRefreshesNearExpiry(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	now := time.Now()
	m, old := signedIn(t, fs, st, now, now.Add(30*time.Second))
	oldAccess := mustAccess(t, st, m.Origin).Token
	tok, err := m.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if n := fs.stats().refreshes; n != 1 {
		t.Errorf("refreshes = %d, want 1", n)
	}
	cred := mustCredentials(t, st, m.Origin)
	if cred.RefreshToken == "" || cred.RefreshToken == old.RefreshToken {
		t.Error("the rotated refresh token was not stored")
	}
	if !cred.RefreshedAt.Equal(now) {
		t.Errorf("RefreshedAt = %v, want %v", cred.RefreshedAt, now)
	}
	a := mustAccess(t, st, m.Origin)
	if tok == oldAccess || a.Token != tok {
		t.Error("the new access token was not stored and returned")
	}
	if !a.ExpiresAt.Equal(now.Add(900 * time.Second)) {
		t.Errorf("ExpiresAt = %v, want now + 900 s", a.ExpiresAt)
	}
}

func TestRefreshSavesRefreshBeforeAccess(t *testing.T) {
	fs := newFakeOAuthServer(t)
	inner := &memStore{}
	now := time.Now()
	m, _ := signedIn(t, fs, inner, now, now.Add(-time.Minute))
	st := &setOrderStore{memStore: inner}
	m.Store = st
	if _, err := m.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	st.logMu.Lock()
	defer st.logMu.Unlock()
	if want := []string{credentialsKey(m.Origin), accessKey(m.Origin)}; !slices.Equal(st.sets, want) {
		t.Errorf("Set order = %q, want %q", st.sets, want)
	}
}

func TestRenewUsesTokenFromOtherProcess(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	now := time.Now()
	m, _ := signedIn(t, fs, st, now, now.Add(10*time.Minute))
	current := mustAccess(t, st, m.Origin).Token
	stale := fakeJWT(map[string]any{"sub": "user-1", "n": -1})

	tok, err := m.Renew(context.Background(), stale)
	if err != nil {
		t.Fatalf("Renew(stale): %v", err)
	}
	if tok != current {
		t.Error("Renew did not take the token another process stored")
	}
	if n := fs.stats().requests; n != 0 {
		t.Errorf("server saw %d requests, want 0", n)
	}

	tok, err = m.Renew(context.Background(), current)
	if err != nil {
		t.Fatalf("Renew(current): %v", err)
	}
	if tok == current {
		t.Error("Renew returned the rejected token")
	}
	if n := fs.stats().refreshes; n != 1 {
		t.Errorf("refreshes = %d, want 1", n)
	}
}

func TestRefreshInvalidGrantExplains(t *testing.T) {
	cases := []struct {
		name             string
		grant, refreshed time.Duration
		want             string
	}{
		{"grant older than 30 days", 31 * 24 * time.Hour, time.Hour, "30 days"},
		{"unused for 7 days", 10 * 24 * time.Hour, 8 * 24 * time.Hour, "7 days"},
		{"revoked", 24 * time.Hour, time.Hour, "revoked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := newFakeOAuthServer(t)
			st := &memStore{}
			now := time.Now()
			m, cred := signedIn(t, fs, st, now, now.Add(-time.Minute))
			cred.GrantStartedAt = now.Add(-c.grant)
			cred.RefreshedAt = now.Add(-c.refreshed)
			if err := saveCredentials(st, m.Origin, cred); err != nil {
				t.Fatal(err)
			}
			fs.mu.Lock()
			fs.refresh = "" // the server no longer knows this refresh token
			fs.mu.Unlock()
			_, err := m.Token(context.Background())
			if clierr.ExitCode(err) != clierr.Auth || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, exit %d, want 3 and %q", err, clierr.ExitCode(err), c.want)
			}
			if keys := st.keys(); len(keys) != 0 {
				t.Errorf("store still holds %q", keys)
			}
		})
	}
}

func TestRefreshNotSentKeepsSignIn(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	now := time.Now()
	m, cred := signedIn(t, fs, st, now, now.Add(-time.Minute))
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	m.OAuth = &OAuth{Origin: deadURL, UserAgent: "test"}
	_, err := m.Token(context.Background())
	if clierr.ExitCode(err) != clierr.General || !strings.Contains(err.Error(), "could not reach") {
		t.Fatalf("err = %v, exit %d, want 1 and 'could not reach'", err, clierr.ExitCode(err))
	}
	got := mustCredentials(t, st, m.Origin)
	if got.ClientID != cred.ClientID || got.RefreshToken != cred.RefreshToken {
		t.Error("the stored sign-in changed although the request never left")
	}
	if _, err := loadAccess(st, m.Origin); err != nil {
		t.Errorf("access entry: %v", err)
	}
}

func TestRefreshAmbiguousClearsSignIn(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter) bool{
		"connection closed after the request": func(w http.ResponseWriter) bool {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return true
		},
		"server error": func(w http.ResponseWriter) bool {
			w.WriteHeader(http.StatusInternalServerError)
			return true
		},
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			fs := newFakeOAuthServer(t)
			st := &memStore{}
			now := time.Now()
			m, _ := signedIn(t, fs, st, now, now.Add(-time.Minute))
			fs.mu.Lock()
			fs.failRefresh = fail
			fs.mu.Unlock()
			_, err := m.Token(context.Background())
			if clierr.ExitCode(err) != clierr.Auth || !strings.Contains(err.Error(), "state on the server is unknown") {
				t.Fatalf("err = %v, exit %d, want 3 and 'state on the server is unknown'", err, clierr.ExitCode(err))
			}
			if keys := st.keys(); len(keys) != 0 {
				t.Errorf("store still holds %q", keys)
			}
		})
	}
}

func TestRefreshRateLimitedKeepsSignIn(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	now := time.Now()
	m, cred := signedIn(t, fs, st, now, now.Add(-time.Minute))
	fs.mu.Lock()
	fs.failRefresh = func(w http.ResponseWriter) bool {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		return true
	}
	fs.mu.Unlock()
	_, err := m.Token(context.Background())
	if clierr.ExitCode(err) != clierr.RateLimit {
		t.Fatalf("err = %v, exit %d, want 5", err, clierr.ExitCode(err))
	}
	if got := mustCredentials(t, st, m.Origin); got.RefreshToken != cred.RefreshToken {
		t.Error("the stored sign-in changed after a rate limit")
	}
}

func TestRefreshWithoutSignIn(t *testing.T) {
	fs := newFakeOAuthServer(t)
	m := testManager(t, fs, &memStore{})
	_, err := m.Token(context.Background())
	if clierr.ExitCode(err) != clierr.Auth || !strings.Contains(err.Error(), "auth login") {
		t.Fatalf("err = %v, exit %d, want 3 and 'auth login'", err, clierr.ExitCode(err))
	}
	if n := fs.stats().requests; n != 0 {
		t.Errorf("server saw %d requests, want 0", n)
	}
}

func TestRefreshStoreFailure(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	now := time.Now()
	m, _ := signedIn(t, fs, st, now, now.Add(-time.Minute))
	st.setErr = errors.New("keyring locked")
	_, err := m.Token(context.Background())
	if clierr.ExitCode(err) != clierr.Auth || !strings.Contains(err.Error(), "did not store") {
		t.Fatalf("err = %v, exit %d, want 3 and 'did not store'", err, clierr.ExitCode(err))
	}
}

func TestNoSecretsOnDisk(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	m := testManager(t, fs, st)
	if _, err := m.Login(context.Background(), LoginOptions{OpenBrowser: browserFor(t, fs), Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := m.Renew(context.Background(), mustAccess(t, st, m.Origin).Token); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if n := fs.stats().refreshes; n != 1 {
		t.Fatalf("refreshes = %d, want 1", n)
	}
	files := 0
	err := filepath.Walk(m.LockDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			files++
			if info.Size() != 0 {
				t.Errorf("%s has %d bytes, want 0", path, info.Size())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Error("no lock file was created under LockDir")
	}
}

func TestTwoProcessesRefreshOnce(t *testing.T) {
	fs := newFakeOAuthServer(t)
	storeDir, lockDir := t.TempDir(), t.TempDir()
	st := &fileStore{dir: storeDir}
	origin := fs.srv.URL
	now := time.Now()
	cred := seedCredentials(now)
	if err := saveCredentials(st, origin, cred); err != nil {
		t.Fatal(err)
	}
	if err := saveAccess(st, origin, &Access{Token: fakeJWT(map[string]any{"sub": "user-1", "n": 0}), ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	fs.clientID = cred.ClientID
	fs.refresh = cred.RefreshToken
	fs.refreshDelay = 200 * time.Millisecond
	fs.mu.Unlock()

	env := []string{
		"UPTIMEIFY_AUTH_TEST_ORIGIN=" + origin,
		"UPTIMEIFY_AUTH_TEST_STORE=" + storeDir,
		"UPTIMEIFY_AUTH_TEST_LOCKDIR=" + lockDir,
	}
	cmds := make([]*exec.Cmd, 4)
	for i := range cmds {
		c := startHelper(t, "refresh", env...)
		if c.Process == nil {
			if err := c.Start(); err != nil {
				t.Fatalf("helper %d: %v", i, err)
			}
		}
		cmds[i] = c
	}
	outs := make([]string, len(cmds))
	for i, c := range cmds {
		err := c.Wait()
		buf, ok := c.Stdout.(*bytes.Buffer)
		if !ok {
			t.Fatalf("helper %d: stdout is %T, want *bytes.Buffer", i, c.Stdout)
		}
		if err != nil {
			t.Fatalf("helper %d: %v", i, err)
		}
		outs[i] = strings.TrimSpace(buf.String())
	}
	if outs[0] == "" {
		t.Fatal("helper 0 printed no token")
	}
	for i, o := range outs[1:] {
		if o != outs[0] {
			t.Errorf("helper %d got a different token than helper 0", i+1)
		}
	}
	if s := fs.stats(); s.refreshes != 1 || s.invalidGrants != 0 {
		t.Errorf("refreshes %d, invalid_grant %d; want 1 and 0", s.refreshes, s.invalidGrants)
	}
	if got := mustCredentials(t, st, origin); got.RefreshToken == cred.RefreshToken {
		t.Error("the rotated refresh token was not stored")
	}
}

func TestLogoutRevokesAndClears(t *testing.T) {
	fs := newFakeOAuthServer(t)
	st := &memStore{}
	now := time.Now()
	m, cred := signedIn(t, fs, st, now, now.Add(10*time.Minute))
	res, err := m.Logout(context.Background())
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !res.WasSignedIn || !res.Revoked || res.RevokeErr != nil || res.DeviceName != cred.DeviceName {
		t.Errorf("result = %+v", res)
	}
	fs.mu.Lock()
	form := fs.revokeForm
	fs.mu.Unlock()
	if form.Get("token") != cred.RefreshToken || form.Get("token_type_hint") != "refresh_token" || form.Get("client_id") != cred.ClientID {
		t.Errorf("revocation form: hint %q, client %q, token matches %v", form.Get("token_type_hint"), form.Get("client_id"), form.Get("token") == cred.RefreshToken)
	}
	if n := fs.stats().revokes; n != 1 {
		t.Errorf("revokes = %d, want 1", n)
	}
	if keys := st.keys(); len(keys) != 0 {
		t.Errorf("store still holds %q", keys)
	}
}

func TestLogoutRevokeFailureStillClears(t *testing.T) {
	fs := newFakeOAuthServer(t)
	fs.revokeStatus = http.StatusBadRequest
	st := &memStore{}
	now := time.Now()
	m, _ := signedIn(t, fs, st, now, now.Add(10*time.Minute))
	res, err := m.Logout(context.Background())
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if res.Revoked || res.RevokeErr == nil || !res.WasSignedIn {
		t.Errorf("result = %+v", res)
	}
	if keys := st.keys(); len(keys) != 0 {
		t.Errorf("store still holds %q", keys)
	}
}

func TestLogoutNotSignedIn(t *testing.T) {
	fs := newFakeOAuthServer(t)
	m := testManager(t, fs, &memStore{})
	res, err := m.Logout(context.Background())
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if res.WasSignedIn {
		t.Error("WasSignedIn = true on an empty store")
	}
	if n := fs.stats().requests; n != 0 {
		t.Errorf("server saw %d requests, want 0", n)
	}
}

// renewWithTokenSize renews once with an access token of about n bytes in a keyring that holds at most limit.
func renewWithTokenSize(t *testing.T, n, limit int) (st *memStore, m *Manager, fs *fakeOAuthServer, warn *bytes.Buffer, tok string) {
	t.Helper()
	fs = newFakeOAuthServer(t)
	fs.accessPad = n * 3 / 4 // base64 of the payload is a third longer than the payload
	st = limitedKeyring(limit)
	now := time.Now()
	m, _ = signedIn(t, fs, st, now, now.Add(-time.Minute)) // access token expired: the next call renews
	warn = &bytes.Buffer{}
	m.Warn = warn
	tok, err := m.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st, m, fs, warn, tok
}

func TestAccessTokenOf1200BytesFitsTheKeyring(t *testing.T) {
	for name, limit := range map[string]int{"macOS": macKeyringLimit, "Windows": winKeyringLimit} {
		st, m, _, warn, tok := renewWithTokenSize(t, 1200, limit)
		if len(tok) < 1200 {
			t.Fatalf("test token has %d bytes", len(tok))
		}
		if a, err := loadAccess(st, m.Origin); err != nil || a.Token != tok {
			t.Errorf("%s: access token not in the keyring: %v", name, err)
		}
		if warn.Len() != 0 {
			t.Errorf("%s: warning for a token that fits: %q", name, warn)
		}
	}
}

func TestAccessTokenOf3000BytesStaysInTheProcess(t *testing.T) {
	_, m, fs, warn, tok := renewWithTokenSize(t, 3000, macKeyringLimit)
	if len(tok) < 3000 {
		t.Fatalf("test token has %d bytes", len(tok))
	}
	if _, err := loadAccess(m.Store, m.Origin); !errors.Is(err, ErrNotFound) {
		t.Errorf("the access token reached the keyring: %v", err)
	}
	// More calls in the same command: no new renewal, no second hint.
	for i := 0; i < 3; i++ {
		got, err := m.Token(context.Background())
		if err != nil || got != tok {
			t.Fatalf("Token #%d = %q, %v, want the held token", i, got, err)
		}
	}
	if n := fs.stats().refreshes; n != 1 {
		t.Errorf("server saw %d renewals, want 1", n)
	}
	if got := strings.Count(warn.String(), "\n"); got != 1 {
		t.Errorf("hints = %d (%q), want exactly one", got, warn)
	}
	if strings.Contains(warn.String(), tok) || strings.Contains(warn.String(), "eyJ") {
		t.Errorf("the hint contains token text: %q", warn)
	}
	// The durable credentials were saved: a new process renews with the new refresh token.
	if c := mustCredentials(t, m.Store, m.Origin); c.RefreshToken == seedCredentials(time.Now()).RefreshToken {
		t.Error("the rotated refresh token was not stored")
	}
}

// A cancelled command must not lose the rotated refresh token: the server has already rotated it.
func TestRefreshSurvivesCancellation(t *testing.T) {
	fs := newFakeOAuthServer(t)
	fs.refreshDelay = 400 * time.Millisecond
	st := &memStore{}
	now := time.Now()
	m, seed := signedIn(t, fs, st, now, now.Add(-time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err := m.Token(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation reported", err)
	}
	c := mustCredentials(t, st, m.Origin)
	if c.RefreshToken == seed.RefreshToken || c.RefreshToken == "" {
		t.Fatalf("stored refresh token = %q, want the rotated one", c.RefreshToken)
	}
	tok, err := m.Token(context.Background())
	if err != nil || tok == "" {
		t.Fatalf("next command: %q, %v", tok, err)
	}
	if got := fs.stats(); got.refreshes != 1 || got.invalidGrants != 0 {
		t.Errorf("refreshes = %d, invalid grants = %d, want 1 and 0 (old refresh token seen once)", got.refreshes, got.invalidGrants)
	}
}
