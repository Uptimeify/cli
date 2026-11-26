package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// memStore is the in-memory Store for tests of this package. The zero value is ready to use.
type memStore struct {
	mu     sync.Mutex
	m      map[string]string
	getErr error // returned by Get when set
	setErr error // returned by Set when set
}

var _ Store = (*memStore)(nil)

func (s *memStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return "", s.getErr
	}
	v, ok := s.m[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (s *memStore) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setErr != nil {
		return s.setErr
	}
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

// keys returns the stored keys, sorted.
func (s *memStore) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// fileStore is a Store shared between test processes: one file per key, named after the SHA-256
// of the key, mode 0600. Writes go to a temporary file that is renamed into place, so a parallel
// process never reads half a file.
type fileStore struct{ dir string }

var _ Store = fileStore{}

func (s fileStore) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:]))
}

func (s fileStore) Get(key string) (string, error) {
	b, err := os.ReadFile(s.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s fileStore) Set(key, value string) error {
	f, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := f.WriteString(value); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	if err := os.Chmod(f.Name(), 0o600); err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), s.path(key))
}

func (s fileStore) Delete(key string) error {
	err := os.Remove(s.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func TestKeyringMapsErrors(t *testing.T) {
	t.Cleanup(keyring.MockInit)
	keyring.MockInit()
	k := Keyring{}
	if _, err := k.Get("k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing: err = %v, want ErrNotFound", err)
	}
	if err := k.Set("k", "v"); err != nil {
		t.Fatal(err)
	}
	if v, err := k.Get("k"); err != nil || v != "v" {
		t.Fatalf("Get = %q, %v", v, err)
	}
	if err := k.Delete("k"); err != nil {
		t.Fatalf("Delete existing: %v", err)
	}
	if err := k.Delete("missing"); err != nil {
		t.Fatalf("Delete missing: err = %v, want nil", err)
	}

	keyring.MockInitWithError(errors.New("dbus: session bus not available"))
	if _, err := k.Get("k"); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("Get without keyring: err = %v, want ErrNoKeyring", err)
	}
	if err := k.Set("k", "v"); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("Set without keyring: err = %v, want ErrNoKeyring", err)
	}
	if err := k.Delete("k"); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("Delete without keyring: err = %v, want ErrNoKeyring", err)
	}

	keyring.MockInitWithError(keyring.ErrSetDataTooBig)
	err := k.Set("k", "v")
	if !errors.Is(err, keyring.ErrSetDataTooBig) || errors.Is(err, ErrNoKeyring) || !strings.Contains(err.Error(), "refused") {
		t.Errorf("Set too big: err = %v", err)
	}
	keyring.MockInit()
}

func TestCredentialsRoundTrip(t *testing.T) {
	st := &memStore{}
	origin := "https://uptimeify.io"
	at := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	in := &Credentials{
		ClientID:       "ucli_" + strings.Repeat("a", 43),
		RegisteredAt:   at,
		DeviceName:     "uptimeify CLI on testhost",
		RefreshToken:   strings.Repeat("r", 32),
		Scope:          "offline_access api:monitors:read",
		GrantStartedAt: at.Add(time.Minute),
		RefreshedAt:    at.Add(2 * time.Minute),
	}
	if err := saveCredentials(st, origin, in); err != nil {
		t.Fatal(err)
	}
	raw, err := st.Get(credentialsKey(origin))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"client_id":`, `"registered_at":`, `"device_name":`, `"refresh_token":`, `"scope":`, `"grant_started_at":`, `"refreshed_at":`} {
		if !strings.Contains(raw, key) {
			t.Errorf("stored JSON lacks %s: %s", key, raw)
		}
	}
	got, err := loadCredentials(st, origin)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != in.ClientID || got.DeviceName != in.DeviceName || got.RefreshToken != in.RefreshToken || got.Scope != in.Scope ||
		!got.RegisteredAt.Equal(in.RegisteredAt) || !got.GrantStartedAt.Equal(in.GrantStartedAt) || !got.RefreshedAt.Equal(in.RefreshedAt) {
		t.Errorf("got %+v, want %+v", got, in)
	}

	// A registration without a finished sign-in omits the empty fields.
	if err := saveCredentials(st, origin, &Credentials{ClientID: in.ClientID, RegisteredAt: at, DeviceName: in.DeviceName}); err != nil {
		t.Fatal(err)
	}
	raw, _ = st.Get(credentialsKey(origin))
	for _, key := range []string{`"refresh_token"`, `"scope"`, `"grant_started_at"`, `"refreshed_at"`} {
		if strings.Contains(raw, key) {
			t.Errorf("empty field %s stored: %s", key, raw)
		}
	}

	exp := at.Add(15 * time.Minute)
	if err := saveAccess(st, origin, &Access{Token: strings.Repeat("j", 40), ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	a, err := loadAccess(st, origin)
	if err != nil || a.Token != strings.Repeat("j", 40) || !a.ExpiresAt.Equal(exp) {
		t.Errorf("access = %+v, %v", a, err)
	}
}

func TestCorruptEntryCountsAsNotSignedIn(t *testing.T) {
	origin := "https://uptimeify.io"
	st := &memStore{}
	st.Set(credentialsKey(origin), "{")
	if _, err := loadCredentials(st, origin); !errors.Is(err, ErrNotFound) {
		t.Errorf("corrupt credentials: err = %v, want ErrNotFound", err)
	}
	st.Set(credentialsKey(origin), `{"device_name":"x"}`)
	if _, err := loadCredentials(st, origin); !errors.Is(err, ErrNotFound) {
		t.Errorf("credentials without client_id: err = %v, want ErrNotFound", err)
	}
	st.Set(accessKey(origin), `{"expires_at":"2026-01-01T00:00:00Z"}`)
	if _, err := loadAccess(st, origin); !errors.Is(err, ErrNotFound) {
		t.Errorf("access without access_token: err = %v, want ErrNotFound", err)
	}
	if k := st.keys(); len(k) != 0 {
		t.Errorf("corrupt entries were kept: %v", k)
	}
}

func TestLoadPassesStoreErrorsThrough(t *testing.T) {
	st := &memStore{getErr: errors.Join(ErrNoKeyring, errors.New("dbus"))}
	if _, err := loadCredentials(st, "https://uptimeify.io"); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("err = %v, want ErrNoKeyring", err)
	}
	if _, err := loadAccess(st, "https://uptimeify.io"); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("err = %v, want ErrNoKeyring", err)
	}
	if _, err := loadCredentials(&memStore{}, "https://uptimeify.io"); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty store: err = %v, want ErrNotFound", err)
	}
}

func TestClearSessionRemovesBothEntries(t *testing.T) {
	origin := "https://uptimeify.io"
	st := &memStore{}
	if err := saveCredentials(st, origin, &Credentials{ClientID: "ucli_a", RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := saveAccess(st, origin, &Access{Token: "a", ExpiresAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := clearSession(st, origin); err != nil {
		t.Fatal(err)
	}
	if k := st.keys(); len(k) != 0 {
		t.Errorf("left over: %v", k)
	}
	if err := clearSession(st, origin); err != nil {
		t.Errorf("clearing an empty store: %v", err)
	}
}

func TestOrigin(t *testing.T) {
	cases := map[string]string{
		"https://Uptimeify.IO":  "https://uptimeify.io",
		"https://uptimeify.io/": "https://uptimeify.io",
		"http://127.0.0.1:3047": "http://127.0.0.1:3047",
	}
	for in, want := range cases {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := Origin(u); got != want {
			t.Errorf("Origin(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKeysPerHost(t *testing.T) {
	st := &memStore{}
	a, b := "https://uptimeify.io", "https://status.example.com"
	saveCredentials(st, a, &Credentials{ClientID: "ucli_a"})
	saveCredentials(st, b, &Credentials{ClientID: "ucli_b"})
	saveAccess(st, a, &Access{Token: "x", ExpiresAt: time.Now()})
	if want := []string{b, a, a + " access"}; !slices.Equal(st.keys(), want) {
		t.Fatalf("keys = %q, want %q", st.keys(), want)
	}
	ca, err := loadCredentials(st, a)
	if err != nil || ca.ClientID != "ucli_a" {
		t.Errorf("host a: %+v, %v", ca, err)
	}
	if err := clearSession(st, a); err != nil {
		t.Fatal(err)
	}
	cb, err := loadCredentials(st, b)
	if err != nil || cb.ClientID != "ucli_b" {
		t.Errorf("host b after clearing a: %+v, %v", cb, err)
	}
}

func TestFileStore(t *testing.T) {
	st := fileStore{dir: t.TempDir()}
	if _, err := st.Get("k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: err = %v", err)
	}
	if err := st.Set("k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := st.Set("k", "v2"); err != nil {
		t.Fatal(err)
	}
	if v, err := st.Get("k"); err != nil || v != "v2" {
		t.Fatalf("Get = %q, %v", v, err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(st.path("k"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, %v", fi.Mode().Perm(), err)
		}
	}
	if err := st.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete("k"); err != nil {
		t.Errorf("delete missing: %v", err)
	}
}
