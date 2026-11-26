package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/zalando/go-keyring"

	"github.com/uptimeify/cli/internal/clierr"
)

// KeyringService is the service name of every keyring entry the CLI writes.
const KeyringService = "uptimeify-cli"

// ErrNotFound means there is no stored sign-in for the host.
var ErrNotFound = errors.New("no stored sign-in")

// ErrNoKeyring means the system keyring cannot be used. There is deliberately no file fallback.
var ErrNoKeyring = errors.New("no system keyring is available")

// Store keeps the secrets of a sign-in. The only production implementation is Keyring.
type Store interface {
	Get(key string) (string, error) // ErrNotFound when absent; errors wrapping ErrNoKeyring when unusable
	Set(key, value string) error
	Delete(key string) error // nil when absent
}

// Keyring stores entries in the system keyring (macOS Keychain, Windows Credential Manager,
// Secret Service on Linux) under the service KeyringService.
//
// It uses github.com/zalando/go-keyring because it needs no cgo (the release builds with
// CGO_ENABLED=0): on macOS it runs /usr/bin/security, on Windows it calls the Credential Manager
// through syscalls, on Linux it talks to Secret Service over D-Bus in pure Go. On macOS the secret
// goes to `security -i` over stdin, so it never appears in the process list; only the service
// name and the key (the origin) are arguments.
type Keyring struct{}

var _ Store = Keyring{}

func (Keyring) Get(key string) (string, error) {
	v, err := keyring.Get(KeyringService, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoKeyring, err)
	}
	return v, nil
}

func (Keyring) Set(key, value string) error {
	err := keyring.Set(KeyringService, key, value)
	if errors.Is(err, keyring.ErrSetDataTooBig) {
		return fmt.Errorf("the system keyring refused the entry: %w", err)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoKeyring, err)
	}
	return nil
}

func (Keyring) Delete(key string) error {
	err := keyring.Delete(KeyringService, key)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrNoKeyring, err)
}

// Credentials is the sign-in of one host: the registered device and, after a finished sign-in,
// the refresh token with its scopes and times.
type Credentials struct {
	ClientID       string    `json:"client_id"`
	RegisteredAt   time.Time `json:"registered_at"`
	DeviceName     string    `json:"device_name"`
	RefreshToken   string    `json:"refresh_token,omitempty"`
	Scope          string    `json:"scope,omitempty"`
	GrantStartedAt time.Time `json:"grant_started_at,omitzero"`
	RefreshedAt    time.Time `json:"refreshed_at,omitzero"`
}

// Access is the current access token of one host. It is a separate entry because Windows limits
// a credential to 2560 bytes and macOS the security command to 4096 bytes.
type Access struct {
	Token     string    `json:"access_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Origin is the profile key of a host and the one place that builds it: scheme and host in lower
// case, the default port left out (:443 for https, :80 for http). A host with non-ASCII characters
// is refused, so a look-alike name never shares a keyring entry or a lock with the real one. The
// keyring entries, the lock and the OAuth requests all use this value.
func Origin(base *url.URL) (string, error) {
	scheme := strings.ToLower(base.Scheme)
	host := strings.ToLower(base.Hostname())
	if host == "" {
		return "", clierr.New(clierr.Usage, "the API URL has no host")
	}
	for _, r := range host {
		if r > unicode.MaxASCII {
			return "", clierr.New(clierr.Usage, "the API host must be plain ASCII (use the punycode form of an international name)")
		}
	}
	port := base.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port == "" {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		return scheme + "://" + host, nil
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

func credentialsKey(origin string) string { return origin }

func accessKey(origin string) string { return origin + " access" }

// loadCredentials returns ErrNotFound for a missing or damaged entry; a damaged one is removed.
func loadCredentials(st Store, origin string) (*Credentials, error) {
	raw, err := st.Get(credentialsKey(origin))
	if err != nil {
		return nil, err
	}
	var c Credentials
	if json.Unmarshal([]byte(raw), &c) != nil || c.ClientID == "" {
		_ = st.Delete(credentialsKey(origin))
		return nil, ErrNotFound
	}
	return &c, nil
}

func saveCredentials(st Store, origin string, c *Credentials) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return st.Set(credentialsKey(origin), string(b))
}

// loadAccess returns ErrNotFound for a missing or damaged entry; a damaged one is removed.
func loadAccess(st Store, origin string) (*Access, error) {
	raw, err := st.Get(accessKey(origin))
	if err != nil {
		return nil, err
	}
	var a Access
	if json.Unmarshal([]byte(raw), &a) != nil || a.Token == "" {
		_ = st.Delete(accessKey(origin))
		return nil, ErrNotFound
	}
	return &a, nil
}

func saveAccess(st Store, origin string, a *Access) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return st.Set(accessKey(origin), string(b))
}

// clearSession removes the access token, then the credentials. Both deletes always run; the
// first error wins.
func clearSession(st Store, origin string) error {
	errAccess := st.Delete(accessKey(origin))
	errCred := st.Delete(credentialsKey(origin))
	if errAccess != nil {
		return errAccess
	}
	return errCred
}
