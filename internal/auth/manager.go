package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
	"github.com/uptimeify/cli/internal/sanitize"
)

const (
	// LoginTimeout bounds the loopback receiver (spec: at most 5 minutes).
	LoginTimeout = 5 * time.Minute
	// firstBindWindow: the server lets an unbound registration live 15 minutes (cli-device.ts);
	// one minute less leaves room for clock skew and the time spent on the consent page.
	firstBindWindow = 14 * time.Minute
	// GrantMaxAge is the absolute lifetime of a grant on the server, counted from the code exchange.
	GrantMaxAge = 30 * 24 * time.Hour
	// IdleLimit is the sliding lifetime of a refresh token on the server.
	IdleLimit = 7 * 24 * time.Hour
	// accessMargin: an access token is used only while it has at least this much time left.
	accessMargin = 60 * time.Second
)

// Manager signs the CLI in to one host and keeps that sign-in. The host is the profile.
type Manager struct {
	Origin   string
	Store    Store
	OAuth    *OAuth
	LockDir  string                 // user cache directory; "" makes renewal fail with a clear error
	Hostname func() (string, error) // nil: os.Hostname
	Now      func() time.Time       // nil: time.Now
	Warn     io.Writer              // stderr: notes that need no action; nil: none

	mem    *Access // access token that did not fit into the keyring: held in this process only
	warned bool
}

// LoginOptions steer one browser sign-in.
type LoginOptions struct {
	Scopes      []string           // requested scopes on top of DefaultScopes (--write, --scope); offline_access is added by the login
	DeviceName  string             // from --device-name; "": uptimeify CLI on <hostname>
	OpenBrowser func(string) error // nil: --no-browser
	Out         io.Writer          // stderr: address and progress
	Timeout     time.Duration      // 0: LoginTimeout
}

// Status describes the stored sign-in for auth status. It holds no secret.
type Status struct {
	SignedIn                                     bool
	DeviceName, Scope, UserID                    string
	AccessExpiresAt, GrantStartedAt, RefreshedAt time.Time
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) lockPath() string { return lockPath(m.LockDir, m.Origin) }

func noKeyringError(err error) error {
	return clierr.New(clierr.Auth, "%v. The CLI keeps sign-ins only in the system keyring (macOS Keychain, Windows Credential Manager, Secret Service on Linux). On servers, in CI and in containers set UPTIMEIFY_TOKEN to an API token instead.", err)
}

// storeError turns a missing keyring into the explanation above and leaves other errors alone.
func storeError(err error) error {
	if errors.Is(err, ErrNoKeyring) {
		return noKeyringError(err)
	}
	return err
}

// Login runs the browser sign-in: register the device once, wait for the browser on the
// loopback receiver, exchange the code and store the result in the keyring.
func (m *Manager) Login(ctx context.Context, o LoginOptions) (*Credentials, error) {
	// Everything that needs no network is checked first, so a bad scope or device name never
	// costs a request.
	scopes, err := RequestScopes(o.Scopes)
	if err != nil {
		return nil, err
	}
	if o.DeviceName != "" {
		if err := ValidateDeviceName(o.DeviceName); err != nil {
			return nil, err
		}
	}
	// The lock comes before the first request: creating the cache directory and the lock file
	// must work, or the sign-in ends here without having sent anything.
	release, err := acquireLock(ctx, m.lockPath(), lockWait)
	if err != nil {
		return nil, err
	}
	defer release()
	// The keyring is checked before any request: no registration is spent on a machine that
	// cannot keep the sign-in.
	cred, err := loadCredentials(m.Store, m.Origin)
	switch {
	case errors.Is(err, ErrNotFound):
		cred = nil
	case err != nil:
		return nil, storeError(err)
	}
	now := m.now()
	reuse := cred != nil && (!cred.GrantStartedAt.IsZero() || now.Sub(cred.RegisteredAt) < firstBindWindow) &&
		(o.DeviceName == "" || o.DeviceName == cred.DeviceName)
	if !reuse {
		device := o.DeviceName
		if device == "" {
			lookup := m.Hostname
			if lookup == nil {
				lookup = os.Hostname
			}
			hostname, herr := lookup()
			if herr != nil {
				hostname = ""
			}
			device = DeviceName(hostname)
		}
		reg, err := m.OAuth.Register(ctx, device)
		if err != nil {
			return nil, err
		}
		cred = &Credentials{ClientID: reg.ClientID, RegisteredAt: now, DeviceName: device}
		// Stored at once, so an interrupted sign-in reuses the registration (5 per hour per IP).
		if err := saveCredentials(m.Store, m.Origin, cred); err != nil {
			return nil, storeError(err)
		}
	}
	startRefresh := cred.RefreshToken
	// The wait for the browser runs without the lock, so other uptimeify processes can renew.
	release()

	p, err := newPKCE()
	if err != nil {
		return nil, err
	}
	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	ln, redirectURI, err := listenLoopback()
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	authURL := m.OAuth.AuthorizeURL(cred.ClientID, redirectURI, state, p.challenge, scopes)

	out := o.Out
	if out == nil {
		out = io.Discard
	}
	fmt.Fprintf(out, "Signing in to %s as device \"%s\".\n", m.Origin, sanitize.Line(cred.DeviceName))
	if o.OpenBrowser != nil {
		fmt.Fprintln(out, "Your browser should open. If it does not, open this address in a browser on this computer:")
	} else {
		fmt.Fprintln(out, "Open this address in a browser on this computer:")
	}
	fmt.Fprintf(out, "\n  %s\n\n", authURL)
	fmt.Fprintln(out, "Waiting up to 5 minutes for the browser ...")
	if o.OpenBrowser != nil {
		if err := o.OpenBrowser(authURL); err != nil {
			fmt.Fprintf(out, "Could not open a browser (%s). Open the address above yourself.\n", sanitize.Line(err.Error()))
		}
	}

	timeout := o.Timeout
	if timeout <= 0 {
		timeout = LoginTimeout
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	code, err := waitForCallback(wctx, ln, state)
	cancel()
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return nil, clierr.New(clierr.Auth, "the sign-in was not completed within 5 minutes: run `uptimeify auth login` again")
		case errors.Is(err, context.Canceled):
			return nil, clierr.New(clierr.General, "the sign-in was cancelled")
		}
		return nil, err
	}

	// Locked again before the code is traded: the new refresh token and the stored sign-in change together.
	release, err = acquireLock(ctx, m.lockPath(), lockWait)
	if err != nil {
		return nil, err
	}
	defer release()
	// Another process may have signed in while this one waited for the browser. Read the stored
	// sign-in again: if it holds another refresh token than the one this login started with, that
	// token is ended after the new one is stored.
	var other *Credentials
	switch cur, err := loadCredentials(m.Store, m.Origin); {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return nil, storeError(err)
	case cur.RefreshToken != "" && cur.RefreshToken != startRefresh:
		other = cur
	}

	tr, err := m.OAuth.Exchange(ctx, cred.ClientID, code, p.verifier, redirectURI)
	if err != nil {
		var refused *OAuthError
		var limited *RateLimitError
		switch {
		case errors.As(err, &refused):
			return nil, clierr.New(clierr.Auth, "%v: run `uptimeify auth login` again", err)
		case errors.As(err, &limited):
			return nil, clierr.New(clierr.RateLimit, "%v", err)
		}
		return nil, err
	}

	now = m.now()
	cred.RefreshToken = tr.RefreshToken
	cred.Scope = sanitize.Line(tr.Scope)
	if cred.Scope == "" {
		_, cred.Scope = jwtClaims(tr.AccessToken)
	}
	cred.GrantStartedAt = now
	cred.RefreshedAt = now
	if err := saveCredentials(m.Store, m.Origin, cred); err != nil {
		// The server has issued a refresh token the CLI cannot keep: end it there, best effort.
		m.revokeQuietly(cred.ClientID, tr.RefreshToken)
		if errors.Is(err, ErrEntryTooBig) {
			return nil, clierr.New(clierr.Auth, "the sign-in record is too large for the system keyring (%v), so nothing was stored. Request fewer scopes, or set UPTIMEIFY_TOKEN to an API token instead", err)
		}
		return nil, clierr.New(clierr.Auth, "signed in, but the system keyring did not store the sign-in (%v): run `uptimeify auth login` again", err)
	}
	m.keepAccess(&Access{Token: tr.AccessToken, ExpiresAt: now.Add(time.Duration(tr.ExpiresIn) * time.Second)})
	if other != nil && other.RefreshToken != tr.RefreshToken {
		if err := m.revokeQuietly(other.ClientID, other.RefreshToken); err != nil && m.Warn != nil {
			fmt.Fprintf(m.Warn, "Note: could not end the previous sign-in on the server (%s). It ends by itself after 7 days without use, or disconnect the device under Connected apps.\n", sanitize.Line(err.Error()))
		}
	}
	return cred, nil
}

// revokeQuietly ends a refresh token on the server and ignores the outcome. It runs after the
// result that matters is decided, so it gets its own short time limit.
func (m *Manager) revokeQuietly(clientID, refreshToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return m.OAuth.Revoke(ctx, clientID, refreshToken)
}

// keepAccess stores the access token. A token that does not fit into the keyring stays in this
// process, and the user gets one hint per command (never the token).
func (m *Manager) keepAccess(a *Access) {
	m.mem = a
	err := saveAccess(m.Store, m.Origin, a)
	if err == nil {
		return
	}
	// A failed write must not leave an older token that the next process would trust.
	_ = m.Store.Delete(accessKey(m.Origin))
	if errors.Is(err, ErrEntryTooBig) && !m.warned && m.Warn != nil {
		m.warned = true
		fmt.Fprintln(m.Warn, "Note: the access token is too large for the system keyring. It is kept in memory for this command only, and the next command renews it again.")
	}
}

// SignedIn reports whether a usable sign-in is stored. A missing keyring is an error.
func (m *Manager) SignedIn() (bool, error) {
	cred, err := loadCredentials(m.Store, m.Origin)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return cred.RefreshToken != "", nil
}

// Status reads both keyring entries. A missing keyring is returned as is (errors.Is ErrNoKeyring).
func (m *Manager) Status() (*Status, error) {
	cred, err := loadCredentials(m.Store, m.Origin)
	if errors.Is(err, ErrNotFound) {
		return &Status{}, nil
	}
	if err != nil {
		return nil, err
	}
	if cred.RefreshToken == "" {
		return &Status{}, nil
	}
	s := &Status{
		SignedIn:       true,
		DeviceName:     sanitize.Line(cred.DeviceName),
		Scope:          sanitize.Line(cred.Scope),
		GrantStartedAt: cred.GrantStartedAt,
		RefreshedAt:    cred.RefreshedAt,
	}
	if a, err := loadAccess(m.Store, m.Origin); err == nil {
		s.UserID, _ = jwtClaims(a.Token)
		s.AccessExpiresAt = a.ExpiresAt
	}
	return s, nil
}

// jwtClaims reads sub and scope from the payload of an access token without checking the
// signature. Only for display: the CLI is not the resource server, the server checks every token.
func jwtClaims(token string) (sub, scope string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var c struct {
		Sub   string `json:"sub"`
		Scope string `json:"scope"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return "", ""
	}
	return sanitize.Line(c.Sub), sanitize.Line(c.Scope)
}
