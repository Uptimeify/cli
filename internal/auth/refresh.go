package auth

import (
	"context"
	"errors"
	"time"

	"github.com/uptimeify/cli/internal/client"
	"github.com/uptimeify/cli/internal/clierr"
)

// refreshTimeout bounds the token request of a renewal, which does not follow the command's context.
const refreshTimeout = 30 * time.Second

var _ client.TokenSource = (*Manager)(nil)

// LogoutResult says what auth logout did. A failed revocation does not stop the local sign-out.
type LogoutResult struct {
	WasSignedIn bool
	Revoked     bool
	RevokeErr   error
	DeviceName  string
}

func notSignedIn() error {
	return clierr.New(clierr.Auth, "not signed in: run `uptimeify auth login`, or set UPTIMEIFY_TOKEN to an API token")
}

// Token returns a usable access token, renewing the sign-in when the stored one runs out.
func (m *Manager) Token(ctx context.Context) (string, error) {
	if tok, ok := m.cachedAccess(); ok {
		return tok, nil
	}
	return m.refresh(ctx, "")
}

// Renew is called by the client after the server answered 401 invalid_token for rejected.
func (m *Manager) Renew(ctx context.Context, rejected string) (string, error) {
	return m.refresh(ctx, rejected)
}

func (m *Manager) cachedAccess() (string, bool) {
	if a := m.mem; a != nil && a.ExpiresAt.After(m.now().Add(accessMargin)) {
		return a.Token, true
	}
	a, err := loadAccess(m.Store, m.Origin)
	if err != nil || !a.ExpiresAt.After(m.now().Add(accessMargin)) {
		return "", false
	}
	return a.Token, true
}

// refresh renews the sign-in under the per-host lock. The server rotates refresh tokens without
// grace and revokes the device when one is presented twice, so two processes must never refresh
// at the same time, and a refresh token is never sent again after an unclear failure.
func (m *Manager) refresh(ctx context.Context, rejected string) (string, error) {
	release, err := acquireLock(ctx, m.lockPath(), lockWait)
	if err != nil {
		return "", err
	}
	defer release()

	// Read again under the lock: another process may have renewed while this one waited.
	if tok, ok := m.cachedAccess(); ok && tok != rejected {
		return tok, nil
	}
	cred, err := loadCredentials(m.Store, m.Origin)
	switch {
	case errors.Is(err, ErrNotFound):
		return "", notSignedIn()
	case err != nil:
		return "", storeError(err)
	case cred.RefreshToken == "":
		return "", notSignedIn()
	}

	// The request is not tied to ctx: once it is sent, the server rotates the refresh token, and a
	// cancelled command (Ctrl-C) must still store the answer, or the sign-in is lost. It has a
	// time limit of its own.
	rctx, stop := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	defer stop()
	tr, err := m.OAuth.Refresh(rctx, cred.ClientID, cred.RefreshToken)
	if err != nil {
		var notSent *NotSentError
		var limited *RateLimitError
		var refused *OAuthError
		switch {
		case errors.As(err, &notSent):
			// Nothing reached the server, nothing was rotated: the sign-in stays.
			return "", clierr.New(clierr.General, "could not reach %s to renew the sign-in: %v", m.Origin, err)
		case errors.As(err, &limited):
			// The limiter answers before the token handler: nothing was rotated.
			return "", clierr.New(clierr.RateLimit, "%v", err)
		case errors.As(err, &refused):
			_ = clearSession(m.Store, m.Origin)
			return "", sessionEnded(cred, m.now())
		default:
			// Sent, but no usable answer: the server may have rotated. Sending the old refresh
			// token again would then be a reuse and revoke the device, so the sign-in ends here.
			_ = clearSession(m.Store, m.Origin)
			return "", clierr.New(clierr.Auth, "the sign-in could not be renewed and its state on the server is unknown (%v): run `uptimeify auth login`", err)
		}
	}

	now := m.now()
	cred.RefreshToken = tr.RefreshToken
	cred.RefreshedAt = now
	if tr.Scope != "" {
		cred.Scope = tr.Scope
	}
	// The rotated refresh token is stored first: without it the sign-in is lost, without the
	// access token the next command only renews once more.
	if err := saveCredentials(m.Store, m.Origin, cred); err != nil {
		return "", clierr.New(clierr.Auth, "the sign-in was renewed, but the system keyring did not store it (%v): run `uptimeify auth login`", err)
	}
	m.keepAccess(&Access{Token: tr.AccessToken, ExpiresAt: now.Add(time.Duration(tr.ExpiresIn) * time.Second)})
	// Reported only now, after the result is stored.
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return tr.AccessToken, nil
}

// sessionEnded explains an invalid_grant. The server decides; the local times only pick the text.
func sessionEnded(c *Credentials, now time.Time) error {
	switch {
	case !c.GrantStartedAt.IsZero() && now.Sub(c.GrantStartedAt) >= GrantMaxAge:
		return clierr.New(clierr.Auth, "the sign-in has ended: a browser sign-in lasts at most 30 days. Run `uptimeify auth login`")
	case !c.RefreshedAt.IsZero() && now.Sub(c.RefreshedAt) >= IdleLimit:
		return clierr.New(clierr.Auth, "the sign-in has ended: it was not used for 7 days. Run `uptimeify auth login`")
	}
	return clierr.New(clierr.Auth, "the sign-in has ended: it was revoked (disconnected under Connected apps, a password change, or an old refresh token was used twice). Run `uptimeify auth login`")
}

// Logout revokes the refresh token at the server as far as possible and always removes both
// keyring entries for this host, the client id included.
func (m *Manager) Logout(ctx context.Context) (*LogoutResult, error) {
	release, err := acquireLock(ctx, m.lockPath(), lockWait)
	if err != nil {
		return nil, err
	}
	defer release()
	cred, err := loadCredentials(m.Store, m.Origin)
	switch {
	case errors.Is(err, ErrNotFound):
		return &LogoutResult{}, nil
	case err != nil:
		return nil, storeError(err)
	}
	res := &LogoutResult{WasSignedIn: true, DeviceName: cred.DeviceName}
	if cred.RefreshToken != "" {
		res.RevokeErr = m.OAuth.Revoke(ctx, cred.ClientID, cred.RefreshToken)
		res.Revoked = res.RevokeErr == nil
	}
	if err := clearSession(m.Store, m.Origin); err != nil {
		return nil, storeError(err)
	}
	return res, nil
}
