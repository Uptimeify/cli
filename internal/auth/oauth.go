package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
	"github.com/uptimeify/cli/internal/sanitize"
)

// Fixed by the server (Paket A): resource, client prefix, registered redirect URI, endpoints and
// the access token lifetime of 15 minutes.
const (
	ResourcePath          = "/api/cli"
	ClientIDPrefix        = "ucli_"
	RegisteredRedirectURI = "http://127.0.0.1/callback"
	registerPath          = "/api/oauth/cli/clients"
	authorizePath         = "/api/auth/oauth2/authorize"
	tokenPath             = "/api/auth/oauth2/token"
	revokePath            = "/api/auth/oauth2/revoke"
	maxAccessLifetime     = 900 * time.Second
)

// maxOAuthBody is a variable only so tests can lower it.
var maxOAuthBody = 64 << 10

var clientIDPattern = regexp.MustCompile(`^` + ClientIDPrefix + `[A-Za-z0-9_-]{1,128}$`)

// OAuth talks to the sign-in endpoints of one origin. It never follows a redirect, so a refresh
// token or an authorization code can only ever reach that origin.
type OAuth struct {
	Origin    string // e.g. https://uptimeify.io, no trailing slash
	UserAgent string
	Debug     io.Writer    // nil: no debug lines
	HTTP      *http.Client // nil or without Timeout: 30 s timeout; never follows a redirect
}

type Registration struct {
	ClientID        string   `json:"client_id"`
	RedirectURI     string   `json:"redirect_uri"`
	Resource        string   `json:"resource"`
	ScopesSupported []string `json:"scopes_supported"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// OAuthError is a clear refusal by the token endpoint (4xx with an "error" field). Code and
// Description are already sanitised and redacted.
type OAuthError struct {
	Status      int
	Code        string
	Description string
}

func (e *OAuthError) Error() string {
	msg := fmt.Sprintf("the server refused the sign-in request (%d %s)", e.Status, e.Code)
	if e.Description != "" {
		msg += ": " + e.Description
	}
	return msg
}

// RateLimitError is a 429 from the token endpoint. The limiter runs before the handler, so the
// server rotated nothing.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("the server rate-limited the sign-in request: try again in %d seconds", int(e.RetryAfter/time.Second))
}

// NotSentError means the request never reached the server (DNS, connect, TLS), so the server
// cannot have rotated anything.
type NotSentError struct{ Err error }

func (e *NotSentError) Error() string { return e.Err.Error() }
func (e *NotSentError) Unwrap() error { return e.Err }

func (o *OAuth) Resource() string { return o.Origin + ResourcePath }

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (o *OAuth) httpClient() *http.Client {
	if o.HTTP == nil {
		return &http.Client{Timeout: 30 * time.Second, CheckRedirect: noRedirect}
	}
	c := *o.HTTP
	if c.Timeout <= 0 {
		// The sign-in lock waits at most lockWait; a client without a limit would hold it forever.
		c.Timeout = 30 * time.Second
	}
	c.CheckRedirect = noRedirect
	return &c
}

// clean makes server text printable on one line, replaces every secret with [redacted] and cuts
// it to 300 runes.
func clean(s string, secrets ...string) string {
	s = sanitize.Line(s)
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300])
	}
	return s
}

// retryAfter reads the Retry-After header, then data.retryAfter from a Nuxt error body, else 60 s.
func retryAfter(h http.Header, raw []byte) time.Duration {
	// Capped at a day like the client's own Retry-After handling; negative and unreadable values
	// are ignored. An absurdly large number counts as the cap.
	if s, err := strconv.ParseInt(strings.TrimSpace(h.Get("Retry-After")), 10, 64); (err == nil || errors.Is(err, strconv.ErrRange) && s > 0) && s > 0 {
		return time.Duration(min(s, 86400)) * time.Second
	}
	var body struct {
		Data struct {
			RetryAfter float64 `json:"retryAfter"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Data.RetryAfter > 0 {
		return time.Duration(math.Ceil(math.Min(body.Data.RetryAfter, 86400))) * time.Second
	}
	return 60 * time.Second
}

// post sends one POST. It never sets Origin or Authorization: the registration refuses a request
// with Origin, and the CLI is a public client without a secret.
func (o *OAuth) post(ctx context.Context, path, contentType string, body []byte) (status int, header http.Header, raw []byte, err error) {
	var sent atomic.Bool
	trace := &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		if info.Err == nil {
			sent.Store(true)
		}
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, o.Origin+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", o.UserAgent)
	res, err := o.httpClient().Do(req)
	if err != nil {
		if !sent.Load() {
			return 0, nil, nil, &NotSentError{Err: fmt.Errorf("request failed: %w", err)}
		}
		return 0, nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(res.Body, int64(maxOAuthBody)+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read the sign-in answer: %w", err)
	}
	if len(raw) > maxOAuthBody {
		return 0, nil, nil, fmt.Errorf("the sign-in answer is larger than %d KB", maxOAuthBody>>10)
	}
	if o.Debug != nil {
		// Method, URL and status only. The OAuth requests carry their secrets in the body, which
		// is never printed.
		fmt.Fprintf(o.Debug, "%s %s -> %d (%d bytes)\n", http.MethodPost, o.Origin+path, res.StatusCode, len(raw))
	}
	if res.StatusCode >= 300 && res.StatusCode <= 399 {
		return res.StatusCode, res.Header, raw, clierr.New(clierr.General, "the server answered the sign-in request with a redirect, refusing to follow it")
	}
	return res.StatusCode, res.Header, raw, nil
}

// Register registers this installation as a device (POST /api/oauth/cli/clients) and checks that
// the answer belongs to this origin.
func (o *OAuth) Register(ctx context.Context, deviceName string) (*Registration, error) {
	body, err := json.Marshal(map[string]string{"device_name": deviceName})
	if err != nil {
		return nil, err
	}
	status, header, raw, err := o.post(ctx, registerPath, "application/json", body)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusCreated:
		var reg Registration
		if err := json.Unmarshal(raw, &reg); err != nil {
			return nil, clierr.New(clierr.General, "the server's registration answer does not match this CLI: it is not JSON")
		}
		if !clientIDPattern.MatchString(reg.ClientID) {
			return nil, clierr.New(clierr.General, "the server's registration answer does not match this CLI: unexpected client id")
		}
		if reg.RedirectURI != RegisteredRedirectURI {
			return nil, clierr.New(clierr.General, "the server's registration answer does not match this CLI: unexpected redirect URI")
		}
		if reg.Resource != o.Resource() {
			return nil, clierr.New(clierr.General, "the server's registration answer does not match this CLI: it names the resource %q, expected %q", clean(reg.Resource), o.Resource())
		}
		return &reg, nil
	case http.StatusNotFound:
		return nil, clierr.New(clierr.Auth, "browser sign-in is switched off on this server: use an API token instead (set UPTIMEIFY_TOKEN)")
	case http.StatusTooManyRequests:
		minutes := int((retryAfter(header, raw) + time.Minute - 1) / time.Minute)
		if minutes < 1 {
			minutes = 1
		}
		return nil, clierr.New(clierr.RateLimit, "too many sign-in registrations from this network: try again in %d minutes", minutes)
	case http.StatusServiceUnavailable:
		return nil, clierr.New(clierr.General, "the server is still starting browser sign-in: try again in a minute")
	}
	var parsed struct {
		Message string `json:"message"`
		Data    struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	_ = json.Unmarshal(raw, &parsed)
	detail := strconv.Itoa(status)
	for _, part := range []string{clean(parsed.Message), clean(parsed.Data.Code)} {
		if part != "" {
			detail += " " + part
		}
	}
	return nil, clierr.New(clierr.General, "the server refused the device registration (%s)", detail)
}

// AuthorizeURL builds the address the browser opens. The server adds prompt=consent itself.
func (o *OAuth) AuthorizeURL(clientID, redirectURI, state, challenge string, scopes []string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "offline_access "+strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", o.Resource())
	return o.Origin + authorizePath + "?" + q.Encode()
}

// Exchange trades the authorization code for the first token pair.
func (o *OAuth) Exchange(ctx context.Context, clientID, code, verifier, redirectURI string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
		"resource":      {o.Resource()},
	}
	return o.token(ctx, form, code, verifier)
}

// Refresh trades the refresh token for a new pair. The server rotates the refresh token.
func (o *OAuth) Refresh(ctx context.Context, clientID, refreshToken string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"resource":      {o.Resource()},
	}
	return o.token(ctx, form, refreshToken)
}

func (o *OAuth) token(ctx context.Context, form url.Values, secrets ...string) (*TokenResponse, error) {
	status, header, raw, err := o.post(ctx, tokenPath, "application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusOK:
		var tr TokenResponse
		if json.Unmarshal(raw, &tr) != nil || tr.AccessToken == "" || tr.RefreshToken == "" || !strings.EqualFold(tr.TokenType, "bearer") || tr.ExpiresIn <= 0 {
			return nil, errors.New("the server's token answer is incomplete")
		}
		if limit := int(maxAccessLifetime / time.Second); tr.ExpiresIn > limit {
			tr.ExpiresIn = limit
		}
		return &tr, nil
	case status == http.StatusTooManyRequests:
		return nil, &RateLimitError{RetryAfter: retryAfter(header, raw)}
	case status >= 400 && status <= 499:
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return nil, &OAuthError{Status: status, Code: clean(e.Error, secrets...), Description: clean(e.Description, secrets...)}
		}
	}
	return nil, fmt.Errorf("the server answered the sign-in request with %d", status)
}

// Revoke asks the server to end the sign-in of refreshToken.
func (o *OAuth) Revoke(ctx context.Context, clientID, refreshToken string) error {
	form := url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {clientID},
	}
	status, _, _, err := o.post(ctx, revokePath, "application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("the server answered the revocation with %d", status)
	}
	return nil
}
