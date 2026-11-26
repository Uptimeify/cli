// Package client talks to the Uptimeify API. It is the only place that holds the token, and it
// only ever sends it to the host it was created for.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
	"github.com/uptimeify/cli/internal/sanitize"
)

// maxBody is a variable only so tests can lower it.
var maxBody = 50 << 20

const (
	maxRetries = 3
	maxWait    = 60 * time.Second
)

// scopePattern is the form a requiredScope from the server must have before it is put into a
// suggested command.
var scopePattern = regexp.MustCompile(`^api:[a-z][a-z-]*:(read|write)$`)

// TokenSource supplies the access token of a browser sign-in.
type TokenSource interface {
	// Token returns the access token for the next request.
	Token(ctx context.Context) (string, error)
	// Renew is called at most once per request, after a 401 with error="invalid_token" for the
	// token `rejected`. It returns a token to retry with, or an error that ends the request.
	Renew(ctx context.Context, rejected string) (string, error)
}

type Options struct {
	BaseURL string
	Token   string
	// Source is used when set; Token is ignored then.
	Source                TokenSource
	Version               string
	AllowInsecureLoopback bool
	Debug                 io.Writer
	Sleep                 func(time.Duration)
}

type Response struct {
	Status      int
	ContentType string
	Body        []byte
}

type APIError struct {
	Status  int
	Code    string
	Message string
	// RequiredScope is the scope the server named as missing, set only when it has the form of a
	// scope.
	RequiredScope string
	// Hint is the next step for the user, empty when there is none. Error() does not include it.
	Hint string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	if e.Code != "" {
		return fmt.Sprintf("%d %s (%s)", e.Status, msg, e.Code)
	}
	return fmt.Sprintf("%d %s", e.Status, msg)
}

func (e *APIError) ExitCode() int {
	switch e.Status {
	case 400, 422:
		return clierr.Usage
	case 401, 403:
		return clierr.Auth
	case 404:
		return clierr.NotFound
	case 429:
		return clierr.RateLimit
	}
	return clierr.General
}

type Client struct {
	base   *url.URL
	token  string
	source TokenSource
	ua     string
	hc     *http.Client
	debug  io.Writer
	sleep  func(context.Context, time.Duration) error
}

var errCrossHost = errors.New("the server redirected to another host, refusing to follow")

// CheckBaseURL validates the API base URL. Its errors never contain the supplied value, since it
// may be a pasted secret.
func CheckBaseURL(raw string, allowInsecureLoopback bool) error {
	_, err := parseBase(raw, allowInsecureLoopback)
	return err
}

// BaseURL validates the API base URL like CheckBaseURL and returns it without a path.
func BaseURL(raw string, allowInsecureLoopback bool) (*url.URL, error) {
	u, err := parseBase(raw, allowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	u.Path = ""
	return u, nil
}

// UserAgent is the User-Agent header of every request the CLI sends.
func UserAgent(version string) string {
	return fmt.Sprintf("uptimeify-cli/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
}

func parseBase(raw string, allowInsecureLoopback bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, clierr.New(clierr.Usage, "the API URL is not a valid URL")
	}
	if u.User != nil {
		return nil, clierr.New(clierr.Usage, "the API URL must not contain credentials")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && u.Hostname() == "127.0.0.1" && allowInsecureLoopback:
	default:
		return nil, clierr.New(clierr.Usage, "the API URL must use https (got scheme %q)", u.Scheme)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, clierr.New(clierr.Usage, "the API URL must not contain a path, query or fragment")
	}
	return u, nil
}

func New(o Options) (*Client, error) {
	if o.Source == nil && o.Token == "" {
		return nil, clierr.New(clierr.Auth, "not signed in: run `uptimeify auth login`, or set UPTIMEIFY_TOKEN to an API token")
	}
	u, err := BaseURL(o.BaseURL, o.AllowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	sleep := func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if o.Sleep != nil {
		sleep = func(_ context.Context, d time.Duration) error { o.Sleep(d); return nil }
	}
	c := &Client{
		base:   u,
		token:  o.Token,
		source: o.Source,
		ua:     UserAgent(o.Version),
		debug:  o.Debug,
		sleep:  sleep,
	}
	c.hc = &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host != u.Host || req.URL.Scheme != u.Scheme {
				return errCrossHost
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	return c, nil
}

// currentToken returns the static API token, or asks the token source.
func (c *Client) currentToken(ctx context.Context) (string, error) {
	if c.source != nil {
		return c.source.Token(ctx)
	}
	return c.token, nil
}

func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body []byte) (*Response, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		return nil, clierr.New(clierr.Usage, "invalid path %q", path)
	}
	for _, seg := range strings.Split(path[1:], "/") {
		dec, _ := url.PathUnescape(seg)
		if seg == "" || seg == "." || seg == ".." || dec == "." || dec == ".." || strings.ContainsAny(seg+dec, `/\`) {
			return nil, clierr.New(clierr.Usage, "invalid path %q", path)
		}
	}
	target := *c.base
	// Path holds the decoded form and RawPath the escaped one, so a%2Fb is sent as written.
	unescaped, err := url.PathUnescape(path)
	if err != nil {
		return nil, clierr.New(clierr.Usage, "invalid path %q", path)
	}
	target.Path, target.RawPath = unescaped, path
	target.RawQuery = query.Encode()

	token, err := c.currentToken(ctx)
	if err != nil {
		return nil, err
	}
	// used holds every token this request sent, so a reflected one is redacted from errors.
	used := []string{token}
	renewed := false
	// attempt counts 429 retries only; the single renewal after invalid_token does not count.
	attempt := 0
	for {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target.String(), rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", c.ua)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := c.hc.Do(req)
		if err != nil {
			if errors.Is(err, errCrossHost) {
				return nil, clierr.New(clierr.General, "%v", errCrossHost)
			}
			return nil, fmt.Errorf("request failed: %w", err)
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, int64(maxBody)+1))
		res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		if len(raw) > maxBody {
			return nil, fmt.Errorf("response is larger than %d MB", maxBody>>20)
		}
		if c.debug != nil {
			// Method, URL and status only. Headers are never printed, so the token cannot leak.
			fmt.Fprintf(c.debug, "%s %s -> %d (%d bytes)\n", method, target.String(), res.StatusCode, len(raw))
		}
		if res.StatusCode == http.StatusUnauthorized && c.source != nil && !renewed &&
			strings.Contains(res.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
			token, err = c.source.Renew(ctx, token)
			if err != nil {
				return nil, err
			}
			renewed = true
			used = append(used, token)
			continue
		}
		if res.StatusCode == http.StatusTooManyRequests && attempt < maxRetries-1 {
			wait := time.Second
			if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			if wait > maxWait {
				wait = maxWait
			}
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
			attempt++
			continue
		}
		if res.StatusCode >= 400 {
			// A server could echo the bearer token back; it must not reach the terminal.
			redact := func(s string) string {
				for _, t := range used {
					if t != "" {
						s = strings.ReplaceAll(s, t, "[redacted]")
					}
				}
				return s
			}
			ae := &APIError{Status: res.StatusCode}
			var parsed struct {
				Message string `json:"message"`
				Data    struct {
					Code          string `json:"code"`
					RequiredScope string `json:"requiredScope"`
				} `json:"data"`
			}
			if json.Unmarshal(raw, &parsed) == nil {
				ae.Message, ae.Code = redact(sanitize.Line(parsed.Message)), redact(sanitize.Line(parsed.Data.Code))
				if s := redact(sanitize.Line(parsed.Data.RequiredScope)); scopePattern.MatchString(s) {
					ae.RequiredScope = s
				}
			}
			ae.Hint = hintFor(ae, c.source != nil)
			return nil, ae
		}
		return &Response{Status: res.StatusCode, ContentType: res.Header.Get("Content-Type"), Body: raw}, nil
	}
}

// hintFor returns the next step for the CLI sign-in error codes of the server, or "".
func hintFor(ae *APIError, browserSignIn bool) string {
	switch {
	case (ae.Code == "cliScopeForbidden" || ae.Code == "paidQuotaUpgradeNotAuthorized") && ae.RequiredScope != "":
		return fmt.Sprintf("this sign-in lacks the scope %s: run `uptimeify auth login --scope %s` and grant it in the browser", ae.RequiredScope, ae.RequiredScope)
	case ae.Code == "cliPathForbidden":
		return "browser sign-ins cannot use this operation: use the dashboard, or an API token in UPTIMEIFY_TOKEN if the token's permissions allow it"
	case ae.Code == "cliPathAmbiguous":
		return "the server refuses paths with encoded slashes, dots, percent signs or double slashes for browser sign-ins: check the arguments"
	case ae.Status == http.StatusUnauthorized && browserSignIn:
		return "the sign-in was not accepted: run `uptimeify auth login`"
	}
	return ""
}
