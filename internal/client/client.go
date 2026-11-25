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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
)

// maxBody is a variable only so tests can lower it.
var maxBody = 50 << 20

const (
	maxRetries = 3
	maxWait    = 60 * time.Second
)

type Options struct {
	BaseURL               string
	Token                 string
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
	Body    []byte
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

// clean drops control characters from server text before it reaches the terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n':
			return ' '
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			return -1
		}
		return r
	}, s)
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
	base  *url.URL
	token string
	ua    string
	hc    *http.Client
	debug io.Writer
	sleep func(context.Context, time.Duration) error
}

var errCrossHost = errors.New("the server redirected to another host, refusing to follow")

func New(o Options) (*Client, error) {
	if o.Token == "" {
		return nil, clierr.New(clierr.Auth, "not signed in: set UPTIMEIFY_TOKEN")
	}
	u, err := url.Parse(o.BaseURL)
	if err != nil || u.Host == "" {
		return nil, clierr.New(clierr.Usage, "invalid API URL %q", o.BaseURL)
	}
	if u.User != nil {
		return nil, clierr.New(clierr.Usage, "the API URL must not contain credentials")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && u.Hostname() == "127.0.0.1" && o.AllowInsecureLoopback:
	default:
		return nil, clierr.New(clierr.Usage, "the API URL must use https (got %q)", o.BaseURL)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, clierr.New(clierr.Usage, "the API URL must not contain a path, query or fragment")
	}
	u.Path = ""
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
		base:  u,
		token: o.Token,
		ua:    fmt.Sprintf("uptimeify-cli/%s (%s/%s)", o.Version, runtime.GOOS, runtime.GOARCH),
		debug: o.Debug,
		sleep: sleep,
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

func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body []byte) (*Response, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		return nil, clierr.New(clierr.Usage, "invalid path %q", path)
	}
	target := *c.base
	target.Path = path
	target.RawQuery = query.Encode()

	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target.String(), rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
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
			continue
		}
		if res.StatusCode >= 400 {
			ae := &APIError{Status: res.StatusCode, Body: raw}
			var parsed struct {
				Message string `json:"message"`
				Data    struct {
					Code string `json:"code"`
				} `json:"data"`
			}
			if json.Unmarshal(raw, &parsed) == nil {
				ae.Message, ae.Code = clean(parsed.Message), clean(parsed.Data.Code)
			}
			return nil, ae
		}
		return &Response{Status: res.StatusCode, ContentType: res.Header.Get("Content-Type"), Body: raw}, nil
	}
}
