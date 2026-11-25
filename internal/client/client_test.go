package client

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
)

func newTest(t *testing.T, h http.HandlerFunc, debug *bytes.Buffer) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	o := Options{BaseURL: srv.URL, Token: "wsm_secret", Version: "test", AllowInsecureLoopback: true, Sleep: func(time.Duration) {}}
	if debug != nil {
		o.Debug = debug
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func TestNewRejectsUnsafeURLs(t *testing.T) {
	for _, u := range []string{"http://uptimeify.io", "http://localhost:3000", "ftp://uptimeify.io", "https://user:pw@uptimeify.io", "", "https://uptimeify.io/prefix", "https://uptimeify.io/?x=1", "https://uptimeify.io/#f"} {
		if _, err := New(Options{BaseURL: u, Token: "t", AllowInsecureLoopback: true}); err == nil {
			t.Errorf("New(%q) accepted an unsafe URL", u)
		}
	}
	if _, err := New(Options{BaseURL: "http://127.0.0.1:3000", Token: "t"}); err == nil {
		t.Error("loopback http accepted without the opt-in")
	}
	for _, ok := range []string{"https://uptimeify.io", "https://uptimeify.io/"} {
		if _, err := New(Options{BaseURL: ok, Token: "t"}); err != nil {
			t.Errorf("New(%q) rejected: %v", ok, err)
		}
	}
	if _, err := New(Options{BaseURL: "https://uptimeify.io", Token: ""}); err == nil {
		t.Error("empty token accepted")
	}
}

func TestDoSendsTokenAndUserAgent(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wsm_secret" {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "uptimeify-cli/test (") {
			t.Errorf("user agent = %q", r.Header.Get("User-Agent"))
		}
		if r.URL.Path != "/api/websites" || r.URL.Query().Get("search") != "a b" {
			t.Errorf("url = %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"items":[]}`))
	}, nil)
	res, err := c.Do(context.Background(), "GET", "/api/websites", map[string][]string{"search": {"a b"}}, nil)
	if err != nil || res.Status != 200 || string(res.Body) != `{"items":[]}` {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestDoNeverFollowsRedirectToOtherHost(t *testing.T) {
	leaked := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
	}))
	defer other.Close()
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}, nil)
	_, err := c.Do(context.Background(), "GET", "/api/websites", nil, nil)
	if err == nil {
		t.Fatal("redirect to another host was not treated as an error")
	}
	if leaked {
		t.Fatal("request reached the other host")
	}
	// Must fail for the right reason (our guard), not a generic transport error.
	if !strings.Contains(err.Error(), "another host") {
		t.Fatalf("error is not the cross-host guard: %v", err)
	}
	if strings.Contains(err.Error(), "wsm_secret") {
		t.Fatal("token in error message")
	}
}

func TestDoFollowsSameHostRedirect(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/a" {
			http.Redirect(w, r, "/api/b", http.StatusFound)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}, nil)
	res, err := c.Do(context.Background(), "GET", "/api/a", nil, nil)
	if err != nil || string(res.Body) != `{"ok":true}` {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestDoRetriesOn429(t *testing.T) {
	calls := 0
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		w.Write([]byte(`{}`))
	}, nil)
	if _, err := c.Do(context.Background(), "POST", "/api/x", nil, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestDoGivesUpAfterRetries(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) }, nil)
	_, err := c.Do(context.Background(), "GET", "/api/x", nil, nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.ExitCode() != 5 {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIErrorMapping(t *testing.T) {
	cases := map[int]int{400: 2, 401: 3, 403: 3, 404: 4, 409: 1, 422: 2, 500: 1}
	for status, want := range cases {
		c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			w.Write([]byte(`{"statusCode":0,"message":"nope","data":{"code":"someCode"}}`))
		}, nil)
		_, err := c.Do(context.Background(), "GET", "/api/x", nil, nil)
		var ae *APIError
		if !errors.As(err, &ae) {
			t.Fatalf("status %d: err = %v", status, err)
		}
		if ae.ExitCode() != want || ae.Code != "someCode" || ae.Message != "nope" {
			t.Errorf("status %d: %+v exit %d, want %d", status, ae, ae.ExitCode(), want)
		}
	}
}

func TestDebugNeverPrintsToken(t *testing.T) {
	var buf bytes.Buffer
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }, &buf)
	if _, err := c.Do(context.Background(), "GET", "/api/x", nil, nil); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 || strings.Contains(buf.String(), "wsm_secret") {
		t.Fatalf("debug output wrong: %q", buf.String())
	}
}

func TestDoCancelsRetryWaitWithContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(429)
	}))
	defer srv.Close()
	c, err := New(Options{BaseURL: srv.URL, Token: "t", AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.Do(ctx, "GET", "/api/x", nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestAPIErrorStripsControlCharacters(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"message":"\u001b]0;evil\u0007ok\u009b\ta\nb","data":{"code":"c\u001bd"}}`))
	}, nil)
	_, err := c.Do(context.Background(), "GET", "/api/x", nil, nil)
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatal(err)
	}
	s := ae.Error()
	if strings.ContainsAny(s, "\x1b\x07\u009b") || !strings.Contains(s, "ok") {
		t.Fatalf("not sanitised: %q", s)
	}
	if ae.Message != "]0;evilok a b" || ae.Code != "cd" {
		t.Fatalf("message %q code %q", ae.Message, ae.Code)
	}
}

func TestDoRejectsMalformedPaths(t *testing.T) {
	var hits atomic.Int32
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte(`{}`)) }, nil)
	for _, p := range []string{"api/x", "/api/x?y=1", "/api/x#z"} {
		_, err := c.Do(context.Background(), "GET", p, nil, nil)
		if err == nil || clierr.ExitCode(err) != clierr.Usage {
			t.Errorf("path %q: err = %v", p, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("server got %d requests", hits.Load())
	}
	var evil atomic.Int32
	evilSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { evil.Add(1) }))
	defer evilSrv.Close()
	_, err := c.Do(context.Background(), "GET", "//"+strings.TrimPrefix(evilSrv.URL, "http://")+"/x", nil, nil)
	if clierr.ExitCode(err) != clierr.Usage {
		t.Errorf("host-looking path: err = %v", err)
	}
	if evil.Load() != 0 {
		t.Fatal("request reached the evil host")
	}
}

func TestDoRejectsDotAndEmptySegments(t *testing.T) {
	var hits atomic.Int32
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte(`{}`)) }, nil)
	for _, p := range []string{"/api/x/..", "/api/x/../y", "/api/x/./y", "/api/x//y", "/api/x/", "/api/x/%2e%2e", "/api/x/%2E", "//evil.example/x"} {
		_, err := c.Do(context.Background(), "GET", p, nil, nil)
		if err == nil || clierr.ExitCode(err) != clierr.Usage {
			t.Errorf("path %q: err = %v", p, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("server got %d requests", hits.Load())
	}
}

func TestDoRefusesRedirectToOtherPort(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}, nil)
	_, err := c.Do(context.Background(), "GET", "/api/x", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "another host") {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("request reached the other port")
	}
}

func TestDoRejectsOversizedResponse(t *testing.T) {
	old := maxBody
	maxBody = 1024
	t.Cleanup(func() { maxBody = old })
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", 2048)))
	}, nil)
	if _, err := c.Do(context.Background(), "GET", "/api/x", nil, nil); err == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestRetryAfterIsCapped(t *testing.T) {
	var waits []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "99999")
		w.WriteHeader(429)
	}))
	defer srv.Close()
	c, err := New(Options{BaseURL: srv.URL, Token: "t", AllowInsecureLoopback: true, Sleep: func(d time.Duration) { waits = append(waits, d) }})
	if err != nil {
		t.Fatal(err)
	}
	c.Do(context.Background(), "GET", "/api/x", nil, nil)
	if len(waits) == 0 || waits[0] != 60*time.Second {
		t.Fatalf("waits = %v", waits)
	}
}

func TestDoKeepsEscapedPathSegments(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/x/a%20b" {
			t.Errorf("escaped path = %q", r.URL.EscapedPath())
		}
		w.Write([]byte(`{}`))
	}, nil)
	if _, err := c.Do(context.Background(), "GET", "/api/x/a%20b", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDoRejectsEncodedSlashes(t *testing.T) {
	var hits atomic.Int32
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }, nil)
	for _, p := range []string{"/api/x/a%2Fb", "/api/x/a%2fb", "/api/x/a%5Cb", "/api/x/a%5cb", "/api/x/a\\b"} {
		if _, err := c.Do(context.Background(), "GET", p, nil, nil); clierr.ExitCode(err) != clierr.Usage {
			t.Errorf("%q: err = %v", p, err)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("%d requests reached the server", hits.Load())
	}
}

func TestBidiControlInServerMessageIsRemoved(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"message":"ab\u202ecd","data":{"code":"x\u2066y"}}`))
	}, nil)
	_, err := c.Do(context.Background(), "GET", "/api/websites", nil, nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Message != "abcd" || ae.Code != "xy" || strings.ContainsAny(err.Error(), "\u202e\u2066") {
		t.Fatalf("err = %v, ae = %+v", err, ae)
	}
}

func TestNewErrorsDoNotEchoURL(t *testing.T) {
	for _, u := range []string{"http://%zz-SECRETVALUE", "http://example.com/SECRETVALUE?k=SECRETVALUE"} {
		_, err := New(Options{BaseURL: u, Token: "t"})
		if err == nil || strings.Contains(err.Error(), "SECRETVALUE") {
			t.Errorf("New(%q) error = %v", u, err)
		}
	}
}

func TestCheckBaseURL(t *testing.T) {
	if CheckBaseURL("https://uptimeify.io", false) != nil || CheckBaseURL("http://127.0.0.1:1", true) != nil {
		t.Error("valid URL rejected")
	}
	if CheckBaseURL("http://127.0.0.1:1", false) == nil || CheckBaseURL("http://example.com", true) == nil {
		t.Error("invalid URL accepted")
	}
}

func TestReflectedTokenIsRedacted(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"message":"bad token wsm_secret here","data":{"code":"x wsm_secret"}}`))
	}, nil)
	_, err := c.Do(context.Background(), "GET", "/api/websites", nil, nil)
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v", err)
	}
	for _, s := range []string{err.Error(), ae.Message, ae.Code} {
		if strings.Contains(s, "wsm_secret") {
			t.Errorf("token leaked in %q", s)
		}
	}
	if !strings.Contains(ae.Message, "[redacted]") {
		t.Errorf("message = %q", ae.Message)
	}
}

func TestSuccessBodyNotAltered(t *testing.T) {
	c, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"note":"wsm_secret"}`))
	}, nil)
	res, err := c.Do(context.Background(), "GET", "/api/websites", nil, nil)
	if err != nil || string(res.Body) != `{"note":"wsm_secret"}` {
		t.Errorf("res = %+v, err = %v", res, err)
	}
}
