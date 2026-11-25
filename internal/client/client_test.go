package client

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	for _, u := range []string{"http://uptimeify.io", "http://localhost:3000", "ftp://uptimeify.io", "https://user:pw@uptimeify.io", ""} {
		if _, err := New(Options{BaseURL: u, Token: "t", AllowInsecureLoopback: true}); err == nil {
			t.Errorf("New(%q) accepted an unsafe URL", u)
		}
	}
	if _, err := New(Options{BaseURL: "http://127.0.0.1:3000", Token: "t"}); err == nil {
		t.Error("loopback http accepted without the opt-in")
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
