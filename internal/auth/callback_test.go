package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
)

type cbOutcome struct {
	code string
	err  error
}

// cbStart opens a loopback listener and runs waitForCallback on it in a goroutine.
func cbStart(t *testing.T, state string) (redirectURI string, done <-chan cbOutcome) {
	t.Helper()
	ln, redirectURI, err := listenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	ch := make(chan cbOutcome, 1)
	go func() {
		code, err := waitForCallback(ctx, ln, state)
		ch <- cbOutcome{code, err}
	}()
	return redirectURI, ch
}

func cbWait(t *testing.T, done <-chan cbOutcome) cbOutcome {
	t.Helper()
	select {
	case o := <-done:
		return o
	case <-time.After(10 * time.Second):
		t.Fatal("waitForCallback did not return")
	}
	return cbOutcome{}
}

func cbDo(t *testing.T, req *http.Request) (int, http.Header, string) {
	t.Helper()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(body)
}

func cbGet(t *testing.T, target string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cbDo(t, req)
}

func cbState(t *testing.T) string {
	t.Helper()
	s, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPKCE(t *testing.T) {
	shape := regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	a, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if !shape.MatchString(a.verifier) {
		t.Errorf("verifier = %q", a.verifier)
	}
	sum := sha256.Sum256([]byte(a.verifier))
	if a.challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Errorf("challenge does not match S256 of the verifier")
	}
	if a.verifier == b.verifier || a.challenge == b.challenge {
		t.Error("two PKCE pairs are equal")
	}
	if s := cbState(t); !shape.MatchString(s) {
		t.Errorf("randomToken = %q", s)
	}
}

func TestListenLoopbackBindsOnlyLoopback(t *testing.T) {
	ln, redirectURI, err := listenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	if addr.IP.String() != "127.0.0.1" {
		t.Errorf("listening on %s", addr.IP)
	}
	if !regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]+/callback$`).MatchString(redirectURI) {
		t.Errorf("redirect URI = %q", redirectURI)
	}
	if want := fmt.Sprintf("http://127.0.0.1:%d/callback", addr.Port); redirectURI != want {
		t.Errorf("redirect URI = %q, want %q", redirectURI, want)
	}
}

func TestCallbackSuccess(t *testing.T) {
	state := cbState(t)
	redirectURI, done := cbStart(t, state)
	status, header, body := cbGet(t, redirectURI+"?code=c1&state="+state)
	o := cbWait(t, done)
	if o.err != nil || o.code != "c1" {
		t.Fatalf("outcome = %+v", o)
	}
	if status != http.StatusOK || !strings.Contains(body, "Signed in") || strings.Contains(body, "c1") {
		t.Errorf("page %d: %s", status, body)
	}
	want := map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
	}
	for k, v := range want {
		if got := header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// A callback without the state of this sign-in is not the browser's answer: it gets the same 404
// as any other request, its error parameter is never read, and the receiver keeps waiting.
func TestCallbackWrongStateIsIgnored(t *testing.T) {
	state := cbState(t)
	redirectURI, done := cbStart(t, state)
	for _, q := range []string{
		"?code=c1&state=wrong",
		"?code=c1",
		"?code=c1&state=",
		"?code=c1&state=" + state + "&state=" + state,
		"?error=access_denied&state=wrong",
		"?error=access_denied",
	} {
		status, _, body := cbGet(t, redirectURI+q)
		if status != http.StatusNotFound || strings.Contains(body, "Sign-in failed") || strings.Contains(body, "Signed in") {
			t.Errorf("%s: page %d: %s", q, status, body)
		}
	}
	select {
	case o := <-done:
		t.Fatalf("a callback without the right state ended the wait: %+v", o)
	default:
	}

	if status, _, _ := cbGet(t, redirectURI+"?code=c1&state="+state); status != http.StatusOK {
		t.Errorf("valid callback = %d", status)
	}
	if o := cbWait(t, done); o.err != nil || o.code != "c1" {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestCallbackDeclined(t *testing.T) {
	state := cbState(t)
	redirectURI, done := cbStart(t, state)
	cbGet(t, redirectURI+"?error=access_denied&error_description=User%20denied&state="+state)
	o := cbWait(t, done)
	if o.err == nil || !strings.Contains(o.err.Error(), "access_denied") || !strings.Contains(o.err.Error(), "User denied") {
		t.Fatalf("outcome = %+v", o)
	}
	if clierr.ExitCode(o.err) != clierr.Auth {
		t.Errorf("exit = %d", clierr.ExitCode(o.err))
	}
}

func TestCallbackIgnoresOtherRequests(t *testing.T) {
	state := cbState(t)
	redirectURI, done := cbStart(t, state)
	base := strings.TrimSuffix(redirectURI, "/callback")
	valid := redirectURI + "?code=c1&state=" + state

	if status, _, _ := cbGet(t, base+"/favicon.ico"); status != http.StatusNotFound {
		t.Errorf("GET /favicon.ico = %d", status)
	}
	post, _ := http.NewRequest(http.MethodPost, valid, nil)
	if status, _, _ := cbDo(t, post); status != http.StatusNotFound {
		t.Errorf("POST /callback = %d", status)
	}
	u, _ := url.Parse(redirectURI)
	foreign, _ := http.NewRequest(http.MethodGet, valid, nil)
	foreign.Host = "localhost:" + u.Port()
	if status, _, _ := cbDo(t, foreign); status != http.StatusNotFound {
		t.Errorf("GET with Host localhost = %d", status)
	}
	select {
	case o := <-done:
		t.Fatalf("a rejected request ended the wait: %+v", o)
	default:
	}

	if status, _, _ := cbGet(t, valid); status != http.StatusOK {
		t.Errorf("valid callback = %d", status)
	}
	if o := cbWait(t, done); o.err != nil || o.code != "c1" {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestCallbackOnlyOnce(t *testing.T) {
	state := cbState(t)
	redirectURI, done := cbStart(t, state)
	// The first callback with the right state is the one, whatever it says.
	status, _, body := cbGet(t, redirectURI+"?error=access_denied&state="+state)
	if status != http.StatusBadRequest || !strings.Contains(body, "Sign-in failed") {
		t.Errorf("page %d: %s", status, body)
	}
	if o := cbWait(t, done); o.err == nil {
		t.Fatalf("outcome = %+v", o)
	}
	res, err := http.Get(redirectURI + "?code=c1&state=" + state)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode == http.StatusOK {
			t.Fatal("a second request was accepted after the first one ended the wait")
		}
	}
}

func TestCallbackDuplicateParams(t *testing.T) {
	state := cbState(t)
	redirectURI, done := cbStart(t, state)
	if status, _, _ := cbGet(t, redirectURI+"?code=c1&state="+state+"&state="+state); status != http.StatusNotFound {
		t.Errorf("duplicate state = %d, want 404", status)
	}
	select {
	case o := <-done:
		t.Fatalf("a duplicate state ended the wait: %+v", o)
	default:
	}

	// With the right state the request is the one: a duplicate code ends the sign-in.
	cbGet(t, redirectURI+"?code=a&code=b&state="+state)
	if o := cbWait(t, done); o.err == nil || !strings.Contains(o.err.Error(), "no authorization code") {
		t.Errorf("duplicate code: outcome = %+v", o)
	}
}

func TestCallbackTimeout(t *testing.T) {
	ln, _, err := listenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := waitForCallback(ctx, ln, cbState(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("the listener is still open after the timeout")
	}
}

func TestCallbackSanitisesBrowserError(t *testing.T) {
	state := cbState(t)
	redirectURI, done := cbStart(t, state)
	cbGet(t, redirectURI+"?error=%1b%5b31mx&state="+state)
	o := cbWait(t, done)
	if o.err == nil || strings.Contains(o.err.Error(), "\x1b") || !strings.Contains(o.err.Error(), "[31mx") {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestBrowserCommand(t *testing.T) {
	addr := "https://a.example/x?y=1&z=2"
	want := map[string][]string{
		"darwin":  {"/usr/bin/open", addr},
		"windows": {"rundll32", "url.dll,FileProtocolHandler", addr},
		"linux":   {"xdg-open", addr},
		"freebsd": {"xdg-open", addr},
	}
	for goos, args := range want {
		cmd, err := browserCommand(goos, addr)
		if err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		if !slices.Equal(cmd.Args, args) {
			t.Errorf("%s: args = %q, want %q", goos, cmd.Args, args)
		}
		if cmd.Stdout != nil || cmd.Stderr != nil {
			t.Errorf("%s: output is wired", goos)
		}
	}
	if _, err := browserCommand("linux", "http://127.0.0.1:4711/x"); err != nil {
		t.Errorf("loopback address refused: %v", err)
	}
	for _, bad := range []string{
		"file:///etc/passwd",
		"http://example.com",
		"http://127.0.0.1.evil.example/x",
		"https://a b",
		"https://a\nb",
		"https://a\x7fb",
		"javascript:alert(1)",
	} {
		if cmd, err := browserCommand("linux", bad); err == nil || cmd != nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestBrowserCommandChecksTheParsedAddress(t *testing.T) {
	for _, bad := range []string{
		"http://127.0.0.1.evil.example/x",
		"http://127.0.0.1@evil.example/x",
		"http://user:pw@127.0.0.1:1/x",
		"https://user@uptimeify.io/x",
		"http://localhost:1/x",
		"https:///x",
		"https:opaque",
	} {
		if cmd, err := browserCommand("linux", bad); err == nil || cmd != nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	cmd, err := browserCommand("linux", "https://uptimeify.io/a?b=1&c=2")
	if err != nil || cmd.Args[len(cmd.Args)-1] != "https://uptimeify.io/a?b=1&c=2" || len(cmd.Args) != 2 {
		t.Errorf("cmd = %v, err = %v", cmd, err)
	}
}
