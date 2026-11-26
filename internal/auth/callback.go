package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
)

// The pages the browser shows after the redirect. Fixed text: no code, no token, nothing from the
// query.
const (
	successPage = `<!doctype html><meta charset="utf-8"><title>Uptimeify CLI</title><p>Signed in. You can close this tab and return to the terminal.</p>`
	failurePage = `<!doctype html><meta charset="utf-8"><title>Uptimeify CLI</title><p>Sign-in failed. Return to the terminal for details.</p>`
)

type pkce struct{ verifier, challenge string }

// randomToken returns 32 bytes from crypto/rand, base64url without padding (43 characters).
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// newPKCE returns a verifier and its S256 challenge. The verifier stays in this process.
func newPKCE() (pkce, error) {
	v, err := randomToken()
	if err != nil {
		return pkce{}, err
	}
	sum := sha256.Sum256([]byte(v))
	return pkce{verifier: v, challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// listenLoopback opens a random free port on 127.0.0.1 only, never on all interfaces.
func listenLoopback() (ln net.Listener, redirectURI string, err error) {
	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("could not open a local port for the browser to return to: %w", err)
	}
	return ln, fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port), nil
}

type callbackResult struct {
	code string
	err  error
}

// stateMatches reports whether q carries exactly one state and it equals want. The comparison
// takes the same time for every wrong value of the same length.
func stateMatches(q url.Values, want string) bool {
	got := q["state"]
	return want != "" && len(got) == 1 && subtle.ConstantTimeCompare([]byte(got[0]), []byte(want)) == 1
}

// evaluateCallback reads the answer of a callback whose state already matched. Only then is an
// error parameter believed: without the state anyone on this computer could send one.
func evaluateCallback(q url.Values) callbackResult {
	if q.Has("error") {
		text := clean(q.Get("error"))
		if d := clean(q.Get("error_description")); d != "" {
			text += ": " + d
		}
		return callbackResult{err: clierr.New(clierr.Auth, "the sign-in was not completed in the browser: %s", text)}
	}
	if len(q["code"]) != 1 || q.Get("code") == "" {
		return callbackResult{err: clierr.New(clierr.Auth, "the browser returned no authorization code: run `uptimeify auth login` again")}
	}
	return callbackResult{code: q.Get("code")}
}

// newReceiverServer is the loopback receiver's server with tight limits: it only ever sees one
// short GET from the browser.
func newReceiverServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		MaxHeaderBytes:    8 << 10,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}

// waitForCallback serves ln until exactly one GET /callback with the right Host header and the
// state of this sign-in arrived, or ctx ends. The state is checked first. Every other request
// (other path, method or Host, missing, repeated or wrong state, anything after the one) gets 404,
// ends nothing and does not count; a stray request on the loopback port cannot cancel the sign-in.
// The server always shuts down before it returns, and ln is closed.
func waitForCallback(ctx context.Context, ln net.Listener, state string) (code string, err error) {
	host := ln.Addr().String()
	results := make(chan callbackResult, 1)
	var handled atomic.Bool
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host || r.URL.Path != "/callback" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if !stateMatches(q, state) || !handled.CompareAndSwap(false, true) {
			http.NotFound(w, r)
			return
		}
		res := evaluateCallback(q)
		page, status := successPage, http.StatusOK
		if res.err != nil {
			page, status = failurePage, http.StatusBadRequest
		}
		hd := w.Header()
		hd.Set("Content-Type", "text/html; charset=utf-8")
		hd.Set("Cache-Control", "no-store")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Content-Security-Policy", "default-src 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, page)
		results <- res
	})
	srv := newReceiverServer(h)
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx) // waits for the page to go out
		_ = ln.Close()         // in case Serve had not started yet
	}()
	select {
	case res := <-results:
		return res.code, res.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
