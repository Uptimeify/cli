package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
)

func oauthFixture(t *testing.T, h http.HandlerFunc) (*OAuth, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &OAuth{Origin: srv.URL, UserAgent: "uptimeify-cli/test"}, srv
}

// oauthReadForm reads an application/x-www-form-urlencoded body and checks that it holds exactly
// the keys want, each once.
func oauthReadForm(t *testing.T, r *http.Request, want ...string) url.Values {
	t.Helper()
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("content type = %q", ct)
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("Origin") != "" {
		t.Errorf("Authorization %q or Origin %q sent", r.Header.Get("Authorization"), r.Header.Get("Origin"))
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("read body: %v", err)
	}
	f, err := url.ParseQuery(string(raw))
	if err != nil {
		t.Errorf("parse form: %v", err)
	}
	if len(f) != len(want) {
		t.Errorf("form keys = %v, want %v", f, want)
	}
	for _, k := range want {
		if len(f[k]) != 1 {
			t.Errorf("form field %s = %v, want exactly one value", k, f[k])
		}
	}
	return f
}

func oauthTokenBody(access, refresh string) string {
	b, _ := json.Marshal(map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    900,
		"refresh_token": refresh,
		"scope":         "offline_access api:monitors:read",
	})
	return string(b)
}

func oauthRegistrationBody(origin string) string {
	b, _ := json.Marshal(map[string]any{
		"client_id":        "ucli_" + strings.Repeat("a", 32),
		"redirect_uri":     RegisteredRedirectURI,
		"resource":         origin + "/api/cli",
		"scopes_supported": AllScopes,
	})
	return string(b)
}

func TestRegisterRequestShape(t *testing.T) {
	o, srv := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/oauth/cli/clients" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content type = %q", ct)
		}
		for _, h := range []string{"Origin", "Sec-Fetch-Site", "Authorization"} {
			if v := r.Header.Get(h); v != "" {
				t.Errorf("%s = %q, must not be sent", h, v)
			}
		}
		if r.Header.Get("User-Agent") != "uptimeify-cli/test" {
			t.Errorf("user agent = %q", r.Header.Get("User-Agent"))
		}
		raw, _ := io.ReadAll(r.Body)
		if string(raw) != `{"device_name":"uptimeify CLI on h"}` {
			t.Errorf("body = %s", raw)
		}
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, oauthRegistrationBody("http://"+r.Host))
	})
	reg, err := o.Register(context.Background(), "uptimeify CLI on h")
	if err != nil {
		t.Fatal(err)
	}
	if reg.ClientID != "ucli_"+strings.Repeat("a", 32) || reg.RedirectURI != RegisteredRedirectURI || reg.Resource != srv.URL+"/api/cli" {
		t.Errorf("registration = %+v", reg)
	}
	if len(reg.ScopesSupported) != len(AllScopes) {
		t.Errorf("scopes_supported = %v", reg.ScopesSupported)
	}
}

func TestRegisterErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header map[string]string
		body   string
		exit   int
		want   string
	}{
		{"switched off", 404, nil, `{"statusCode":404,"message":"Not Found","data":{"code":"notFound"}}`, clierr.Auth, "UPTIMEIFY_TOKEN"},
		{"rate limited body", 429, nil, `{"data":{"code":"rateLimited","retryAfter":1800}}`, clierr.RateLimit, "30 minutes"},
		{"rate limited header", 429, map[string]string{"Retry-After": "120"}, `{"data":{"code":"rateLimited"}}`, clierr.RateLimit, "2 minutes"},
		{"starting", 503, nil, `{"data":{"code":"cliOauthUnavailable"}}`, clierr.General, "still starting"},
		{"bad name", 400, nil, `{"statusCode":400,"message":"Invalid device name","data":{"code":"cliDeviceNameInvalid"}}`, clierr.General, "cliDeviceNameInvalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			_, err := o.Register(context.Background(), "uptimeify CLI on h")
			if err == nil {
				t.Fatal("no error")
			}
			if clierr.ExitCode(err) != tc.exit || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v (exit %d), want exit %d containing %q", err, clierr.ExitCode(err), tc.exit, tc.want)
			}
		})
	}
}

func TestRegisterRejectsForeignAnswer(t *testing.T) {
	cases := []struct {
		field, value, want string
	}{
		{"resource", "https://evil.example/api/cli", "expected"},
		{"client_id", "abc", "unexpected client id"},
		{"redirect_uri", "http://127.0.0.1:5/callback", "unexpected redirect URI"},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
				var m map[string]any
				_ = json.Unmarshal([]byte(oauthRegistrationBody("http://"+r.Host)), &m)
				m[tc.field] = tc.value
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(m)
			})
			_, err := o.Register(context.Background(), "uptimeify CLI on h")
			if err == nil || !strings.Contains(err.Error(), tc.want) || clierr.ExitCode(err) != clierr.General {
				t.Errorf("err = %v, want exit 1 containing %q", err, tc.want)
			}
		})
	}
}

func TestAuthorizeURL(t *testing.T) {
	o := &OAuth{Origin: "https://uptimeify.io"}
	raw := o.AuthorizeURL("ucli_abc", "http://127.0.0.1:4711/callback", "st", "ch", []string{"api:monitors:read", "api:monitors:write"})
	prefix := "https://uptimeify.io/api/auth/oauth2/authorize?"
	if !strings.HasPrefix(raw, prefix) {
		t.Fatalf("url = %s", raw)
	}
	q, err := url.ParseQuery(strings.TrimPrefix(raw, prefix))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"client_id":             "ucli_abc",
		"response_type":         "code",
		"redirect_uri":          "http://127.0.0.1:4711/callback",
		"scope":                 "offline_access api:monitors:read api:monitors:write",
		"state":                 "st",
		"code_challenge":        "ch",
		"code_challenge_method": "S256",
		"resource":              "https://uptimeify.io/api/cli",
	}
	if len(q) != len(want) {
		t.Errorf("parameters = %v, want exactly %d", q, len(want))
	}
	for k, v := range want {
		if len(q[k]) != 1 || q[k][0] != v {
			t.Errorf("%s = %v, want [%s]", k, q[k], v)
		}
	}
	if q.Has("prompt") {
		t.Error("prompt must not be sent, the server sets it")
	}
	if !strings.HasPrefix(q.Get("scope"), "offline_access ") {
		t.Errorf("scope = %q", q.Get("scope"))
	}
}

func TestExchangeFormFields(t *testing.T) {
	code, verifier := "code-"+"1", strings.Repeat("v", 43)
	access, refresh := "at-"+"1", fmt.Sprintf("rt-%d", 1)
	o, srv := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/auth/oauth2/token" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		f := oauthReadForm(t, r, "grant_type", "code", "redirect_uri", "client_id", "code_verifier", "resource")
		want := map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  "http://127.0.0.1:4711/callback",
			"client_id":     "ucli_abc",
			"code_verifier": verifier,
			"resource":      "http://" + r.Host + "/api/cli",
		}
		for k, v := range want {
			if f.Get(k) != v {
				t.Errorf("%s = %q, want %q", k, f.Get(k), v)
			}
		}
		io.WriteString(w, oauthTokenBody(access, refresh))
	})
	tr, err := o.Exchange(context.Background(), "ucli_abc", code, verifier, "http://127.0.0.1:4711/callback")
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != access || tr.RefreshToken != refresh || tr.ExpiresIn != 900 || tr.Scope != "offline_access api:monitors:read" {
		t.Errorf("token answer = %+v", tr)
	}
	if o.Resource() != srv.URL+"/api/cli" {
		t.Errorf("resource = %s", o.Resource())
	}
}

func TestRefreshFormFields(t *testing.T) {
	refresh := fmt.Sprintf("rt-%d", 1)
	o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
		f := oauthReadForm(t, r, "grant_type", "refresh_token", "client_id", "resource")
		if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != refresh || f.Get("client_id") != "ucli_abc" || f.Get("resource") != "http://"+r.Host+"/api/cli" {
			t.Errorf("form = %v", f)
		}
		io.WriteString(w, oauthTokenBody("at-"+"2", fmt.Sprintf("rt-%d", 2)))
	})
	tr, err := o.Refresh(context.Background(), "ucli_abc", refresh)
	if err != nil {
		t.Fatal(err)
	}
	if tr.RefreshToken != fmt.Sprintf("rt-%d", 2) {
		t.Errorf("refresh token = %q", tr.RefreshToken)
	}
}

func TestTokenAnswerValidation(t *testing.T) {
	base := map[string]any{"access_token": "at-" + "1", "token_type": "Bearer", "expires_in": 900, "refresh_token": fmt.Sprintf("rt-%d", 2), "scope": "offline_access"}
	cases := map[string]func(m map[string]any){
		"without refresh token": func(m map[string]any) { delete(m, "refresh_token") },
		"token type mac":        func(m map[string]any) { m["token_type"] = "mac" },
		"expires_in zero":       func(m map[string]any) { m["expires_in"] = 0 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
				m := map[string]any{}
				for k, v := range base {
					m[k] = v
				}
				change(m)
				_ = json.NewEncoder(w).Encode(m)
			})
			if _, err := o.Refresh(context.Background(), "ucli_abc", fmt.Sprintf("rt-%d", 1)); err == nil || !strings.Contains(err.Error(), "incomplete") {
				t.Errorf("err = %v, want incomplete", err)
			}
		})
	}
	t.Run("expires_in capped", func(t *testing.T) {
		o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
			m := map[string]any{}
			for k, v := range base {
				m[k] = v
			}
			m["expires_in"] = 3600
			_ = json.NewEncoder(w).Encode(m)
		})
		tr, err := o.Refresh(context.Background(), "ucli_abc", fmt.Sprintf("rt-%d", 1))
		if err != nil {
			t.Fatal(err)
		}
		if tr.ExpiresIn != 900 {
			t.Errorf("expires_in = %d, want 900", tr.ExpiresIn)
		}
	})
}

func TestTokenErrors(t *testing.T) {
	refresh := fmt.Sprintf("rt-%d", 12345)
	t.Run("invalid_grant", func(t *testing.T) {
		o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "invalid refresh token " + refresh})
		})
		_, err := o.Refresh(context.Background(), "ucli_abc", refresh)
		var oe *OAuthError
		if !errors.As(err, &oe) {
			t.Fatalf("err = %v, want *OAuthError", err)
		}
		if oe.Status != 400 || oe.Code != "invalid_grant" {
			t.Errorf("OAuthError = %+v", oe)
		}
		if strings.Contains(err.Error(), refresh) || !strings.Contains(oe.Description, "[redacted]") {
			t.Errorf("refresh token not redacted: %v", err)
		}
	})
	t.Run("rate limited", func(t *testing.T) {
		o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
		})
		_, err := o.Refresh(context.Background(), "ucli_abc", refresh)
		var re *RateLimitError
		if !errors.As(err, &re) || re.RetryAfter.Seconds() != 7 {
			t.Fatalf("err = %v, want *RateLimitError with 7 s", err)
		}
		if !strings.Contains(err.Error(), "7 seconds") {
			t.Errorf("message = %v", err)
		}
	})
	t.Run("server error", func(t *testing.T) {
		o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"error":"server_error"}`)
		})
		_, err := o.Refresh(context.Background(), "ucli_abc", refresh)
		var oe *OAuthError
		var ns *NotSentError
		if err == nil || errors.As(err, &oe) || errors.As(err, &ns) {
			t.Fatalf("err = %v, want a plain error", err)
		}
	})
}

func TestTokenNeverFollowsRedirect(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(other.Close)
	o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/auth/oauth2/token", http.StatusTemporaryRedirect)
	})
	_, err := o.Refresh(context.Background(), "ucli_abc", fmt.Sprintf("rt-%d", 1))
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v, want a redirect refusal", err)
	}
	// A caller's own client, which would follow redirects, does not lift the rule.
	o.HTTP = &http.Client{}
	_, err = o.Refresh(context.Background(), "ucli_abc", fmt.Sprintf("rt-%d", 1))
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("own client: err = %v, want a redirect refusal", err)
	}
	if o.HTTP.CheckRedirect != nil {
		t.Error("the caller's client was changed")
	}
	if hits.Load() != 0 {
		t.Errorf("the other server got %d requests", hits.Load())
	}
}

func TestNotSentVsSent(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	origin := closed.URL
	closed.Close()
	o := &OAuth{Origin: origin, UserAgent: "uptimeify-cli/test"}
	_, err := o.Refresh(context.Background(), "ucli_abc", fmt.Sprintf("rt-%d", 1))
	var ns *NotSentError
	if !errors.As(err, &ns) {
		t.Fatalf("closed server: err = %v, want *NotSentError", err)
	}

	o, _ = oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		conn.Close()
	})
	_, err = o.Refresh(context.Background(), "ucli_abc", fmt.Sprintf("rt-%d", 1))
	if err == nil || errors.As(err, &ns) {
		t.Fatalf("connection dropped after the request: err = %v, want an error that is not *NotSentError", err)
	}
}

func TestOAuthBodyLimit(t *testing.T) {
	old := maxOAuthBody
	maxOAuthBody = 1024
	t.Cleanup(func() { maxOAuthBody = old })
	o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("a", 2048))
	})
	_, err := o.Refresh(context.Background(), "ucli_abc", fmt.Sprintf("rt-%d", 1))
	if err == nil || !strings.Contains(err.Error(), "larger than 1 KB") {
		t.Fatalf("err = %v", err)
	}
}

func TestOAuthDebugHasNoSecrets(t *testing.T) {
	code, verifier, refresh := "code-"+"1", strings.Repeat("v", 43), fmt.Sprintf("rt-%d", 1)
	var debug bytes.Buffer
	o, srv := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, oauthTokenBody("at-"+"9", fmt.Sprintf("rt-%d", 2)))
	})
	o.Debug = &debug
	if _, err := o.Exchange(context.Background(), "ucli_abc", code, verifier, "http://127.0.0.1:4711/callback"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Refresh(context.Background(), "ucli_abc", refresh); err != nil {
		t.Fatal(err)
	}
	out := debug.String()
	if !strings.Contains(out, "POST "+srv.URL+"/api/auth/oauth2/token -> 200") {
		t.Errorf("debug = %q", out)
	}
	for _, secret := range []string{code, verifier, refresh, fmt.Sprintf("rt-%d", 2)} {
		if strings.Contains(out, secret) {
			t.Errorf("debug output contains %q", secret)
		}
	}
}

func TestRevokeForm(t *testing.T) {
	refresh := fmt.Sprintf("rt-%d", 1)
	var status atomic.Int32
	status.Store(http.StatusOK)
	o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/auth/oauth2/revoke" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		f := oauthReadForm(t, r, "token", "token_type_hint", "client_id")
		if f.Get("token") != refresh || f.Get("token_type_hint") != "refresh_token" || f.Get("client_id") != "ucli_abc" {
			t.Errorf("form = %v", f)
		}
		w.WriteHeader(int(status.Load()))
	})
	if err := o.Revoke(context.Background(), "ucli_abc", refresh); err != nil {
		t.Fatalf("200: err = %v", err)
	}
	status.Store(http.StatusBadRequest)
	if err := o.Revoke(context.Background(), "ucli_abc", refresh); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("400: err = %v", err)
	}
}

func TestRetryAfterIsCappedAndIgnoresBadValues(t *testing.T) {
	cases := map[string]time.Duration{
		"120":                  120 * time.Second,
		"99999999":             86400 * time.Second,
		"99999999999999999999": 86400 * time.Second,
		"-5":                   60 * time.Second,
		"0":                    60 * time.Second,
		"soon":                 60 * time.Second,
		"":                     60 * time.Second,
	}
	for in, want := range cases {
		h := http.Header{}
		if in != "" {
			h.Set("Retry-After", in)
		}
		if got := retryAfter(h, nil); got != want {
			t.Errorf("Retry-After %q = %v, want %v", in, got, want)
		}
	}
}

// A 3xx answer is an error and is never followed, so no secret can be sent to the Location.
func TestRegisterAndRevokeDoNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer target.Close()
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		o, _ := oauthFixture(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/steal", status)
		})
		if _, err := o.Register(context.Background(), "dev"); err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Errorf("Register after %d: err = %v, want a redirect error", status, err)
		}
		if err := o.Revoke(context.Background(), "ucli_"+strings.Repeat("a", 8), "rt-1"); err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Errorf("Revoke after %d: err = %v, want a redirect error", status, err)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("the redirect target was called %d times", hits.Load())
	}
}
