package auth

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/uptimeify/cli/internal/clierr"
)

var scopeForm = regexp.MustCompile(`^api:[a-z][a-z-]*:(read|write)$`)

func TestAllScopesMatchServer(t *testing.T) {
	if len(AllScopes) != 28 {
		t.Fatalf("len(AllScopes) = %d, want 28", len(AllScopes))
	}
	seen := map[string]bool{}
	for _, s := range AllScopes {
		if seen[s] {
			t.Errorf("duplicate scope %q", s)
		}
		seen[s] = true
		if !scopeForm.MatchString(s) {
			t.Errorf("scope %q does not have the server's form", s)
		}
	}
}

func TestDefaultScopesExcludeSeparateScopes(t *testing.T) {
	d := DefaultScopes()
	if len(d) != 11 {
		t.Fatalf("len(DefaultScopes()) = %d, want 11", len(d))
	}
	for _, s := range d {
		if !strings.HasSuffix(s, ":read") {
			t.Errorf("default scopes contain %q, want read scopes only", s)
		}
		for _, p := range []string{"api:users:", "api:billing:", "api:audit:", "api:statuspage-subscribers:"} {
			if strings.HasPrefix(s, p) {
				t.Errorf("default scopes contain %q", s)
			}
		}
	}
	d[0] = "changed"
	if AllScopes[0] != "api:monitors:read" {
		t.Fatalf("changing the returned slice changed AllScopes: %q", AllScopes[0])
	}
}

func TestWriteScopes(t *testing.T) {
	w := WriteScopes()
	if len(w) != 11 {
		t.Fatalf("len(WriteScopes()) = %d, want 11", len(w))
	}
	for _, s := range w {
		if !strings.HasSuffix(s, ":write") || slices.Contains(DefaultScopes(), s) {
			t.Errorf("unexpected write scope %q", s)
		}
		for _, p := range []string{"api:users:", "api:billing:"} {
			if strings.HasPrefix(s, p) {
				t.Errorf("write scopes contain %q", s)
			}
		}
	}
	got, err := RequestScopes(w)
	if err != nil || len(got) != 22 {
		t.Fatalf("read plus write: %d scopes, %v", len(got), err)
	}
}

func TestRequestScopes(t *testing.T) {
	got, err := RequestScopes(nil)
	if err != nil || !slices.Equal(got, DefaultScopes()) {
		t.Fatalf("RequestScopes(nil) = %v, %v", got, err)
	}

	got, err = RequestScopes([]string{"api:billing:write"})
	if err != nil || len(got) != 12 {
		t.Fatalf("with billing: %v, %v", got, err)
	}
	if got[11] != "api:billing:write" {
		t.Errorf("api:billing:write at the wrong place: %v", got)
	}
	last := -1
	for _, s := range got {
		i := slices.Index(AllScopes, s)
		if i <= last {
			t.Fatalf("not in AllScopes order: %v", got)
		}
		last = i
	}

	got, err = RequestScopes([]string{" api:monitors:read ", ""})
	if err != nil || !slices.Equal(got, DefaultScopes()) {
		t.Errorf("duplicate of a default scope: %v, %v", got, err)
	}

	_, err = RequestScopes([]string{"api:bogus:read"})
	if clierr.ExitCode(err) != clierr.Usage || !strings.Contains(err.Error(), "api:bogus:read") {
		t.Errorf("unknown scope: err = %v", err)
	}
}

func TestDeviceName(t *testing.T) {
	cases := map[string]string{
		"Pascals-MacBook.local":            "uptimeify CLI on Pascals-MacBook.local",
		"a" + string(rune(0x202e)) + "b c": "uptimeify CLI on abc",
		"":                                 "uptimeify CLI on unknown host",
	}
	for in, want := range cases {
		if got := DeviceName(in); got != want {
			t.Errorf("DeviceName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := DeviceName(strings.Repeat("x", 200)); len(got) != 64 {
		t.Errorf("long hostname: len = %d, want 64", len(got))
	}
	// Bidi override (U+202E) and zero-width space (U+200B) are built at run time, so the source
	// file holds no invisible characters.
	for _, in := range []string{"Pascals-MacBook.local", "a" + string(rune(0x202e)) + "b c", "", strings.Repeat("x", 200), "h\x1b[31m" + string(rune(0xe9)) + string(rune(0x200b)) + "\tst"} {
		got := DeviceName(in)
		for i := 0; i < len(got); i++ {
			if got[i] < 0x20 || got[i] > 0x7e {
				t.Errorf("DeviceName(%q) = %q has a non-printable or non-ASCII byte", in, got)
				break
			}
		}
	}
}

func TestValidateDeviceName(t *testing.T) {
	ok := []string{"x", "my laptop", strings.Repeat("a", 64), "Pascals \u00e9 Mac"}
	for _, n := range ok {
		if err := ValidateDeviceName(n); err != nil {
			t.Errorf("ValidateDeviceName(%q) = %v", n, err)
		}
	}
	bad := []string{"", " ", strings.Repeat("a", 65), "a\x1bb", "a\tb", "a" + string(rune(0x202e)) + "b",
		"a" + string(rune(0x200b)) + "b", "a" + string(rune(0xa0)) + "b", "a" + string(rune(0x2028)) + "b", "a\nb"}
	for _, n := range bad {
		err := ValidateDeviceName(n)
		if clierr.ExitCode(err) != clierr.Usage {
			t.Errorf("ValidateDeviceName(%q) = %v, want a usage error", n, err)
		}
	}
}
