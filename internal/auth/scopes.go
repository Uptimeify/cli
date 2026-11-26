// Package auth signs the CLI in with the browser (OAuth with PKCE) and keeps the sign-in in the system keyring.
package auth

import (
	"slices"
	"strings"

	"github.com/uptimeify/cli/internal/clierr"
)

// AllScopes mirrors CLI_API_SCOPES in monitoring-app/shared/utils/cli-api-scopes.ts, same order.
var AllScopes = []string{
	"api:monitors:read",
	"api:monitors:write",
	"api:maintenance:read",
	"api:maintenance:write",
	"api:incidents:read",
	"api:incidents:write",
	"api:im:read",
	"api:im:write",
	"api:im-config:read",
	"api:im-config:write",
	"api:compliance:read",
	"api:compliance:write",
	"api:alerts:read",
	"api:alerts:write",
	"api:statuspages:read",
	"api:statuspages:write",
	"api:reports:read",
	"api:reports:write",
	"api:customers:read",
	"api:customers:write",
	"api:organization:read",
	"api:organization:write",
	"api:users:read",
	"api:users:write",
	"api:billing:read",
	"api:billing:write",
	"api:audit:read",
	"api:statuspage-subscribers:read",
}

// defaultScopeCount is the number of leading AllScopes entries that belong to the areas a
// sign-in may use by default. User management, billing, audit and status page subscribers are
// separate scopes: they are never part of the default or of --write, only of --scope.
const defaultScopeCount = 22

func areaScopes(suffix string) []string {
	var out []string
	for _, s := range AllScopes[:defaultScopeCount] {
		if strings.HasSuffix(s, suffix) {
			out = append(out, s)
		}
	}
	return out
}

// DefaultScopes returns the scopes auth login requests without a flag: only the :read scopes of
// the default areas. offline_access is not part of it; the login adds it.
func DefaultScopes() []string { return areaScopes(":read") }

// WriteScopes returns the :write scopes of the default areas, requested by auth login --write.
func WriteScopes() []string { return areaScopes(":write") }

// IsScope reports whether s is a scope the server knows.
func IsScope(s string) bool {
	return slices.Contains(AllScopes, s)
}

// RequestScopes returns the default scopes plus extra, in AllScopes order and without duplicates.
// Unknown scopes are refused before any request, since the server answers a bad authorize
// request in the browser and the CLI would wait until its timeout.
func RequestScopes(extra []string) ([]string, error) {
	want := map[string]bool{}
	for _, s := range DefaultScopes() {
		want[s] = true
	}
	for _, s := range extra {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !IsScope(s) {
			return nil, clierr.New(clierr.Usage, "unknown scope %q: scopes look like api:monitors:write, see uptimeify auth login --help", s)
		}
		want[s] = true
	}
	out := make([]string, 0, len(want))
	for _, s := range AllScopes {
		if want[s] {
			out = append(out, s)
		}
	}
	return out, nil
}
