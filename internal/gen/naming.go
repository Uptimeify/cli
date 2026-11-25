// Package gen turns the OpenAPI description into the command manifest.
package gen

import (
	"regexp"
	"strings"
)

var camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// Kebab turns camelCase and snake_case into kebab-case. It names path segments and query flags.
func Kebab(s string) string {
	s = camelBoundary.ReplaceAllString(s, "$1-$2")
	return strings.ToLower(strings.ReplaceAll(s, "_", "-"))
}

func isParam(seg string) bool { return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") }

func segments(path string) []string {
	return strings.Split(strings.TrimPrefix(strings.Trim(path, "/"), "api/"), "/")
}

// PathParams returns the parameter names in path order.
func PathParams(path string) []string {
	var out []string
	for _, seg := range segments(path) {
		if isParam(seg) {
			out = append(out, seg[1:len(seg)-1])
		}
	}
	return out
}

// DeriveName builds the command path. hasChildParam says whether "<path>/{x}" exists, which is
// what makes a path a collection.
func DeriveName(method, path string, hasChildParam bool) []string {
	segs := segments(path)
	var name []string
	for _, seg := range segs {
		if !isParam(seg) {
			name = append(name, Kebab(seg))
		}
	}
	collection := hasChildParam && !isParam(segs[len(segs)-1])
	switch strings.ToLower(method) {
	case "get":
		if collection {
			return append(name, "list")
		}
		return append(name, "get")
	case "post":
		if collection {
			return append(name, "create")
		}
		return name
	case "patch":
		return append(name, "update")
	case "put":
		return append(name, "set")
	case "delete":
		return append(name, "delete")
	}
	panic("gen: unsupported HTTP method " + method) // Build rejects them before it gets here
}
