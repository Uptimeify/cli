package auth

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/uptimeify/cli/internal/clierr"
)

// maxDeviceName is the server's limit for device names.
const maxDeviceName = 64

// DeviceName builds the name shown under Connected apps. Only ASCII letters, digits, '.', '_' and
// '-' of the hostname are kept, so the name always passes the server's rules (1 to 64 characters,
// no control, format or bidi characters).
func DeviceName(hostname string) string {
	var b strings.Builder
	for _, r := range hostname {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	host := b.String()
	if host == "" {
		host = "unknown host"
	}
	name := "uptimeify CLI on " + host
	if len(name) > maxDeviceName {
		name = name[:maxDeviceName]
	}
	return name
}

// ValidateDeviceName applies the server's rules to a name given with --device-name: 1 to 64
// characters, no control, format or special space characters (only the plain space), and not only
// spaces.
func ValidateDeviceName(name string) error {
	if n := utf8.RuneCountInString(name); n < 1 || n > maxDeviceName {
		return clierr.New(clierr.Usage, "the device name must be 1 to %d characters", maxDeviceName)
	}
	if strings.TrimSpace(name) == "" {
		return clierr.New(clierr.Usage, "the device name must not be only spaces")
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) ||
			(unicode.Is(unicode.Zs, r) && r != ' ') || !utf8.ValidRune(r) {
			return clierr.New(clierr.Usage, "the device name must not contain control, format or special space characters")
		}
	}
	return nil
}
