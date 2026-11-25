// Package sanitize strips what must never reach a terminal from server-controlled text. It is a
// leaf package so that both the client and the output code use the same rules.
package sanitize

import "strings"

// stripped reports whether r must never reach a terminal: C0, DEL, C1, bidi controls and the
// line/paragraph separators. Other format characters (ZWJ) stay, emoji and some scripts need them.
func stripped(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, r == 0x2028, r == 0x2029:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// Line makes s safe for one line or table cell: tab and newline become a space, control and bidi
// characters are removed.
func Line(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n':
			return ' '
		case stripped(r):
			return -1
		}
		return r
	}, s)
}

// Text is Line for multi-line output: newline and tab survive.
func Text(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\t' && r != '\n' && stripped(r) {
			return -1
		}
		return r
	}, s)
}
