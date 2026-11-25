// Package output prints API responses. Table cells come from the server and may contain anything
// a customer typed, so every text path strips control characters before they reach the terminal.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"strings"
	"text/tabwriter"
)

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

// Sanitize makes s safe for one table cell: tab and newline become a space, control and bidi
// characters are removed.
func Sanitize(s string) string {
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

// sanitizeText is Sanitize for multi-line output: newline and tab survive.
func sanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\t' && r != '\n' && stripped(r) {
			return -1
		}
		return r
	}, s)
}

func cell(v any) string {
	switch x := v.(type) {
	case nil:
		return "-"
	case string:
		return Sanitize(x)
	case json.Number:
		return x.String()
	case bool:
		return fmt.Sprint(x)
	}
	return "…"
}

func rows(body []byte) ([]map[string]any, bool) {
	dec := func(target any) bool {
		d := json.NewDecoder(bytes.NewReader(body))
		d.UseNumber()
		return d.Decode(target) == nil
	}
	var list []map[string]any
	if dec(&list) {
		return list, true
	}
	var wrapped struct {
		Items []map[string]any `json:"items"`
	}
	if dec(&wrapped) && wrapped.Items != nil {
		return wrapped.Items, true
	}
	return nil, false
}

// kind classifies a content type: json, text (also unparseable types) or other (binary).
func kind(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	switch {
	case err != nil, strings.HasPrefix(mt, "text/"):
		return "text"
	case mt == "application/json", strings.HasSuffix(mt, "+json"):
		return "json"
	}
	return "other"
}

func Render(w io.Writer, body []byte, contentType string, columns []string, asJSON bool) error {
	switch kind(contentType) {
	case "text":
		_, err := io.WriteString(w, sanitizeText(string(body)))
		return err
	case "other":
		_, err := w.Write(body)
		return err
	}
	if asJSON {
		_, err := fmt.Fprintf(w, "%s\n", bytes.TrimRight(body, "\n"))
		return err
	}
	if list, ok := rows(body); ok && len(columns) > 0 {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		header := make([]string, len(columns))
		for i, c := range columns {
			header[i] = strings.ToUpper(c)
		}
		fmt.Fprintln(tw, strings.Join(header, "\t"))
		for _, row := range list {
			cells := make([]string, len(columns))
			for i, c := range columns {
				cells[i] = cell(row[c])
			}
			fmt.Fprintln(tw, strings.Join(cells, "\t"))
		}
		return tw.Flush()
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		_, err := io.WriteString(w, sanitizeText(string(body)))
		return err
	}
	_, err := fmt.Fprintln(w, sanitizeText(pretty.String()))
	return err
}
