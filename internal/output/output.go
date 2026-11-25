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

	"github.com/uptimeify/cli/internal/sanitize"
)

func cell(v any) string {
	switch x := v.(type) {
	case nil:
		return "-"
	case string:
		return sanitize.Line(x)
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
		_, err := io.WriteString(w, sanitize.Text(string(body)))
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
		_, err := io.WriteString(w, sanitize.Text(string(body)))
		return err
	}
	_, err := fmt.Fprintln(w, sanitize.Text(pretty.String()))
	return err
}

// IsBinary reports whether a response of this content type is rendered as raw bytes.
func IsBinary(contentType string) bool { return kind(contentType) == "other" }

// IsJSON reports whether a response of this content type is rendered as JSON.
func IsJSON(contentType string) bool { return kind(contentType) == "json" }
