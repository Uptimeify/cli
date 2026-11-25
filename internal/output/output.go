// Package output prints API responses. Table cells come from the server and may contain anything
// a customer typed, so they are stripped of control characters before they reach the terminal.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Sanitize removes C0 and C1 control characters; tab and newline become a space.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n':
			return ' '
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
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

func Render(w io.Writer, body []byte, contentType string, columns []string, asJSON bool) error {
	if !strings.HasPrefix(contentType, "application/json") {
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
		_, err := w.Write(body)
		return err
	}
	_, err := fmt.Fprintln(w, pretty.String())
	return err
}
