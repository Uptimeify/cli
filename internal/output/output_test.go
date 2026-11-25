package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderTable(t *testing.T) {
	var buf bytes.Buffer
	body := []byte(`{"items":[{"id":1,"name":"Shop","paused":false,"nested":{"a":1}},{"id":2,"name":null,"paused":true}]}`)
	if err := Render(&buf, body, "application/json", []string{"id", "name", "paused"}, false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "ID") || !strings.Contains(lines[1], "Shop") || !strings.Contains(lines[2], "true") {
		t.Fatalf("table = %q", buf.String())
	}
}

func TestRenderJSONIsUnchanged(t *testing.T) {
	var buf bytes.Buffer
	body := []byte(`{"items":[{"id":1}]}`)
	if err := Render(&buf, body, "application/json; charset=utf-8", []string{"id"}, true); err != nil {
		t.Fatal(err)
	}
	if buf.String() != string(body)+"\n" {
		t.Fatalf("json = %q", buf.String())
	}
}

func TestRenderObjectAndBinary(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, []byte(`{"id":1}`), "application/json", nil, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\"id\": 1") {
		t.Fatalf("object = %q", buf.String())
	}
	buf.Reset()
	if err := Render(&buf, []byte("a,b\n1,2\n"), "text/csv", nil, false); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "a,b\n1,2\n" {
		t.Fatalf("csv = %q", buf.String())
	}
}

func TestSanitizeStripsControlCharacters(t *testing.T) {
	got := Sanitize("ok\x1b[31mred\x07\u009b0m\ttab\nline")
	if got != "ok[31mred0m tab line" {
		t.Fatalf("Sanitize = %q", got)
	}
}

func TestTableCellsAreSanitized(t *testing.T) {
	var buf bytes.Buffer
	body := []byte(`[{"name":"a\u001b]0;evil\u0007b"}]`)
	if err := Render(&buf, body, "application/json", []string{"name"}, false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(buf.String(), "\x1b\x07") {
		t.Fatalf("control characters reached the terminal: %q", buf.String())
	}
}
