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

func renderStr(t *testing.T, body, ct string, cols []string, asJSON bool) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, []byte(body), ct, cols, asJSON); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestPrettyObjectIsSanitized(t *testing.T) {
	got := renderStr(t, "{\"name\":\"a\u009b2Jb\"}", "application/json", nil, false)
	if strings.ContainsRune(got, '\u009b') || !strings.Contains(got, "a") || !strings.Contains(got, "b") {
		t.Fatalf("got %q", got)
	}
}

func TestMalformedJSONIsSanitized(t *testing.T) {
	got := renderStr(t, "{\"a\":\"\x1b]0;x\x07", "application/json", nil, false)
	if strings.ContainsAny(got, "\x1b\x07") {
		t.Fatalf("got %q", got)
	}
}

func TestJSONDetectedByMediaType(t *testing.T) {
	for _, ct := range []string{"Application/JSON; charset=utf-8", "application/problem+json"} {
		got := renderStr(t, `[{"id":1}]`, ct, []string{"id"}, false)
		if !strings.HasPrefix(got, "ID") {
			t.Fatalf("%s: got %q", ct, got)
		}
	}
}

func TestTextIsSanitizedKeepingNewlineAndTab(t *testing.T) {
	got := renderStr(t, "line1\n\x1b[31mred\tx", "text/plain", nil, false)
	if got != "line1\n[31mred\tx" {
		t.Fatalf("got %q", got)
	}
}

func TestPDFIsRaw(t *testing.T) {
	body := "%PDF\x1b\x00\xff"
	if got := renderStr(t, body, "application/pdf", nil, false); got != body {
		t.Fatalf("got %q", got)
	}
}

func TestAsJSONKeepsRawBytes(t *testing.T) {
	body := "{\"a\":\"x\u009by\"}"
	if got := renderStr(t, body, "application/json", nil, true); got != body+"\n" {
		t.Fatalf("got %q", got)
	}
}

func TestIsBinary(t *testing.T) {
	for ct, want := range map[string]bool{
		"application/pdf": true, "application/octet-stream": true, "image/png": true,
		"application/json": false, "application/problem+json; charset=utf-8": false,
		"text/csv; charset=utf-8": false, "text/plain": false, "": false,
	} {
		if got := IsBinary(ct); got != want {
			t.Errorf("IsBinary(%q) = %v, want %v", ct, got, want)
		}
	}
}
