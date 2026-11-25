package sanitize

import "testing"

func TestLineStripsControlCharacters(t *testing.T) {
	got := Line("ok\x1b[31mred\x07\u009b0m\ttab\nline")
	if got != "ok[31mred0m tab line" {
		t.Fatalf("Line = %q", got)
	}
}

func TestLineBidiKeepsZWJ(t *testing.T) {
	if got := Line("a‮b⁦c‍d"); got != "abc‍d" {
		t.Fatalf("got %q", got)
	}
}

func TestTextKeepsNewlineAndTab(t *testing.T) {
	if got := Text("a\nb\tc\x1bd‮e"); got != "a\nb\tcde" {
		t.Fatalf("got %q", got)
	}
}
