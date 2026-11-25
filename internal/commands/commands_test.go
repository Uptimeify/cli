package commands

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/uptimeify/cli/internal/client"
	"github.com/uptimeify/cli/internal/clierr"
	"github.com/uptimeify/cli/internal/gen"
)

type call struct {
	method, path string
	query        url.Values
	body         string
}

type fake struct {
	calls []call
	res   *client.Response
}

func (f *fake) Do(_ context.Context, method, path string, query url.Values, body []byte) (*client.Response, error) {
	f.calls = append(f.calls, call{method, path, query, string(body)})
	if f.res != nil {
		return f.res, nil
	}
	return &client.Response{Status: 200, ContentType: "application/json", Body: []byte(`{}`)}, nil
}

var testOps = []gen.Op{
	{Name: []string{"websites", "list"}, Method: "GET", Path: "/api/websites", Columns: []string{"id"},
		Query: []gen.Param{{Name: "customerId", Type: "string"}, {Name: "search", Type: "string"}}},
	{Name: []string{"websites", "create"}, Method: "POST", Path: "/api/websites", HasBody: true, BodyRequired: true},
	{Name: []string{"im", "teams", "members", "delete"}, Method: "DELETE", Path: "/api/im/teams/{id}/members/{memberId}", PathParams: []string{"id", "memberId"}},
}

func run(t *testing.T, f *fake, tty bool, stdin string, args ...string) (string, error) {
	t.Helper()
	return runTTY(t, f, tty, false, stdin, args...)
}

func runTTY(t *testing.T, f *fake, tty, stdoutTTY bool, stdin string, args ...string) (string, error) {
	t.Helper()
	out, _, err := runIO(t, f, tty, stdoutTTY, stdin, args...)
	return out, err
}

// runIO also returns what the commands wrote to Deps.Err.
func runIO(t *testing.T, f *fake, tty, stdoutTTY bool, stdin string, args ...string) (string, string, error) {
	t.Helper()
	root := &cobra.Command{Use: "uptimeify", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().Bool("json", false, "")
	var out, errOut bytes.Buffer
	Register(root, testOps, Deps{
		NewClient: func() (Doer, error) { return f, nil },
		Out:       &out,
		Err:       &errOut,
		In:        strings.NewReader(stdin),
		IsTTY:     func() bool { return tty },

		StdoutIsTTY: func() bool { return stdoutTTY },
	})
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(&out)
	err := root.Execute()
	return out.String(), errOut.String(), err
}

func TestListSendsOnlySetFlags(t *testing.T) {
	f := &fake{res: &client.Response{Status: 200, ContentType: "application/json", Body: []byte(`{"items":[{"id":7}]}`)}}
	out, err := run(t, f, true, "", "websites", "list", "--customer-id", "42")
	if err != nil {
		t.Fatal(err)
	}
	c := f.calls[0]
	if c.method != "GET" || c.path != "/api/websites" || c.query.Encode() != "customerId=42" {
		t.Errorf("call = %+v", c)
	}
	if !strings.Contains(out, "ID") || !strings.Contains(out, "7") {
		t.Errorf("out = %q", out)
	}
}

func TestPathParamsAreEscaped(t *testing.T) {
	f := &fake{}
	if _, err := run(t, f, true, "", "im", "teams", "members", "delete", "a/b", "9", "--yes"); err != nil {
		t.Fatal(err)
	}
	if got := f.calls[0].path; got != "/api/im/teams/a%2Fb/members/9" {
		t.Errorf("path = %q", got)
	}
}

func TestWrongArgCountIsUsageError(t *testing.T) {
	_, err := run(t, &fake{}, true, "", "im", "teams", "members", "delete", "1", "--yes")
	if clierr.ExitCode(err) != clierr.Usage {
		t.Errorf("err = %v", err)
	}
}

func TestDeleteAsksAndAbortsWithoutTTY(t *testing.T) {
	f := &fake{}
	if _, err := run(t, f, false, "", "im", "teams", "members", "delete", "1", "2"); clierr.ExitCode(err) != clierr.Usage {
		t.Errorf("without tty and --yes: err = %v", err)
	}
	if _, err := run(t, f, true, "n\n", "im", "teams", "members", "delete", "1", "2"); err == nil {
		t.Error("answer n did not abort")
	}
	if len(f.calls) != 0 {
		t.Fatalf("delete was sent without confirmation: %+v", f.calls)
	}
	out, errOut, err := runIO(t, f, true, false, "y\n", "im", "teams", "members", "delete", "1", "2")
	if err != nil || len(f.calls) != 1 {
		t.Errorf("answer y: err = %v, calls = %d", err, len(f.calls))
	}
	if !strings.Contains(errOut, "Delete ") || strings.Contains(out, "Delete ") {
		t.Errorf("prompt must be on Err only: out = %q, err = %q", out, errOut)
	}
}

func TestPathArgumentsRejectDotAndEmpty(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "%2e%2e", "%2E"} {
		f := &fake{}
		_, err := run(t, f, true, "", "im", "teams", "members", "delete", "5", bad, "--yes")
		if clierr.ExitCode(err) != clierr.Usage || len(f.calls) != 0 {
			t.Errorf("last %q: err = %v, calls = %d", bad, err, len(f.calls))
		}
	}
	f := &fake{}
	_, err := run(t, f, true, "", "im", "teams", "members", "delete", "..", "5", "--yes")
	if clierr.ExitCode(err) != clierr.Usage || len(f.calls) != 0 {
		t.Errorf("first ..: err = %v, calls = %d", err, len(f.calls))
	}
	for _, ok := range []string{"v1.2", "a..b"} {
		f := &fake{}
		if _, err := run(t, f, true, "", "im", "teams", "members", "delete", "5", ok, "--yes"); err != nil || len(f.calls) != 1 {
			t.Errorf("%q: err = %v, calls = %d", ok, err, len(f.calls))
		}
	}
}

func TestFieldStringVersusJSON(t *testing.T) {
	f := &fake{}
	for _, c := range []struct{ field, want string }{
		{"code=123456", `{"code":"123456"}`},
		{"id:=12345678901234567890", `{"id":12345678901234567890}`},
		{"on=true", `{"on":"true"}`},
		{"a=b=c", `{"a":"b=c"}`},
	} {
		f.calls = nil
		if _, err := run(t, f, true, "", "websites", "create", "--field", c.field); err != nil {
			t.Fatal(err)
		}
		if got := f.calls[0].body; got != c.want {
			t.Errorf("%s: body = %s, want %s", c.field, got, c.want)
		}
	}
	f.calls = nil
	_, err := run(t, f, true, "", "websites", "create", "--field", "x:=notjson")
	if clierr.ExitCode(err) != clierr.Usage || len(f.calls) != 0 || !strings.Contains(err.Error(), "x") {
		t.Errorf("err = %v, calls = %d", err, len(f.calls))
	}
	_, err = run(t, f, true, "", "websites", "create", "--field", "x:=1 2")
	if clierr.ExitCode(err) != clierr.Usage {
		t.Errorf("trailing data accepted: %v", err)
	}
}

func TestJSONFlagIsSanitisedOnATerminal(t *testing.T) {
	body := "{\"name\":\"a\u009b[2Jb\"}"
	res := &client.Response{Status: 200, ContentType: "application/json", Body: []byte(body)}
	out, err := runTTY(t, &fake{res: res}, true, true, "", "websites", "list", "--json")
	if err != nil || strings.ContainsRune(out, '\u009b') || !strings.Contains(out, "[2J") {
		t.Errorf("tty: out = %q, err = %v", out, err)
	}
	out, err = runTTY(t, &fake{res: res}, true, false, "", "websites", "list", "--json")
	if err != nil || out != body+"\n" {
		t.Errorf("piped: out = %q, err = %v", out, err)
	}
}

func TestBodyFromFieldsFileAndStdin(t *testing.T) {
	f := &fake{}
	if _, err := run(t, f, true, "", "websites", "create", "--field", "name=Shop", "--field", "interval:=60", "--field", "paused:=false"); err != nil {
		t.Fatal(err)
	}
	if got := f.calls[0].body; got != `{"interval":60,"name":"Shop","paused":false}` {
		t.Errorf("fields body = %s", got)
	}
	file := filepath.Join(t.TempDir(), "b.json")
	os.WriteFile(file, []byte(`{"name":"File"}`), 0o600)
	if _, err := run(t, f, true, "", "websites", "create", "--body", file); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, f, true, `{"name":"Stdin"}`, "websites", "create", "--body", "-"); err != nil {
		t.Fatal(err)
	}
	if f.calls[1].body != `{"name":"File"}` || f.calls[2].body != `{"name":"Stdin"}` {
		t.Errorf("bodies = %q, %q", f.calls[1].body, f.calls[2].body)
	}
}

func TestBodyErrors(t *testing.T) {
	f := &fake{}
	for _, args := range [][]string{
		{"websites", "create"},
		{"websites", "create", "--body", "-", "--field", "a=b"},
		{"websites", "create", "--field", "noequals"},
		{"websites", "create", "--field", "=v"},
		{"websites", "create", "--field", ":=1"},
	} {
		stdin := ""
		if len(args) > 2 && args[2] == "--body" {
			stdin = "{not json"
		}
		if _, err := run(t, f, true, stdin, args...); clierr.ExitCode(err) != clierr.Usage {
			t.Errorf("%v: err = %v", args, err)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("invalid input reached the API: %+v", f.calls)
	}
}

func TestEmbeddedManifestBuildsATree(t *testing.T) {
	ops, err := Ops()
	if err != nil || len(ops) == 0 {
		t.Fatalf("Ops: %d, %v", len(ops), err)
	}
	root := &cobra.Command{Use: "uptimeify"}
	root.PersistentFlags().Bool("json", false, "")
	Register(root, ops, Deps{})
	for _, op := range ops {
		cmd, _, err := root.Find(op.Name)
		if err != nil || cmd.Name() != op.Name[len(op.Name)-1] || cmd.RunE == nil {
			t.Fatalf("command %v is not reachable: %v", op.Name, err)
		}
	}
}

func TestBinaryResponseNeverReachesATerminal(t *testing.T) {
	pdf := &client.Response{Status: 200, ContentType: "application/pdf", Body: []byte("%PDF-1.7\x00\x1b[2J")}
	out, err := runTTY(t, &fake{res: pdf}, true, true, "", "websites", "list")
	if clierr.ExitCode(err) != clierr.Usage || !strings.Contains(err.Error(), "application/pdf") {
		t.Errorf("err = %v", err)
	}
	if out != "" {
		t.Errorf("wrote %q to the terminal", out)
	}
}

func TestBinaryResponseIsWrittenUnchangedWhenRedirected(t *testing.T) {
	pdf := &client.Response{Status: 200, ContentType: "application/pdf", Body: []byte("%PDF-1.7\x00\x1b[2J")}
	out, err := runTTY(t, &fake{res: pdf}, true, false, "", "websites", "list")
	if err != nil || out != string(pdf.Body) {
		t.Errorf("out = %q, err = %v", out, err)
	}
}
