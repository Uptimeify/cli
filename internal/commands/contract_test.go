package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/uptimeify/cli/internal/clierr"
	"github.com/uptimeify/cli/internal/gen"
)

// specOps returns "METHOD path-with-params-replaced" for every operation in the spec.
func specOps(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../../spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	param := regexp.MustCompile(`\{[^}]+\}`)
	known := map[string]bool{}
	for path, item := range doc.Paths {
		for method := range item {
			switch method {
			case "get", "post", "put", "patch", "delete":
				known[strings.ToUpper(method)+" "+param.ReplaceAllString(path, "X")] = true
			}
		}
	}
	return known
}

// runOp registers the full manifest and runs one command with the given args.
func runOp(ops []gen.Op, f *fake, args []string) error {
	root := &cobra.Command{Use: "uptimeify", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().Bool("json", false, "")
	var out bytes.Buffer
	Register(root, ops, Deps{
		NewClient: func() (Doer, error) { return f, nil },
		Out:       &out,
		Err:       &out,
		In:        strings.NewReader(""),
		IsTTY:     func() bool { return false },

		StdoutIsTTY: func() bool { return false },
	})
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(&out)
	return root.Execute()
}

// opArgs builds placeholder arguments; params[i] replaces path argument i.
func opArgs(op gen.Op, params []string, yes bool) []string {
	args := append([]string{}, op.Name...)
	args = append(args, params...)
	if op.HasBody {
		args = append(args, "--field", "a=1")
	}
	if yes && op.Method == "DELETE" {
		args = append(args, "--yes")
	}
	return args
}

func placeholders(op gen.Op) []string {
	p := make([]string, len(op.PathParams))
	for i := range p {
		p[i] = "X"
	}
	return p
}

func TestEveryCommandSendsARequestTheSpecKnows(t *testing.T) {
	known := specOps(t)
	ops, err := Ops()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		f := &fake{}
		if err := runOp(ops, f, opArgs(op, placeholders(op), true)); err != nil {
			t.Errorf("%v: %v", op.Name, err)
			continue
		}
		if len(f.calls) != 1 {
			t.Errorf("%v: %d requests", op.Name, len(f.calls))
			continue
		}
		if key := f.calls[0].method + " " + f.calls[0].path; !known[key] {
			// paths are built from X placeholders, so the key matches the spec form
			t.Errorf("%v sent %q, which the spec does not define", op.Name, key)
		}
	}
	t.Logf("exercised %d commands", len(ops))
}

func TestContractEveryOperationHasExactlyOneCommand(t *testing.T) {
	known := specOps(t)
	ops, err := Ops()
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != len(known) {
		t.Errorf("manifest has %d commands, the spec has %d operations: run make generate", len(ops), len(known))
	}
	param := regexp.MustCompile(`\{[^}]+\}`)
	seen := map[string]int{}
	for _, op := range ops {
		seen[op.Method+" "+param.ReplaceAllString(op.Path, "X")]++
	}
	for k := range known {
		if seen[k] != 1 {
			t.Errorf("spec operation %q has %d commands", k, seen[k])
		}
	}
	for k := range seen {
		if !known[k] {
			t.Errorf("command for %q, which the spec does not define", k)
		}
	}
}

func TestContractDeleteWithoutYesSendsNothing(t *testing.T) {
	ops, err := Ops()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, op := range ops {
		if op.Method != "DELETE" {
			continue
		}
		n++
		f := &fake{}
		err := runOp(ops, f, opArgs(op, placeholders(op), false))
		if clierr.ExitCode(err) != clierr.Usage || len(f.calls) != 0 {
			t.Errorf("%v: err = %v, requests = %d", op.Name, err, len(f.calls))
		}
	}
	if n == 0 {
		t.Fatal("no DELETE commands in the manifest")
	}
}

func TestContractDotDotPathArgumentSendsNothing(t *testing.T) {
	ops, err := Ops()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		for i := range op.PathParams {
			p := placeholders(op)
			p[i] = ".."
			f := &fake{}
			err := runOp(ops, f, opArgs(op, p, true))
			if clierr.ExitCode(err) != clierr.Usage || len(f.calls) != 0 {
				t.Errorf("%v arg %d: err = %v, requests = %d", op.Name, i, err, len(f.calls))
			}
		}
	}
}
