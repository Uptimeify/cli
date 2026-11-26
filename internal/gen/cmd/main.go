// Command gen writes the command manifest. Usage:
//
//	gen -spec spec/openapi.json -overrides internal/gen/overrides.json -confirm internal/gen/confirm.json -out internal/commands/ops.json
//	gen -check-breaking old-ops.json new-ops.json
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/uptimeify/cli/internal/gen"
)

func readOps(path string) []gen.Op {
	b, err := os.ReadFile(path)
	fail(err)
	var ops []gen.Op
	fail(json.Unmarshal(b, &ops))
	return ops
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func main() {
	spec := flag.String("spec", "spec/openapi.json", "OpenAPI document")
	overridesPath := flag.String("overrides", "internal/gen/overrides.json", "name overrides")
	confirmPath := flag.String("confirm", "internal/gen/confirm.json", "non-DELETE operations that need confirmation")
	out := flag.String("out", "internal/commands/ops.json", "manifest to write")
	breaking := flag.Bool("check-breaking", false, "compare two manifests: <old> <new>")
	flag.Parse()

	if *breaking {
		if flag.NArg() != 2 {
			fail(fmt.Errorf("-check-breaking needs <old> <new>"))
		}
		if found := gen.Breaking(readOps(flag.Arg(0)), readOps(flag.Arg(1))); len(found) > 0 {
			fmt.Fprintln(os.Stderr, "breaking changes to commands (needs a major version):")
			for _, g := range found {
				fmt.Fprintln(os.Stderr, " ", g)
			}
			os.Exit(1)
		}
		return
	}

	raw, err := os.ReadFile(*spec)
	fail(err)
	overrides := map[string]string{}
	ob, err := os.ReadFile(*overridesPath)
	switch {
	case err == nil:
		fail(json.Unmarshal(ob, &overrides))
	case errors.Is(err, os.ErrNotExist) && *overridesPath == "internal/gen/overrides.json":
		// default file absent: generate without overrides
	default:
		fail(err)
	}
	var confirm []string
	cb, err := os.ReadFile(*confirmPath)
	switch {
	case err == nil:
		fail(json.Unmarshal(cb, &confirm))
	case errors.Is(err, os.ErrNotExist) && *confirmPath == "internal/gen/confirm.json":
		// default file absent: only DELETE asks
	default:
		fail(err)
	}
	ops, err := gen.Build(raw, overrides, confirm)
	fail(err)
	b, err := json.MarshalIndent(ops, "", " ")
	fail(err)
	fail(os.WriteFile(*out, append(b, '\n'), 0o644))
	fmt.Printf("wrote %d commands to %s\n", len(ops), *out)
}
