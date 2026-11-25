// Package commands builds the command tree from the generated manifest (ops.json).
package commands

import (
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/uptimeify/cli/internal/client"
	"github.com/uptimeify/cli/internal/clierr"
	"github.com/uptimeify/cli/internal/gen"
)

//go:embed ops.json
var manifest []byte

type Doer interface {
	Do(ctx context.Context, method, path string, query url.Values, body []byte) (*client.Response, error)
}

type Deps struct {
	NewClient func() (Doer, error)
	Out       io.Writer
	// Err receives prompts, so they stay visible when Out is redirected. Nil falls back to Out.
	Err   io.Writer
	In    io.Reader
	IsTTY func() bool
	// StdoutIsTTY reports whether standard output is a terminal; binary responses are refused there.
	StdoutIsTTY func() bool
}

func Ops() ([]gen.Op, error) {
	var ops []gen.Op
	err := json.Unmarshal(manifest, &ops)
	return ops, err
}

func child(parent *cobra.Command, name string) *cobra.Command {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	c := &cobra.Command{Use: name}
	parent.AddCommand(c)
	return c
}

func Register(root *cobra.Command, ops []gen.Op, d Deps) {
	for _, op := range ops {
		cmd := root
		for _, part := range op.Name {
			cmd = child(cmd, part)
		}
		op := op
		use := op.Name[len(op.Name)-1]
		for _, p := range op.PathParams {
			use += " <" + p + ">"
		}
		cmd.Use = use
		cmd.Short = op.Summary
		cmd.Long = op.Summary + "\n\n" + op.Method + " " + op.Path
		cmd.Args = func(_ *cobra.Command, args []string) error {
			if len(op.PathParams) == 0 && len(args) > 0 {
				return clierr.New(clierr.Usage, "this command takes no arguments")
			}
			if len(args) != len(op.PathParams) {
				return clierr.New(clierr.Usage, "expected %d argument(s): %s", len(op.PathParams), strings.Join(op.PathParams, ", "))
			}
			return nil
		}
		for _, q := range op.Query {
			help := q.Description
			if len(q.Enum) > 0 {
				help = strings.TrimSpace(help + " One of: " + strings.Join(q.Enum, ", ") + ".")
			}
			cmd.Flags().String(gen.Kebab(q.Name), "", help)
		}
		if op.HasBody {
			cmd.Flags().String("body", "", "JSON request body: a file path, or - for standard input")
			cmd.Flags().StringArray("field", nil, "body field, repeatable: key=value sends a string, key:=json sends parsed JSON (numbers, booleans, objects)")
		}
		if op.Method == "DELETE" {
			cmd.Flags().Bool("yes", false, "do not ask for confirmation")
		}
		cmd.RunE = func(c *cobra.Command, args []string) error { return execute(c, args, op, d) }
	}
}
