package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/uptimeify/cli/internal/clierr"
	"github.com/uptimeify/cli/internal/gen"
	"github.com/uptimeify/cli/internal/output"
)

func requestBody(c *cobra.Command, op gen.Op, in io.Reader) ([]byte, error) {
	if !op.HasBody {
		return nil, nil
	}
	file, _ := c.Flags().GetString("body")
	fields, _ := c.Flags().GetStringArray("field")
	switch {
	case file != "" && len(fields) > 0:
		return nil, clierr.New(clierr.Usage, "use either --body or --field, not both")
	case file != "":
		var raw []byte
		var err error
		if file == "-" {
			raw, err = io.ReadAll(in)
		} else {
			raw, err = os.ReadFile(file)
		}
		if err != nil {
			return nil, clierr.New(clierr.Usage, "read body: %v", err)
		}
		if !json.Valid(raw) {
			return nil, clierr.New(clierr.Usage, "the body is not valid JSON")
		}
		return raw, nil
	case len(fields) > 0:
		obj := map[string]any{}
		for _, f := range fields {
			key, value, ok := strings.Cut(f, "=")
			if !ok || key == "" {
				return nil, clierr.New(clierr.Usage, "--field needs key=value, got %q", f)
			}
			var parsed any
			if json.Unmarshal([]byte(value), &parsed) != nil {
				parsed = value
			}
			obj[key] = parsed
		}
		return json.Marshal(obj)
	case op.BodyRequired:
		return nil, clierr.New(clierr.Usage, "this command needs a body: use --body <file> or --field key=value")
	}
	return nil, nil
}

func confirm(c *cobra.Command, op gen.Op, target string, d Deps) error {
	if op.Method != "DELETE" {
		return nil
	}
	if yes, _ := c.Flags().GetBool("yes"); yes {
		return nil
	}
	if d.IsTTY == nil || !d.IsTTY() {
		return clierr.New(clierr.Usage, "refusing to delete without confirmation: pass --yes")
	}
	fmt.Fprintf(d.Out, "Delete %s? This cannot be undone. [y/N] ", target)
	answer, _ := bufio.NewReader(d.In).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		return clierr.New(clierr.General, "aborted")
	}
	return nil
}

func execute(c *cobra.Command, args []string, op gen.Op, d Deps) error {
	path := op.Path
	for i, p := range op.PathParams {
		path = strings.Replace(path, "{"+p+"}", url.PathEscape(args[i]), 1)
	}
	query := url.Values{}
	for _, q := range op.Query {
		if f := c.Flags().Lookup(flagName(q.Name)); f != nil && f.Changed {
			query.Set(q.Name, f.Value.String())
		}
	}
	body, err := requestBody(c, op, d.In)
	if err != nil {
		return err
	}
	if err := confirm(c, op, path, d); err != nil {
		return err
	}
	cl, err := d.NewClient()
	if err != nil {
		return err
	}
	res, err := cl.Do(c.Context(), op.Method, path, query, body)
	if err != nil {
		return err
	}
	if output.IsBinary(res.ContentType) && d.StdoutIsTTY != nil && d.StdoutIsTTY() {
		return clierr.New(clierr.Usage, "binary response (%s): redirect the output to a file", mediaType(res.ContentType))
	}
	asJSON, _ := c.Flags().GetBool("json")
	return output.Render(d.Out, res.Body, res.ContentType, op.Columns, asJSON)
}

func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "unknown"
	}
	return mt
}
