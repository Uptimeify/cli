package commands

import (
	"bufio"
	"bytes"
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
	"github.com/uptimeify/cli/internal/sanitize"
)

// maxRequestBody is a variable only so tests can lower it.
var maxRequestBody int64 = 10 << 20

func readBody(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxRequestBody+1))
	if err != nil {
		return nil, clierr.New(clierr.Usage, "read body: %v", err)
	}
	if int64(len(raw)) > maxRequestBody {
		return nil, clierr.New(clierr.Usage, "the body is larger than 10 MB")
	}
	return raw, nil
}

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
		in := in
		if file != "-" {
			f, err := os.Open(file)
			if err != nil {
				return nil, clierr.New(clierr.Usage, "read body: %v", err)
			}
			defer f.Close()
			in = f
		}
		raw, err := readBody(in)
		if err != nil {
			return nil, err
		}
		if !json.Valid(raw) {
			return nil, clierr.New(clierr.Usage, "the body is not valid JSON")
		}
		return raw, nil
	case len(fields) > 0:
		obj := map[string]any{}
		for _, f := range fields {
			key, value, ok := strings.Cut(f, "=")
			isJSON := strings.HasSuffix(key, ":")
			key = strings.TrimSuffix(key, ":")
			if !ok || key == "" {
				return nil, clierr.New(clierr.Usage, "--field needs key=value or key:=json, got %q", f)
			}
			if !isJSON {
				obj[key] = value
				continue
			}
			dec := json.NewDecoder(strings.NewReader(value))
			dec.UseNumber()
			var parsed any
			if dec.Decode(&parsed) != nil || dec.More() {
				return nil, clierr.New(clierr.Usage, "--field %s:=: the value is not valid JSON", key)
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
	if !op.Confirm {
		return nil
	}
	if yes, _ := c.Flags().GetBool("yes"); yes {
		return nil
	}
	verb := "run " + strings.Join(op.Name, " ")
	if op.Method == "DELETE" {
		verb = "delete"
	}
	if d.IsTTY == nil || !d.IsTTY() {
		return clierr.New(clierr.Usage, "refusing to %s without confirmation: pass --yes", verb)
	}
	prompt := d.Err
	if prompt == nil {
		prompt = d.Out
	}
	if op.Method == "DELETE" {
		fmt.Fprintf(prompt, "Delete %s? This cannot be undone. [y/N] ", target)
	} else {
		fmt.Fprintf(prompt, "Run %s on %s? This cannot be undone. [y/N] ", strings.Join(op.Name, " "), target)
	}
	answer, _ := bufio.NewReader(d.In).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		return clierr.New(clierr.General, "aborted")
	}
	return nil
}

func execute(c *cobra.Command, args []string, op gen.Op, d Deps) error {
	path := op.Path
	for i, p := range op.PathParams {
		// A dot segment would climb out of the template (.../members/.. is .../teams/5 after a proxy),
		// and a slash or backslash, also encoded, would become another path segment once a proxy decodes it.
		if dec, _ := url.PathUnescape(args[i]); args[i] == "" || dec == "" || args[i] == "." || args[i] == ".." || dec == "." || dec == ".." || strings.ContainsAny(args[i]+dec, `/\`) {
			return clierr.New(clierr.Usage, "invalid value %q for <%s>", args[i], p)
		}
		path = strings.Replace(path, "{"+p+"}", url.PathEscape(args[i]), 1)
	}
	query := url.Values{}
	for _, q := range op.Query {
		if f := c.Flags().Lookup(gen.Kebab(q.Name)); f != nil && f.Changed {
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
	if asJSON && d.StdoutIsTTY != nil && d.StdoutIsTTY() && output.IsJSON(res.ContentType) {
		// Valid JSON strings can still carry raw control characters; a terminal must not act on them.
		_, err := io.WriteString(d.Out, sanitize.Text(string(bytes.TrimRight(res.Body, "\n")))+"\n")
		return err
	}
	return output.Render(d.Out, res.Body, res.ContentType, op.Columns, asJSON)
}

func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "unknown"
	}
	return mt
}
