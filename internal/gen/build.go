package gen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

var methods = []string{"get", "post", "put", "patch", "delete"}

type rawParam struct {
	Name        string `json:"name"`
	In          string `json:"in"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Schema      struct {
		Type json.RawMessage `json:"type"`
		Enum []any           `json:"enum"`
	} `json:"schema"`
}

type rawOp struct {
	OperationID string     `json:"operationId"`
	Summary     string     `json:"summary"`
	Parameters  []rawParam `json:"parameters"`
	RequestBody *struct {
		Required bool `json:"required"`
	} `json:"requestBody"`
	Responses map[string]struct {
		Content map[string]struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"content"`
	} `json:"responses"`
}

// typeName reads "type", which in OpenAPI 3.1 is a string or a list such as ["string","null"].
func typeName(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		for _, t := range list {
			if t != "null" {
				return t
			}
		}
	}
	return ""
}

// orderedKeys returns the keys of a JSON object in document order (a Go map would lose it).
func orderedKeys(raw json.RawMessage) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil
		}
		keys = append(keys, k.(string))
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return nil
		}
	}
	return keys
}

type node struct {
	Type       json.RawMessage `json:"type"`
	Properties json.RawMessage `json:"properties"`
	Items      json.RawMessage `json:"items"`
	props      map[string]json.RawMessage
}

func parseNode(raw json.RawMessage) node {
	var n node
	_ = json.Unmarshal(raw, &n)
	_ = json.Unmarshal(n.Properties, &n.props)
	return n
}

// columns picks up to eight scalar fields of the listed item, in schema order.
func columns(schema json.RawMessage) []string {
	n := parseNode(schema)
	item := n.Items
	if wrapped, ok := n.props["items"]; ok {
		item = parseNode(wrapped).Items
	}
	if item == nil {
		return nil
	}
	in := parseNode(item)
	var cols []string
	for _, key := range orderedKeys(in.Properties) {
		switch typeName(parseNode(in.props[key]).Type) {
		case "string", "integer", "number", "boolean":
			cols = append(cols, key)
		}
		if len(cols) == 8 {
			break
		}
	}
	return cols
}

// Build turns the OpenAPI document into the manifest, sorted by command name. overrides maps
// "METHOD /api/path" to a full command name; a name collision without override is an error.
func Build(spec []byte, overrides map[string]string) ([]Op, error) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	var ops []Op
	seen := map[string]string{}
	paths := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths) // deterministic collision messages
	for _, path := range paths {
		item := doc.Paths[path]
		_, hasChildParam := childParam(doc.Paths, path)
		for _, method := range methods {
			raw, ok := item[method]
			if !ok {
				continue
			}
			var ro rawOp
			if err := json.Unmarshal(raw, &ro); err != nil {
				return nil, fmt.Errorf("%s %s: %w", method, path, err)
			}
			key := strings.ToUpper(method) + " " + path
			name := DeriveName(method, path, hasChildParam)
			if o, ok := overrides[key]; ok {
				name = strings.Fields(o)
			}
			joined := strings.Join(name, " ")
			if other, dup := seen[joined]; dup {
				return nil, fmt.Errorf("command name %q is used by %q and %q, add an entry to overrides.json", joined, other, key)
			}
			seen[joined] = key
			op := Op{Name: name, Method: strings.ToUpper(method), Path: path, ID: ro.OperationID, Summary: ro.Summary, PathParams: PathParams(path)}
			for _, p := range ro.Parameters {
				if p.In != "query" {
					continue
				}
				prm := Param{Name: p.Name, Type: typeName(p.Schema.Type), Required: p.Required, Description: p.Description}
				for _, e := range p.Schema.Enum {
					prm.Enum = append(prm.Enum, fmt.Sprint(e))
				}
				op.Query = append(op.Query, prm)
			}
			if ro.RequestBody != nil {
				op.HasBody, op.BodyRequired = true, ro.RequestBody.Required
			}
			if method == "get" {
				if ok200, ok := ro.Responses["200"]; ok {
					op.Columns = columns(ok200.Content["application/json"].Schema)
				}
			}
			ops = append(ops, op)
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		return strings.Join(ops[i].Name, " ") < strings.Join(ops[j].Name, " ")
	})
	return ops, nil
}

func childParam(paths map[string]map[string]json.RawMessage, path string) (string, bool) {
	prefix := path + "/{"
	for other := range paths {
		if strings.HasPrefix(other, prefix) && !strings.Contains(other[len(prefix):], "/") {
			return other, true
		}
	}
	return "", false
}

// Removed lists command names that exist in old but not in cur.
func Removed(old, cur []Op) []string {
	have := map[string]bool{}
	for _, op := range cur {
		have[strings.Join(op.Name, " ")] = true
	}
	var gone []string
	for _, op := range old {
		if n := strings.Join(op.Name, " "); !have[n] {
			gone = append(gone, n)
		}
	}
	sort.Strings(gone)
	return gone
}
