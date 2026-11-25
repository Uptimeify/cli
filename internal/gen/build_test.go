package gen

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func mini(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/mini.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuild(t *testing.T) {
	ops, err := Build(mini(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, op := range ops {
		names = append(names, strings.Join(op.Name, " "))
	}
	want := []string{"websites create", "websites delete", "websites get", "websites list"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	list := ops[3]
	if !reflect.DeepEqual(list.Columns, []string{"id", "name", "paused"}) {
		t.Errorf("columns = %v", list.Columns)
	}
	if len(list.Query) != 2 || list.Query[1].Enum[1] != "dns" {
		t.Errorf("query = %+v", list.Query)
	}
	if create := ops[0]; !create.HasBody || !create.BodyRequired {
		t.Errorf("create body flags wrong: %+v", create)
	}
	if get := ops[2]; !reflect.DeepEqual(get.PathParams, []string{"id"}) || len(get.Query) != 0 {
		t.Errorf("get = %+v", get)
	}
}

func TestBuildCollisionFails(t *testing.T) {
	spec := []byte(`{"paths":{
	  "/api/organizations":{"patch":{"operationId":"a","responses":{}}},
	  "/api/organizations/{id}":{"patch":{"operationId":"b","responses":{}}}}}`)
	_, err := Build(spec, nil)
	if err == nil || !strings.Contains(err.Error(), "organizations update") {
		t.Fatalf("want collision error, got %v", err)
	}
	ops, err := Build(spec, map[string]string{"PATCH /api/organizations": "organizations update-current"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ops[1].Name, " "); got != "organizations update-current" {
		t.Errorf("override not applied: %s", got)
	}
}

func TestRemoved(t *testing.T) {
	old := []Op{{Name: []string{"a", "list"}}, {Name: []string{"a", "get"}}}
	cur := []Op{{Name: []string{"a", "list"}}}
	if got := Removed(old, cur); !reflect.DeepEqual(got, []string{"a get"}) {
		t.Errorf("Removed = %v", got)
	}
}

func TestBuildRejectsReservedAndAmbiguousNames(t *testing.T) {
	cases := map[string]struct{ spec, want string }{
		"reserved command":   {`{"paths":{"/api/config":{"get":{"operationId":"a","responses":{}}}}}`, "GET /api/config"},
		"reserved flag":      {`{"paths":{"/api/x":{"get":{"operationId":"a","parameters":[{"name":"Yes","in":"query"}],"responses":{}}}}}`, "GET /api/x"},
		"duplicate flag":     {`{"paths":{"/api/x":{"get":{"operationId":"a","parameters":[{"name":"fooBar","in":"query"},{"name":"foo_bar","in":"query"}],"responses":{}}}}}`, "--foo-bar"},
		"unsupported method": {`{"paths":{"/api/x":{"head":{"operationId":"a","responses":{}}}}}`, "HEAD /api/x"},
	}
	for name, c := range cases {
		_, err := Build([]byte(c.spec), nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want mention of %q", name, err, c.want)
		}
	}
	for _, name := range []string{"auth", "doctor", "help", "completion", "version", "config"} {
		spec := []byte(`{"paths":{"/api/` + name + `":{"get":{"operationId":"a","responses":{}}}}}`)
		if _, err := Build(spec, nil); err == nil || !strings.Contains(err.Error(), "overrides.json") {
			t.Errorf("%s: err = %v", name, err)
		}
		if _, err := Build(spec, map[string]string{"GET /api/" + name: "x-" + name + " get"}); err != nil {
			t.Errorf("%s with override: %v", name, err)
		}
	}
	for _, f := range []string{"json", "body", "field", "yes", "help"} {
		spec := []byte(`{"paths":{"/api/x":{"get":{"operationId":"a","parameters":[{"name":"` + f + `","in":"query"}],"responses":{}}}}}`)
		if _, err := Build(spec, nil); err == nil || !strings.Contains(err.Error(), "--"+f) {
			t.Errorf("flag %s: err = %v", f, err)
		}
	}
}

func TestBreaking(t *testing.T) {
	base := Op{Name: []string{"a", "get"}, Method: "GET", Path: "/api/a/{id}", PathParams: []string{"id"}, Query: []Param{{Name: "fooBar"}}}
	with := func(f func(*Op)) []Op { o := base; f(&o); return []Op{o} }
	cases := map[string]struct {
		cur  []Op
		want string
	}{
		"removed": {nil, "uptimeify a get: removed or renamed"},
		"method":  {with(func(o *Op) { o.Method = "POST" }), "uptimeify a get: method changed (GET -> POST)"},
		"path":    {with(func(o *Op) { o.Path = "/api/b/{id}" }), "uptimeify a get: path changed (/api/a/{id} -> /api/b/{id})"},
		"params":  {with(func(o *Op) { o.PathParams = []string{"id", "x"} }), "uptimeify a get: path parameters changed (1 -> 2)"},
		"flag":    {with(func(o *Op) { o.Query = nil }), "uptimeify a get: query flag --foo-bar removed"},
	}
	for name, c := range cases {
		got := Breaking([]Op{base}, c.cur)
		found := false
		for _, l := range got {
			found = found || l == c.want
		}
		if !found {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
	added := []Op{
		{Name: base.Name, Method: base.Method, Path: base.Path, PathParams: base.PathParams, Query: []Param{{Name: "fooBar"}, {Name: "newFlag"}}},
		{Name: []string{"b", "list"}, Method: "GET", Path: "/api/b"},
	}
	if got := Breaking([]Op{base}, added); len(got) != 0 {
		t.Errorf("additive change reported: %q", got)
	}
}

func TestDeriveNamePanicsOnUnknownMethod(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic for an unknown method")
		}
	}()
	DeriveName("trace", "/api/x", false)
}
