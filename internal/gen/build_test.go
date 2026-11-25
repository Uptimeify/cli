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
