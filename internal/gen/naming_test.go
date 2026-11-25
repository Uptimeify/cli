package gen

import (
	"reflect"
	"testing"
)

func TestDeriveName(t *testing.T) {
	cases := []struct {
		method, path string
		child        bool
		want         []string
	}{
		{"get", "/api/websites", true, []string{"websites", "list"}},
		{"get", "/api/websites/{id}", false, []string{"websites", "get"}},
		{"post", "/api/websites", true, []string{"websites", "create"}},
		{"patch", "/api/websites/{id}", false, []string{"websites", "update"}},
		{"delete", "/api/websites/{id}", false, []string{"websites", "delete"}},
		{"post", "/api/incidents/{id}/false-alarm", false, []string{"incidents", "false-alarm"}},
		{"put", "/api/incidents/{id}/postmortem", false, []string{"incidents", "postmortem", "set"}},
		{"get", "/api/websites/{id}/uptime-stats", false, []string{"websites", "uptime-stats", "get"}},
		{"get", "/api/customers/{id}/websites", false, []string{"customers", "websites", "get"}},
		{"delete", "/api/im/teams/{id}/members/{memberId}", false, []string{"im", "teams", "members", "delete"}},
		{"get", "/api/maintenanceWindows/check_batch", false, []string{"maintenance-windows", "check-batch", "get"}},
	}
	for _, c := range cases {
		if got := DeriveName(c.method, c.path, c.child); !reflect.DeepEqual(got, c.want) {
			t.Errorf("DeriveName(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

func TestPathParams(t *testing.T) {
	got := PathParams("/api/im/teams/{id}/members/{memberId}")
	if want := []string{"id", "memberId"}; !reflect.DeepEqual(got, want) {
		t.Errorf("PathParams = %v, want %v", got, want)
	}
}
