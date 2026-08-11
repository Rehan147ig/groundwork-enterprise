package schema

import (
	"strings"
	"testing"
)

func TestIsUpToDate(t *testing.T) {
	tests := []struct {
		name    string
		current string
		want    bool
	}{
		{"empty schema", "", false},
		{"exact embedded schema", ZED(), true},
		{"trivially reindented schema is still exact", strings.ReplaceAll(ZED(), "\t", "    "), true},
		{"extra definitions around the model are tolerated", ZED() + "\ndefinition audit_log {\n\trelation owner: user\n}\n", true},
		{"missing view permission anchor", strings.Replace(ZED(), "permission view = viewer + parent->view", "permission view = viewer", 1), false},
		{"missing a definition", strings.Replace(ZED(), "definition tool_action {", "definition platform_action {", 1), false},
		{"weakened viewer relation", strings.ReplaceAll(ZED(), "relation viewer: user | group#member", "relation viewer: user"), false},
		{"unrelated schema", "definition foo {\n\trelation bar: user\n}\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUpToDate(tt.current); got != tt.want {
				t.Fatalf("IsUpToDate = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestZEDNonEmpty(t *testing.T) {
	if strings.TrimSpace(ZED()) == "" {
		t.Fatal("embedded schema must not be empty")
	}
	if !strings.Contains(ZED(), "permission view = viewer + parent->view") {
		t.Fatal("schema must contain the folder-inheritance anchor")
	}
}
