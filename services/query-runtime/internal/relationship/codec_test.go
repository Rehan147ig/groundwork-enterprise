package relationship

import "testing"

func TestPermissionMapping(t *testing.T) {
	cases := []struct {
		permission, wantRelation string
	}{
		{PermissionView, RelationViewer},
		{PermissionUse, RelationUse},
		{PermissionExecute, RelationExecute},
	}
	for _, c := range cases {
		if got := PermissionToRelation(c.permission); got != c.wantRelation {
			t.Errorf("PermissionToRelation(%q) = %q, want %q", c.permission, got, c.wantRelation)
		}
		if got := RelationToPermission(c.wantRelation); got != c.permission {
			t.Errorf("RelationToPermission(%q) = %q, want %q", c.wantRelation, got, c.permission)
		}
	}
	if got := PermissionToRelation("sudo"); got != "sudo" {
		t.Errorf("unknown permission must pass through unchanged, got %q", got)
	}
}

func TestSubjectCodecRoundTrip(t *testing.T) {
	cases := []SubjectRef{
		UserRef("alice"),
		UserRef("principal:legacy-alice"), // legacy prefix lives in the ID
		GroupRef("eng"),
		{Type: TypeGroup, ID: "eng", Relation: ""}, // group as direct subject
		{Type: TypeFolder, ID: "finance-folder"},
	}
	for _, in := range cases {
		enc := EncodeSubject(in)
		out, err := ParseSubject(enc)
		if err != nil {
			t.Fatalf("parse %q: %v", enc, err)
		}
		if out != in {
			t.Errorf("round trip %q: got %+v, want %+v", enc, out, in)
		}
	}
}

func TestObjectCodecRoundTrip(t *testing.T) {
	cases := []ResourceRef{
		DocumentRef("budget-2026"),
		FolderRef("finance-folder"),
		ToolRef("github"),
		ToolActionRef("github", "create_issue"), // composite ID with a colon
	}
	for _, in := range cases {
		enc := EncodeObject(in)
		out, err := ParseObject(enc)
		if err != nil {
			t.Fatalf("parse %q: %v", enc, err)
		}
		if out != in {
			t.Errorf("round trip %q: got %+v, want %+v", enc, out, in)
		}
	}
}

func TestCodecRejectsMalformed(t *testing.T) {
	if _, err := ParseSubject(""); err == nil {
		t.Error("empty subject must fail")
	}
	if _, err := ParseSubject("group:g#"); err == nil {
		t.Error("empty userset must fail")
	}
	if _, err := ParseSubject("g"); err == nil {
		t.Error("missing type: must fail")
	}
	if _, err := ParseObject("document:"); err == nil {
		t.Error("missing id must fail")
	}
	if _, err := ParseObject(":id"); err == nil {
		t.Error("missing type must fail")
	}
}

func TestEscapeIDRoundTrip(t *testing.T) {
	ids := []string{"plain-id", "tool:action", "a:b:c", "has~tilde", "colon:and~tilde"}
	for _, in := range ids {
		escaped := EscapeID(in)
		for _, r := range escaped {
			if r == ':' {
				t.Errorf("EscapeID(%q) = %q still contains a colon", in, escaped)
			}
		}
		if got := UnescapeID(escaped); got != in {
			t.Errorf("escape round trip %q: got %q", in, got)
		}
	}
}
