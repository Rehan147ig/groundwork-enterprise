package secretref

import (
	"strings"
	"testing"
)

func TestParseKeyring(t *testing.T) {
	cases := []struct {
		in          string
		wantPurpose string
		wantID      string
	}{
		{"keyring://connector/msgraph", "connector", "msgraph"},
		{"keyring://connector", "connector", ""},
		{"keyring://connector/msgraph/t1", "connector", "msgraph/t1"},
		{"keyring:///connector/msgraph", "connector", "msgraph"},
	}
	for _, tc := range cases {
		r, err := Parse(tc.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.in, err)
		}
		if !r.IsKeyring() || r.Purpose != tc.wantPurpose || r.ID != tc.wantID {
			t.Fatalf("Parse(%q) = %+v, want purpose %q id %q", tc.in, r, tc.wantPurpose, tc.wantID)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"keyring://",
		"keyring:///",
		"keyring://?query",
		"keyring://connector/msgraph?x=1",
		"env://",
		"env://A/B",
		"env://A?x=1",
		"http://example.com/secret",
		"plaintext-secret",
		"file:///etc/passwd",
	}
	for _, in := range bad {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", in)
		}
	}
}

func TestParseEnvAndSecretsManager(t *testing.T) {
	r, err := Parse("env://MS_GRAPH_CLIENT_SECRET")
	if err != nil {
		t.Fatalf("Parse env: %v", err)
	}
	if !r.IsEnv() || r.ID != "MS_GRAPH_CLIENT_SECRET" {
		t.Fatalf("env ref = %+v", r)
	}
	for _, sm := range []string{
		"secretsmanager://msgraph-prod",
		"aws:secretsmanager:msgraph-prod",
		"gcp:secretmanager:msgraph-prod",
		"vault://msgraph-prod",
	} {
		r, err := Parse(sm)
		if err != nil {
			t.Fatalf("Parse(%q): %v", sm, err)
		}
		if !r.IsSecretsManager() {
			t.Fatalf("%q parsed as %+v, want secrets-manager scheme", sm, r)
		}
	}
}

func TestIsKeyringRef(t *testing.T) {
	if !IsKeyringRef("keyring://connector/msgraph") {
		t.Fatal("keyring ref must parse")
	}
	if IsKeyringRef("env://X") || IsKeyringRef("keyring://") || IsKeyringRef("") {
		t.Fatal("non-keyring refs must not parse as keyring")
	}
}

func TestGuardProductionRef(t *testing.T) {
	if err := GuardProductionRef("keyring://connector/msgraph"); err != nil {
		t.Fatalf("keyring ref must pass production: %v", err)
	}
	if err := GuardProductionRef("secretsmanager://x"); err != nil {
		t.Fatalf("secrets-manager ref must pass production gate: %v", err)
	}
	err := GuardProductionRef("env://MS_GRAPH_CLIENT_SECRET")
	if err == nil || !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("env ref in production must fail closed, got %v", err)
	}
	if err := GuardProductionRef(""); err == nil {
		t.Fatal("empty ref must fail")
	}
}
