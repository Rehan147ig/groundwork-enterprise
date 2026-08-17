package main

import "testing"

func TestValidateAuditSaltRejectsRepoLiterals(t *testing.T) {
	for _, salt := range []string{
		"example-audit-salt-017-AaBbCcDdEe",
		"quickstart_demo_salt_37840ed_valid",
		"change-me",
		"change_me",
		"changeme",
		"default",
		"default-salt",
		"default_salt",
		"default-salt-change-me",
		"default_salt_change_me",
		"secret",
		"password",
		"salt",
		"groundwork",
		"groundwork-salt",
		"groundwork_audit_salt",
	} {
		if err := validateAuditSalt(salt); err == nil {
			t.Fatalf("expected salt %q to be rejected as predictable", salt)
		}
	}
}

func TestValidateAuditSaltAllowsEmpty(t *testing.T) {
	if err := validateAuditSalt(""); err != nil {
		t.Fatalf("expected empty salt to be allowed, got %v", err)
	}
}

func TestValidateAuditSaltRejectsShort(t *testing.T) {
	if err := validateAuditSalt("tooshort"); err == nil {
		t.Fatal("expected salt shorter than 16 chars to be rejected")
	}
}

func TestValidateAuditSaltAllowsStrongRandom(t *testing.T) {
	if err := validateAuditSalt("a7f3e9c1d2b84f6e9a0c1d2e3f4a5b6c"); err != nil {
		t.Fatalf("expected strong random salt to be allowed, got %v", err)
	}
}
