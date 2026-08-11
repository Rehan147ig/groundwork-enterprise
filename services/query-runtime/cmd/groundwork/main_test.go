package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allTemplates loads and validates every embedded template.
func allTemplates(t *testing.T) map[string]PolicyTemplate {
	t.Helper()
	templates, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	if len(templates) == 0 {
		t.Fatal("no templates embedded")
	}
	for name, tpl := range templates {
		if problems := tpl.Validate(); len(problems) > 0 {
			t.Errorf("template %q invalid: %s", name, strings.Join(problems, "; "))
		}
	}
	return templates
}

func TestTemplatesValidate(t *testing.T) {
	templates := allTemplates(t)
	for name := range templates {
		if !templates[name].ReadOnly {
			t.Errorf("template %q must be read-only", name)
		}
	}
}

func TestTemplateValidationRejectsWriteActionInReadOnly(t *testing.T) {
	tpl := PolicyTemplate{
		Name: "bad", Region: "uk", ReadOnly: true,
		Tools:  []TplTool{{Name: "w", Transport: "builtin", Actions: []TplAction{{Action: "write", RiskLevel: "low", ReadOnly: false}}}},
		Budget: TplBudget{MaxActionsPerRun: 1, MaxToolCallsPerActionPerRun: 1, MaxRunDurationSeconds: 60},
	}
	problems := tpl.Validate()
	found := false
	for _, p := range problems {
		if strings.Contains(p, "read_only=true") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected read-only violation, got %v", problems)
	}
}

func TestRunTemplatesListsAll(t *testing.T) {
	templates := allTemplates(t)
	var out bytes.Buffer
	if code := runTemplates(&out); code != exitOK {
		t.Fatalf("runTemplates exit %d", code)
	}
	for name := range templates {
		if !strings.Contains(out.String(), name) {
			t.Errorf("templates output missing %q", name)
		}
	}
}

func TestRunInitWritesScaffold(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"init", "--dir", dir, "--template", "finance-agent"}, &out, &errOut)
	if code != exitOK {
		t.Fatalf("init exit %d: %s", code, errOut.String())
	}
	for _, file := range []string{"groundwork.env", "policy.json", "README.md", "delegation-rs256.pem", "delegation-rs256.pem.pub"} {
		if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
			t.Errorf("missing scaffold file %s: %v", file, err)
		}
	}
	// groundwork.env must be valid KEY=VALUE (except comments) and
	// reference the generated key path.
	envData, err := os.ReadFile(filepath.Join(dir, "groundwork.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(envData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "=") {
			t.Errorf("env line not KEY=VALUE: %q", line)
		}
	}
	if !strings.Contains(string(envData), "GROUNDWORK_DELEGATION_RS_PRIVATE_KEY_FILE=") {
		t.Error("env file does not wire the generated RSA key")
	}
	// policy.json must round-trip as a valid template.
	policyData, err := os.ReadFile(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tpl PolicyTemplate
	if err := json.Unmarshal(policyData, &tpl); err != nil {
		t.Fatalf("policy.json not valid JSON: %v", err)
	}
	if problems := tpl.Validate(); len(problems) > 0 {
		t.Errorf("rendered policy invalid: %s", strings.Join(problems, "; "))
	}
	if tpl.Name != "finance-agent" {
		t.Errorf("policy name = %q, want finance-agent", tpl.Name)
	}
	// RSA key must parse.
	keyData, err := os.ReadFile(filepath.Join(dir, "delegation-rs256.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Errorf("delegation key not PEM RSA PRIVATE KEY")
	}
	// Idempotency: second run without --force fails.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"init", "--dir", dir, "--template", "finance-agent"}, &out, &errOut); code == exitOK {
		t.Error("second init without --force should fail")
	}
	// With --force it succeeds.
	errOut.Reset()
	if code := run([]string{"init", "--dir", dir, "--template", "customer-support", "--force"}, &out, &errOut); code != exitOK {
		t.Errorf("init --force exit %d: %s", code, errOut.String())
	}
	policyData2, _ := os.ReadFile(filepath.Join(dir, "policy.json"))
	if strings.Contains(string(policyData2), "customer-support") == false {
		t.Error("--force did not replace policy.json with the new template")
	}
}

func TestRunInitRejectsUnknownTemplate(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"init", "--template", "does-not-exist", "--dir", t.TempDir()}, &out, &errOut)
	if code == exitOK {
		t.Fatal("unknown template should fail")
	}
	if !strings.Contains(errOut.String(), "unknown template") {
		t.Errorf("expected unknown template error, got %q", errOut.String())
	}
}

func TestLoadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.env")
	content := "# comment\n\nEMPTY_IGNORED=\nDATABASE_URL=postgres://a:b@h/db\nQUOTED=\"v1\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", "real-wins")
	if err := loadEnvFile(path); err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}
	if got := os.Getenv("DATABASE_URL"); got != "real-wins" {
		t.Errorf("real env must win, got %q", got)
	}
	if got := os.Getenv("QUOTED"); got != "v1" {
		t.Errorf("QUOTED = %q, want v1", got)
	}
	if got := os.Getenv("EMPTY_IGNORED"); got != "" {
		t.Errorf("empty value must not be set, got %q", got)
	}
}

func TestLoadEnvFileMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.env")
	if err := os.WriteFile(path, []byte("NOEQUALS\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadEnvFile(path); err == nil {
		t.Fatal("malformed env file should error")
	}
}

func TestDoctorFailsClosedInProduction(t *testing.T) {
	t.Setenv("GROUNDWORK_ENV", "production")
	t.Setenv("ALLOW_DEMO_IDENTITY", "true")
	t.Setenv("GROUNDWORK_JWT_HS_SECRET", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("SPICEDB_ENDPOINT", "")
	var out, errOut bytes.Buffer
	code := run([]string{"doctor"}, &out, &errOut)
	if code != exitCheck {
		t.Fatalf("doctor should fail closed in production, exit %d", code)
	}
	text := out.String()
	for _, want := range []string{"FAIL", "identity", "delegation", "demo_identity"} {
		if !strings.Contains(text, want) {
			t.Errorf("doctor output missing %q:\n%s", want, text)
		}
	}
}

func TestDoctorPassesLocalMode(t *testing.T) {
	t.Setenv("GROUNDWORK_ENV", "local")
	t.Setenv("GROUNDWORK_JWT_HS_SECRET", strings.Repeat("a", 32))
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", strings.Repeat("b", 32))
	t.Setenv("DATABASE_URL", "")
	t.Setenv("SPICEDB_ENDPOINT", "")
	t.Setenv("QDRANT_URL", "")
	t.Setenv("ELASTICSEARCH_URL", "")
	t.Setenv("ALLOW_DEMO_IDENTITY", "")
	var out, errOut bytes.Buffer
	code := run([]string{"doctor"}, &out, &errOut)
	if code != exitOK {
		t.Fatalf("doctor local mode should pass, exit %d:\n%s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "PASSED: all checks passed") {
		t.Errorf("expected success line:\n%s", out.String())
	}
}

func TestDoctorJSONOutput(t *testing.T) {
	t.Setenv("GROUNDWORK_ENV", "local")
	t.Setenv("GROUNDWORK_JWT_HS_SECRET", strings.Repeat("a", 32))
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", strings.Repeat("b", 32))
	var out, errOut bytes.Buffer
	code := run([]string{"doctor", "--json"}, &out, &errOut)
	if code != exitOK {
		t.Fatalf("doctor exit %d", code)
	}
	var results []checkResult
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("no checks in JSON output")
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"frobnicate"}, &out, &errOut); code != exitUsage {
		t.Errorf("unknown command exit = %d, want %d", code, exitUsage)
	}
}
