package deployment

import (
	"os"
	"strings"
	"testing"
)

func TestRegionJurisdiction(t *testing.T) {
	cases := map[string]struct {
		region       Region
		jurisdiction string
		frameworks   []string
	}{
		"EU":     {RegionEU, "eu", []string{"eu_ai_act", "dora", "gdpr", "iso_42001", "nist_ai_rmf"}},
		"UK":     {RegionUK, "uk", []string{"uk_customer_policy", "iso_42001", "nist_ai_rmf"}},
		"US":     {RegionUS, "us", []string{"us_customer_policy", "nist_ai_rmf", "iso_42001"}},
		"custom": {Region("eu-central-1"), "eu-central-1", nil}, // customer-defined jurisdiction: no default frameworks
	}
	for name, tc := range cases {
		if tc.region.Jurisdiction() != tc.jurisdiction {
			t.Errorf("%s: jurisdiction = %q, want %q", name, tc.region.Jurisdiction(), tc.jurisdiction)
		}
		if len(tc.frameworks) == 0 {
			continue
		}
		got := tc.region.ComplianceFrameworks()
		for i, want := range tc.frameworks {
			if got[i] != want {
				t.Errorf("%s: framework[%d] = %q, want %q", name, i, got[i], want)
			}
		}
	}
}

func TestParseRegionRejectsBodiesAndJunk(t *testing.T) {
	for _, junk := range []string{"", " ", "us;DROP", "eu\njunk", "a/b", strings.Repeat("x", 70)} {
		if _, err := ParseRegion(junk); err == nil {
			t.Errorf("ParseRegion(%q) should fail", junk)
		}
	}
	for _, ok := range []string{"EU", "uk", "us", "eu-central-1", "custom_region_1"} {
		if _, err := ParseRegion(ok); err != nil {
			t.Errorf("ParseRegion(%q) failed: %v", ok, err)
		}
	}
}

func TestValidateCoLocatedDeployment(t *testing.T) {
	cfg := DeploymentConfig{
		DeploymentRegion:       "EU",
		Jurisdiction:           "eu",
		AuditStorageConfigured: true,
		Gateway:                GatewayEndpoint{Enabled: true, Ports: []int{80, 443}, Region: "EU"},
		Services: []ServiceEndpoint{
			{Name: "gateway", Port: 80, Public: true},
			{Name: "query-runtime", Port: 8080},
			{Name: "qdrant", Port: 6333},
			{Name: "spicedb", Port: 50051},
			{Name: "postgres", Port: 5432},
		},
	}
	opts := ValidateOptions{Production: true, StrictKeys: true, LookupEnv: func(k string) string {
		if strings.HasPrefix(k, "GROUNDWORK_") {
			return "set"
		}
		return ""
	}}
	if problems := Validate(cfg, opts); len(problems) != 0 {
		t.Errorf("co-located EU deployment should validate clean, got: %v", problems)
	}
}

func TestValidateFailsClosedOnProblems(t *testing.T) {
	cfg := DeploymentConfig{
		DeploymentRegion: "EU",
		// Postgres in another region with NO transfer policy.
		PostgresRegion: "us-east-1",
		// Telemetry outside the jurisdiction.
		TelemetryRegion: "us-east-1",
		// No audit storage.
		AuditStorageConfigured: false,
		// Backend marked public (only gateway may be).
		Services: []ServiceEndpoint{
			{Name: "gateway", Port: 80, Public: true},
			{Name: "qdrant", Port: 6333, Public: true, Exposed: true},
		},
		// Model endpoint outside the region with no policy.
		ModelEndpoints: []ModelEndpoint{{Name: "llm", URL: "https://llm.example", Region: "us-east-1"}},
	}
	opts := ValidateOptions{Production: true, StrictKeys: true, LookupEnv: func(k string) string { return "" }}
	problems := Validate(cfg, opts)
	codes := map[string]bool{}
	for _, p := range problems {
		codes[p.Code] = true
	}
	for _, want := range []string{"region_mismatch", "telemetry_jurisdiction", "audit_storage_not_configured", "backend_port_public", "unapproved_external_endpoint", "production_key_missing"} {
		if !codes[want] {
			t.Errorf("expected problem %q, got codes %v", want, codes)
		}
	}
}

func TestValidateTransferPolicyAllowsCrossRegion(t *testing.T) {
	cfg := DeploymentConfig{
		DeploymentRegion:       "EU",
		Jurisdiction:           "eu",
		TelemetryRegion:        "eu-west-3",
		BackupRegion:           "eu-central-1",
		AuditStorageConfigured: true,
		TransferPolicies: []TransferPolicy{
			{ID: "tp-1", Kind: "telemetry", From: "EU", To: "eu-west-3", DataClass: "anonymized_telemetry", Allowed: true},
			{ID: "tp-2", Kind: "backup", From: "EU", To: "eu-central-1", DataClass: "encrypted_backup", Allowed: true},
		},
	}
	problems := Validate(cfg, ValidateOptions{Production: false})
	for _, p := range problems {
		if p.Code == "region_mismatch" || p.Code == "telemetry_jurisdiction" {
			t.Errorf("explicit transfer policy should permit the flow, got problem: %v", p)
		}
	}
}

func TestValidateDeniedTransferPolicyFailsClosed(t *testing.T) {
	cfg := DeploymentConfig{
		DeploymentRegion:       "EU",
		TelemetryRegion:        "eu-west-3",
		AuditStorageConfigured: true,
		TransferPolicies: []TransferPolicy{
			{ID: "tp-1", Kind: "telemetry", From: "EU", To: "eu-west-3", Allowed: false}, // explicit denial
		},
	}
	problems := Validate(cfg, ValidateOptions{Production: false})
	found := false
	for _, p := range problems {
		if p.Code == "telemetry_jurisdiction" {
			found = true
		}
	}
	if !found {
		t.Error("telemetry flow explicitly denied must fail closed (telemetry_jurisdiction)")
	}
}

func TestValidateMissingRegion(t *testing.T) {
	problems := Validate(DeploymentConfig{}, ValidateOptions{Production: true})
	found := false
	for _, p := range problems {
		if p.Code == "region_missing" {
			found = true
		}
	}
	if !found {
		t.Error("empty deployment region must produce region_missing")
	}
}

func TestValidateProductionDemoIdentityFails(t *testing.T) {
	cfg := DeploymentConfig{DeploymentRegion: "EU", AuditStorageConfigured: true}
	opts := ValidateOptions{Production: true, LookupEnv: func(k string) string {
		if k == "ALLOW_DEMO_IDENTITY" {
			return "true"
		}
		return ""
	}}
	for _, p := range Validate(cfg, opts) {
		if p.Code == "demo_identity_in_production" {
			return
		}
	}
	t.Error("ALLOW_DEMO_IDENTITY=true must fail production validation")
}

func TestTenantRegionResolver(t *testing.T) {
	r, err := BuildTenantRegionResolver("acme:EU,contoso:uk,dataworks:eu-central-1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if region, j, ok := r.Resolve("acme"); !ok || region != "EU" || j != "eu" {
		t.Errorf("acme -> %q/%q/%v", region, j, ok)
	}
	if region, j, ok := r.Resolve("contoso"); !ok || region != "uk" || j != "uk" {
		t.Errorf("contoso -> %q/%q/%v", region, j, ok)
	}
	if _, _, ok := r.Resolve("unprovisioned"); ok {
		t.Error("unprovisioned tenant must resolve as not ok (fail closed)")
	}
	if _, err := BuildTenantRegionResolver("acme:EU,bad"); err == nil {
		t.Error("malformed spec must fail at build time")
	}
	if _, err := BuildTenantRegionResolver("acme:INVALID REGION!!"); err == nil {
		t.Error("invalid region must fail at build time")
	}
}

func TestTenantRegionResolverEmptySpec(t *testing.T) {
	r, err := BuildTenantRegionResolver("")
	if err != nil || r != nil {
		t.Errorf("empty spec should yield nil resolver, got %v, %v", r, err)
	}
}

func TestParseTransferPolicies(t *testing.T) {
	policies := ParseTransferPolicies("telemetry:EU:uk,backup:EU:US,audit:eu-central-1:EU")
	if len(policies) != 3 {
		t.Fatalf("want 3 policies, got %d: %v", len(policies), policies)
	}
	if !policies[0].Allows("telemetry", "EU", "uk") {
		t.Errorf("telemetry EU->uk should be allowed: %+v", policies[0])
	}
	if policies[0].Allows("telemetry", "uk", "EU") {
		t.Errorf("reverse direction must not be allowed: %+v", policies[0])
	}
	if policies[1].Allows("model", "EU", "US") {
		t.Errorf("kind mismatch must not be allowed: %+v", policies[1])
	}
}

func TestParseTransferPoliciesIgnoresMalformed(t *testing.T) {
	policies := ParseTransferPolicies("telemetry:EU:uk,model:EU:US,banana:EU:uk,telemetry:EU,telemetry::uk,,:,:")
	if len(policies) != 2 {
		t.Fatalf("malformed/unknown entries must be dropped, got %d: %v", len(policies), policies)
	}
}

func TestConfigFromEnvironment(t *testing.T) {
	restore := make(map[string]string)
	set := func(k, v string) {
		restore[k] = os.Getenv(k)
		if v == "" {
			_ = os.Unsetenv(k)
		} else {
			_ = os.Setenv(k, v)
		}
	}
	defer func() {
		for k, v := range restore {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	}()

	set("GROUNDWORK_DEPLOYMENT_REGION", "EU")
	set("GROUNDWORK_JURISDICTION", "")
	set("GROUNDWORK_POSTGRES_REGION", "fr-central-1")
	set("GROUNDWORK_TELEMETRY_REGION", "uk")
	set("GROUNDWORK_TRANSFER_POLICIES", "telemetry:EU:uk")
	set("GROUNDWORK_EGRESS_ALLOWLIST", "api.openai.com, models.example.com")
	set("GROUNDWORK_BACKUP_ENABLED", "true")
	set("GATEWAY_HTTP_PORT", "443")
	set("GROUNDWORK_QDRANT_EXPOSED", "6333")
	set("DATABASE_URL", "postgres://x")

	cfg := ConfigFromEnvironment()
	if cfg.DeploymentRegion != "EU" {
		t.Errorf("deployment region = %q", cfg.DeploymentRegion)
	}
	if got := cfg.EffectiveRegion("postgres"); got != "fr-central-1" {
		t.Errorf("postgres region = %q", got)
	}
	if got := cfg.EffectiveRegion("telemetry"); got != "uk" {
		t.Errorf("telemetry region = %q", got)
	}
	if got := cfg.EffectiveRegion("qdrant"); got != "EU" {
		t.Errorf("co-located qdrant should resolve to EU, got %q", got)
	}
	if !cfg.AuditStorageConfigured {
		t.Error("DATABASE_URL must mark audit storage configured")
	}
	if !cfg.BackupEnabled {
		t.Error("GROUNDWORK_BACKUP_ENABLED=true must set BackupEnabled")
	}
	if !cfg.Gateway.Enabled || cfg.Gateway.Ports[0] != 443 {
		t.Errorf("gateway = %+v", cfg.Gateway)
	}
	for _, svc := range cfg.Services {
		if svc.Name == "qdrant" && !svc.Exposed {
			t.Error("GROUNDWORK_QDRANT_EXPOSED=6333 must mark qdrant exposed")
		}
		if svc.Name == "postgres" && svc.Exposed {
			t.Error("postgres must stay private without an _EXPOSED flag")
		}
	}
	if len(cfg.EgressAllowlist) != 2 {
		t.Errorf("egress allowlist = %v", cfg.EgressAllowlist)
	}
	if cfg.EffectiveRegion("telemetry") != "uk" || !cfg.TransferPolicies[0].Allows("telemetry", "EU", "uk") {
		t.Errorf("transfer policies not carried through: %+v", cfg.TransferPolicies)
	}
}
