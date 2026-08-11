package exports

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFrameworksClosedSet(t *testing.T) {
	ids := map[string]bool{}
	for _, fw := range Frameworks() {
		if fw.ID == "" || fw.Name == "" || fw.Jurisdiction == "" || len(fw.Controls) == 0 {
			t.Errorf("incomplete framework: %+v", fw)
		}
		if ids[fw.ID] {
			t.Errorf("duplicate framework id %q", fw.ID)
		}
		ids[fw.ID] = true
		for _, c := range fw.Controls {
			if len(c.EvidenceKinds) == 0 {
				t.Errorf("%s/%s has no evidence kinds", fw.ID, c.ID)
			}
		}
	}
	if !ids["eu_ai_act"] || !ids["dora"] || !ids["gdpr"] || !ids["iso_42001"] || !ids["nist_ai_rmf"] ||
		!ids["uk_customer_policy"] || !ids["us_customer_policy"] {
		t.Errorf("closed set incomplete: %v", ids)
	}
	if Lookup("bogus") != nil {
		t.Error("unknown framework must not resolve")
	}
}

func TestBuildStatusDerivation(t *testing.T) {
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()
	evidence := []EvidenceRef{
		{EventID: "e1", Kind: EvidenceKindDecision, OccurredAt: from.Add(time.Hour), ImmutableDigest: "d1", Region: "EU", Jurisdiction: "eu"},
		{EventID: "e2", Kind: EvidenceKindEmergencyControl, OccurredAt: from.Add(2 * time.Hour), ImmutableDigest: "d2", Region: "EU", Jurisdiction: "eu"},
	}
	fw := Lookup("eu_ai_act")
	export := Build(*fw, "acme", "EU", "eu", "owner-1", from, to, evidence, ChainResult{Checked: 10, Verified: true})

	byID := map[string]ControlReport{}
	for _, c := range export.Controls {
		byID[c.ControlID] = c
	}

	if got := byID["art_9_risk_management"]; got.Status != StatusSatisfied {
		t.Errorf("art_9: both kinds evidenced + chain ok ⇒ satisfied, got %q", got.Status)
	}
	if got := byID["art_12_logging"]; got.Status != StatusPartiallyMet {
		t.Errorf("art_12: only 2/3 kinds ⇒ partially_met, got %q", got.Status)
	}
	if got := byID["art_27_registry"]; got.Status != StatusNoEvidence {
		t.Errorf("art_27: nothing evidenced ⇒ no_evidence, got %q", got.Status)
	}
	if len(export.Limitations) == 0 {
		t.Error("export must always carry limitations")
	}
	if export.Region != "EU" || export.Jurisdiction != "eu" || export.TenantID != "acme" {
		t.Errorf("export identity fields wrong: %+v", export)
	}
}

func TestBuildChainUnverified(t *testing.T) {
	from := time.Now().Add(-time.Hour)
	to := time.Now()
	evidence := []EvidenceRef{{EventID: "e1", Kind: EvidenceKindDecision, OccurredAt: from.Add(time.Minute), ImmutableDigest: "d1"}}
	fw := Lookup("nist_ai_rmf")
	export := Build(*fw, "acme", "US", "us", "", from, to, evidence, ChainResult{Checked: 5, Problems: 1, Verified: false})
	for _, report := range export.Controls {
		if report.ControlID == "map_1" {
			if report.Status != StatusChainUnverified {
				t.Errorf("chain problems must downgrade matched evidence to chain_unverified, got %q", report.Status)
			}
			return
		}
	}
	t.Error("map_1 control not found in nist_ai_rmf profile")
}

func TestServiceUnknownFramework(t *testing.T) {
	svc := NewService(nil)
	_, err := svc.Export(context.Background(), "bogus", "acme", "EU", "eu", "o", time.Now().Add(-time.Hour), time.Now())
	if !errors.Is(err, ErrUnknownFramework) {
		t.Errorf("want ErrUnknownFramework, got %v", err)
	}
}

func TestServiceInvalidWindow(t *testing.T) {
	src := &fakeSource{}
	svc := NewService(src)
	_, err := svc.Export(context.Background(), "gdpr", "acme", "EU", "eu", "o", time.Now(), time.Now().Add(-time.Hour))
	if err == nil {
		t.Error("inverted window must fail")
	}
}

type fakeSource struct {
	evidence []EvidenceRef
	chain    ChainResult
}

func (f *fakeSource) Evidence(_ context.Context, _ string, _, _ time.Time) ([]EvidenceRef, error) {
	return f.evidence, nil
}

func (f *fakeSource) VerifyChain(_ context.Context, _ string) (ChainResult, error) {
	return f.chain, nil
}

func TestServiceExportEndToEnd(t *testing.T) {
	from := time.Now().Add(-48 * time.Hour)
	to := time.Now()
	src := &fakeSource{
		evidence: []EvidenceRef{
			{EventID: "e1", Kind: EvidenceKindRunStart, OccurredAt: from.Add(time.Hour), ImmutableDigest: "d1", Region: "UK", Jurisdiction: "uk"},
			{EventID: "e2", Kind: EvidenceKindDecision, OccurredAt: from.Add(2 * time.Hour), ImmutableDigest: "d2", Region: "UK", Jurisdiction: "uk"},
			{EventID: "e3", Kind: EvidenceKindRunEnd, OccurredAt: from.Add(3 * time.Hour), ImmutableDigest: "d3", Region: "UK", Jurisdiction: "uk"},
		},
		chain: ChainResult{Checked: 3, Verified: true},
	}
	svc := NewService(src)
	export, err := svc.Export(context.Background(), "uk_customer_policy", "acme", "UK", "uk", "owner-9", from, to)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if export.FrameworkID != "uk_customer_policy" || export.Region != "UK" || export.TenantID != "acme" {
		t.Errorf("export header: %+v", export)
	}
	byID := map[string]ControlReport{}
	for _, c := range export.Controls {
		byID[c.ControlID] = c
	}
	if got := byID["c_1_access_control"]; got.Status != StatusPartiallyMet {
		t.Errorf("c_1: decision+delegation_mint wanted, only decision ⇒ partially_met, got %q", got.Status)
	}
	if got := byID["c_2_logging"]; got.Status != StatusSatisfied {
		t.Errorf("c_2: run_start+decision both present ⇒ satisfied, got %q", got.Status)
	}
}
