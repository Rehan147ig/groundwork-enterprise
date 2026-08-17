package exports

import (
	"testing"
	"time"
)

func TestExportsBuild(t *testing.T) {
	// Minimal evidence slice containing each evidence kind at least once.
	evidence := []EvidenceRef{
		{EventID: "ev-decision-1", Kind: EvidenceKindDecision, OccurredAt: time.Now()},
		{EventID: "ev-approval-1", Kind: EvidenceKindApproval, OccurredAt: time.Now()},
		{EventID: "ev-emergency-1", Kind: EvidenceKindEmergencyControl, OccurredAt: time.Now()},
		{EventID: "ev-delegation-1", Kind: EvidenceKindDelegationMint, OccurredAt: time.Now()},
		{EventID: "ev-delegation-revoke-1", Kind: EvidenceKindDelegationRevoke, OccurredAt: time.Now()},
		{EventID: "ev-run-start-1", Kind: EvidenceKindRunStart, OccurredAt: time.Now()},
		{EventID: "ev-run-end-1", Kind: EvidenceKindRunEnd, OccurredAt: time.Now()},
	}

	chain := ChainResult{Checked: 1, Problems: 0, Verified: true}

	newFrameworks := []string{"soc2_type2", "pci_dss_v4", "hipaa_security"}
	region := "us-east-1"
	from := time.Now().Add(-24 * time.Hour) // last 24h
	to := time.Now()
	for _, fwID := range newFrameworks {
		fw := Lookup(fwID)
		if fw == nil {
			t.Fatalf("framework %s not found", fwID)
		}
		exp := Build(*fw, "tenant-1", region, fw.Jurisdiction, "owner-1", from, to, evidence, chain)
		// Verify that no control is reported as NoEvidence; each should be at least partially met.
		for _, ctrl := range exp.Controls {
			if ctrl.Status == StatusNoEvidence {
				t.Errorf("framework %s control %s has NoEvidence", fwID, ctrl.ControlID)
			}
			// Ensure status is one of the valid statuses.
			switch ctrl.Status {
			case StatusSatisfied, StatusPartiallyMet, StatusChainUnverified:
				// ok
			default:
				t.Errorf("framework %s control %s has unexpected status %s", fwID, ctrl.ControlID, ctrl.Status)
			}
		}
	}
}
