// Package exports builds framework evidence exports (Phase 4e):
// per-jurisdiction compliance profiles map Groundwork's tamper-evident
// governance evidence to control-level reports an auditor can review.
//
// Profiles: EU AI Act, DORA, GDPR, ISO/IEC 42001, NIST AI RMF, and the
// UK/US customer policies. An export is a deterministic, tenant-scoped,
// region/jurisdiction-tagged report: every claim references evidence
// event ids with immutable digests and a chain-verification status.
// The exports service never fabricates evidence: a control with no
// matching evidence is reported as "no_evidence", not "satisfied".
package exports

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrUnknownFramework is returned for an id outside the closed set.
var ErrUnknownFramework = errors.New("exports: unknown framework")

// ControlStatus is the closed set of control statuses. Status is
// derived only from matching evidence — never guessed.
type ControlStatus string

const (
	StatusSatisfied       ControlStatus = "satisfied"        // matching evidence + chain verified
	StatusPartiallyMet    ControlStatus = "partially_met"    // some (not all) kinds evidenced
	StatusNoEvidence      ControlStatus = "no_evidence"      // nothing in the window
	StatusChainUnverified ControlStatus = "chain_unverified" // evidence present but chain check failed
)

// Framework is one compliance profile.
type Framework struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Jurisdiction string    `json:"jurisdiction"` // primary jurisdiction the profile targets
	Controls     []Control `json:"controls"`
}

// Control is one auditable control within a framework. EvidenceKinds
// are the evidence event kinds that substantiate the control.
type Control struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	EvidenceKinds []string `json:"evidence_kinds"` // subset of the closed evidence kind set
}

// EvidenceKind is the closed evidence event kind set (mirrors
// runtime.EvidenceKind*; kept local so this package stays independent).
const (
	EvidenceKindDecision         = "decision"
	EvidenceKindApproval         = "approval"
	EvidenceKindDelegationMint   = "delegation_mint"
	EvidenceKindDelegationRevoke = "delegation_revoke"
	EvidenceKindEmergencyControl = "emergency_control"
	EvidenceKindRunStart         = "run_start"
	EvidenceKindRunEnd           = "run_end"
)

// EvidenceRef is one evidence event included in an export. Only safe
// metadata travels — never tokens, secrets, or payloads.
type EvidenceRef struct {
	EventID         string    `json:"event_id"`
	Kind            string    `json:"kind"`
	OccurredAt      time.Time `json:"occurred_at"`
	Decision        string    `json:"decision,omitempty"`
	ReasonCode      string    `json:"reason_code,omitempty"`
	Region          string    `json:"region,omitempty"`
	Jurisdiction    string    `json:"jurisdiction,omitempty"`
	ImmutableDigest string    `json:"immutable_digest"`
}

// ChainResult is the outcome of verifying the tenant's evidence chains.
type ChainResult struct {
	Checked  int    `json:"checked"`
	Problems int    `json:"problems"`
	Verified bool   `json:"verified"`
	Detail   string `json:"detail,omitempty"`
}

// ControlReport is one control's status plus its supporting evidence.
type ControlReport struct {
	ControlID   string        `json:"control_id"`
	Title       string        `json:"title"`
	Status      ControlStatus `json:"status"`
	Evidence    []EvidenceRef `json:"evidence"`
	Limitations []string      `json:"limitations"`
}

// Export is a tenant-scoped framework evidence report.
type Export struct {
	FrameworkID   string          `json:"framework"`
	FrameworkName string          `json:"framework_name"`
	Region        string          `json:"region"`
	Jurisdiction  string          `json:"jurisdiction"`
	TenantID      string          `json:"tenant_id"`
	Owner         string          `json:"owner,omitempty"` // requesting actor principal
	GeneratedAt   time.Time       `json:"generated_at"`
	WindowFrom    time.Time       `json:"window_from"`
	WindowTo      time.Time       `json:"window_to"`
	Controls      []ControlReport `json:"controls"`
	Chain         ChainResult     `json:"chain_verification"`
	// Limitations is the export-level disclaimer: what this report can
	// and cannot prove. Never empty — an evidence-based export states
	// its boundaries.
	Limitations []string `json:"limitations"`
}

// Source provides the evidence the export is built from.
type Source interface {
	// Evidence returns tenant-scoped evidence events in [from, to).
	Evidence(ctx context.Context, tenantID string, from, to time.Time) ([]EvidenceRef, error)
	// VerifyChain verifies the tenant's evidence chains up to now.
	VerifyChain(ctx context.Context, tenantID string) (ChainResult, error)
}

// Frameworks returns the closed set of framework profiles.
func Frameworks() []Framework {
	return []Framework{
		{
			ID:           "eu_ai_act",
			Name:         "EU AI Act",
			Jurisdiction: "eu",
			Controls: []Control{
				{ID: "art_9_risk_management", Title: "Article 9 — Risk management system", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindEmergencyControl}},
				{ID: "art_12_logging", Title: "Article 12 — Record-keeping / automatic logging", EvidenceKinds: []string{EvidenceKindRunStart, EvidenceKindRunEnd, EvidenceKindDecision}},
				{ID: "art_26_transparency", Title: "Article 26 — Obligations of deployers (transparency)", EvidenceKinds: []string{EvidenceKindDelegationMint, EvidenceKindApproval}},
				{ID: "art_27_registry", Title: "Article 27 — Registration of high-risk AI systems", EvidenceKinds: []string{EvidenceKindDelegationMint, EvidenceKindRunStart}},
			},
		},
		{
			ID:           "dora",
			Name:         "DORA (Digital Operational Resilience Act)",
			Jurisdiction: "eu",
			Controls: []Control{
				{ID: "art_17_ict_risk", Title: "Article 17 — ICT risk management", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindEmergencyControl}},
				{ID: "art_18_detection", Title: "Article 18 — Detection of anomalous activity / logging", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindRunStart}},
				{ID: "art_24_oversight", Title: "Article 24 — Third-party ICT provider oversight", EvidenceKinds: []string{EvidenceKindDelegationMint, EvidenceKindDelegationRevoke}},
			},
		},
		{
			ID:           "gdpr",
			Name:         "GDPR (General Data Protection Regulation)",
			Jurisdiction: "eu",
			Controls: []Control{
				{ID: "art_5_integrity", Title: "Article 5(1)(f) — Integrity and confidentiality", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindApproval}},
				{ID: "art_30_records", Title: "Article 30 — Records of processing activities", EvidenceKinds: []string{EvidenceKindRunStart, EvidenceKindRunEnd}},
				{ID: "art_32_security", Title: "Article 32 — Security of processing", EvidenceKinds: []string{EvidenceKindEmergencyControl, EvidenceKindDelegationRevoke}},
			},
		},
		{
			ID:           "iso_42001",
			Name:         "ISO/IEC 42001 — AI Management System",
			Jurisdiction: "eu",
			Controls: []Control{
				{ID: "clause_6_planning", Title: "Clause 6 — Planning AI risk treatment", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindEmergencyControl}},
				{ID: "clause_8_operations", Title: "Clause 8 — Operational planning and control", EvidenceKinds: []string{EvidenceKindRunStart, EvidenceKindRunEnd}},
				{ID: "clause_10_improvement", Title: "Clause 10 — Continual improvement (correction)", EvidenceKinds: []string{EvidenceKindEmergencyControl, EvidenceKindDelegationRevoke}},
			},
		},
		{
			ID:           "nist_ai_rmf",
			Name:         "NIST AI RMF (AI Risk Management Framework)",
			Jurisdiction: "us",
			Controls: []Control{
				{ID: "govern_1", Title: "Govern — Establish risk management governance", EvidenceKinds: []string{EvidenceKindEmergencyControl, EvidenceKindDelegationMint}},
				{ID: "map_1", Title: "Map — Frame AI risk in context", EvidenceKinds: []string{EvidenceKindRunStart, EvidenceKindDecision}},
				{ID: "measure_3", Title: "Measure — Assess AI risk impacts", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindApproval}},
				{ID: "manage_1", Title: "Manage — Prioritize and act on AI risks", EvidenceKinds: []string{EvidenceKindEmergencyControl, EvidenceKindDecision}},
			},
		},
		{
			ID:           "uk_customer_policy",
			Name:         "UK customer policy",
			Jurisdiction: "uk",
			Controls: []Control{
				{ID: "c_1_access_control", Title: "Access control — least privilege", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindDelegationMint}},
				{ID: "c_2_logging", Title: "Logging and monitoring", EvidenceKinds: []string{EvidenceKindRunStart, EvidenceKindDecision}},
				{ID: "c_3_change", Title: "Change and configuration management", EvidenceKinds: []string{EvidenceKindEmergencyControl, EvidenceKindDelegationRevoke}},
			},
		},
		{
			ID:           "us_customer_policy",
			Name:         "US customer policy",
			Jurisdiction: "us",
			Controls: []Control{
				{ID: "c_1_access_control", Title: "Access control — least privilege", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindDelegationMint}},
				{ID: "c_2_monitoring", Title: "Continuous monitoring", EvidenceKinds: []string{EvidenceKindRunStart, EvidenceKindDecision}},
				{ID: "c_3_config", Title: "Configuration management", EvidenceKinds: []string{EvidenceKindEmergencyControl, EvidenceKindDelegationRevoke}},
			},
		},
		{
			ID:           "soc2_type2",
			Name:         "SOC 2 Type II",
			Jurisdiction: "us",
			Controls: []Control{
				{ID: "cc6.1_access_control", Title: "CC6.1 Access Control", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindApproval}},
				{ID: "cc6.6_encryption", Title: "CC6.6 Encryption", EvidenceKinds: []string{EvidenceKindDecision}},
				{ID: "cc7.2_audit_logging", Title: "CC7.2 Audit Logging", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindEmergencyControl}},
			},
		},
		{
			ID:           "pci_dss_v4",
			Name:         "PCI DSS v4",
			Jurisdiction: "us",
			Controls: []Control{
				{ID: "req7_restrict_access", Title: "Requirement 7 – Restrict access to system components", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindApproval}},
				{ID: "req10_log_monitor", Title: "Requirement 10 – Log and monitor all access", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindEmergencyControl}},
			},
		},
		{
			ID:           "hipaa_security",
			Name:         "HIPAA Security Rule",
			Jurisdiction: "us",
			Controls: []Control{
				{ID: "hipaa_312_a1", Title: "§164.312(a)(1) Access Control", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindApproval}},
				{ID: "hipaa_312_b", Title: "§164.312(b) Audit Controls", EvidenceKinds: []string{EvidenceKindDecision, EvidenceKindEmergencyControl}},
			},
		},
	}
}

// Lookup returns the framework with the given id, or nil.
func Lookup(id string) *Framework {
	for i := range Frameworks() {
		if Frameworks()[i].ID == id {
			return &Frameworks()[i]
		}
	}
	return nil
}

// Build produces the framework evidence export for the tenant. It is
// deterministic: same evidence + chain result ⇒ same report (modulo
// GeneratedAt).
func Build(fw Framework, tenantID, region, jurisdiction, owner string, from, to time.Time, evidence []EvidenceRef, chain ChainResult) Export {
	reports := make([]ControlReport, 0, len(fw.Controls))
	for _, control := range fw.Controls {
		report := ControlReport{
			ControlID:   control.ID,
			Title:       control.Title,
			Status:      StatusNoEvidence,
			Evidence:    nil,
			Limitations: nil,
		}
		wanted := map[string]bool{}
		for _, kind := range control.EvidenceKinds {
			wanted[kind] = true
		}
		matchedKinds := map[string]bool{}
		for _, ev := range evidence {
			if !wanted[ev.Kind] {
				continue
			}
			report.Evidence = append(report.Evidence, ev)
			matchedKinds[ev.Kind] = true
		}
		if len(report.Evidence) > 0 {
			sort.Slice(report.Evidence, func(i, j int) bool {
				return report.Evidence[i].OccurredAt.Before(report.Evidence[j].OccurredAt)
			})
			switch {
			case !chain.Verified:
				report.Status = StatusChainUnverified
				report.Limitations = append(report.Limitations, "evidence present but chain verification reported problems")
			case len(matchedKinds) == len(wanted):
				report.Status = StatusSatisfied
			default:
				report.Status = StatusPartiallyMet
				report.Limitations = append(report.Limitations, fmt.Sprintf(
					"only kinds %s evidenced (want %s)", sortedKeys(matchedKinds), strings.Join(control.EvidenceKinds, ", ")))
			}
		}
		reports = append(reports, report)
	}

	return Export{
		FrameworkID:   fw.ID,
		FrameworkName: fw.Name,
		Region:        region,
		Jurisdiction:  jurisdiction,
		TenantID:      tenantID,
		Owner:         owner,
		GeneratedAt:   time.Now().UTC(),
		WindowFrom:    from,
		WindowTo:      to,
		Controls:      reports,
		Chain:         chain,
		Limitations: []string{
			"export is generated from the tenant's immutable evidence chains and reflects only the configured time window",
			"evidence status is derived from matching evidence kinds; it is not a certification of the framework",
			"digests reference the evidence chain; verify them against the chain verification result",
		},
	}
}

// Service builds exports from a live Source.
type Service struct {
	src Source
}

// NewService builds an export service over the given evidence source.
func NewService(src Source) *Service { return &Service{src: src} }

// Export builds the framework report for the tenant. Unknown framework
// ids return ErrUnknownFramework; the region/jurisdiction passed here
// must come from trusted deployment configuration, never request bodies.
func (s *Service) Export(ctx context.Context, frameworkID, tenantID, region, jurisdiction, owner string, from, to time.Time) (Export, error) {
	fw := Lookup(frameworkID)
	if fw == nil {
		return Export{}, fmt.Errorf("%w: %q", ErrUnknownFramework, frameworkID)
	}
	if to.IsZero() || to.Before(from) || from.IsZero() {
		return Export{}, errors.New("exports: invalid time window")
	}
	evidence, err := s.src.Evidence(ctx, tenantID, from, to)
	if err != nil {
		return Export{}, err
	}
	chain, err := s.src.VerifyChain(ctx, tenantID)
	if err != nil {
		return Export{}, err
	}
	return Build(*fw, tenantID, region, jurisdiction, owner, from, to, evidence, chain), nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
