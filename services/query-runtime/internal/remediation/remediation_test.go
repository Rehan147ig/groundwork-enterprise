package remediation

import (
	"context"
	"testing"

	"groundwork/query-runtime/internal/leakreport"
)

func TestJiraPayloadFormat(t *testing.T) {
	// Test that CreateIssue returns early for non-high severity findings
	lowSeverity := leakreport.Finding{
		Kind:       leakreport.KindWorldReadable,
		Severity:   leakreport.SeverityLow,
		DocumentID: "gh:12345",
		Owner:      "alice",
		Detail:     "Document is world-readable via user:*",
	}
	client := NewJiraClient(JiraConfig{
		BaseURL:    "https://jira.example.com",
		ProjectKey: "GROUND",
		Token:      "atlassian_token",
	})
	_, err := client.CreateIssue(context.Background(), lowSeverity, "bob", nil)
	if err != nil {
		t.Fatalf("unexpected error for low severity: %v", err)
	}

	// Test that CreateIssue returns early for non-matching kinds
	mediumFinding := leakreport.Finding{
		Kind:       leakreport.KindOverexposed,
		Severity:   leakreport.SeverityMedium,
		DocumentID: "gh:12345",
		Owner:      "alice",
		Detail:     "Document is overexposed",
	}
	_, err = client.CreateIssue(context.Background(), mediumFinding, "bob", nil)
	if err != nil {
		t.Fatalf("unexpected error for overexposed: %v", err)
	}
}

func TestLinearPayloadFormat(t *testing.T) {
	// Test that CreateIssue returns early for non-high severity findings
	lowSeverity := leakreport.Finding{
		Kind:       leakreport.KindCrossDepartment,
		Severity:   leakreport.SeverityLow,
		DocumentID: "gh:67890",
		Owner:      "bob",
		Detail:     "Cross-department access detected",
	}
	client := NewLinearClient(LinearConfig{
		APIURL:    "https://api.linear.app/graphql",
		Token:     "linear_token",
		ProjectID: "proj_123",
	})
	_, err := client.CreateIssue(context.Background(), lowSeverity, "alice", nil)
	if err != nil {
		t.Fatalf("unexpected error for low severity: %v", err)
	}

	// Test that CreateIssue returns early for non-matching kinds
	mediumFinding := leakreport.Finding{
		Kind:       leakreport.KindOrphaned,
		Severity:   leakreport.SeverityLow,
		DocumentID: "gh:67890",
		Owner:      "bob",
		Detail:     "Orphaned document",
	}
	_, err = client.CreateIssue(context.Background(), mediumFinding, "alice", nil)
	if err != nil {
		t.Fatalf("unexpected error for orphaned: %v", err)
	}
}
