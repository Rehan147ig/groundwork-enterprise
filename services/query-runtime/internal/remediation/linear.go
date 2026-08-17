package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"groundwork/query-runtime/internal/leakreport"
)

// JiraClient.CreateIssue uses leakReportHistoryDB;
// LinearClient.CreateIssue expects the same interface to be passed in.

// LinearConfig holds the configuration for Linear integration.
type LinearConfig struct {
	APIURL    string `env:"LINEAR_API_URL"`
	Token     string `env:"LINEAR_API_TOKEN"`
	ProjectID string `env:"LINEAR_PROJECT_ID"`
}

// LinearIssueRecord represents a Linear issue returned from the API.
type LinearIssueRecord struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Slug   string `json:"slug"`
	Status string `json:"status"`
}

// LinearClient handles communication with Linear GraphQL API.
type LinearClient struct {
	cfg    LinearConfig
	client *http.Client
}

// NewLinearClient creates a new LinearClient.
func NewLinearClient(cfg LinearConfig) *LinearClient {
	return &LinearClient{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// CreateIssue creates a Linear issue for a leak finding.
// It checks for high-severity world-readable or cross-department findings
// and avoids duplicate ticket creation via the leakReportHistoryDB.
func (c *LinearClient) CreateIssue(ctx context.Context, finding leakreport.Finding, documentOwner string, db leakReportHistoryDB) (string, error) {
	// Skip if finding is not high severity or not a world-readable/cross-department kind
	if finding.Severity != leakreport.SeverityHigh {
		return "", nil
	}
	if finding.Kind != leakreport.KindWorldReadable && finding.Kind != leakreport.KindCrossDepartment {
		return "", nil
	}

	// Check if a ticket already exists for this finding to avoid duplicates
	ticketExists, err := db.TicketExists(ctx, finding.Kind, finding.DocumentID)
	if err != nil {
		return "", fmt.Errorf("failed to check leak report history: %w", err)
	}
	if ticketExists {
		return "", nil // Ticket already created; skip duplicate
	}

	input := map[string]any{
		"data": map[string]any{
			"title": fmt.Sprintf("Security: %s - %s", finding.Kind, finding.Detail),
			"description": fmt.Sprintf(`Leak report finding detected:

Kind: %s
Severity: high
Detail: %s
Document ID: %s
Owner: %s

Automated remediation: create security review task.`, finding.Kind, finding.Detail, finding.DocumentID, documentOwner),
			"status": map[string]any{
				"id": "unstarted",
			},
			"teamId": c.cfg.ProjectID,
			"priority": map[string]any{
				"id": "P2",
			},
		},
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("failed to marshal linear payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.APIURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create linear request: %w", err)
	}
	req.SetBasicAuth("", c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call linear API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("linear API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			Issue LinearIssueRecord `json:"issue"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode linear response: %w", err)
	}

	// Record the created ticket in leak report history to avoid duplicates
	if err := db.RecordTicket(ctx, finding.Kind, finding.DocumentID, result.Data.Issue.ID); err != nil {
		_ = fmt.Sprintf("failed to record leak report ticket: %v", err)
	}

	return result.Data.Issue.ID, nil
}
