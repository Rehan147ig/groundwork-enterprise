package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"groundwork/query-runtime/internal/leakreport"
)

// leakReportHistoryDB is the interface for tracking created tickets
// to avoid duplicate ticket creation across Jira and Linear integrations.
type leakReportHistoryDB interface {
	TicketExists(ctx context.Context, findingKind leakreport.Kind, documentID string) (bool, error)
	RecordTicket(ctx context.Context, findingKind leakreport.Kind, documentID, ticketKey string) error
}

// JiraConfig holds the configuration for Jira integration.
type JiraConfig struct {
	BaseURL    string `env:"JIRA_BASE_URL"`
	ProjectKey string `env:"JIRA_PROJECT_KEY"`
	Token      string `env:"JIRA_API_TOKEN"`
}

// JiraIssue represents a Jira issue payload.
type JiraIssue struct {
	Fields JiraFields `json:"fields"`
}

type JiraFields struct {
	Project     JiraProject   `json:"project"`
	Summary     string        `json:"summary"`
	Description string        `json:"description"`
	IssueType   JiraIssueType `json:"issuetype"`
	Assignee    JiraUser      `json:"assignee"`
	Labels      []string      `json:"labels"`
}

type JiraProject struct {
	Key string `json:"key"`
}

type JiraIssueType struct {
	Name string `json:"name"`
}

type JiraUser struct {
	Name string `json:"name"`
}

// JiraResponse represents the Jira API response.
type JiraResponse struct {
	Key string `json:"key"`
	ID  string `json:"id"`
}

// JiraClient handles communication with Jira REST API.
type JiraClient struct {
	cfg    JiraConfig
	client *http.Client
}

// NewJiraClient creates a new JiraClient.
func NewJiraClient(cfg JiraConfig) *JiraClient {
	return &JiraClient{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// CreateIssue creates a Jira issue for a leak finding.
// It checks for high-severity world-readable or cross-department findings
// and avoids duplicate ticket creation via the leakReportHistoryDB.
func (c *JiraClient) CreateIssue(ctx context.Context, finding leakreport.Finding, documentOwner string, db leakReportHistoryDB) (string, error) {
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

	payload := JiraIssue{
		Fields: JiraFields{
			Project: JiraProject{Key: c.cfg.ProjectKey},
			Summary: fmt.Sprintf("Security: %s - %s", finding.Kind, finding.Detail),
			Description: fmt.Sprintf(`Leak report finding detected:

Kind: %s
Severity: high
Detail: %s
Document ID: %s
Owner: %s

Automated remediation: create security review task.`, finding.Kind, finding.Detail, finding.DocumentID, documentOwner),
			IssueType: JiraIssueType{Name: "Task"},
			Assignee:  JiraUser{Name: documentOwner},
			Labels:    []string{"security", "leak-report", strings.ToLower(string(finding.Kind))},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jira payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.BaseURL+"/rest/api/3/issue", bytes.NewReader(jsonPayload))
	if err != nil {
		return "", fmt.Errorf("failed to create jira request: %w", err)
	}
	req.SetBasicAuth("", c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call jira API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("jira API returned %d: %s", resp.StatusCode, string(body))
	}

	var result JiraResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode jira response: %w", err)
	}

	// Record the created ticket in leak report history to avoid duplicates
	if err := db.RecordTicket(ctx, finding.Kind, finding.DocumentID, result.Key); err != nil {
		_ = fmt.Sprintf("failed to record leak report ticket: %v", err)
	}

	return result.Key, nil
}
