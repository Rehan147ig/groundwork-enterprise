// Policy template model for `groundwork init --template <name>`.
//
// A template is a starter governance policy: the tools, actions, grants,
// and budget policy the operator intends to register through the
// governance API (/v1/governance/tools, /v1/governance/grants,
// /v1/governance/budgets). Templates are validated before they can be
// written — a "read-only" template must be read-only end to end, so a
// bad template cannot silently mint a write-capable policy.
package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"groundwork/query-runtime/internal/runtime"
)

// PolicyTemplate is one embedded starter policy.
type PolicyTemplate struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ReadOnly    bool       `json:"read_only"`
	Purpose     string     `json:"purpose"`
	Region      string     `json:"region"`
	Tools       []TplTool  `json:"tools"`
	Grants      []TplGrant `json:"grants"`
	Budget      TplBudget  `json:"budget_policy"`
	Notes       []string   `json:"notes"`
}

// TplTool is a governed tool with its actions, mapped 1:1 onto
// RegisterToolRequest + RegisterToolActionRequest.
type TplTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Transport   string      `json:"transport"`
	Actions     []TplAction `json:"actions"`
}

// TplAction is one tool action, mapped onto RegisterToolActionRequest.
type TplAction struct {
	Action                string `json:"action"`
	ResourceType          string `json:"resource_type"`
	RiskLevel             string `json:"risk_level"`
	ReadOnly              bool   `json:"read_only"`
	RequiresHumanApproval bool   `json:"requires_human_approval"`
}

// TplGrant is a per-agent grant, mapped onto GrantToolRequest. AgentID
// and VersionID are placeholders the operator replaces after the agent
// is registered (POST /v1/agents).
type TplGrant struct {
	AgentLabel string          `json:"agent_label"`
	ToolAccess []TplToolAccess `json:"tools"`
}

// TplToolAccess is one tool access entry inside a grant.
type TplToolAccess struct {
	Tool             string   `json:"tool"`
	Actions          []string `json:"actions"`
	ResourceScope    string   `json:"resource_scope"`
	RegionConstraint string   `json:"region_constraint"`
	CallLimitPerRun  int      `json:"call_limit_per_run"`
	RequiresApproval bool     `json:"requires_approval"`
}

// TplBudget is the starter budget policy, mapped onto
// BudgetPolicyRequest.
type TplBudget struct {
	MaxActionsPerRun            int `json:"max_actions_per_run"`
	MaxDeniedPerRun             int `json:"max_denied_per_run"`
	MaxApprovalRequiredPerRun   int `json:"max_approval_required_per_run"`
	MaxToolCallsPerActionPerRun int `json:"max_tool_calls_per_action_per_run"`
	MaxRunDurationSeconds       int `json:"max_run_duration_seconds"`
	MaxCitationsPerQuery        int `json:"max_citations_per_query"`
}

// Validate checks the template against the governance API contract.
// Every violation is returned; a template with any violation must never
// be written by `init`.
func (t *PolicyTemplate) Validate() []string {
	var problems []string
	if t.Name == "" {
		problems = append(problems, "name is required")
	}
	if t.Region == "" {
		problems = append(problems, "region is required (e.g. uk, eu, us)")
	}
	if len(t.Tools) == 0 {
		problems = append(problems, "at least one tool is required")
	}
	seenTool := map[string]bool{}
	for _, tool := range t.Tools {
		if tool.Name == "" {
			problems = append(problems, "tool name is required")
			continue
		}
		if seenTool[tool.Name] {
			problems = append(problems, fmt.Sprintf("duplicate tool %q", tool.Name))
		}
		seenTool[tool.Name] = true
		switch tool.Transport {
		case runtime.ToolTransportBuiltin, runtime.ToolTransportHTTP, runtime.ToolTransportMCP, runtime.ToolTransportInternal:
		default:
			problems = append(problems, fmt.Sprintf("tool %q: invalid transport %q", tool.Name, tool.Transport))
		}
		if len(tool.Actions) == 0 {
			problems = append(problems, fmt.Sprintf("tool %q: at least one action is required", tool.Name))
		}
		seenAction := map[string]bool{}
		for _, a := range tool.Actions {
			if a.Action == "" {
				problems = append(problems, fmt.Sprintf("tool %q: action name is required", tool.Name))
				continue
			}
			if seenAction[a.Action] {
				problems = append(problems, fmt.Sprintf("tool %q: duplicate action %q", tool.Name, a.Action))
			}
			seenAction[a.Action] = true
			switch a.RiskLevel {
			case runtime.RiskLevelLow, runtime.RiskLevelMedium, runtime.RiskLevelHigh, runtime.RiskLevelCritical:
			default:
				problems = append(problems, fmt.Sprintf("tool %q action %q: invalid risk_level %q", tool.Name, a.Action, a.RiskLevel))
			}
			if t.ReadOnly && !a.ReadOnly {
				problems = append(problems, fmt.Sprintf("read-only template tool %q action %q must set read_only=true", tool.Name, a.Action))
			}
		}
	}
	for _, g := range t.Grants {
		if g.AgentLabel == "" {
			problems = append(problems, "grant agent_label is required")
		}
		for _, ta := range g.ToolAccess {
			if !seenTool[ta.Tool] {
				problems = append(problems, fmt.Sprintf("grant %q references unknown tool %q", g.AgentLabel, ta.Tool))
				continue
			}
			for _, action := range ta.Actions {
				found := false
				for _, tool := range t.Tools {
					if tool.Name != ta.Tool {
						continue
					}
					for _, a := range tool.Actions {
						if a.Action == action {
							found = true
						}
					}
				}
				if !found {
					problems = append(problems, fmt.Sprintf("grant %q references unknown action %q on tool %q", g.AgentLabel, action, ta.Tool))
				}
			}
			if ta.RegionConstraint != "" && !strings.EqualFold(ta.RegionConstraint, t.Region) {
				problems = append(problems, fmt.Sprintf("grant %q region_constraint %q does not match template region %q", g.AgentLabel, ta.RegionConstraint, t.Region))
			}
			if ta.CallLimitPerRun <= 0 {
				problems = append(problems, fmt.Sprintf("grant %q tool %q: call_limit_per_run must be positive", g.AgentLabel, ta.Tool))
			}
		}
	}
	if t.Budget.MaxActionsPerRun <= 0 || t.Budget.MaxDeniedPerRun < 0 ||
		t.Budget.MaxApprovalRequiredPerRun < 0 || t.Budget.MaxToolCallsPerActionPerRun <= 0 ||
		t.Budget.MaxRunDurationSeconds <= 0 || t.Budget.MaxCitationsPerQuery < 0 {
		problems = append(problems, "budget_policy values must be positive (denied/approval/citations may be zero)")
	}
	return problems
}

// MarshalPolicy renders the template as the policy.json document that
// init writes. The document carries the template metadata plus the
// operator-facing sections.
func (t *PolicyTemplate) MarshalPolicy() ([]byte, error) {
	return json.MarshalIndent(t, "", "  ")
}
