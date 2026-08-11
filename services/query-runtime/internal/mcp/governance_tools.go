// Phase 6 MCP surface: agent trust, external agents, delegation
// chains, consents, transfer policies, external budgets, and evidence
// provenance as MCP tools. This mirrors the /v1/governance REST surface
// on the shared GovernanceService — the exact same enforcement code
// path, evidence, and fail-closed behavior, with a different transport.
//
// Security model:
//   - tenant/region come from the MCP server's bootstrap context (stdio)
//     or the API-key context (/mcp), never from tool arguments;
//   - every governance MUTATION requires a verified user_token; without
//     one the tool fails closed with no state change (mirrors
//     requireVerifiedIdentity on REST). Demo identities are rejected;
//   - the actor is the canonicalized token subject; admin is the
//     verified Identity.Admin flag — never inferred from arguments;
//   - raw tokens are never returned; results carry digests + jti only.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"groundwork/query-runtime/internal/runtime"
)

// governanceToolArgs is the generic envelope for Phase 6 governance
// tools: the verified identity token plus tool-specific JSON fields.
// (Kept as documentation of the shared arg shape; dispatch reads the
// raw args per-tool.)
type governanceToolArgs struct {
	UserToken string `json:"user_token"`
	Admin     bool   `json:"admin,omitempty"` // ignored; admin comes from the token
}

// govToolResult is a successful governance tool result (JSON-encoded).
func govToolResult(v any) (mcpToolResult, *jsonrpcError) {
	data, err := json.Marshal(v)
	if err != nil {
		return mcpToolResult{}, &jsonrpcError{Code: -32603, Message: "internal error: result encoding"}
	}
	return mcpToolResult{Content: []mcpContent{{Type: "text", Text: string(data)}}}, nil
}

// govFailClosed renders a fail-closed tool result with no state change.
func govFailClosed(format string, args ...any) (mcpToolResult, *jsonrpcError) {
	msg := fmt.Sprintf(format, args...)
	return mcpToolResult{
		Content: []mcpContent{{Type: "text", Text: "FAIL CLOSED: " + msg}},
		IsError: true,
	}, nil
}

// govIdentity resolves a verified actor from the tool's user_token.
// Demo / missing / invalid identities fail closed — mutations never run
// as an unverified actor. Returns the canonical actor principal.
func (s *Server) govIdentity(ctx context.Context, tenantID string, raw json.RawMessage) (actor string, admin bool, ok bool) {
	if s.governance == nil {
		return "", false, false
	}
	var args struct {
		UserToken string `json:"user_token"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", false, false
	}
	identity, err := runtime.ResolveEffectiveIdentity(ctx, s.verifier, false, args.UserToken, "")
	if err != nil || !identity.Verified {
		return "", false, false
	}
	effective, _, err := runtime.CanonicalizeIdentity(ctx, s.resolver, s.canonicalIdentity, tenantID, identity)
	if err != nil || effective == "" {
		return "", false, false
	}
	return effective, identity.Admin, true
}

// dispatchGovernance routes a Phase 6 governance tool call. handled is
// false when the tool name is not a governance tool.
func (s *Server) dispatchGovernance(ctx context.Context, tenantID, region, name string, args json.RawMessage) (mcpToolResult, *jsonrpcError, bool) {
	if !isGovernanceTool(name) {
		return mcpToolResult{}, nil, false
	}
	result, rpcErr := s.dispatchGovernanceCall(ctx, tenantID, name, args)
	return result, rpcErr, true
}

// dispatchGovernanceCall runs one governance tool by name.
func (s *Server) dispatchGovernanceCall(ctx context.Context, tenantID, name string, args json.RawMessage) (mcpToolResult, *jsonrpcError) {
	switch name {
	// ---------------------------------------------------------------
	// Trust relationships
	// ---------------------------------------------------------------
	case "governance_trust_relationship_list":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		rels, err := s.governance.ListTrustRelationships(ctx, tenantID)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"relationships": rels, "count": len(rels)})

	case "governance_trust_relationship_get":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		var a struct {
			RelationshipID string `json:"relationship_id"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.RelationshipID == "" {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "relationship_id is required"}
		}
		rel, err := s.governance.GetTrustRelationship(ctx, tenantID, a.RelationshipID)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"relationship": rel})

	case "governance_trust_relationship_create":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		actor, admin, ok := s.govIdentity(ctx, tenantID, args)
		if !ok {
			return govFailClosed("a verified end-user identity is required for this mutation")
		}
		var a runtime.TrustRelationshipRequest
		if err := json.Unmarshal(args, &a); err != nil {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "invalid arguments"}
		}
		rel, err := s.governance.CreateTrustRelationship(ctx, tenantID, actor, admin, a)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"relationship": rel})

	case "governance_trust_relationship_transition":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		actor, admin, ok := s.govIdentity(ctx, tenantID, args)
		if !ok {
			return govFailClosed("a verified end-user identity is required for this mutation")
		}
		var a struct {
			RelationshipID string `json:"relationship_id"`
			Action         string `json:"action"` // approve|activate|suspend|resume|revoke
			Reason         string `json:"reason"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.RelationshipID == "" || a.Action == "" {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "relationship_id and action are required"}
		}
		rel, err := s.governance.TransitionTrustRelationship(ctx, tenantID, a.RelationshipID, actor, admin, a.Action, runtime.TrustTransitionRequest{Reason: a.Reason})
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"relationship": rel})

	// ---------------------------------------------------------------
	// Delegation chains
	// ---------------------------------------------------------------
	case "governance_delegation_chain":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		var a struct {
			GrantID string `json:"grant_id"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.GrantID == "" {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "grant_id is required"}
		}
		chain, err := s.governance.GetDelegationChain(ctx, tenantID, a.GrantID)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"chain": chain})

	case "governance_delegation_chain_control":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		actor, admin, ok := s.govIdentity(ctx, tenantID, args)
		if !ok {
			return govFailClosed("a verified end-user identity is required for this mutation")
		}
		var a struct {
			GrantID string `json:"grant_id"`
			Action  string `json:"action"` // revoke|suspend|resume
			Reason  string `json:"reason"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.GrantID == "" || a.Action == "" || a.Reason == "" {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "grant_id, action, and reason are required"}
		}
		req := runtime.ControlRequest{Reason: a.Reason}
		var changed int
		var err error
		switch a.Action {
		case "revoke":
			changed, err = s.governance.RevokeDelegationChain(ctx, tenantID, a.GrantID, actor, admin, req)
		case "suspend":
			changed, err = s.governance.SuspendDelegationChain(ctx, tenantID, a.GrantID, actor, admin, req)
		case "resume":
			changed, err = s.governance.ResumeDelegationChain(ctx, tenantID, a.GrantID, actor, admin, req)
		default:
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "action must be revoke, suspend, or resume"}
		}
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"grants_changed": changed})

	// ---------------------------------------------------------------
	// External agents
	// ---------------------------------------------------------------
	case "governance_external_agent_list":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		agents, err := s.governance.ListExternalAgents(ctx, tenantID)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"agents": agents, "count": len(agents)})

	case "governance_external_agent_get":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		var a struct {
			ExternalAgentID string `json:"external_agent_id"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.ExternalAgentID == "" {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "external_agent_id is required"}
		}
		agent, err := s.governance.GetExternalAgent(ctx, tenantID, a.ExternalAgentID)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"agent": agent})

	case "governance_external_agent_onboard":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		actor, admin, ok := s.govIdentity(ctx, tenantID, args)
		if !ok {
			return govFailClosed("a verified end-user identity is required for this mutation")
		}
		var a runtime.ExternalAgentRequest
		if err := json.Unmarshal(args, &a); err != nil {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "invalid arguments"}
		}
		agent, err := s.governance.OnboardExternalAgent(ctx, tenantID, actor, admin, a)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"agent": agent})

	case "governance_external_agent_transition":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		actor, admin, ok := s.govIdentity(ctx, tenantID, args)
		if !ok {
			return govFailClosed("a verified end-user identity is required for this mutation")
		}
		var a struct {
			ExternalAgentID string `json:"external_agent_id"`
			Action          string `json:"action"` // activate|suspend|revoke
			Reason          string `json:"reason"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.ExternalAgentID == "" || a.Action == "" {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "external_agent_id and action are required"}
		}
		agent, err := s.governance.TransitionExternalAgent(ctx, tenantID, a.ExternalAgentID, actor, admin, a.Action, runtime.TrustTransitionRequest{Reason: a.Reason})
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"agent": agent})

	// ---------------------------------------------------------------
	// Consents
	// ---------------------------------------------------------------
	case "governance_consent_list":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		consents, err := s.governance.ListConsentRecords(ctx, tenantID)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"consents": consents, "count": len(consents)})

	case "governance_consent_create":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		actor, admin, ok := s.govIdentity(ctx, tenantID, args)
		if !ok {
			return govFailClosed("a verified end-user identity is required for this mutation")
		}
		var a runtime.ConsentRequest
		if err := json.Unmarshal(args, &a); err != nil {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "invalid arguments"}
		}
		consent, err := s.governance.CreateConsentRecord(ctx, tenantID, actor, admin, a)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"consent": consent})

	case "governance_consent_revoke":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		actor, admin, ok := s.govIdentity(ctx, tenantID, args)
		if !ok {
			return govFailClosed("a verified end-user identity is required for this mutation")
		}
		var a struct {
			ConsentID string `json:"consent_id"`
			Reason    string `json:"reason"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.ConsentID == "" {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "consent_id is required"}
		}
		consent, err := s.governance.RevokeConsentRecord(ctx, tenantID, a.ConsentID, actor, admin, a.Reason)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"consent": consent})

	// ---------------------------------------------------------------
	// Transfer policies
	// ---------------------------------------------------------------
	case "governance_transfer_policy_list":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		policies, err := s.governance.ListTransferPolicies(ctx, tenantID)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"policies": policies, "count": len(policies)})

	case "governance_transfer_policy_upsert":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		actor, admin, ok := s.govIdentity(ctx, tenantID, args)
		if !ok {
			return govFailClosed("a verified end-user identity is required for this mutation")
		}
		var a runtime.TransferPolicyRequest
		if err := json.Unmarshal(args, &a); err != nil {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "invalid arguments"}
		}
		policy, err := s.governance.UpsertTransferPolicy(ctx, tenantID, actor, admin, a)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"policy": policy})

	case "governance_transfer_policy_transition":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		actor, admin, ok := s.govIdentity(ctx, tenantID, args)
		if !ok {
			return govFailClosed("a verified end-user identity is required for this mutation")
		}
		var a struct {
			PolicyID string `json:"policy_id"`
			Action   string `json:"action"` // activate|suspend|revoke
			Reason   string `json:"reason"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.PolicyID == "" || a.Action == "" {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "policy_id and action are required"}
		}
		policy, err := s.governance.TransitionTransferPolicy(ctx, tenantID, a.PolicyID, actor, admin, a.Action, runtime.TrustTransitionRequest{Reason: a.Reason})
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"policy": policy})

	// ---------------------------------------------------------------
	// External budgets
	// ---------------------------------------------------------------
	case "governance_external_budget_list":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		budgets, err := s.governance.ListExternalBudgets(ctx, tenantID)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"budgets": budgets, "count": len(budgets)})

	case "governance_external_budget_upsert":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		actor, admin, ok := s.govIdentity(ctx, tenantID, args)
		if !ok {
			return govFailClosed("a verified end-user identity is required for this mutation")
		}
		var a runtime.ExternalBudgetRequest
		if err := json.Unmarshal(args, &a); err != nil {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "invalid arguments"}
		}
		budget, err := s.governance.UpsertExternalBudget(ctx, tenantID, actor, admin, a)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"budget": budget})

	// ---------------------------------------------------------------
	// Provenance
	// ---------------------------------------------------------------
	case "governance_evidence_provenance":
		if s.governance == nil {
			return govFailClosed("governance service unavailable")
		}
		var a struct {
			EvidenceID string `json:"evidence_id"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.EvidenceID == "" {
			return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "evidence_id is required"}
		}
		view, err := s.governance.GetEvidenceProvenance(ctx, tenantID, a.EvidenceID)
		if err != nil {
			return govFailClosed("%v", err)
		}
		return govToolResult(map[string]any{"provenance": view})

	default:
		// Unreachable from dispatchGovernance (guarded by
		// isGovernanceTool); keep the compiler honest.
		return mcpToolResult{}, &jsonrpcError{Code: -32602, Message: "unknown governance tool"}
	}
}

// governanceTools returns the Phase 6 MCP tool registry entries.
func governanceTools() []mcpTool {
	stringArg := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}

	return []mcpTool{
		{
			Name:        "governance_trust_relationship_list",
			Description: "List all agent trust relationships for the tenant. Read-only; no identity required.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}},
		},
		{
			Name:        "governance_trust_relationship_get",
			Description: "Get one agent trust relationship by id. Read-only.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"relationship_id": stringArg("The trust relationship id."),
				},
				"required": []string{"relationship_id"},
			},
		},
		{
			Name:        "governance_trust_relationship_create",
			Description: "Create an agent trust relationship (parent agent -> child agent or external agent). Requires a verified user_token (owner-or-admin).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_token":            stringArg("Signed end-user identity assertion. Required."),
					"parent_agent_id":       stringArg("Source-of-authority agent (registry identity)."),
					"child_agent_id":        stringArg("Child agent id (exactly one of child_agent_id / external_agent_id)."),
					"external_agent_id":     stringArg("External agent id (exactly one of child_agent_id / external_agent_id)."),
					"trust_domain":          stringArg("Trust domain label, e.g. finance."),
					"purpose":               stringArg("Purpose the relationship attests."),
					"max_delegation_depth":  map[string]any{"type": "integer", "description": "Max chain depth (1-10)."},
					"allowed_tools_actions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional scoped tool:action allow-list."},
					"region":                stringArg("Region the relationship applies to."),
					"expires_at":            stringArg("RFC3339 expiry."),
					"approval_required":     map[string]any{"type": "boolean", "description": "Start in requested state needing human approval."},
				},
				"required": []string{"user_token", "parent_agent_id", "trust_domain", "purpose", "region", "expires_at"},
			},
		},
		{
			Name:        "governance_trust_relationship_transition",
			Description: "Transition a trust relationship: approve|activate|suspend|resume|revoke. Requires a verified user_token.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_token":      stringArg("Signed end-user identity assertion. Required."),
					"relationship_id": stringArg("Trust relationship id."),
					"action":          stringArg("approve|activate|suspend|resume|revoke"),
					"reason":          stringArg("Mandatory reason for the transition."),
				},
				"required": []string{"user_token", "relationship_id", "action"},
			},
		},
		{
			Name:        "governance_delegation_chain",
			Description: "Get the verified delegation chain (root first) for a grant. Read-only.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"grant_id": stringArg("Delegation grant id.")},
				"required":   []string{"grant_id"},
			},
		},
		{
			Name:        "governance_delegation_chain_control",
			Description: "Cascade revoke|suspend|resume across a grant and every descendant (admin-only). Requires a verified user_token with an admin role.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_token": stringArg("Signed end-user identity assertion. Required."),
					"grant_id":   stringArg("Root grant id of the chain."),
					"action":     stringArg("revoke|suspend|resume"),
					"reason":     stringArg("Mandatory reason."),
				},
				"required": []string{"user_token", "grant_id", "action", "reason"},
			},
		},
		{
			Name:        "governance_external_agent_list",
			Description: "List onboarded external agents. Read-only.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}},
		},
		{
			Name:        "governance_external_agent_get",
			Description: "Get one external agent. Read-only.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"external_agent_id": stringArg("External agent id.")},
				"required":   []string{"external_agent_id"},
			},
		},
		{
			Name:        "governance_external_agent_onboard",
			Description: "Onboard an external agent (admin-only). Requires a verified user_token with an admin role. Identity comes from the onboarded issuer/audience — never from this call.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_token":            stringArg("Signed end-user identity assertion. Required."),
					"external_agent_id":     stringArg("The external agent's stable id."),
					"agent_id":              stringArg("Paired agent-registry identity."),
					"organization_id":       stringArg("External organization id."),
					"verified_issuer":       stringArg("OIDC/JWKS issuer the identity must present."),
					"allowed_audiences":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Audiences the identity must match."},
					"auth_method":           stringArg("oidc|jwt_jwks|mtls|internal_demo"),
					"trust_tier":            stringArg("verified|partner|customer"),
					"region":                stringArg("Region the external agent operates in."),
					"allowed_tools_actions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional scoped tool:action allow-list."},
					"security_contact":      stringArg("Optional security contact."),
				},
				"required": []string{"user_token", "external_agent_id", "agent_id", "organization_id", "verified_issuer", "allowed_audiences", "auth_method", "region"},
			},
		},
		{
			Name:        "governance_external_agent_transition",
			Description: "Transition an external agent: activate|suspend|revoke (admin-only). Requires a verified user_token with an admin role.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_token":        stringArg("Signed end-user identity assertion. Required."),
					"external_agent_id": stringArg("External agent id."),
					"action":            stringArg("activate|suspend|revoke"),
					"reason":            stringArg("Mandatory reason."),
				},
				"required": []string{"user_token", "external_agent_id", "action"},
			},
		},
		{
			Name:        "governance_consent_list",
			Description: "List customer consent records. Read-only.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}},
		},
		{
			Name:        "governance_consent_create",
			Description: "Record a customer's consent for an external agent (admin-only). Requires a verified user_token with an admin role.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_token":            stringArg("Signed end-user identity assertion. Required."),
					"organization_id":       stringArg("External organization id."),
					"external_agent_id":     stringArg("External agent id."),
					"customer_principal_id": stringArg("Customer principal the consent covers."),
					"purpose":               stringArg("Purpose the consent authorizes."),
					"resource_ref_pattern":  stringArg("Optional resource pattern (default '*')."),
					"ttl_seconds":           map[string]any{"type": "integer", "description": "Optional TTL."},
				},
				"required": []string{"user_token", "organization_id", "external_agent_id", "customer_principal_id", "purpose"},
			},
		},
		{
			Name:        "governance_consent_revoke",
			Description: "Revoke a customer consent (admin-only, write-once). Requires a verified user_token with an admin role.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_token": stringArg("Signed end-user identity assertion. Required."),
					"consent_id": stringArg("Consent record id."),
					"reason":     stringArg("Mandatory reason."),
				},
				"required": []string{"user_token", "consent_id"},
			},
		},
		{
			Name:        "governance_transfer_policy_list",
			Description: "List cross-region transfer policies. Read-only.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}},
		},
		{
			Name:        "governance_transfer_policy_upsert",
			Description: "Create or update a cross-region transfer policy (admin-only). Requires a verified user_token with an admin role.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_token":      stringArg("Signed end-user identity assertion. Required."),
					"source_region":   stringArg("Source region."),
					"target_region":   stringArg("Target region (must differ)."),
					"purpose_pattern": stringArg("'*' or an exact purpose."),
					"enabled":         map[string]any{"type": "boolean", "description": "Whether the policy allows transfers."},
				},
				"required": []string{"user_token", "source_region", "target_region", "purpose_pattern"},
			},
		},
		{
			Name:        "governance_transfer_policy_transition",
			Description: "activate|suspend|revoke a transfer policy (admin-only). Requires a verified user_token with an admin role.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_token": stringArg("Signed end-user identity assertion. Required."),
					"policy_id":  stringArg("Transfer policy id."),
					"action":     stringArg("activate|suspend|revoke"),
					"reason":     stringArg("Mandatory reason."),
				},
				"required": []string{"user_token", "policy_id", "action"},
			},
		},
		{
			Name:        "governance_external_budget_list",
			Description: "List external-agent budget policies. Read-only.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}},
		},
		{
			Name:        "governance_external_budget_upsert",
			Description: "Configure an external-agent budget (admin-only). Requires a verified user_token with an admin role.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_token":                        stringArg("Signed end-user identity assertion. Required."),
					"scope_type":                        stringArg("external_agent|external_organization|customer"),
					"external_agent_id":                 stringArg("External agent id."),
					"organization_id":                   stringArg("Required for organization scope."),
					"customer_principal_id":             stringArg("Required for customer scope."),
					"max_total_actions":                 map[string]any{"type": "integer", "description": "Cap on total actions."},
					"max_actions_per_run":               map[string]any{"type": "integer", "description": "Cap per run."},
					"max_denied_per_run":                map[string]any{"type": "integer", "description": "Cap of denied decisions per run."},
					"max_approval_required_per_run":     map[string]any{"type": "integer", "description": "Cap of approval-required decisions per run."},
					"max_tool_calls_per_action_per_run": map[string]any{"type": "integer", "description": "Cap of tool calls per action per run."},
				},
				"required": []string{"user_token", "scope_type", "external_agent_id"},
			},
		},
		{
			Name:        "governance_evidence_provenance",
			Description: "Resolve the provenance view for one evidence event (who delegated, what scope, final outcome). Read-only; never returns raw tokens.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"evidence_id": stringArg("Evidence event id.")},
				"required":   []string{"evidence_id"},
			},
		},
	}
}

// isGovernanceTool reports whether a tool name belongs to the Phase 6
// governance registry.
func isGovernanceTool(name string) bool {
	return strings.HasPrefix(name, "governance_")
}
