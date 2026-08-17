package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-groundwork/internal/client"
)

// newTestClient spins up a fake runtime and returns a client bound to it.
func newTestClient(t *testing.T) (*client.Client, *client.FakeRuntime) {
	t.Helper()
	fake := client.NewFakeRuntime()
	c, err := client.New(client.Config{BaseURL: fake.URL(t), APIKey: fake.APIKey()})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, fake
}

// bindResource wires a resource to the test client (as Configure does).
func bindResource(t *testing.T, r resource.ResourceWithConfigure, c *client.Client) {
	t.Helper()
	resp := resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Configure: %s", resp.Diagnostics)
	}
}

// tfValue converts a map[string]any config into a tftypes.Value for an
// attribute type.
func tfValue(t *testing.T, ctx context.Context, typ attr.Type, v any) tftypes.Value {
	t.Helper()
	tt := typ.TerraformType(ctx)
	switch tv := v.(type) {
	case nil:
		return tftypes.NewValue(tt, nil)
	case map[string]any:
		obj, ok := tt.(tftypes.Object)
		if !ok {
			t.Fatalf("expected object type, got %v", tt)
		}
		attrs := map[string]tftypes.Value{}
		for k, av := range tv {
			at, ok := obj.AttributeTypes[k]
			if !ok {
				t.Fatalf("unknown attribute %q", k)
			}
			attrs[k] = tftypes.NewValue(at, terraformPrimitive(t, at, av))
		}
		return tftypes.NewValue(tt, attrs)
	case []any:
		var et tftypes.Type
		switch st := tt.(type) {
		case tftypes.List:
			et = st.ElementType
		case tftypes.Set:
			et = st.ElementType
		default:
			t.Fatalf("expected list/set type, got %v", tt)
		}
		elems := make([]tftypes.Value, 0, len(tv))
		for _, e := range tv {
			elems = append(elems, tftypes.NewValue(et, terraformPrimitive(t, et, e)))
		}
		return tftypes.NewValue(tt, elems)
	default:
		return tftypes.NewValue(tt, terraformPrimitive(t, tt, tv))
	}
}

// terraformPrimitive converts a scalar test value (or a nested
// object/slice) to the raw Go value tftypes expects for the type.
func terraformPrimitive(t *testing.T, tt tftypes.Type, v any) any {
	t.Helper()
	switch tv := v.(type) {
	case nil:
		return nil
	case map[string]any:
		obj, ok := tt.(tftypes.Object)
		if !ok {
			t.Fatalf("expected object type, got %v", tt)
		}
		attrs := map[string]tftypes.Value{}
		for k, av := range tv {
			at, ok := obj.AttributeTypes[k]
			if !ok {
				t.Fatalf("unknown attribute %q", k)
			}
			attrs[k] = tftypes.NewValue(at, terraformPrimitive(t, at, av))
		}
		return attrs
	case []any:
		var et tftypes.Type
		switch st := tt.(type) {
		case tftypes.List:
			et = st.ElementType
		case tftypes.Set:
			et = st.ElementType
		default:
			t.Fatalf("expected list/set type, got %v", tt)
		}
		elems := make([]tftypes.Value, 0, len(tv))
		for _, e := range tv {
			elems = append(elems, tftypes.NewValue(et, terraformPrimitive(t, et, e)))
		}
		return elems
	case string, bool, int64, float64:
		return tv
	default:
		t.Fatalf("unsupported test value %T", v)
		return nil
	}
}

// planFor builds a Create/Update plan from a raw config map.
func planFor(t *testing.T, r resource.Resource, cfg map[string]any) tfsdk.Plan {
	t.Helper()
	ctx := context.Background()
	sresp := resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, &sresp)
	if sresp.Diagnostics.HasError() {
		t.Fatalf("Schema: %s", sresp.Diagnostics)
	}
	val := tfValue(t, ctx, sresp.Schema.Type(), cfg)
	return tfsdk.Plan{Raw: val, Schema: sresp.Schema}
}

// stateFor builds an existing-state model for Update/Delete requests.
func stateFor(t *testing.T, r resource.Resource, cfg map[string]any) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	sresp := resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, &sresp)
	if sresp.Diagnostics.HasError() {
		t.Fatalf("Schema: %s", sresp.Diagnostics)
	}
	val := tfValue(t, ctx, sresp.Schema.Type(), cfg)
	return tfsdk.State{Raw: val, Schema: sresp.Schema}
}

// response helpers initialize response State with the resource schema,
// mirroring what the framework does before invoking resource methods.
func newCreateResponse(t *testing.T, r resource.Resource) resource.CreateResponse {
	t.Helper()
	s := resourceSchema(t, r)
	return resource.CreateResponse{State: tfsdk.State{Schema: s}}
}

func newReadResponse(t *testing.T, r resource.Resource) resource.ReadResponse {
	t.Helper()
	s := resourceSchema(t, r)
	return resource.ReadResponse{State: tfsdk.State{Schema: s}}
}

func newUpdateResponse(t *testing.T, r resource.Resource) resource.UpdateResponse {
	t.Helper()
	s := resourceSchema(t, r)
	return resource.UpdateResponse{State: tfsdk.State{Schema: s}}
}

func newDeleteResponse(t *testing.T, r resource.Resource) resource.DeleteResponse {
	t.Helper()
	s := resourceSchema(t, r)
	return resource.DeleteResponse{State: tfsdk.State{Schema: s}}
}

func resourceSchema(t *testing.T, r resource.Resource) rschema.Schema {
	t.Helper()
	sresp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &sresp)
	if sresp.Diagnostics.HasError() {
		t.Fatalf("Schema: %s", sresp.Diagnostics)
	}
	return sresp.Schema
}

// TestConfigureValidation exercises the provider configuration gate.
func TestConfigureValidation(t *testing.T) {
	ctx := context.Background()
	p := New("test")

	// Missing api_base_url fails closed.
	sresp := provider.SchemaResponse{}
	p.Schema(ctx, provider.SchemaRequest{}, &sresp)
	nullRaw := tftypes.NewValue(sresp.Schema.Type().TerraformType(ctx), map[string]tftypes.Value{
		"api_base_url":    tftypes.NewValue(tftypes.String, nil),
		"api_key":         tftypes.NewValue(tftypes.String, nil),
		"region":          tftypes.NewValue(tftypes.String, nil),
		"timeout_seconds": tftypes.NewValue(tftypes.Number, nil),
	})
	var provResp provider.ConfigureResponse
	p.Configure(ctx, provider.ConfigureRequest{Config: tfsdk.Config{Raw: nullRaw, Schema: sresp.Schema}}, &provResp)
	if !provResp.Diagnostics.HasError() {
		t.Fatal("expected configure error for empty config")
	}

	// Non-https base URL fails closed.
	raw := tftypes.NewValue(sresp.Schema.Type().TerraformType(ctx), map[string]tftypes.Value{
		"api_base_url":    tftypes.NewValue(tftypes.String, "http://insecure.example"),
		"api_key":         tftypes.NewValue(tftypes.String, "k"),
		"region":          tftypes.NewValue(tftypes.String, nil),
		"timeout_seconds": tftypes.NewValue(tftypes.Number, nil),
	})
	cfg := tfsdk.Config{Raw: raw, Schema: sresp.Schema}
	provResp = provider.ConfigureResponse{}
	p.Configure(ctx, provider.ConfigureRequest{Config: cfg}, &provResp)
	if !provResp.Diagnostics.HasError() {
		t.Fatal("expected configure error for non-https base URL")
	}

	// Valid config binds a client.
	validRaw := tftypes.NewValue(sresp.Schema.Type().TerraformType(ctx), map[string]tftypes.Value{
		"api_base_url":    tftypes.NewValue(tftypes.String, "https://gw.example.com"),
		"api_key":         tftypes.NewValue(tftypes.String, "k"),
		"region":          tftypes.NewValue(tftypes.String, "US"),
		"timeout_seconds": tftypes.NewValue(tftypes.Number, 15),
	})
	provResp = provider.ConfigureResponse{}
	p.Configure(ctx, provider.ConfigureRequest{Config: tfsdk.Config{Raw: validRaw, Schema: sresp.Schema}}, &provResp)
	if provResp.Diagnostics.HasError() {
		t.Fatalf("unexpected configure errors: %s", provResp.Diagnostics)
	}
	if provResp.ResourceData == nil {
		t.Fatal("expected ResourceData client after configure")
	}
}

func TestTenantResourceCRUD(t *testing.T) {
	ctx := context.Background()
	c, fake := newTestClient(t)
	r := &TenantResource{}
	bindResource(t, r, c)

	// Create
	createResp := newCreateResponse(t, r)
	r.Create(ctx, resource.CreateRequest{Plan: planFor(t, r, map[string]any{
		"id":            nil,
		"tenant_id":     "acme-prod",
		"region":        "US",
		"capacity_tier": "enterprise",
		"reason":        "provisioned via terraform",
		"status":        nil,
	})}, &createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("Create: %s", createResp.Diagnostics)
	}
	var state tenantModel
	if err := createResp.State.Get(ctx, &state); err != nil {
		t.Fatalf("state get: %v", err)
	}
	if state.ID.ValueString() != "acme-prod" || state.Status.ValueString() != "active" || state.CapacityTier.ValueString() != "enterprise" {
		t.Fatalf("unexpected state: %+v", state)
	}

	// Read
	readResp := newReadResponse(t, r)
	r.Read(ctx, resource.ReadRequest{State: createResp.State}, &readResp)
	if readResp.Diagnostics.HasError() {
		t.Fatalf("Read: %s", readResp.Diagnostics)
	}
	var readState tenantModel
	if err := readResp.State.Get(ctx, &readState); err != nil {
		t.Fatalf("state get: %v", err)
	}
	if readState.Region.ValueString() != "US" {
		t.Fatalf("unexpected read state: %+v", readState)
	}

	// Update (tier change re-provisions idempotently)
	updateResp := newUpdateResponse(t, r)
	r.Update(ctx, resource.UpdateRequest{
		Plan:  planFor(t, r, map[string]any{"id": "acme-prod", "tenant_id": "acme-prod", "region": "US", "capacity_tier": "plus", "reason": "tier upgrade", "status": "active"}),
		State: createResp.State,
	}, &updateResp)
	if updateResp.Diagnostics.HasError() {
		t.Fatalf("Update: %s", updateResp.Diagnostics)
	}

	// Delete deprovisions (non-destructive: record still present).
	deleteResp := newDeleteResponse(t, r)
	r.Delete(ctx, resource.DeleteRequest{State: createResp.State}, &deleteResp)
	if deleteResp.Diagnostics.HasError() {
		t.Fatalf("Delete: %s", deleteResp.Diagnostics)
	}
	if got := fake.TenantStatus("acme-prod"); got != "deprovisioned" {
		t.Fatalf("expected deprovisioned (non-destructive), got %q", got)
	}
}

func TestTenantResourceImport(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t)
	r := &TenantResource{}
	bindResource(t, r, c)

	sr := resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, &sr)

	importResp := resource.ImportStateResponse{}
	importResp.State.Schema = sr.Schema
	importResp.State.Raw = tftypes.NewValue(sr.Schema.Type().TerraformType(ctx), nil)
	r.ImportState(ctx, resource.ImportStateRequest{ID: "acme-imported"}, &importResp)
	if importResp.Diagnostics.HasError() {
		t.Fatalf("ImportState: %s", importResp.Diagnostics)
	}
	var st tenantModel
	if err := importResp.State.Get(ctx, &st); err != nil {
		t.Fatalf("state get: %v", err)
	}
	if st.ID.ValueString() != "acme-imported" {
		t.Fatalf("expected imported id, got %q", st.ID.ValueString())
	}
}

func TestAgentResourceCRUD(t *testing.T) {
	ctx := context.Background()
	c, fake := newTestClient(t)
	r := &AgentResource{}
	bindResource(t, r, c)

	createResp := newCreateResponse(t, r)
	r.Create(ctx, resource.CreateRequest{Plan: planFor(t, r, map[string]any{
		"id":                 nil,
		"name":               "support-agent",
		"description":        "customer support triage",
		"owner_principal_id": "team-support",
		"business_purpose":   "support",
		"risk_tier":          "medium",
		"environment":        "production",
		"state":              nil,
		"active_version":     nil,
		"version": map[string]any{
			"version":               "v1.0.0",
			"model_provider":        "anthropic",
			"model_name":            "claude-sonnet-4-5",
			"prompt_digest":         "sha256:abc",
			"tool_manifest_digest":  nil,
			"policy_bundle_version": nil,
			"artifact_digest":       nil,
		},
	})}, &createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("Create: %s", createResp.Diagnostics)
	}
	var state agentModel
	if err := createResp.State.Get(ctx, &state); err != nil {
		t.Fatalf("state get: %v", err)
	}
	if state.ID.ValueString() != "agent-1" || state.State.ValueString() != "active" {
		t.Fatalf("unexpected state: %+v", state)
	}

	// Update with a new version.
	updateResp := newUpdateResponse(t, r)
	r.Update(ctx, resource.UpdateRequest{
		Plan: planFor(t, r, map[string]any{
			"id": "agent-1", "name": "support-agent", "description": "customer support triage",
			"owner_principal_id": "team-support", "business_purpose": "support",
			"risk_tier": "medium", "environment": "production",
			"state": "active", "active_version": "v1.0.0",
			"version": map[string]any{
				"version": "v2.0.0", "model_provider": "anthropic", "model_name": "claude-sonnet-4-5",
				"prompt_digest": "sha256:def", "tool_manifest_digest": nil, "policy_bundle_version": nil, "artifact_digest": nil,
			},
		}),
		State: createResp.State,
	}, &updateResp)
	if updateResp.Diagnostics.HasError() {
		t.Fatalf("Update: %s", updateResp.Diagnostics)
	}

	// Delete revokes (non-destructive semantics in the API).
	deleteResp := newDeleteResponse(t, r)
	r.Delete(ctx, resource.DeleteRequest{State: createResp.State}, &deleteResp)
	if deleteResp.Diagnostics.HasError() {
		t.Fatalf("Delete: %s", deleteResp.Diagnostics)
	}
	if got := fake.AgentLifecycle("agent-1"); got != "" {
		t.Fatalf("expected revoked agent removed from registry, got %q", got)
	}
}

func TestGrantResourceCRUD(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t)
	r := &AgentToolGrantResource{}
	bindResource(t, r, c)

	createResp := newCreateResponse(t, r)
	r.Create(ctx, resource.CreateRequest{Plan: planFor(t, r, map[string]any{
		"id":                 nil,
		"agent_id":           "agent-1",
		"version_id":         "ver-1",
		"tool_id":            "tool-1",
		"action_id":          "read",
		"resource_scope":     "acme-docs://*",
		"region_constraint":  "US",
		"call_limit_per_run": int64(10),
		"requires_approval":  true,
	})}, &createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("Create: %s", createResp.Diagnostics)
	}
	var state grantModel
	if err := createResp.State.Get(ctx, &state); err != nil {
		t.Fatalf("state get: %v", err)
	}
	if state.ID.ValueString() != "grant-1" || !state.RequiresApproval.ValueBool() {
		t.Fatalf("unexpected state: %+v", state)
	}

	// Read.
	readResp := newReadResponse(t, r)
	r.Read(ctx, resource.ReadRequest{State: createResp.State}, &readResp)
	if readResp.Diagnostics.HasError() {
		t.Fatalf("Read: %s", readResp.Diagnostics)
	}

	// Update recreates the grant.
	updateResp := newUpdateResponse(t, r)
	r.Update(ctx, resource.UpdateRequest{
		Plan: planFor(t, r, map[string]any{
			"id": "grant-1", "agent_id": "agent-1", "version_id": "ver-1", "tool_id": "tool-1",
			"action_id": "write", "resource_scope": "acme-docs://*", "region_constraint": "US",
			"call_limit_per_run": int64(5), "requires_approval": false,
		}),
		State: createResp.State,
	}, &updateResp)
	if updateResp.Diagnostics.HasError() {
		t.Fatalf("Update: %s", updateResp.Diagnostics)
	}

	// Delete revokes.
	deleteResp := newDeleteResponse(t, r)
	r.Delete(ctx, resource.DeleteRequest{State: createResp.State}, &deleteResp)
	if deleteResp.Diagnostics.HasError() {
		t.Fatalf("Delete: %s", deleteResp.Diagnostics)
	}
}

func TestConnectorResourceCRUD(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t)
	r := &ConnectorResource{}
	bindResource(t, r, c)

	createResp := newCreateResponse(t, r)
	r.Create(ctx, resource.CreateRequest{Plan: planFor(t, r, map[string]any{
		"id":          nil,
		"name":        "prod-docs",
		"type":        "confluence",
		"description": "prod confluence",
		"lifecycle":   nil,
		"config": map[string]any{
			"base_url":              "https://wiki.example.com",
			"region":                "US",
			"timeout_ms":            int64(5000),
			"retry_max":             int64(2),
			"retry_idempotent_only": true,
			"max_response_bytes":    int64(1048576),
			"tls_verify":            true,
			"secret_ref":            "keyring://confluence-prod",
			"client_cert_ref":       nil,
			"allowed_content_types": []any{"application/json"},
			"redaction_fields":      []any{"authorization"},
		},
		"actions": []any{
			map[string]any{
				"name": "search", "transport_method": "GET", "path_template": "/rest/api/search",
				"resource_type": "page", "risk": "low", "read_only": true, "requires_approval": false,
				"max_request_bytes": int64(1024), "max_response_bytes": int64(10240),
				"allowed_versions": nil, "args": nil,
			},
		},
	})}, &createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("Create: %s", createResp.Diagnostics)
	}
	var state connectorModel
	if err := createResp.State.Get(ctx, &state); err != nil {
		t.Fatalf("state get: %v", err)
	}
	if state.ID.ValueString() != "conn-1" || state.Lifecycle.ValueString() != "active" {
		t.Fatalf("unexpected state: %+v", state)
	}
	if state.Config == nil || state.Config.SecretRef.ValueString() != "keyring://confluence-prod" {
		t.Fatalf("secret ref missing from state: %+v", state.Config)
	}

	// Update publishes a new config version.
	updateResp := newUpdateResponse(t, r)
	r.Update(ctx, resource.UpdateRequest{
		Plan: planFor(t, r, map[string]any{
			"id": "conn-1", "name": "prod-docs", "type": "confluence", "description": "prod confluence",
			"lifecycle": "active",
			"config": map[string]any{
				"base_url": "https://wiki.example.com", "region": "EU", "timeout_ms": nil, "retry_max": nil,
				"retry_idempotent_only": nil, "max_response_bytes": nil, "tls_verify": nil,
				"secret_ref": "keyring://confluence-prod-eu", "client_cert_ref": nil,
				"allowed_content_types": nil, "redaction_fields": nil,
			},
			"actions": []any{},
		}),
		State: createResp.State,
	}, &updateResp)
	if updateResp.Diagnostics.HasError() {
		t.Fatalf("Update: %s", updateResp.Diagnostics)
	}

	// Delete revokes.
	deleteResp := newDeleteResponse(t, r)
	r.Delete(ctx, resource.DeleteRequest{State: createResp.State}, &deleteResp)
	if deleteResp.Diagnostics.HasError() {
		t.Fatalf("Delete: %s", deleteResp.Diagnostics)
	}
}

func TestPolicyResourceCRUD(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t)
	r := &PolicyResource{}
	bindResource(t, r, c)

	createResp := newCreateResponse(t, r)
	r.Create(ctx, resource.CreateRequest{Plan: planFor(t, r, map[string]any{
		"id":              nil,
		"source_region":   "US",
		"target_region":   "EU",
		"purpose_pattern": "*",
		"enabled":         true,
	})}, &createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("Create: %s", createResp.Diagnostics)
	}
	var state policyModel
	if err := createResp.State.Get(ctx, &state); err != nil {
		t.Fatalf("state get: %v", err)
	}
	if state.ID.ValueString() != "policy-1" || !state.Enabled.ValueBool() {
		t.Fatalf("unexpected state: %+v", state)
	}

	// Read refreshes enabled state.
	readResp := newReadResponse(t, r)
	r.Read(ctx, resource.ReadRequest{State: createResp.State}, &readResp)
	if readResp.Diagnostics.HasError() {
		t.Fatalf("Read: %s", readResp.Diagnostics)
	}

	// Update replaces the body.
	updateResp := newUpdateResponse(t, r)
	r.Update(ctx, resource.UpdateRequest{
		Plan:  planFor(t, r, map[string]any{"id": "policy-1", "source_region": "US", "target_region": "APAC", "purpose_pattern": "data-sync", "enabled": false}),
		State: createResp.State,
	}, &updateResp)
	if updateResp.Diagnostics.HasError() {
		t.Fatalf("Update: %s", updateResp.Diagnostics)
	}

	// Delete revokes.
	deleteResp := newDeleteResponse(t, r)
	r.Delete(ctx, resource.DeleteRequest{State: createResp.State}, &deleteResp)
	if deleteResp.Diagnostics.HasError() {
		t.Fatalf("Delete: %s", deleteResp.Diagnostics)
	}
}

func TestBudgetResourceCRUD(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t)
	r := &BudgetResource{}
	bindResource(t, r, c)

	createResp := newCreateResponse(t, r)
	r.Create(ctx, resource.CreateRequest{Plan: planFor(t, r, map[string]any{
		"id":                                nil,
		"scope_type":                        "agent_version",
		"agent_version_id":                  "ver-1",
		"grant_id":                          nil,
		"max_actions_per_run":               int64(5),
		"max_denied_per_run":                int64(2),
		"max_approval_required_per_run":     int64(1),
		"max_tool_calls_per_action_per_run": int64(3),
		"max_run_duration_seconds":          int64(300),
		"max_citations_per_query":           int64(10),
	})}, &createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("Create: %s", createResp.Diagnostics)
	}
	var state budgetModel
	if err := createResp.State.Get(ctx, &state); err != nil {
		t.Fatalf("state get: %v", err)
	}
	if state.ID.ValueString() != "budget-1" || state.MaxActionsPerRun.ValueInt64() != 5 {
		t.Fatalf("unexpected state: %+v", state)
	}

	// Update tightens limits.
	updateResp := newUpdateResponse(t, r)
	r.Update(ctx, resource.UpdateRequest{
		Plan: planFor(t, r, map[string]any{
			"id": "budget-1", "scope_type": "agent_version", "agent_version_id": "ver-1", "grant_id": nil,
			"max_actions_per_run": int64(2), "max_denied_per_run": int64(0), "max_approval_required_per_run": int64(0),
			"max_tool_calls_per_action_per_run": int64(1), "max_run_duration_seconds": int64(120), "max_citations_per_query": int64(5),
		}),
		State: createResp.State,
	}, &updateResp)
	if updateResp.Diagnostics.HasError() {
		t.Fatalf("Update: %s", updateResp.Diagnostics)
	}

	// Delete zeroes the budget (non-destructive deprovision).
	deleteResp := newDeleteResponse(t, r)
	r.Delete(ctx, resource.DeleteRequest{State: createResp.State}, &deleteResp)
	if deleteResp.Diagnostics.HasError() {
		t.Fatalf("Delete: %s", deleteResp.Diagnostics)
	}
}
