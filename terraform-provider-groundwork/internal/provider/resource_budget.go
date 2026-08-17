package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-groundwork/internal/client"
)

// Ensure BudgetResource satisfies the resource.Resource interface.
var _ resource.Resource = &BudgetResource{}
var _ resource.ResourceWithImportState = &BudgetResource{}

// BudgetResource manages a run-level budget policy scoped to a tenant,
// an agent version, or a grant. Delete ZEROES the budget — the runtime
// has no destructive budget endpoint, so Terraform delete deprovisions
// the policy to its least-privileged state: all-zero limits fail
// closed on every budget check.
type BudgetResource struct {
	client *client.Client
}

// NewBudgetResource returns the groundwork_budget resource.
func NewBudgetResource() resource.Resource {
	return &BudgetResource{}
}

// Metadata registers the resource type name.
func (r *BudgetResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "groundwork_budget"
}

// Schema defines the budget resource surface.
func (r *BudgetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A run-level budget policy. Delete zeroes the policy (non-destructive; all-zero limits fail closed).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Budget policy ID.",
				Computed:    true,
			},
			"scope_type": schema.StringAttribute{
				Description: "Scope: tenant, agent_version, or grant.",
				Required:    true,
			},
			"agent_version_id": schema.StringAttribute{
				Description: "Agent version ID when scope_type is agent_version.",
				Optional:    true,
			},
			"grant_id": schema.StringAttribute{
				Description: "Grant ID when scope_type is grant.",
				Optional:    true,
			},
			"max_actions_per_run": schema.Int64Attribute{
				Description: "Maximum evaluated actions per run.",
				Optional:    true,
			},
			"max_denied_per_run": schema.Int64Attribute{
				Description: "Maximum denied actions per run.",
				Optional:    true,
			},
			"max_approval_required_per_run": schema.Int64Attribute{
				Description: "Maximum approval-required actions per run.",
				Optional:    true,
			},
			"max_tool_calls_per_action_per_run": schema.Int64Attribute{
				Description: "Maximum tool calls per action per run.",
				Optional:    true,
			},
			"max_run_duration_seconds": schema.Int64Attribute{
				Description: "Maximum run duration in seconds.",
				Optional:    true,
			},
			"max_citations_per_query": schema.Int64Attribute{
				Description: "Maximum citations per query.",
				Optional:    true,
			},
		},
	}
}

// budgetModel maps the budget resource schema.
type budgetModel struct {
	ID                          types.String `tfsdk:"id"`
	ScopeType                   types.String `tfsdk:"scope_type"`
	AgentVersionID              types.String `tfsdk:"agent_version_id"`
	GrantID                     types.String `tfsdk:"grant_id"`
	MaxActionsPerRun            types.Int64  `tfsdk:"max_actions_per_run"`
	MaxDeniedPerRun             types.Int64  `tfsdk:"max_denied_per_run"`
	MaxApprovalRequiredPerRun   types.Int64  `tfsdk:"max_approval_required_per_run"`
	MaxToolCallsPerActionPerRun types.Int64  `tfsdk:"max_tool_calls_per_action_per_run"`
	MaxRunDurationSeconds       types.Int64  `tfsdk:"max_run_duration_seconds"`
	MaxCitationsPerQuery        types.Int64  `tfsdk:"max_citations_per_query"`
}

// Configure binds the provider API client.
func (r *BudgetResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected ConfigureData",
			"Expected *client.Client, got a different type.",
		)
		return
	}
	r.client = c
}

// Create upserts the budget policy (idempotent by Idempotency-Key).
func (r *BudgetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan budgetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	budget, err := r.client.UpsertBudget(ctx, budgetInput(plan))
	if err != nil {
		resp.Diagnostics.AddError("Failed to create budget policy", err.Error())
		return
	}

	applyBudget(&plan, budget)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the budget from the API.
func (r *BudgetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state budgetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	budget, err := r.client.GetBudget(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to read budget policy", err.Error())
		return
	}

	applyBudget(&state, budget)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update replaces the budget limits (upsert semantics).
func (r *BudgetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan budgetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	budget, err := r.client.UpsertBudget(ctx, budgetInput(plan))
	if err != nil {
		resp.Diagnostics.AddError("Failed to update budget policy", err.Error())
		return
	}

	applyBudget(&plan, budget)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete ZEROES the budget — non-destructive deprovision. The runtime
// keeps the policy row and evidence; with all limits at zero, every
// budget check fails closed.
func (r *BudgetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state budgetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, err := r.client.ZeroBudget(ctx, budgetInput(state)); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Failed to deprovision budget policy", err.Error())
		return
	}
	resp.State.RemoveResource(ctx)
}

// ImportState imports an existing budget by its policy ID.
func (r *BudgetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// applyBudget copies server-derived budget fields into the model.
func applyBudget(m *budgetModel, b client.BudgetPolicy) {
	m.ID = types.StringValue(b.ID)
	m.ScopeType = types.StringValue(b.ScopeType)
	m.AgentVersionID = types.StringValue(b.AgentVersionID)
	m.GrantID = types.StringValue(b.GrantID)
	m.MaxActionsPerRun = types.Int64Value(int64(b.MaxActionsPerRun))
	m.MaxDeniedPerRun = types.Int64Value(int64(b.MaxDeniedPerRun))
	m.MaxApprovalRequiredPerRun = types.Int64Value(int64(b.MaxApprovalRequiredPerRun))
	m.MaxToolCallsPerActionPerRun = types.Int64Value(int64(b.MaxToolCallsPerActionPerRun))
	m.MaxRunDurationSeconds = types.Int64Value(int64(b.MaxRunDurationSeconds))
	m.MaxCitationsPerQuery = types.Int64Value(int64(b.MaxCitationsPerQuery))
}

func budgetInput(m budgetModel) client.BudgetInput {
	return client.BudgetInput{
		ScopeType:                   m.ScopeType.ValueString(),
		AgentVersionID:              m.AgentVersionID.ValueString(),
		GrantID:                     m.GrantID.ValueString(),
		MaxActionsPerRun:            int(m.MaxActionsPerRun.ValueInt64()),
		MaxDeniedPerRun:             int(m.MaxDeniedPerRun.ValueInt64()),
		MaxApprovalRequiredPerRun:   int(m.MaxApprovalRequiredPerRun.ValueInt64()),
		MaxToolCallsPerActionPerRun: int(m.MaxToolCallsPerActionPerRun.ValueInt64()),
		MaxRunDurationSeconds:       int(m.MaxRunDurationSeconds.ValueInt64()),
		MaxCitationsPerQuery:        int(m.MaxCitationsPerQuery.ValueInt64()),
	}
}
