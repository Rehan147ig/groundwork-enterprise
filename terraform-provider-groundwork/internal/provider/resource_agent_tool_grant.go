package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-groundwork/internal/client"
)

// Ensure AgentToolGrantResource satisfies the resource.Resource interface.
var _ resource.Resource = &AgentToolGrantResource{}
var _ resource.ResourceWithImportState = &AgentToolGrantResource{}

// AgentToolGrantResource manages a governance tool grant for an agent
// version. Delete revokes the grant (non-destructive; evidence kept).
type AgentToolGrantResource struct {
	client *client.Client
}

// NewAgentToolGrantResource returns the groundwork_agent_tool_grant resource.
func NewAgentToolGrantResource() resource.Resource {
	return &AgentToolGrantResource{}
}

// Metadata registers the resource type name.
func (r *AgentToolGrantResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "groundwork_agent_tool_grant"
}

// Schema defines the grant resource surface.
func (r *AgentToolGrantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A governance tool grant binding an agent version to a tool action. Delete revokes (non-destructive).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Grant ID.",
				Computed:    true,
			},
			"agent_id": schema.StringAttribute{
				Description: "Agent that receives the grant.",
				Required:    true,
			},
			"version_id": schema.StringAttribute{
				Description: "Agent version scoped to the grant.",
				Required:    true,
			},
			"tool_id": schema.StringAttribute{
				Description: "Tool the grant covers.",
				Required:    true,
			},
			"action_id": schema.StringAttribute{
				Description: "Tool action the grant covers.",
				Required:    true,
			},
			"resource_scope": schema.StringAttribute{
				Description: "Resource scope the grant applies to, e.g. acme-docs://*.",
				Optional:    true,
			},
			"region_constraint": schema.StringAttribute{
				Description: "Region the grant is constrained to.",
				Optional:    true,
			},
			"call_limit_per_run": schema.Int64Attribute{
				Description: "Maximum calls of this action per run. 0 means unlimited.",
				Optional:    true,
			},
			"requires_approval": schema.BoolAttribute{
				Description: "Whether every call requires human approval.",
				Optional:    true,
			},
		},
	}
}

// grantModel maps the grant resource schema.
type grantModel struct {
	ID               types.String `tfsdk:"id"`
	AgentID          types.String `tfsdk:"agent_id"`
	VersionID        types.String `tfsdk:"version_id"`
	ToolID           types.String `tfsdk:"tool_id"`
	ActionID         types.String `tfsdk:"action_id"`
	ResourceScope    types.String `tfsdk:"resource_scope"`
	RegionConstraint types.String `tfsdk:"region_constraint"`
	CallLimitPerRun  types.Int64  `tfsdk:"call_limit_per_run"`
	RequiresApproval types.Bool   `tfsdk:"requires_approval"`
}

// Configure binds the provider API client.
func (r *AgentToolGrantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create mints the tool grant.
func (r *AgentToolGrantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	grant, err := r.client.GrantToolAccess(ctx, grantInput(plan))
	if err != nil {
		resp.Diagnostics.AddError("Failed to create tool grant", err.Error())
		return
	}

	applyGrant(&plan, grant)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the grant from the API.
func (r *AgentToolGrantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	grant, err := r.client.GetGrant(ctx, state.AgentID.ValueString(), state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to read tool grant", err.Error())
		return
	}

	applyGrant(&state, grant)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update recreates the grant when any grant field changes. Grants are
// immutable server-side; update revokes the old grant and mints a new
// one under a fresh grant ID.
func (r *AgentToolGrantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.RevokeGrant(ctx, state.ID.ValueString(), "superseded by terraform update"); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Failed to revoke superseded grant", err.Error())
		return
	}

	grant, err := r.client.GrantToolAccess(ctx, grantInput(plan))
	if err != nil {
		resp.Diagnostics.AddError("Failed to recreate tool grant", err.Error())
		return
	}

	applyGrant(&plan, grant)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete revokes the grant — non-destructive: the grant record and its
// evidence chain remain for audit replay.
func (r *AgentToolGrantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RevokeGrant(ctx, state.ID.ValueString(), "revoked by terraform delete"); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Failed to revoke tool grant", err.Error())
		return
	}
	resp.State.RemoveResource(ctx)
}

// ImportState imports an existing grant by its grant ID.
func (r *AgentToolGrantResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// applyGrant copies server-derived grant fields into the model.
func applyGrant(m *grantModel, g client.AgentToolGrant) {
	m.ID = types.StringValue(g.ID)
	m.AgentID = types.StringValue(g.AgentID)
	m.VersionID = types.StringValue(g.VersionID)
	m.ToolID = types.StringValue(g.ToolID)
	m.ActionID = types.StringValue(g.ActionID)
	m.ResourceScope = types.StringValue(g.ResourceScope)
	m.RegionConstraint = types.StringValue(g.RegionConstraint)
	m.CallLimitPerRun = types.Int64Value(int64(g.CallLimitPerRun))
	m.RequiresApproval = types.BoolValue(g.RequiresApproval)
}

func grantInput(m grantModel) client.GrantInput {
	return client.GrantInput{
		AgentID:          m.AgentID.ValueString(),
		VersionID:        m.VersionID.ValueString(),
		ToolID:           m.ToolID.ValueString(),
		ActionID:         m.ActionID.ValueString(),
		ResourceScope:    m.ResourceScope.ValueString(),
		RegionConstraint: m.RegionConstraint.ValueString(),
		CallLimitPerRun:  int(m.CallLimitPerRun.ValueInt64()),
		RequiresApproval: m.RequiresApproval.ValueBool(),
	}
}
