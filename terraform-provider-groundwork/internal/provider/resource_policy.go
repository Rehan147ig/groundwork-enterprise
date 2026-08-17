package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-groundwork/internal/client"
)

// Ensure PolicyResource satisfies the resource.Resource interface.
var _ resource.Resource = &PolicyResource{}
var _ resource.ResourceWithImportState = &PolicyResource{}

// PolicyResource manages a data-transfer policy (region-to-region
// purpose allowlists). Delete revokes the policy — non-destructive.
type PolicyResource struct {
	client *client.Client
}

// NewPolicyResource returns the groundwork_policy resource.
func NewPolicyResource() resource.Resource {
	return &PolicyResource{}
}

// Metadata registers the resource type name.
func (r *PolicyResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "groundwork_policy"
}

// Schema defines the policy resource surface.
func (r *PolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A data-transfer policy allowlisting purpose-scoped transfers between regions. Delete revokes (non-destructive).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Policy ID.",
				Computed:    true,
			},
			"source_region": schema.StringAttribute{
				Description: "Source region, e.g. US.",
				Required:    true,
			},
			"target_region": schema.StringAttribute{
				Description: "Target region, e.g. EU.",
				Required:    true,
			},
			"purpose_pattern": schema.StringAttribute{
				Description: "Purpose allowlist pattern: * (any) or an exact purpose.",
				Required:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the policy is currently enforced.",
				Optional:    true,
			},
		},
	}
}

// policyModel maps the policy resource schema.
type policyModel struct {
	ID             types.String `tfsdk:"id"`
	SourceRegion   types.String `tfsdk:"source_region"`
	TargetRegion   types.String `tfsdk:"target_region"`
	PurposePattern types.String `tfsdk:"purpose_pattern"`
	Enabled        types.Bool   `tfsdk:"enabled"`
}

// Configure binds the provider API client.
func (r *PolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create upserts the transfer policy (idempotent by Idempotency-Key).
func (r *PolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.UpsertTransferPolicy(ctx, policyInput(plan))
	if err != nil {
		resp.Diagnostics.AddError("Failed to create transfer policy", err.Error())
		return
	}

	applyPolicy(&plan, policy)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the policy from the API.
func (r *PolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.GetTransferPolicy(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to read transfer policy", err.Error())
		return
	}

	applyPolicy(&state, policy)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update replaces the policy body and reconciles enabled state.
func (r *PolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.UpsertTransferPolicy(ctx, policyInput(plan))
	if err != nil {
		resp.Diagnostics.AddError("Failed to update transfer policy", err.Error())
		return
	}

	applyPolicy(&plan, policy)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete REVOKES the policy — non-destructive: the policy and its
// evidence chain remain for audit replay.
func (r *PolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RevokeTransferPolicy(ctx, state.ID.ValueString(), "revoked by terraform delete"); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Failed to revoke transfer policy", err.Error())
		return
	}
	resp.State.RemoveResource(ctx)
}

// ImportState imports an existing policy by its policy ID.
func (r *PolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// applyPolicy copies server-derived policy fields into the model.
func applyPolicy(m *policyModel, p client.TransferPolicy) {
	m.ID = types.StringValue(p.ID)
	m.SourceRegion = types.StringValue(p.SourceRegion)
	m.TargetRegion = types.StringValue(p.TargetRegion)
	m.PurposePattern = types.StringValue(p.PurposePattern)
	m.Enabled = types.BoolValue(p.Enabled)
}

func policyInput(m policyModel) client.PolicyInput {
	return client.PolicyInput{
		SourceRegion:   m.SourceRegion.ValueString(),
		TargetRegion:   m.TargetRegion.ValueString(),
		PurposePattern: m.PurposePattern.ValueString(),
		Enabled:        m.Enabled.ValueBool(),
	}
}
