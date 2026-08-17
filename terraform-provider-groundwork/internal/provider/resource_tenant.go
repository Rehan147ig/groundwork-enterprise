package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-groundwork/internal/client"
)

// Ensure TenantResource satisfies the resource.Resource interface.
var _ resource.Resource = &TenantResource{}
var _ resource.ResourceWithImportState = &TenantResource{}

// TenantResource manages a Groundwork tenant. Terraform delete
// DEPROVISIONS the tenant — it never destructively deletes: the
// directory record, hash-chained evidence, and audit trail remain
// intact and queryable.
type TenantResource struct {
	client *client.Client
}

// NewTenantResource returns the groundwork_tenant resource.
func NewTenantResource() resource.Resource {
	return &TenantResource{}
}

// Metadata registers the resource type name.
func (r *TenantResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "groundwork_tenant"
}

// Schema defines the tenant resource surface.
func (r *TenantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A Groundwork tenant. Delete deprovisions (non-destructive): the tenant record and its evidence chain are retained.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Tenant ID (equals tenant_id).",
				Computed:    true,
			},
			"tenant_id": schema.StringAttribute{
				Description: "Tenant identifier, e.g. acme-prod.",
				Required:    true,
			},
			"region": schema.StringAttribute{
				Description: "Region the tenant is provisioned in (e.g. US, EU).",
				Required:    true,
			},
			"capacity_tier": schema.StringAttribute{
				Description: "Capacity model tier: standard, plus, or enterprise. Empty defaults to standard.",
				Optional:    true,
				Computed:    true,
			},
			"reason": schema.StringAttribute{
				Description: "Auditable reason attached to every provisioning transition.",
				Optional:    true,
				Computed:    true,
			},
			"status": schema.StringAttribute{
				Description: "Tenant lifecycle status (active, disabled, deprovisioned).",
				Computed:    true,
			},
		},
	}
}

// tenantModel maps the tenant resource schema.
type tenantModel struct {
	ID           types.String `tfsdk:"id"`
	TenantID     types.String `tfsdk:"tenant_id"`
	Region       types.String `tfsdk:"region"`
	CapacityTier types.String `tfsdk:"capacity_tier"`
	Reason       types.String `tfsdk:"reason"`
	Status       types.String `tfsdk:"status"`
}

// Configure binds the provider API client.
func (r *TenantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create provisions the tenant (idempotent for the same region).
func (r *TenantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan tenantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	reason := plan.Reason.ValueString()
	if strings.TrimSpace(reason) == "" {
		reason = "provisioned by terraform"
	}
	tenant, err := r.client.ProvisionTenant(ctx, plan.TenantID.ValueString(), plan.Region.ValueString(), plan.CapacityTier.ValueString(), reason)
	if err != nil {
		resp.Diagnostics.AddError("Failed to provision tenant", err.Error())
		return
	}

	plan.ID = types.StringValue(tenant.TenantID)
	plan.TenantID = types.StringValue(tenant.TenantID)
	plan.Region = types.StringValue(tenant.Region)
	plan.Status = types.StringValue(tenant.Status)
	plan.CapacityTier = types.StringValue(tenant.Tier)
	plan.Reason = types.StringValue(tenant.Reason)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the tenant from the API.
func (r *TenantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state tenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tenant, err := r.client.GetTenant(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to read tenant", err.Error())
		return
	}

	state.TenantID = types.StringValue(tenant.TenantID)
	state.Region = types.StringValue(tenant.Region)
	state.Status = types.StringValue(tenant.Status)
	state.CapacityTier = types.StringValue(tenant.Tier)
	state.Reason = types.StringValue(tenant.Reason)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies configuration changes. Region is immutable after
// provisioning (a change fails server-side); capacity tier and reason
// are re-provisioned idempotently. Enabled/disabled toggling is not
// part of the resource surface — a tenant's status is server-derived.
func (r *TenantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state tenantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	reason := plan.Reason.ValueString()
	if strings.TrimSpace(reason) == "" {
		reason = "updated by terraform"
	}
	tenant, err := r.client.ProvisionTenant(ctx, plan.TenantID.ValueString(), plan.Region.ValueString(), plan.CapacityTier.ValueString(), reason)
	if err != nil {
		resp.Diagnostics.AddError("Failed to update tenant", err.Error())
		return
	}

	plan.ID = types.StringValue(tenant.TenantID)
	plan.Status = types.StringValue(tenant.Status)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete DEPROVISIONS the tenant. The deprovision is non-destructive:
// the directory record, hash-chained lifecycle evidence, and audit
// trail all remain intact for compliance replay.
func (r *TenantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	reason := state.Reason.ValueString()
	if strings.TrimSpace(reason) == "" {
		reason = "deprovisioned by terraform delete"
	}
	if err := r.client.DeprovisionTenant(ctx, state.ID.ValueString(), reason); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Failed to deprovision tenant", err.Error())
		return
	}
	resp.State.RemoveResource(ctx)
}

// ImportState imports an existing tenant by its tenant_id.
func (r *TenantResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
