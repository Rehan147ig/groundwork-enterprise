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

// Ensure AgentResource satisfies the resource.Resource interface.
var _ resource.Resource = &AgentResource{}
var _ resource.ResourceWithImportState = &AgentResource{}

// AgentResource manages an agent in the agent registry. Terraform
// delete REVOKES the agent — non-destructive: the agent, its versions,
// lifecycle events, and evidence remain intact.
type AgentResource struct {
	client *client.Client
}

// NewAgentResource returns the groundwork_agent resource.
func NewAgentResource() resource.Resource {
	return &AgentResource{}
}

// Metadata registers the resource type name.
func (r *AgentResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "groundwork_agent"
}

// agentVersionModel is the optional version to publish with the agent.
type agentVersionModel struct {
	Version             types.String `tfsdk:"version"`
	ModelProvider       types.String `tfsdk:"model_provider"`
	ModelName           types.String `tfsdk:"model_name"`
	PromptDigest        types.String `tfsdk:"prompt_digest"`
	ToolManifestDigest  types.String `tfsdk:"tool_manifest_digest"`
	PolicyBundleVersion types.String `tfsdk:"policy_bundle_version"`
	ArtifactDigest      types.String `tfsdk:"artifact_digest"`
}

// Schema defines the agent resource surface.
func (r *AgentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An agent in the Groundwork registry. Delete revokes (non-destructive).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Agent ID.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "Agent name.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Human-readable description.",
				Optional:    true,
			},
			"owner_principal_id": schema.StringAttribute{
				Description: "Principal ID of the agent owner.",
				Optional:    true,
			},
			"business_purpose": schema.StringAttribute{
				Description: "Declared business purpose (used by policy evaluation).",
				Optional:    true,
			},
			"risk_tier": schema.StringAttribute{
				Description: "Risk tier: low, medium, high, or critical.",
				Required:    true,
			},
			"environment": schema.StringAttribute{
				Description: "Deployment environment, e.g. production.",
				Optional:    true,
			},
			"state": schema.StringAttribute{
				Description: "Lifecycle state (active, suspended, revoked, retired).",
				Computed:    true,
			},
			"active_version": schema.StringAttribute{
				Description: "Currently active version string.",
				Computed:    true,
			},
			"version": schema.SingleNestedAttribute{
				Description: "Version to publish at create/update time.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"version": schema.StringAttribute{
						Description: "Version string, e.g. v1.0.0.",
						Required:    true,
					},
					"model_provider": schema.StringAttribute{
						Description: "Model provider, e.g. anthropic.",
						Optional:    true,
					},
					"model_name": schema.StringAttribute{
						Description: "Model name, e.g. claude-sonnet-4-5.",
						Optional:    true,
					},
					"prompt_digest": schema.StringAttribute{
						Description: "SHA-256 digest of the agent prompt.",
						Optional:    true,
					},
					"tool_manifest_digest": schema.StringAttribute{
						Description: "SHA-256 digest of the tool manifest.",
						Optional:    true,
					},
					"policy_bundle_version": schema.StringAttribute{
						Description: "Policy bundle version the agent runs against.",
						Optional:    true,
					},
					"artifact_digest": schema.StringAttribute{
						Description: "SHA-256 digest of the deployed artifact.",
						Optional:    true,
					},
				},
			},
		},
	}
}

// agentModel maps the agent resource schema.
type agentModel struct {
	ID               types.String       `tfsdk:"id"`
	Name             types.String       `tfsdk:"name"`
	Description      types.String       `tfsdk:"description"`
	OwnerPrincipalID types.String       `tfsdk:"owner_principal_id"`
	BusinessPurpose  types.String       `tfsdk:"business_purpose"`
	RiskTier         types.String       `tfsdk:"risk_tier"`
	Environment      types.String       `tfsdk:"environment"`
	State            types.String       `tfsdk:"state"`
	ActiveVersion    types.String       `tfsdk:"active_version"`
	Version          *agentVersionModel `tfsdk:"version"`
}

// Configure binds the provider API client.
func (r *AgentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create registers the agent, optionally publishing its first version.
func (r *AgentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan agentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	agent, err := r.client.CreateAgent(ctx, client.CreateAgentInput{
		Name:             plan.Name.ValueString(),
		Description:      plan.Description.ValueString(),
		OwnerPrincipalID: plan.OwnerPrincipalID.ValueString(),
		BusinessPurpose:  plan.BusinessPurpose.ValueString(),
		RiskTier:         plan.RiskTier.ValueString(),
		Environment:      plan.Environment.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to create agent", err.Error())
		return
	}

	if plan.Version != nil && !plan.Version.Version.IsNull() {
		if err := r.client.AddAgentVersion(ctx, agent.ID, versionInput(*plan.Version)); err != nil {
			resp.Diagnostics.AddError("Failed to publish agent version", err.Error())
			return
		}
		agent, err = r.client.GetAgent(ctx, agent.ID)
		if err != nil {
			resp.Diagnostics.AddError("Failed to refresh agent", err.Error())
			return
		}
	}

	if err := r.applyState(ctx, agent.ID, "active"); err != nil {
		resp.Diagnostics.AddError("Failed to activate agent", err.Error())
		return
	}
	agent, err = r.client.GetAgent(ctx, agent.ID)
	if err != nil {
		resp.Diagnostics.AddError("Failed to refresh agent", err.Error())
		return
	}

	plan.ID = types.StringValue(agent.ID)
	plan.State = types.StringValue(agent.LifecycleState)
	plan.ActiveVersion = types.StringValue(agent.ActiveVersion)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the agent from the API.
func (r *AgentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state agentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	agent, err := r.client.GetAgent(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to read agent", err.Error())
		return
	}

	state.State = types.StringValue(agent.LifecycleState)
	state.ActiveVersion = types.StringValue(agent.ActiveVersion)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update publishes new versions and reconciles the agent to the active
// lifecycle state.
func (r *AgentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state agentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Version != nil && !plan.Version.Version.IsNull() && (state.Version == nil || state.Version.Version.ValueString() != plan.Version.Version.ValueString()) {
		if err := r.client.AddAgentVersion(ctx, state.ID.ValueString(), versionInput(*plan.Version)); err != nil {
			resp.Diagnostics.AddError("Failed to publish agent version", err.Error())
			return
		}
	}

	agent, err := r.client.GetAgent(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to refresh agent", err.Error())
		return
	}
	if plan.Version != nil && !plan.Version.Version.IsNull() {
		plan.ActiveVersion = types.StringValue(agent.ActiveVersion)
	}

	if agent.LifecycleState != "active" && !isTerminal(agent.LifecycleState) {
		if err := r.applyState(ctx, state.ID.ValueString(), "active"); err != nil {
			resp.Diagnostics.AddError("Failed to reactivate agent", err.Error())
			return
		}
	}

	plan.State = types.StringValue("active")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete REVOKES the agent — non-destructive: the registry record,
// versions, lifecycle events, and evidence remain for audit.
func (r *AgentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state agentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RevokeAgent(ctx, state.ID.ValueString(), "revoked by terraform delete"); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Failed to revoke agent", err.Error())
		return
	}
	resp.State.RemoveResource(ctx)
}

// ImportState imports an existing agent by its agent ID.
func (r *AgentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// applyState transitions a non-terminal agent to the desired state.
func (r *AgentResource) applyState(ctx context.Context, agentID, desired string) error {
	if desired != "active" {
		return nil
	}
	current, err := r.client.GetAgent(ctx, agentID)
	if err != nil {
		return err
	}
	if current.LifecycleState == "active" || isTerminal(current.LifecycleState) {
		return nil
	}
	_, err = r.client.ActivateAgent(ctx, agentID, "activated by terraform")
	return err
}

// isTerminal reports whether a lifecycle state can no longer transition.
func isTerminal(state string) bool {
	return state == "revoked" || state == "retired"
}

func versionInput(v agentVersionModel) client.AddAgentVersionInput {
	return client.AddAgentVersionInput{
		Version:             strings.TrimSpace(v.Version.ValueString()),
		ModelProvider:       v.ModelProvider.ValueString(),
		ModelName:           v.ModelName.ValueString(),
		PromptDigest:        v.PromptDigest.ValueString(),
		ToolManifestDigest:  v.ToolManifestDigest.ValueString(),
		PolicyBundleVersion: v.PolicyBundleVersion.ValueString(),
		ArtifactDigest:      v.ArtifactDigest.ValueString(),
	}
}
