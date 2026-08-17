package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-groundwork/internal/client"
)

// Ensure ConnectorResource satisfies the resource.Resource interface.
var _ resource.Resource = &ConnectorResource{}
var _ resource.ResourceWithImportState = &ConnectorResource{}

// ConnectorResource manages a registered connector (REST or MCP).
// Delete revokes the connector — non-destructive: registry rows,
// versions, invocations, and evidence remain intact.
type ConnectorResource struct {
	client *client.Client
}

// NewConnectorResource returns the groundwork_connector resource.
func NewConnectorResource() resource.Resource {
	return &ConnectorResource{}
}

// Metadata registers the resource type name.
func (r *ConnectorResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "groundwork_connector"
}

// connectorConfigModel maps the connector config surface.
type connectorConfigModel struct {
	BaseURL             types.String `tfsdk:"base_url"`
	Region              types.String `tfsdk:"region"`
	TimeoutMS           types.Int64  `tfsdk:"timeout_ms"`
	RetryMax            types.Int64  `tfsdk:"retry_max"`
	RetryIdempotentOnly types.Bool   `tfsdk:"retry_idempotent_only"`
	MaxResponseBytes    types.Int64  `tfsdk:"max_response_bytes"`
	TLSVerify           types.Bool   `tfsdk:"tls_verify"`
	SecretRef           types.String `tfsdk:"secret_ref"`
	ClientCertRef       types.String `tfsdk:"client_cert_ref"`
	AllowedContentTypes types.List   `tfsdk:"allowed_content_types"`
	RedactionFields     types.List   `tfsdk:"redaction_fields"`
}

// connectorActionModel maps one action manifest entry.
type connectorActionModel struct {
	Name             types.String `tfsdk:"name"`
	TransportMethod  types.String `tfsdk:"transport_method"`
	PathTemplate     types.String `tfsdk:"path_template"`
	ResourceType     types.String `tfsdk:"resource_type"`
	Risk             types.String `tfsdk:"risk"`
	ReadOnly         types.Bool   `tfsdk:"read_only"`
	RequiresApproval types.Bool   `tfsdk:"requires_approval"`
	MaxRequestBytes  types.Int64  `tfsdk:"max_request_bytes"`
	MaxResponseBytes types.Int64  `tfsdk:"max_response_bytes"`
	AllowedVersions  types.List   `tfsdk:"allowed_versions"`
	Args             types.List   `tfsdk:"args"`
}

// Schema defines the connector resource surface.
func (r *ConnectorResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A registered connector (REST or MCP). Delete revokes (non-destructive). Secrets are secret references only.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Connector ID.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "Connector name.",
				Required:    true,
			},
			"type": schema.StringAttribute{
				Description: "Connector type: s3, gcs, notion, sharepoint, snowflake, googledrive, confluence, mcp, or a custom REST provider.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Human-readable description.",
				Optional:    true,
			},
			"lifecycle": schema.StringAttribute{
				Description: "Connector lifecycle state (active, suspended, revoked).",
				Computed:    true,
			},
			"config": schema.SingleNestedAttribute{
				Description: "Transport-level connector configuration.",
				Required:    true,
				Attributes: map[string]schema.Attribute{
					"base_url": schema.StringAttribute{
						Description: "Operator-supplied base URL (never derived from agent requests).",
						Optional:    true,
					},
					"region": schema.StringAttribute{
						Description: "Region the connector endpoints live in.",
						Optional:    true,
					},
					"timeout_ms": schema.Int64Attribute{
						Description: "Per-request timeout in milliseconds.",
						Optional:    true,
					},
					"retry_max": schema.Int64Attribute{
						Description: "Maximum retries for retryable failures.",
						Optional:    true,
					},
					"retry_idempotent_only": schema.BoolAttribute{
						Description: "Only retry idempotent requests.",
						Optional:    true,
					},
					"max_response_bytes": schema.Int64Attribute{
						Description: "Maximum accepted response size.",
						Optional:    true,
					},
					"tls_verify": schema.BoolAttribute{
						Description: "Verify upstream TLS certificates.",
						Optional:    true,
					},
					"secret_ref": schema.StringAttribute{
						Description: "Reference to the connector credential in Groundwork Secrets (keyring://...). Never a raw secret.",
						Optional:    true,
						Sensitive:   true,
					},
					"client_cert_ref": schema.StringAttribute{
						Description: "Reference to a client certificate in Groundwork Secrets (keyring://...).",
						Optional:    true,
						Sensitive:   true,
					},
					"allowed_content_types": schema.ListAttribute{
						Description: "Content types the gateway may forward.",
						Optional:    true,
						ElementType: types.StringType,
					},
					"redaction_fields": schema.ListAttribute{
						Description: "Fields redacted from evidence and logs.",
						Optional:    true,
						ElementType: types.StringType,
					},
				},
			},
			"actions": schema.SetNestedAttribute{
				Description: "Declarative action manifest for the connector.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "Action name.",
							Required:    true,
						},
						"transport_method": schema.StringAttribute{
							Description: "HTTP method (REST) or MCP tool name (MCP).",
							Required:    true,
						},
						"path_template": schema.StringAttribute{
							Description: "REST only: /path/{arg} — never raw agent URLs.",
							Optional:    true,
						},
						"resource_type": schema.StringAttribute{
							Description: "Resource type the action targets.",
							Optional:    true,
						},
						"risk": schema.StringAttribute{
							Description: "Risk rating: low, medium, high, or critical.",
							Required:    true,
						},
						"read_only": schema.BoolAttribute{
							Description: "Action performs no mutation.",
							Optional:    true,
						},
						"requires_approval": schema.BoolAttribute{
							Description: "Every call requires human approval.",
							Optional:    true,
						},
						"max_request_bytes": schema.Int64Attribute{
							Description: "Maximum accepted request size.",
							Optional:    true,
						},
						"max_response_bytes": schema.Int64Attribute{
							Description: "Maximum accepted response size.",
							Optional:    true,
						},
						"allowed_versions": schema.ListAttribute{
							Description: "Agent version IDs allowed to call this action; empty means any active version.",
							Optional:    true,
							ElementType: types.StringType,
						},
						"args": schema.ListAttribute{
							Description: "Allowlisted argument names.",
							Optional:    true,
							ElementType: types.StringType,
						},
					},
				},
			},
		},
	}
}

// connectorModel maps the connector resource schema.
type connectorModel struct {
	ID          types.String           `tfsdk:"id"`
	Name        types.String           `tfsdk:"name"`
	Type        types.String           `tfsdk:"type"`
	Description types.String           `tfsdk:"description"`
	Lifecycle   types.String           `tfsdk:"lifecycle"`
	Config      *connectorConfigModel  `tfsdk:"config"`
	Actions     []connectorActionModel `tfsdk:"actions"`
}

// Configure binds the provider API client.
func (r *ConnectorResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create registers the connector and activates it.
func (r *ConnectorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan connectorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input, d := connectorInput(ctx, plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	detail, err := r.client.RegisterConnector(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("Failed to register connector", err.Error())
		return
	}

	if err := r.client.ActivateConnector(ctx, detail.Connector.ID, "activated by terraform"); err != nil {
		resp.Diagnostics.AddError("Failed to activate connector", err.Error())
		return
	}

	plan.ID = types.StringValue(detail.Connector.ID)
	plan.Lifecycle = types.StringValue(detail.Connector.Lifecycle)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the connector from the API.
func (r *ConnectorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state connectorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	detail, err := r.client.GetConnector(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to read connector", err.Error())
		return
	}

	state.Lifecycle = types.StringValue(detail.Connector.Lifecycle)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update publishes a new connector config version and reconciles the
// lifecycle to active.
func (r *ConnectorResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state connectorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input, d := connectorInput(ctx, plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	detail, err := r.client.UpdateConnectorConfig(ctx, state.ID.ValueString(), input)
	if err != nil {
		resp.Diagnostics.AddError("Failed to update connector config", err.Error())
		return
	}

	if detail.Connector.Lifecycle != "active" {
		if err := r.client.ActivateConnector(ctx, state.ID.ValueString(), "reactivated by terraform"); err != nil {
			resp.Diagnostics.AddError("Failed to reactivate connector", err.Error())
			return
		}
	}

	plan.Lifecycle = types.StringValue("active")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete REVOKES the connector — non-destructive: registry rows,
// versions, invocations, and evidence remain for audit.
func (r *ConnectorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state connectorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RevokeConnector(ctx, state.ID.ValueString(), "revoked by terraform delete"); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Failed to revoke connector", err.Error())
		return
	}
	resp.State.RemoveResource(ctx)
}

// ImportState imports an existing connector by its connector ID.
func (r *ConnectorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// connectorInput converts the plan into the client input.
func connectorInput(ctx context.Context, m connectorModel) (client.RegisterConnectorInput, diag.Diagnostics) {
	var d diag.Diagnostics
	if m.Config == nil {
		d.AddError("Missing connector config", "config is required")
		return client.RegisterConnectorInput{}, d
	}
	in := client.RegisterConnectorInput{
		Name:        m.Name.ValueString(),
		Type:        m.Type.ValueString(),
		Description: m.Description.ValueString(),
		Config: client.ConnectorConfig{
			BaseURL:             m.Config.BaseURL.ValueString(),
			Region:              m.Config.Region.ValueString(),
			TimeoutMS:           int(m.Config.TimeoutMS.ValueInt64()),
			RetryMax:            int(m.Config.RetryMax.ValueInt64()),
			RetryIdempotentOnly: m.Config.RetryIdempotentOnly.ValueBool(),
			MaxResponseBytes:    int(m.Config.MaxResponseBytes.ValueInt64()),
			TLSVerify:           m.Config.TLSVerify.ValueBool(),
			SecretRef:           m.Config.SecretRef.ValueString(),
			ClientCertRef:       m.Config.ClientCertRef.ValueString(),
		},
	}
	d.Append(m.Config.AllowedContentTypes.ElementsAs(ctx, &in.Config.AllowedContentTypes, false)...)
	d.Append(m.Config.RedactionFields.ElementsAs(ctx, &in.Config.RedactionFields, false)...)
	for _, a := range m.Actions {
		act := client.ConnectorAction{
			Name:             a.Name.ValueString(),
			TransportMethod:  a.TransportMethod.ValueString(),
			PathTemplate:     a.PathTemplate.ValueString(),
			ResourceType:     a.ResourceType.ValueString(),
			Risk:             a.Risk.ValueString(),
			ReadOnly:         a.ReadOnly.ValueBool(),
			RequiresApproval: a.RequiresApproval.ValueBool(),
			MaxRequestBytes:  int(a.MaxRequestBytes.ValueInt64()),
			MaxResponseBytes: int(a.MaxResponseBytes.ValueInt64()),
		}
		d.Append(a.AllowedVersions.ElementsAs(ctx, &act.AllowedVersions, false)...)
		d.Append(a.Args.ElementsAs(ctx, &act.Args, false)...)
		in.Actions = append(in.Actions, act)
	}
	return in, d
}
