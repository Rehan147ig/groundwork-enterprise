package provider

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-groundwork/internal/client"
)

// ProviderName is the provider type name registered with Terraform.
const ProviderName = "groundwork"

// Ensure Provider satisfies the provider.Provider interface.
var _ provider.Provider = &Provider{}

// Provider is the groundwork Terraform provider (Plugin Framework).
type Provider struct {
	version string
}

// New returns a new groundwork provider instance.
func New(version string) *Provider {
	return &Provider{version: version}
}

// Metadata returns the provider type name and version.
func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = ProviderName
	resp.Version = p.version
}

// Schema defines the provider configuration surface. The API key is
// sensitive; region optionally defaults tenant/connector placement.
func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Groundwork runtime authorization and evidence for enterprise AI agents.",
		Attributes: map[string]schema.Attribute{
			"api_base_url": schema.StringAttribute{
				Description: "Base URL of the Groundwork API (https required).",
				Required:    true,
			},
			"api_key": schema.StringAttribute{
				Description: "Groundwork API key used to authenticate every request.",
				Required:    true,
				Sensitive:   true,
			},
			"region": schema.StringAttribute{
				Description: "Default region for tenant-level operations, e.g. US or EU.",
				Optional:    true,
			},
			"timeout_seconds": schema.Int64Attribute{
				Description: "Timeout (seconds) for individual API calls. Defaults to 30.",
				Optional:    true,
			},
		},
	}
}

// Configure validates the provider configuration and builds the API
// client, which is handed to every resource.
func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	baseURL := strings.TrimSpace(cfg.APIBaseURL.ValueString())
	if baseURL == "" {
		resp.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
			path.Root("api_base_url"),
			"Invalid API Base URL",
			"api_base_url must be set.",
		))
	}
	if strings.TrimSpace(cfg.APIKey.ValueString()) == "" {
		resp.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
			path.Root("api_key"),
			"Invalid API Key",
			"api_key must be set.",
		))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	timeout := time.Duration(0)
	if !cfg.TimeoutSeconds.IsNull() && !cfg.TimeoutSeconds.IsUnknown() {
		timeout = time.Duration(cfg.TimeoutSeconds.ValueInt64()) * time.Second
	}

	c, err := client.New(client.Config{
		BaseURL: baseURL,
		APIKey:  cfg.APIKey.ValueString(),
		Region:  strings.TrimSpace(cfg.Region.ValueString()),
		Timeout: timeout,
	})
	if err != nil {
		resp.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
			path.Root("api_base_url"),
			"Invalid provider configuration",
			err.Error(),
		))
		return
	}

	resp.ResourceData = c
	resp.DataSourceData = c
}

// Resources returns the provider's resource factories.
func (p *Provider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewTenantResource,
		NewAgentResource,
		NewAgentToolGrantResource,
		NewConnectorResource,
		NewPolicyResource,
		NewBudgetResource,
	}
}

// DataSources returns the provider's data source factories.
func (p *Provider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// providerModel maps the provider schema to a struct.
type providerModel struct {
	APIBaseURL     types.String `tfsdk:"api_base_url"`
	APIKey         types.String `tfsdk:"api_key"`
	Region         types.String `tfsdk:"region"`
	TimeoutSeconds types.Int64  `tfsdk:"timeout_seconds"`
}
