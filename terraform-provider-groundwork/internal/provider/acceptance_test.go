package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"terraform-provider-groundwork/internal/client"
)

// Acceptance tests run against a disposable Groundwork stack. Set
// TF_ACC=1, GW_API_BASE_URL (https), and GW_API_KEY to run them; they
// are skipped otherwise. The same fake runtime used by the unit tests
// satisfies the contract for local verification when a stack is not
// available, but the intended target is a real disposable stack.
var (
	accBaseURL = os.Getenv("GW_API_BASE_URL")
	accAPIKey  = os.Getenv("GW_API_KEY")
)

func testProtoV6Provider() tfprotov6.ProviderServer {
	return providerserver.NewProtocol6(New("test"))()
}

func accFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"groundwork": func() (tfprotov6.ProviderServer, error) {
			return testProtoV6Provider(), nil
		},
	}
}

func accConfig(t *testing.T) string {
	t.Helper()
	if accBaseURL == "" || accAPIKey == "" {
		t.Skip("acceptance tests require TF_ACC=1 plus GW_API_BASE_URL and GW_API_KEY")
	}
	return fmt.Sprintf(`
provider "groundwork" {
  api_base_url = %q
  api_key      = %q
}
`, accBaseURL, accAPIKey)
}

func TestAccTenant(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: accFactories(),
		Steps: []resource.TestStep{
			{
				Config: accConfig(t) + `
resource "groundwork_tenant" "test" {
  tenant_id     = "tf-acc-tenant"
  region        = "US"
  capacity_tier = "enterprise"
  reason        = "acceptance test"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("groundwork_tenant.test", "tenant_id", "tf-acc-tenant"),
					resource.TestCheckResourceAttr("groundwork_tenant.test", "region", "US"),
					resource.TestCheckResourceAttr("groundwork_tenant.test", "status", "active"),
				),
			},
			{
				ResourceName:            "groundwork_tenant.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"reason", "status"},
			},
		},
	})
}

func TestAccAgent(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: accFactories(),
		Steps: []resource.TestStep{
			{
				Config: accConfig(t) + `
resource "groundwork_agent" "test" {
  name            = "tf-acc-agent"
  description     = "acceptance test agent"
  business_purpose = "testing"
  risk_tier       = "low"
  environment     = "test"
  version {
    version       = "v1.0.0"
    model_provider = "anthropic"
    model_name     = "claude-sonnet-4-5"
  }
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("groundwork_agent.test", "name", "tf-acc-agent"),
					resource.TestCheckResourceAttr("groundwork_agent.test", "state", "active"),
				),
			},
			{
				ResourceName:            "groundwork_agent.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"version", "state", "active_version"},
			},
		},
	})
}

func TestAccAgentToolGrant(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: accFactories(),
		Steps: []resource.TestStep{
			{
				Config: accConfig(t) + `
resource "groundwork_agent" "g" {
  name       = "tf-acc-grant-agent"
  risk_tier  = "medium"
  version {
    version = "v1.0.0"
  }
}
resource "groundwork_agent_tool_grant" "test" {
  agent_id          = groundwork_agent.g.id
  version_id        = groundwork_agent.g.version.version
  tool_id           = "slack"
  action_id         = "send_message"
  resource_scope    = "slack://C123456"
  region_constraint = "US"
  call_limit_per_run = 5
  requires_approval = true
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("groundwork_agent_tool_grant.test", "tool_id", "slack"),
					resource.TestCheckResourceAttr("groundwork_agent_tool_grant.test", "requires_approval", "true"),
				),
			},
		},
	})
}

func TestAccConnector(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: accFactories(),
		Steps: []resource.TestStep{
			{
				Config: accConfig(t) + `
resource "groundwork_connector" "test" {
  name = "tf-acc-connector"
  type = "mcp"
  config {
    base_url  = "https://mcp.example.com"
    region    = "US"
    secret_ref = "keyring://tf-acc-connector"
  }
  actions {
    name             = "search"
    transport_method = "search_documents"
    risk             = "low"
    read_only        = true
  }
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("groundwork_connector.test", "name", "tf-acc-connector"),
					resource.TestCheckResourceAttr("groundwork_connector.test", "lifecycle", "active"),
				),
			},
			{
				ResourceName:            "groundwork_connector.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"config", "actions"},
			},
		},
	})
}

func TestAccPolicy(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: accFactories(),
		Steps: []resource.TestStep{
			{
				Config: accConfig(t) + `
resource "groundwork_policy" "test" {
  source_region   = "US"
  target_region   = "EU"
  purpose_pattern = "*"
  enabled         = true
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("groundwork_policy.test", "source_region", "US"),
					resource.TestCheckResourceAttr("groundwork_policy.test", "enabled", "true"),
				),
			},
			{
				ResourceName:      "groundwork_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccBudget(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: accFactories(),
		Steps: []resource.TestStep{
			{
				Config: accConfig(t) + `
resource "groundwork_budget" "test" {
  scope_type           = "tenant"
  max_actions_per_run  = 10
  max_run_duration_seconds = 600
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("groundwork_budget.test", "scope_type", "tenant"),
					resource.TestCheckResourceAttr("groundwork_budget.test", "max_actions_per_run", "10"),
				),
			},
			{
				ResourceName:      "groundwork_budget.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// accDestroyClient builds a client to assert post-destroy state.
func accDestroyClient() *client.Client {
	c, err := client.New(client.Config{BaseURL: accBaseURL, APIKey: accAPIKey})
	if err != nil {
		return nil
	}
	return c
}

func testAccCheckTenantDeprovisioned() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		c := accDestroyClient()
		if c == nil {
			return fmt.Errorf("failed to build destroy-check client")
		}
		for _, m := range s.Modules {
			if r, ok := m.Resources["groundwork_tenant.test"]; ok {
				ten, err := c.GetTenant(context.Background(), r.Primary.ID)
				if err != nil {
					return fmt.Errorf("tenant must remain readable after delete: %w", err)
				}
				if ten.Status != "deprovisioned" {
					return fmt.Errorf("expected non-destructive deprovision, got status %q", ten.Status)
				}
			}
		}
		return nil
	}
}
