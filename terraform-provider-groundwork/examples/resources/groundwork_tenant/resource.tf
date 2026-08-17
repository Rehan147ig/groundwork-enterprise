resource "groundwork_tenant" "acme" {
  tenant_id     = "acme-prod"
  region        = "US"
  capacity_tier = "enterprise"
  reason        = "managed by terraform"
}