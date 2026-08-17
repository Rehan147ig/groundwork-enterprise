resource "groundwork_agent" "support" {
  name              = "support-agent"
  description       = "Customer support triage agent"
  owner_principal_id = "team-support"
  business_purpose  = "triage support tickets and draft replies"
  risk_tier         = "medium"
  environment       = "production"

  version {
    version              = "v1.0.0"
    model_provider       = "anthropic"
    model_name           = "claude-sonnet-4-5"
    prompt_digest        = "sha256:4b5e..."
    tool_manifest_digest = "sha256:9c1d..."
    artifact_digest      = "sha256:7f2e..."
  }
}