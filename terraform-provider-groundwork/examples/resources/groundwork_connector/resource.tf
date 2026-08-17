resource "groundwork_connector" "confluence" {
  name        = "prod-confluence"
  type        = "confluence"
  description = "Production Confluence content"
  config {
    base_url              = "https://wiki.example.com"
    region                = "US"
    timeout_ms            = 5000
    retry_max             = 2
    retry_idempotent_only = true
    max_response_bytes    = 1048576
    tls_verify            = true
    # Secret REFERENCES only — raw credentials never enter state.
    secret_ref            = "keyring://confluence-prod"
    allowed_content_types = ["application/json"]
    redaction_fields      = ["authorization", "cookie"]
  }
  actions {
    name             = "search"
    transport_method = "GET"
    path_template    = "/rest/api/content/search"
    resource_type    = "page"
    risk             = "low"
    read_only        = true
  }
  actions {
    name             = "update_page"
    transport_method = "PUT"
    path_template    = "/rest/api/content/{id}"
    resource_type    = "page"
    risk             = "high"
    requires_approval = true
    max_response_bytes = 10240
    args             = ["id", "title", "body"]
  }
}