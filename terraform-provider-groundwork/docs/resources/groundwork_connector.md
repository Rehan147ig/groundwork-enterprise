---
page_title: "groundwork_connector Resource - groundwork"
subcategory: ""
description: |-
  A registered connector (REST or MCP). Delete revokes (non-destructive). Secrets are secret references only.
---

# groundwork_connector (Resource)

A registered connector (REST or MCP). Delete **revokes** the connector
(non-destructive): registry rows, versions, invocations, and evidence
remain intact.

**Security rule:** authentication material is accepted as secret
*references* only (`secret_ref`, `client_cert_ref`). Raw credentials
never enter Terraform state.

## Example Usage

```terraform
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
}
```

## Schema

### Required

- `config` (Block, Required) Transport-level connector configuration.
  - `base_url` (String, Optional) Operator-supplied base URL (never
    derived from agent requests).
  - `region` (String, Optional) Region the connector endpoints live in.
  - `timeout_ms` (Number, Optional) Per-request timeout in
    milliseconds.
  - `retry_max` (Number, Optional) Maximum retries for retryable
    failures.
  - `retry_idempotent_only` (Boolean, Optional) Only retry idempotent
    requests.
  - `max_response_bytes` (Number, Optional) Maximum accepted response
    size.
  - `tls_verify` (Boolean, Optional) Verify upstream TLS certificates.
  - `secret_ref` (String, Optional, Sensitive) Reference to the
    connector credential in Groundwork Secrets (`keyring://...`). Never
    a raw secret.
  - `client_cert_ref` (String, Optional, Sensitive) Reference to a
    client certificate in Groundwork Secrets (`keyring://...`).
  - `allowed_content_types` (List of String, Optional) Content types
    the gateway may forward.
  - `redaction_fields` (List of String, Optional) Fields redacted from
    evidence and logs.
- `name` (String) Connector name.
- `type` (String) Connector type: `s3`, `gcs`, `notion`, `sharepoint`,
  `snowflake`, `googledrive`, `confluence`, `mcp`, or a custom REST
  provider.

### Optional

- `actions` (Set of Block, Optional) Declarative action manifest for
  the connector.
  - `name` (String, Required) Action name.
  - `transport_method` (String, Required) HTTP method (REST) or MCP tool
    name (MCP).
  - `path_template` (String, Optional) REST only: `/path/{arg}` — never
    raw agent URLs.
  - `resource_type` (String, Optional) Resource type the action targets.
  - `risk` (String, Required) Risk rating: `low`, `medium`, `high`, or
    `critical`.
  - `read_only` (Boolean, Optional) Action performs no mutation.
  - `requires_approval` (Boolean, Optional) Every call requires human
    approval.
  - `max_request_bytes` (Number, Optional) Maximum accepted request
    size.
  - `max_response_bytes` (Number, Optional) Maximum accepted response
    size.
  - `allowed_versions` (List of String, Optional) Agent version IDs
    allowed to call this action; empty means any active version.
  - `args` (List of String, Optional) Allowlisted argument names.
- `description` (String) Human-readable description.

### Read-Only

- `id` (String) Connector ID.
- `lifecycle` (String) Connector lifecycle state (`active`, `suspended`,
  `revoked`).

## Import

Connectors can be imported using their connector ID:

```
terraform import groundwork_connector.confluence <connector-id>
```