terraform {
  required_providers {
    groundwork = {
      source  = "groundwork/groundwork"
      version = "~> 0.1"
    }
  }
}

provider "groundwork" {
  # https URL to the Groundwork query-runtime API.
  api_base_url = "https://gw.example.com"
  # Groundwork API key (administrator scope). Prefer a secret
  # reference such as a Vault token lookup; never commit the raw key.
  api_key = var.groundwork_api_key
  # Optional default region for tenant-level operations.
  region = "US"
}

variable "groundwork_api_key" {
  type      = string
  sensitive = true
}