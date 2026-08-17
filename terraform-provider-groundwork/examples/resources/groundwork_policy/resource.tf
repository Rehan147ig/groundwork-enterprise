resource "groundwork_policy" "us_to_eu_sync" {
  source_region   = "US"
  target_region   = "EU"
  purpose_pattern = "*"
  enabled         = true
}