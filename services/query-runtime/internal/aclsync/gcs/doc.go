// Package gcs syncs Google Cloud Storage object permissions into
// Groundwork.
//
// CONTRACT (Milestone 4): object ACLs alone do NOT model effective GCS
// IAM. This connector's strict supported subset is object-level ACLs
// only; bucket policies (IAM), IAM roles, inherited bucket grants,
// uniform-bucket-level-access mode, and encryption-access rules are NOT
// modeled. Outside that subset the connector fails closed — a resource
// whose effective access depends on unmodeled policy is denied.
//
// Before claiming per-user authorization for a GCS-backed resource,
// verify the deployment relies exclusively on object ACLs with
// fine-grained access enabled; anything else requires extending this
// subset. The contract test suite (internal/aclsync/contract) is the
// gate for any change here.
package gcs
