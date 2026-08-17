// Package s3 syncs Amazon S3 object permissions into Groundwork.
//
// CONTRACT (Milestone 4): object ACLs alone do NOT model effective S3
// IAM. This connector's strict supported subset is object-level ACLs
// (per-object grants) only; bucket policies, IAM roles/policies, access
// points, object ownership grants, and encryption-access rules are NOT
// modeled. Outside that subset the connector fails closed — a resource
// whose effective access depends on unmodeled policy is treated as
// denied rather than guessed at.
//
// Before claiming per-user authorization for an S3-backed resource,
// verify the deployment relies exclusively on object ACLs; anything else
// requires extending this subset. The contract test suite
// (internal/aclsync/contract) is the gate for any change here.
package s3
