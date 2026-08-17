// Package notion syncs Notion page permissions into Groundwork.
//
// CONTRACT (Milestone 4): Notion permissions are integration-scoped and
// may NOT expose each end-user's effective permission. This connector
// therefore does NOT claim per-user authorization: it maps only what
// Notion's API proves (integration-level access and workspace/team
// scopes). It does NOT declare the contract's
// CapabilityEffectivePermissions, and any page whose effective access
// cannot be proven from provider data is treated as denied (fail
// closed), never guessed at.
//
// Do not present Notion-sourced permissions as per-user authorization;
// use them as integration-level context only. The contract test suite
// (internal/aclsync/contract) is the gate for any change here.
package notion
