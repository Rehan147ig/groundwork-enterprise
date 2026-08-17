// Package snowflake syncs Snowflake grants into Groundwork.
//
// CONTRACT (Milestone 4): Snowflake authorization is role-based and
// inherited. This connector models role inheritance and actual effective
// grants (role → role grants and role → privilege grants resolved to the
// effective grantee set); it does NOT treat direct grants as the whole
// story. Any privilege whose effective grantee cannot be resolved
// through the role hierarchy is treated as denied (fail closed).
//
// Queries issued by this connector MUST be validated against a real
// Snowflake account before being relied on for authorization decisions —
// the SQL dialect and system tables are account-version dependent. The
// contract test suite (internal/aclsync/contract) is the gate for any
// change here.
package snowflake
