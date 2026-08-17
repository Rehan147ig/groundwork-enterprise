// Package atlassian syncs Atlassian Confluence space/page permissions
// into Groundwork.
//
// CONTRACT (Milestone 4): Confluence permissions are space- and
// page-level grants with group inheritance. This connector models space
// and page grants as exposed by the Confluence REST API; anonymous
// access and unmodeled sharing states fail closed (deny). The contract
// test suite (internal/aclsync/contract) is the gate for any change
// here.
package atlassian
