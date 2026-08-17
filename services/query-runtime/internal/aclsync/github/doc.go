// Package github syncs GitHub repository access into Groundwork.
//
// CONTRACT (Milestone 4): GitHub authorization combines teams (nested),
// direct collaborators, and organization defaults. This connector
// models teams, nested teams, and direct collaborator grants; org-level
// default permissions and outside-collaborator edge cases are
// conservatively mapped (only explicitly read-granting roles become
// viewers), and anything unmodeled fails closed (deny). The contract
// test suite (internal/aclsync/contract) is the gate for any change
// here.
package github
