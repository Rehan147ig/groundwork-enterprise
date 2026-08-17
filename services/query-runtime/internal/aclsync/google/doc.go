// Package google syncs Google Drive permissions into Groundwork.
//
// CONTRACT (Milestone 4): Drive permissions are per-resource grants
// with inheritance (shared drives/folders). This connector models
// per-file/per-folder grants and folder inheritance as exposed by the
// Drive API; link-sharing visibility (Anyone with the link / org-wide)
// is conservatively mapped to deny unless a grant is provable for the
// principal, and anything unmodeled fails closed.
//
// The contract test suite (internal/aclsync/contract) is the gate for
// any change here.
package google
