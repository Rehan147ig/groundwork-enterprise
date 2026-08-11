// Package schema holds the Groundwork authorization model for SpiceDB.
// The model lives in ONE place — the embedded groundwork.zed — and is
// consumed by every component that touches a SpiceDB server:
//
//   - the SpiceDB adapter's Bootstrap (writes it) and deep Ready
//     (verifies what is written matches),
//   - the seeders and sync tools (provision the target before the first
//     relationship is written),
//   - drift checks after schema rollouts (ReadSchema + IsUpToDate).
//
// Before this package existed the model was a string constant inside the
// adapter, which the tooling could not reuse — the two could drift
// silently. Now there is exactly one schema text in the repository.
//
// The model is the single source of truth for the authorization
// semantics:
//
//   - group#member       nested membership (user | group#member)
//   - folder#viewer      user | group#member
//   - document#parent    folder
//   - document#view      direct viewer ∪ folder view via parent
//   - tool#use           user only (governed delegated principals)
//   - tool_action#execute user only
//
// Folder inheritance is folded into the document "view" permission
// because SpiceDB cannot compute a relation — only a permission. The
// union therefore lives in the document "view" permission (and "view" on
// folder), and the adapter checks the permission name on folder/document
// and the relation name on tool/tool_action. Check semantics are
// identical; the Write/Delete/List surfaces are unchanged (relations
// only).
//
// Bootstrap is idempotent: WriteSchema is declarative, and a schema that
// removes relations still in use is rejected by SpiceDB, surfacing model
// drift instead of silently corrupting checks.
package schema

import (
	_ "embed"
	"strings"
)

//go:embed groundwork.zed
var zedSource string

// ZED returns the embedded authorization model (groundwork.zed).
func ZED() string { return zedSource }

// IsUpToDate reports whether the schema currently written to a SpiceDB
// server already carries the embedded model. It is intentionally
// tolerant of supersets — an operator may have added managed
// definitions (console-created types, platform types) around the
// Groundwork model — but it must not tolerate a weakened or missing
// model. A schema is up to date when it contains every definition and
// the view-permission (inheritance) anchor of groundwork.zed.
func IsUpToDate(current string) bool {
	s := strings.TrimSpace(current)
	if s == "" {
		return false
	}
	if strings.TrimSpace(zedSource) == s {
		return true
	}
	anchors := []string{
		"definition user",
		"definition group",
		"definition folder",
		"definition document",
		"definition tool",
		"definition tool_action",
		"relation member: user | group#member",
		"relation viewer: user | group#member",
		"relation parent: folder",
		"relation use: user",
		"relation execute: user",
		"permission view = viewer + parent->view",
	}
	for _, a := range anchors {
		if !strings.Contains(s, a) {
			return false
		}
	}
	return true
}
