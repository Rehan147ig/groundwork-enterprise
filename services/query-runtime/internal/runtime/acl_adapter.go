package runtime

import (
	"context"
	"fmt"

	"groundwork/query-runtime/internal/relationship"
)

// ACLAdapter adapts a relationship.Authorizer to the runtime.ACLChecker
// contract the query engine consumes. It is the neutral engine path: the
// document-level check becomes a typed relationship check (user, view,
// document), preserving the tenancy and soft-delete guards exactly.
//
// Business logic never imports a concrete backend checker directly; the
// adapter is wired from cmd/* with whichever Authorizer is configured.
type ACLAdapter struct {
	Auth relationship.Authorizer
}

// NewACLAdapter builds an ACLChecker over a relationship.Authorizer.
func NewACLAdapter(auth relationship.Authorizer) *ACLAdapter {
	return &ACLAdapter{Auth: auth}
}

// CanAccess implements runtime.ACLChecker with the same guard order as
// the legacy ACLChecker.CanAccess: tenancy/soft-delete checks first
// (no backend call), then the viewer check. Backend failures are mapped
// to ErrACLUnavailable so the engine classifies them fail-closed.
func (a *ACLAdapter) CanAccess(ctx context.Context, req QueryRequest, chunk Chunk) (bool, error) {
	if req.TenantID == "" || req.UserID == "" || chunk.DocumentID == "" || chunk.TenantID != req.TenantID || chunk.SoftDeleted {
		return false, nil
	}
	if a.Auth == nil {
		return false, fmt.Errorf("%w: no authorizer configured", ErrACLUnavailable)
	}
	allowed, err := a.Auth.Check(ctx, relationship.CheckRequest{
		TenantID:   req.TenantID,
		Subject:    relationship.UserRef(req.UserID),
		Permission: relationship.PermissionView,
		Resource:   relationship.DocumentRef(chunk.DocumentID),
	})
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrACLUnavailable, err)
	}
	return allowed, nil
}

var _ ACLChecker = (*ACLAdapter)(nil)
