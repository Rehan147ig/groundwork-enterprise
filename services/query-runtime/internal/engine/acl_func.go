package engine

import (
	"context"

	"groundwork/query-runtime/internal/runtime"
)

// ACLCheckFunc adapts a plain function to the engine's ACLChecker
// contract (used by tests and by callers bridging external stores).
type ACLCheckFunc func(ctx context.Context, req runtime.QueryRequest, chunk runtime.Chunk) (bool, error)

// CanAccess implements ACLChecker.
func (f ACLCheckFunc) CanAccess(ctx context.Context, req runtime.QueryRequest, chunk runtime.Chunk) (bool, error) {
	return f(ctx, req, chunk)
}

var _ ACLChecker = ACLCheckFunc(nil)
