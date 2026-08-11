package engine

import (
	"context"
	"errors"
	"sync/atomic"

	"groundwork/query-runtime/internal/policy"
	"groundwork/query-runtime/internal/runtime"
)

// PolicyACLChecker adapts the L1 policy engine (rules + cache + L2
// backend) to the engine's ACLChecker contract. Failures at any L1/L2
// stage fail closed: a backend_error decision surfaces as an error, and
// the engine's fail-closed path returns zero citations.
type PolicyACLChecker struct {
	Engine *policy.Engine

	l1 atomic.Int64
	l2 atomic.Int64
}

// NewPolicyACLChecker wraps the L1 engine and wires its decision
// callback to per-source counters.
func NewPolicyACLChecker(eng *policy.Engine) *PolicyACLChecker {
	wrapper := &PolicyACLChecker{Engine: eng}
	eng.OnDecision = func(decision policy.Decision) {
		switch decision.Source {
		case policy.SourceRule, policy.SourceCache:
			wrapper.l1.Add(1)
		case policy.SourceBackend, policy.SourceBackendError:
			wrapper.l2.Add(1)
		}
	}
	return wrapper
}

// CanAccess implements engine.ACLChecker.
func (p *PolicyACLChecker) CanAccess(ctx context.Context, req runtime.QueryRequest, chunk runtime.Chunk) (bool, error) {
	decision := p.Engine.CanAccess(ctx, req.TenantID, req.UserID, req.Region, chunk.DocumentID, chunk.RequiredScope, chunk.OwnerACLTags)
	if decision.Allowed {
		return true, nil
	}
	if decision.Source == policy.SourceBackendError {
		return false, errors.New(decision.Reason)
	}
	return false, nil
}

// Reporter returns (l1Decisions, l2Fallbacks) since construction.
// Wired into the engine's PolicyReporter so the audit trace shows the
// L1/L2 split per query.
func (p *PolicyACLChecker) Reporter() (int, int) {
	return int(p.l1.Load()), int(p.l2.Load())
}
