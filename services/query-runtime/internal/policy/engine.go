package policy

import (
	"context"
	"strings"
	"time"
)

// Callback receives decisions for observability (metrics, traces).
type Callback func(Decision)

// Engine is the L1 authorization engine: rules first, then the
// decision cache, then the L2 backend (fail closed on backend errors).
// It implements the engine's chunk-level check so the query path can
// wire it directly as the ACL checker.
type Engine struct {
	Set     *PolicySet
	Cache   *PolicyCache
	Backend Backend // L2; nil means rules+cache only
	Groups  GroupDirectory
	// OnDecision, when set, is invoked for every decision.
	OnDecision Callback
}

// CanAccess evaluates (user, document) under the L1 policy set and
// cache, falling back to the L2 backend only on rule/cache miss.
//
// The decision order mirrors a Zanzibar/SpiceDB caching layer:
// explicit L1 rules decide instantly; otherwise a warm cache entry
// decides; otherwise the L2 backend is consulted and the outcome is
// cached. Failures at any stage fail closed (deny).
func (e *Engine) CanAccess(ctx context.Context, tenantID, userID, region, docID, scope string, ownerTags []string) Decision {
	start := time.Now()
	if e.Set != nil {
		groups := []string(nil)
		if e.Groups != nil {
			groups, _ = e.Groups.GroupsFor(ctx, tenantID, userID)
		}
		if ev := e.Set.Evaluate(tenantID, userID, groups, docID, scope); ev.Matched {
			decision := Decision{
				Allowed: ev.Allowed,
				Source:  SourceRule,
				RuleID:  ev.RuleID,
				Reason:  "policy_rule",
				Latency: time.Since(start),
			}
			e.emit(decision)
			return decision
		}
	}

	if e.Cache != nil {
		key := Key(tenantID, userID, region, docID, scope, ownerTags)
		if decision, ok := e.Cache.Get(key); ok {
			decision.Latency = time.Since(start)
			e.emit(decision)
			return decision
		}
		if decision, ok := e.checkBackend(ctx, tenantID, userID, docID, start); ok {
			ttl := e.cacheTTL(decision.Allowed)
			e.Cache.Put(key, decision, ttl, tenantID, userID, docID, scope)
			return decision
		}
	}

	if decision, ok := e.checkBackend(ctx, tenantID, userID, docID, start); ok {
		return decision
	}
	decision := Decision{Allowed: false, Source: SourceBackendError, Reason: "backend_unavailable", Latency: time.Since(start)}
	e.emit(decision)
	return decision
}

// checkBackend consults the L2 backend. ok=false means the backend
// failed (fail closed with a backend_error decision, never fall open).
func (e *Engine) checkBackend(ctx context.Context, tenantID, userID, docID string, start time.Time) (Decision, bool) {
	if e.Backend == nil {
		return Decision{}, false
	}
	allowed, err := e.Backend.CanAccess(ctx, tenantID, userID, docID)
	decision := Decision{
		Allowed: allowed,
		Source:  SourceBackend,
		Reason:  "l2_backend",
		Latency: time.Since(start),
	}
	if err != nil {
		decision = Decision{Allowed: false, Source: SourceBackendError, Reason: classifyBackendError(err), Latency: time.Since(start)}
	}
	e.emit(decision)
	return decision, true
}

func (e *Engine) cacheTTL(allowed bool) time.Duration {
	if e.Cache == nil {
		return 0
	}
	if allowed {
		return e.Cache.cfg.PosTTL
	}
	return e.Cache.cfg.NegTTL
}

func (e *Engine) emit(decision Decision) {
	if e.OnDecision != nil {
		e.OnDecision(decision)
	}
}

// classifyBackendError maps L2 errors to stable reasons (fail closed).
func classifyBackendError(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"):
		return "backend_timeout"
	case strings.Contains(msg, "circuit"):
		return "backend_circuit_open"
	default:
		return "backend_unavailable"
	}
}
