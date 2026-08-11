// Package policy implements the L1 in-process authorization layer:
// Cedar-style attribute rules evaluated in Go memory (<0.2ms) plus a
// decision cache in front of the L2 ReBAC backend, with sub-second
// revocation invalidation.
//
// Query-time authorization becomes tiered:
//
//	L1 rules  — deny/allow rules evaluated in-process (tenant, user,
//	            groups, document, scope). A matched rule decides the
//	            check without touching the network.
//	L1 cache  — recent L2 (or L1) decisions cached per
//	            (tenant, user, document, scope) with short TTLs.
//	L2 backend — the ReBAC engine (SpiceDB) for nested graph
//	            inheritance. Only consulted on cache misses.
//
// Privilege-revocation events (employee termination, group membership
// change, document grant revocation) call Invalidate* and the affected
// entries are dropped immediately — a revoked user can never keep
// reading from a warm cache. All failures fail closed.
package policy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// DecisionSource classifies where a decision came from.
type DecisionSource string

const (
	SourceRule         DecisionSource = "rule"          // evaluated by an L1 rule
	SourceCache        DecisionSource = "cache"         // cached decision, TTL valid
	SourceBackend      DecisionSource = "backend"       // L2 backend consulted
	SourceBackendError DecisionSource = "backend_error" // L2 failed, fail closed
)

// Decision is one authorization outcome.
type Decision struct {
	Allowed bool           `json:"allowed"`
	Source  DecisionSource `json:"source"`
	RuleID  string         `json:"rule_id,omitempty"`
	Reason  string         `json:"reason,omitempty"`
	Latency time.Duration  `json:"-"`
}

// ErrPolicyEngineUnavailable is returned when no L2 backend is wired
// and no rule matched: the check cannot be confirmed, so it fails.
var ErrPolicyEngineUnavailable = errors.New("policy engine: backend unavailable")

// Backend is the adapter between the engine's chunk-level checks and
// the L2 relation backend.
type Backend interface {
	CanAccess(ctx context.Context, tenantID, userID string, docID string) (bool, error)
}

// BackendFunc adapts a function to Backend.
type BackendFunc func(ctx context.Context, tenantID, userID, docID string) (bool, error)

func (f BackendFunc) CanAccess(ctx context.Context, tenantID, userID, docID string) (bool, error) {
	return f(ctx, tenantID, userID, docID)
}

// GroupDirectory resolves a user's current group memberships for L1
// rule evaluation. The aclsync webhook receivers keep it current.
type GroupDirectory interface {
	GroupsFor(ctx context.Context, tenantID, userID string) ([]string, error)
}

// MemoryGroups is a simple in-memory GroupDirectory for tests and
// single-node deployments.
type MemoryGroups struct {
	mu     sync.RWMutex
	member map[string][]string // key: tenant + "\x00" + user -> groups
}

func NewMemoryGroups() *MemoryGroups { return &MemoryGroups{member: map[string][]string{}} }

func (m *MemoryGroups) Set(tenantID, userID string, groups ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.member[tenantID+"\x00"+userID] = groups
}

// SetMembership adds or removes one group membership (webhook-driven).
func (m *MemoryGroups) SetMembership(_ context.Context, tenantID, userID, groupID string, member bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID + "\x00" + userID
	groups := m.member[key]
	idx := -1
	for i, g := range groups {
		if g == groupID {
			idx = i
			break
		}
	}
	if member && idx < 0 {
		m.member[key] = append(groups, groupID)
	} else if !member && idx >= 0 {
		m.member[key] = append(groups[:idx], groups[idx+1:]...)
	}
	return nil
}

func (m *MemoryGroups) GroupsFor(_ context.Context, tenantID, userID string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	groups := m.member[tenantID+"\x00"+userID]
	out := make([]string, len(groups))
	copy(out, groups)
	return out, nil
}

// ---- Cedar-style rule set ----

// Effect of a policy rule.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Rule is one L1 policy rule. Empty fields match anything. Document
// supports exact ids and glob patterns ("doc-*"). Later rules with the
// same specificity override earlier ones (explicit-deny wins by
// default when rules match).
type Rule struct {
	ID       string `json:"id"`
	Tenant   string `json:"tenant,omitempty"`   // exact tenant, or "" for any
	User     string `json:"user,omitempty"`     // exact user, or "" for any
	Group    string `json:"group,omitempty"`    // user must be a member of this group
	Document string `json:"document,omitempty"` // exact id, glob ("doc-*"), or "" for any
	Scope    string `json:"scope,omitempty"`    // required scope, or "" for any
	Effect   Effect `json:"effect"`
}

// PolicySet is an ordered list of L1 rules. Evaluate returns the first
// matching rule; deny rules win when a user matches both an allow and a
// deny rule with equal match specificity.
type PolicySet struct {
	rules []Rule
	mu    sync.RWMutex
}

func NewPolicySet(rules ...Rule) *PolicySet { return &PolicySet{rules: rules} }

// Add appends a rule.
func (p *PolicySet) Add(rule Rule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = append(p.rules, rule)
}

// Rules returns a copy of the current rules.
func (p *PolicySet) Rules() []Rule {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Rule, len(p.rules))
	copy(out, p.rules)
	return out
}

// Evaluation is the outcome of PolicySet.Evaluate.
type Evaluation struct {
	Matched bool   `json:"matched"`
	Allowed bool   `json:"allowed"`
	RuleID  string `json:"rule_id,omitempty"`
}

// Evaluate applies the rule set to one (tenant, user, groups, doc,
// scope) context.
func (p *PolicySet) Evaluate(tenantID, userID string, groups []string, docID, scope string) Evaluation {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, r := range p.rules {
		if !ruleMatches(r, tenantID, userID, groups, docID, scope) {
			continue
		}
		return Evaluation{Matched: true, Allowed: r.Effect == EffectAllow, RuleID: r.ID}
	}
	return Evaluation{}
}

func ruleMatches(r Rule, tenantID, userID string, groups []string, docID, scope string) bool {
	if r.Tenant != "" && r.Tenant != tenantID {
		return false
	}
	if r.User != "" && r.User != userID {
		return false
	}
	if r.Group != "" && !contains(groups, r.Group) {
		return false
	}
	if r.Document != "" && !globMatch(r.Document, docID) {
		return false
	}
	if r.Scope != "" && r.Scope != scope {
		return false
	}
	return true
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// globMatch supports exact ids and simple "*" globs ("doc-*", "*-prod").
func globMatch(pattern, value string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	parts := strings.Split(pattern, "*")
	if len(parts) > 2 {
		return false // only a single wildcard is supported
	}
	if len(parts) == 1 {
		return parts[0] == value
	}
	return strings.HasPrefix(value, parts[0]) && strings.HasSuffix(value, parts[1])
}
