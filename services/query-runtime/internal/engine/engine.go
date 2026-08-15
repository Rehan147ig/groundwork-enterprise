package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"groundwork/query-runtime/internal/firewall"
	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/runtime"
)

type RetrievalClient interface {
	Retrieve(ctx context.Context, req runtime.QueryRequest, limit int) ([]runtime.Candidate, error)
}

type ACLChecker interface {
	CanAccess(ctx context.Context, req runtime.QueryRequest, chunk runtime.Chunk) (bool, error)
}

type AuditWriter interface {
	Write(ctx context.Context, entry AuditEntry) error
}

// BackpressureGate is the Phase 8.2 outbox backpressure check. It is
// implemented by outbox.Backpressure and wired from cmd/query-runtime;
// nil-safe.
type BackpressureGate interface {
	Allow(ctx context.Context, tenantID string) error
	// ErrExceeded returns the sentinel error Allow returns when the
	// high-water mark is reached, so callers can classify refusals
	// without importing the outbox package.
	ErrExceeded() error
}

type Engine struct {
	Config  TimeoutConfig
	Backend RetrievalClient
	ACL     ACLChecker
	Auditor AuditWriter

	// ShadowMode runs the engine in observe-only mode: tenant and region remain hard
	// boundaries, but per-user ACL denials are recorded rather than enforced, so
	// operators can see what the agent receives today vs. what would be blocked once
	// enforcement is switched on. Default (false) is full fail-closed enforcement.
	ShadowMode bool

	RetrievalCircuit *CircuitBreaker
	ACLCircuit       *CircuitBreaker
	// AuditCircuit fast-fails audit writes after the Postgres audit_log
	// is repeatedly unreachable. PR #22 HA review fix #2: today, a
	// dead/slow Postgres lets thousands of concurrent goroutines all wait
	// the full AUDIT_TIMEOUT_MS before fail-closed; the breaker collapses
	// that into one detection + fast-fail-closed for subsequent queries
	// during the outage. Fail-closed behavior is PRESERVED — when the
	// breaker is open, writeAudit returns an error and the existing
	// failClosed path in Execute returns zero citations to the agent
	// (TestAuditWrite_FailsEngine pins this).
	//
	// Threshold tuning: 5 failures within 30s is more forgiving than the
	// retrieval/ACL breakers (3 / 10s) because audit-write failures can
	// include transient lock contention; we don't want a brief lock
	// queue depth to open the breaker.
	AuditCircuit *CircuitBreaker
	// Backpressure (Phase 8.2) is the outbox high-water gate. Checked
	// before every audit write: when the tenant's pending outbox is
	// at/above the mark, the query fails closed (outbox_backpressure,
	// zero citations) instead of deepening the backlog. Nil-safe.
	Backpressure BackpressureGate

	// Firewall is the Zero-Trust Context Firewall (PII redaction,
	// indirect prompt-injection scan, provenance watermarking) applied
	// to permitted chunks BEFORE they reach the model. Nil-safe: no
	// firewall means the context passes through unchanged.
	Firewall *firewall.ContextFirewall

	// PolicyReporter, when set, is invoked after the ACL stage to stamp
	// the L1/L2 decision split onto the trace (wired to the L1 policy
	// engine's counters). Nil-safe.
	PolicyReporter func() (l1, l2 int)

	mu sync.Mutex
}

func (e *Engine) Execute(ctx context.Context, req runtime.QueryRequest) runtime.QueryResponse {
	started := time.Now()
	trace := runtime.RuntimeTrace{
		TraceID:    traceIDFor(req),
		TenantID:   req.TenantID,
		UserID:     req.UserID,
		Region:     req.Region,
		StartedAt:  started,
		ShadowMode: e.ShadowMode,
	}
	defer func() { gwmetrics.RecordQueryLatency(req.TenantID, time.Since(started)) }()
	cfg := e.Config.WithDefaults()
	totalCtx, cancel := context.WithTimeout(ctx, cfg.Total)
	defer cancel()

	if req.TenantID == "" || req.UserID == "" || req.Region == "" {
		return e.failClosed(totalCtx, req, started, "validation", "missing_verified_tenant_context", errors.New("tenant, region, and user must be verified before engine execution"))
	}
	if e.Backend == nil {
		return e.failClosed(totalCtx, req, started, "retrieval", "retrieval_backend_unavailable", errors.New("retrieval backend unavailable"))
	}
	if e.ACL == nil {
		return e.failClosed(totalCtx, req, started, "acl", "acl_backend_unavailable", errors.New("acl backend unavailable"))
	}

	candidates, err := e.retrieve(totalCtx, cfg, req, 50)
	if err != nil {
		return e.failClosed(totalCtx, req, started, "qdrant", classifyEngineError("qdrant", err), err)
	}

	permitted, blockedACL, blockedRegion, decisions, blockedValid := e.filterChunksConcurrently(totalCtx, cfg, req, candidates)
	if e.PolicyReporter != nil {
		l1, l2 := e.PolicyReporter()
		trace.PolicyL1Decisions = l1
		trace.PolicyL2Fallbacks = l2
	}

	// Shadow mode is observe-only. Tenant and region stay hard boundaries, but the
	// per-user ACL decision is recorded rather than enforced: chunks that WOULD be
	// blocked are still returned so operators can compare what the agent receives
	// today against what Groundwork would strip once enforcement is switched on.
	resultSet := permitted
	decisionMode := "engine_live_acl_fail_closed"
	wouldBlockByACL := 0
	if e.ShadowMode {
		resultSet = append(append(make([]runtime.Candidate, 0, len(permitted)+len(blockedValid)), permitted...), blockedValid...)
		decisionMode = "engine_shadow_observe"
		wouldBlockByACL = blockedACL
		blockedACL = 0
	}

	reranked := rerank(resultSet, 7)
	if e.Firewall != nil && e.Firewall.Enabled() {
		// Preserve the original chunk metadata (scope, owner tags,
		// freshness) so the firewall only rewrites text + adds the
		// provenance watermark; block mode may drop chunks, so the
		// mapping is by chunk id, not index.
		meta := make(map[string]runtime.Candidate, len(reranked))
		fwCandidates := make([]firewall.Candidate, 0, len(reranked))
		for _, c := range reranked {
			meta[c.Chunk.ChunkID] = c
			fwCandidates = append(fwCandidates, firewall.Candidate{
				TenantID:   c.Chunk.TenantID,
				Region:     c.Chunk.Region,
				DocumentID: c.Chunk.DocumentID,
				ChunkID:    c.Chunk.ChunkID,
				ChunkHash:  c.Chunk.ChunkHash,
				Page:       c.Chunk.Page,
				Offset:     c.Chunk.Offset,
				Text:       c.Chunk.Text,
				Score:      c.Score,
				Freshness:  c.Chunk.FreshnessScore,
			})
		}
		sanitized, report, err := e.Firewall.Sanitize(totalCtx, req.TenantID, fwCandidates)
		if err != nil {
			return e.failClosed(totalCtx, req, started, "firewall", "context_firewall_error", err)
		}
		reranked = reranked[:0]
		for _, fc := range sanitized {
			c, ok := meta[fc.ChunkID]
			if !ok {
				continue
			}
			c.Chunk.Text = fc.Text
			c.Chunk.Watermark = fc.Watermark
			c.Score = fc.Score
			reranked = append(reranked, c)
		}
		if report != nil {
			trace.FirewallRedactions = report.Redactions
			trace.FirewallInjectionHits = report.InjectionHits
			trace.FirewallBlockedChunks = report.InjectionBlocked
			trace.FirewallWatermarked = report.Watermarked
		}
	}
	confidence := confidence(reranked)

	trace.LatencyMs = time.Since(started).Milliseconds()
	trace.VectorCandidates = len(candidates)
	trace.KeywordCandidates = 0
	trace.BlockedByACL = blockedACL
	trace.BlockedByResidency = blockedRegion
	trace.RerankedCandidates = len(reranked)
	trace.DecisionMode = decisionMode
	trace.WouldBlockByACL = wouldBlockByACL
	trace.AccessDecisions = decisions
	trace.ImmutableDigest = traceDigest(trace)
	if err := e.writeAudit(totalCtx, cfg, trace, req); err != nil {
		// Phase 8.2: a backpressure refusal gets its own error code so
		// operators can distinguish "evidence pipeline backed up" from
		// "audit store broken" without digging into messages.
		if e.Backpressure != nil && errors.Is(err, e.Backpressure.ErrExceeded()) {
			return e.failClosed(totalCtx, req, started, "audit", "outbox_backpressure", err)
		}
		return e.failClosed(totalCtx, req, started, "audit", "audit_write_failed", err)
	}

	outcome := "allowed"
	if len(reranked) == 0 {
		outcome = "denied"
	}
	gwmetrics.RecordQuery(req.TenantID, outcome)

	if len(reranked) == 0 {
		return runtime.QueryResponse{
			Answer:     "No grounded answer was found in the permitted source set.",
			Confidence: 0,
			Citations:  []runtime.Citation{},
			Trace:      trace,
		}
	}
	return runtime.QueryResponse{
		Answer:     "Grounded answer assembled from permitted, region-valid chunks.",
		Confidence: confidence,
		Citations:  toCitations(reranked),
		Trace:      trace,
	}
}

func (e *Engine) retrieve(ctx context.Context, cfg TimeoutConfig, req runtime.QueryRequest, limit int) ([]runtime.Candidate, error) {
	e.mu.Lock()
	if e.RetrievalCircuit == nil {
		e.RetrievalCircuit = NewCircuitBreaker(3, 10*time.Second)
	}
	retrievalCircuit := e.RetrievalCircuit
	e.mu.Unlock()
	if err := retrievalCircuit.Allow(); err != nil {
		gwmetrics.SetCircuitBreakerState("qdrant", circuitMetricState(retrievalCircuit.State()))
		return nil, err
	}
	retrievalCtx, cancel := context.WithTimeout(ctx, cfg.QdrantSearch)
	defer cancel()
	candidates, err := e.Backend.Retrieve(retrievalCtx, req, limit)
	if err != nil {
		retrievalCircuit.ReportFailure()
		gwmetrics.SetCircuitBreakerState("qdrant", circuitMetricState(retrievalCircuit.State()))
		return nil, err
	}
	retrievalCircuit.ReportSuccess()
	gwmetrics.SetCircuitBreakerState("qdrant", circuitMetricState(retrievalCircuit.State()))
	return candidates, nil
}

func (e *Engine) filterChunksConcurrently(ctx context.Context, cfg TimeoutConfig, req runtime.QueryRequest, candidates []runtime.Candidate) ([]runtime.Candidate, int, int, []runtime.AccessDecision, []runtime.Candidate) {
	e.mu.Lock()
	if e.ACLCircuit == nil {
		e.ACLCircuit = NewCircuitBreaker(3, 10*time.Second)
	}
	aclCircuit := e.ACLCircuit
	e.mu.Unlock()
	if err := aclCircuit.Allow(); err != nil {
		decisions := make([]runtime.AccessDecision, 0, len(candidates))
		for _, candidate := range candidates {
			decisions = append(decisions, decisionFromCandidate(candidate, false, "acl_circuit_open_fail_closed"))
			gwmetrics.RecordBlockedChunks(req.TenantID, "acl_circuit_open_fail_closed", 1)
		}
		gwmetrics.RecordRelationshipBackendUnreachable(req.TenantID)
		gwmetrics.SetCircuitBreakerState("relationship", circuitMetricState(aclCircuit.State()))
		return nil, len(candidates), 0, decisions, nil
	}

	aclCtx, cancel := context.WithTimeout(ctx, cfg.ACLCheck)
	defer cancel()

	type result struct {
		candidate runtime.Candidate
		allowed   bool
		regionOK  bool
		reason    string
		err       error
	}

	sem := make(chan struct{}, 10)
	resultCh := make(chan result, len(candidates))
	for _, candidate := range candidates {
		go func(item runtime.Candidate) {
			if item.Chunk.Region != req.Region || item.Chunk.TenantID != req.TenantID {
				resultCh <- result{candidate: item, allowed: false, regionOK: false, reason: "wrong_tenant"}
				return
			}
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-aclCtx.Done():
				resultCh <- result{candidate: item, allowed: false, regionOK: true, reason: "acl_timeout_fail_closed", err: aclCtx.Err()}
				return
			}
			checkStarted := time.Now()
			allowed, err := e.ACL.CanAccess(aclCtx, req, item.Chunk)
			checkDuration := time.Since(checkStarted)
			if err != nil {
				gwmetrics.RecordACLCheck(req.TenantID, "error", checkDuration)
				resultCh <- result{candidate: item, allowed: false, regionOK: true, reason: classifyACLError(err), err: err}
				return
			}
			if !allowed {
				gwmetrics.RecordACLCheck(req.TenantID, "denied", checkDuration)
				resultCh <- result{candidate: item, allowed: false, regionOK: true, reason: "acl_denied"}
				return
			}
			gwmetrics.RecordACLCheck(req.TenantID, "allowed", checkDuration)
			resultCh <- result{candidate: item, allowed: true, regionOK: true, reason: "allowed"}
		}(candidate)
	}

	permitted := make([]runtime.Candidate, 0, len(candidates))
	// blockedValid holds candidates that passed the tenant + region boundary but were
	// denied (or could not be confirmed) by the ACL layer — exactly what shadow mode
	// surfaces as "would be blocked" while still returning them.
	blockedValid := make([]runtime.Candidate, 0, len(candidates))
	decisions := make([]runtime.AccessDecision, 0, len(candidates))
	blockedACL := 0
	blockedRegion := 0
	aclErrors := 0

	for range candidates {
		select {
		case item := <-resultCh:
			decisions = append(decisions, decisionFromCandidate(item.candidate, item.allowed && item.regionOK, item.reason))
			if !item.regionOK {
				blockedRegion++
				gwmetrics.RecordBlockedChunks(req.TenantID, item.reason, 1)
				continue
			}
			if item.err != nil {
				aclErrors++
				gwmetrics.RecordRelationshipBackendUnreachable(req.TenantID)
			}
			if !item.allowed {
				blockedACL++
				blockedValid = append(blockedValid, item.candidate)
				gwmetrics.RecordBlockedChunks(req.TenantID, item.reason, 1)
				continue
			}
			permitted = append(permitted, item.candidate)
		case <-aclCtx.Done():
			remaining := len(candidates) - len(decisions)
			blockedACL += remaining
			for _, candidate := range candidates[len(decisions):] {
				decisions = append(decisions, decisionFromCandidate(candidate, false, "acl_timeout_fail_closed"))
				gwmetrics.RecordBlockedChunks(req.TenantID, "acl_timeout_fail_closed", 1)
			}
			aclErrors++
			aclCircuit.ReportFailure()
			gwmetrics.RecordRelationshipBackendUnreachable(req.TenantID)
			gwmetrics.SetCircuitBreakerState("relationship", circuitMetricState(aclCircuit.State()))
			return permitted, blockedACL, blockedRegion, decisions, blockedValid
		}
	}

	if aclErrors > 0 {
		aclCircuit.ReportFailure()
	} else {
		aclCircuit.ReportSuccess()
	}
	gwmetrics.SetCircuitBreakerState("relationship", circuitMetricState(aclCircuit.State()))
	return permitted, blockedACL, blockedRegion, decisions, blockedValid
}

func (e *Engine) writeAudit(ctx context.Context, cfg TimeoutConfig, trace runtime.RuntimeTrace, req runtime.QueryRequest) error {
	if e.Auditor == nil {
		return errors.New("audit writer unavailable")
	}
	// Phase 8.2 backpressure: the evidence pipeline must be able to
	// absorb this write. A backed-up outbox refuses new work
	// fail-closed (Execute maps this to outbox_backpressure, zero
	// citations) rather than growing the backlog.
	if e.Backpressure != nil {
		if err := e.Backpressure.Allow(ctx, req.TenantID); err != nil {
			return err
		}
	}
	// PR #22 HA fix #2: short-circuit when the audit DB is repeatedly
	// unreachable. When the breaker is OPEN, the write fast-fails;
	// Execute's caller maps the error to failClosed("audit", ...) and
	// the agent receives zero citations. Fail-closed PRESERVED.
	e.mu.Lock()
	if e.AuditCircuit == nil {
		e.AuditCircuit = NewCircuitBreaker(5, 30*time.Second)
	}
	auditCircuit := e.AuditCircuit
	e.mu.Unlock()
	if err := auditCircuit.Allow(); err != nil {
		gwmetrics.SetCircuitBreakerState("audit", circuitMetricState(auditCircuit.State()))
		return err
	}

	auditCtx, cancel := context.WithTimeout(ctx, cfg.AuditWrite)
	defer cancel()
	err := e.Auditor.Write(auditCtx, auditEntryFromTrace(trace, req))
	if err != nil {
		auditCircuit.ReportFailure()
	} else {
		auditCircuit.ReportSuccess()
	}
	gwmetrics.SetCircuitBreakerState("audit", circuitMetricState(auditCircuit.State()))
	return err
}

func (e *Engine) failClosed(ctx context.Context, req runtime.QueryRequest, started time.Time, stage string, code string, err error) runtime.QueryResponse {
	trace := runtime.RuntimeTrace{
		TraceID:         traceIDFor(req),
		TenantID:        req.TenantID,
		UserID:          req.UserID,
		Region:          req.Region,
		StartedAt:       started,
		LatencyMs:       time.Since(started).Milliseconds(),
		DecisionMode:    "engine_fail_closed",
		FailureStage:    stage,
		ErrorCode:       code,
		ErrorMessage:    err.Error(),
		AccessDecisions: []runtime.AccessDecision{{Allowed: false, Reason: code}},
	}
	trace.ImmutableDigest = traceDigest(trace)
	if e.Auditor != nil && stage != "audit" {
		_ = e.writeAudit(ctx, e.Config.WithDefaults(), trace, req)
	}
	gwmetrics.RecordQuery(req.TenantID, "fail_closed")
	return runtime.QueryResponse{
		Answer:     "No grounded answer was found in the permitted source set.",
		Confidence: 0,
		Citations:  []runtime.Citation{},
		Trace:      trace,
	}
}

func classifyEngineError(stage string, err error) string {
	if errors.Is(err, ErrCircuitOpen) || errors.Is(err, runtime.ErrCircuitOpen) || strings.Contains(err.Error(), "circuit open") {
		return stage + "_circuit_open"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return stage + "_timeout"
	}
	return stage + "_error"
}

func classifyACLError(err error) string {
	switch {
	case errors.Is(err, runtime.ErrCircuitOpen) || strings.Contains(err.Error(), "circuit open"):
		return "acl_circuit_open"
	case errors.Is(err, runtime.ErrACLTimeout) || errors.Is(err, context.DeadlineExceeded):
		return "acl_timeout"
	case errors.Is(err, runtime.ErrACLModelMissing):
		return "acl_model_missing"
	case errors.Is(err, runtime.ErrACLBackendUnavailable), errors.Is(err, runtime.ErrACLUnavailable):
		return "acl_backend_unavailable"
	default:
		return "acl_backend_unavailable"
	}
}

func auditEntryFromTrace(trace runtime.RuntimeTrace, req runtime.QueryRequest) AuditEntry {
	blocked := trace.BlockedByACL + trace.BlockedByResidency
	failClosed := trace.FailureStage != ""
	if failClosed && blocked == 0 {
		blocked = trace.VectorCandidates
	}
	// Summarize the ACL outcome and reason for the audit record. Per-chunk decisions
	// live on the trace; the ledger row captures the query-level decision.
	aclDecision := "allowed"
	reason := "allowed"
	switch {
	case failClosed:
		aclDecision = "fail_closed"
		reason = trace.ErrorCode
	case trace.RerankedCandidates == 0:
		aclDecision = "denied"
		reason = firstBlockedReason(trace.AccessDecisions)
	}
	// When canonical identity is enabled the runtime resolves the verified end-user to a
	// canonical principal and sets req.UserID = "principal:<uuid>" before Engine.Execute.
	// We record that resolution on the immutable audit row without changing the engine's
	// contract: a "principal:" prefix means the query ran against a canonical principal.
	identityResolution := ""
	principalID := ""
	if id := strings.TrimPrefix(trace.UserID, "principal:"); id != trace.UserID {
		identityResolution = "resolved"
		principalID = id
	}
	return AuditEntry{
		TraceID:             trace.TraceID,
		TenantID:            trace.TenantID,
		UserID:              trace.UserID,
		QueryHash:           hashText(req.Question),
		TimestampUTC:        trace.StartedAt.UTC(),
		Region:              trace.Region,
		CandidatesRetrieved: trace.VectorCandidates + trace.KeywordCandidates,
		CandidatesAllowed:   trace.RerankedCandidates,
		CandidatesBlocked:   blocked,
		FailClosed:          failClosed || trace.FailureStage != "",
		FailStage:           trace.FailureStage,
		ErrorCode:           trace.ErrorCode,
		ErrorMessage:        trace.ErrorMessage,
		TotalLatencyMs:      int(trace.LatencyMs),
		CircuitBreakerState: "closed",
		DecisionMode:        trace.DecisionMode,
		ACLDecision:         aclDecision,
		Reason:              reason,
		IdentityResolution:  identityResolution,
		PrincipalID:         principalID,
		// PR #21: agent attribution + per-chunk decisions.
		//   AgentKeyID is the stable api_keys.id of the calling key
		//     (TenantContext.KeyID, set by server.query before Execute
		//     is invoked). Zero when no key context is available.
		//   AgentKeyName is the snapshot of api_keys.name at write time.
		//   AccessDecisions are pulled straight off the trace — the
		//     engine already accumulates them per chunk; this just
		//     carries them onto the audit row for Replay + Leak Report.
		// All three fields are non-chained metadata (see ComputeDigest
		// in trace.go).
		AgentKeyID:      req.AgentKeyID,
		AgentKeyName:    req.AgentKeyName,
		AccessDecisions: trace.AccessDecisions,
	}
}

// firstBlockedReason returns the reason of the first non-allowed access decision,
// used to summarize why a query returned no permitted chunks.
func firstBlockedReason(decisions []runtime.AccessDecision) string {
	for _, decision := range decisions {
		if !decision.Allowed {
			if decision.Reason != "" {
				return decision.Reason
			}
			return "denied"
		}
	}
	return "no_results"
}

func hashText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func circuitMetricState(state string) float64 {
	if state == "open" {
		return 1
	}
	return 0
}

func decisionFromCandidate(candidate runtime.Candidate, allowed bool, reason string) runtime.AccessDecision {
	chunk := candidate.Chunk
	return runtime.AccessDecision{
		ChunkID:       chunk.ChunkID,
		ChunkHash:     chunk.ChunkHash,
		DocumentID:    chunk.DocumentID,
		Allowed:       allowed,
		Reason:        reason,
		Region:        chunk.Region,
		RequiredScope: chunk.RequiredScope,
	}
}

func rerank(candidates []runtime.Candidate, limit int) []runtime.Candidate {
	sort.Slice(candidates, func(i, j int) bool {
		left := candidates[i].Score * candidates[i].Chunk.FreshnessScore
		right := candidates[j].Score * candidates[j].Chunk.FreshnessScore
		return left > right
	})
	if len(candidates) > limit {
		return candidates[:limit]
	}
	return candidates
}

func confidence(candidates []runtime.Candidate) float64 {
	if len(candidates) == 0 {
		return 0
	}
	score := candidates[0].Score * 45
	if score > 0.99 {
		return 0.99
	}
	return score
}

func toCitations(candidates []runtime.Candidate) []runtime.Citation {
	citations := make([]runtime.Citation, 0, len(candidates))
	for _, candidate := range candidates {
		chunk := candidate.Chunk
		citations = append(citations, runtime.Citation{
			DocumentID:     chunk.DocumentID,
			ChunkID:        chunk.ChunkID,
			ChunkHash:      chunk.ChunkHash,
			Page:           chunk.Page,
			Offset:         chunk.Offset,
			Text:           chunk.Text,
			Score:          candidate.Score,
			FreshnessScore: chunk.FreshnessScore,
			Watermark:      chunk.Watermark,
		})
	}
	return citations
}

// traceIDFor prefers the caller-supplied correlation/trace id so the
// audit row and logs line up with the client-visible id; a fresh one is
// generated only when the caller did not provide one.
func traceIDFor(req runtime.QueryRequest) string {
	if id := strings.TrimSpace(req.TraceID); id != "" {
		return id
	}
	return newTraceID()
}

func newTraceID() string {
	var bytes [12]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return time.Now().Format("20060102150405")
	}
	return hex.EncodeToString(bytes[:])
}

func traceDigest(trace runtime.RuntimeTrace) string {
	payload, _ := json.Marshal(trace)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
