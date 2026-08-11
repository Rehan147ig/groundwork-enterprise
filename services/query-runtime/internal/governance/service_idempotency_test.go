package governance

import (
	"context"
	"sync"
	"testing"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// idemSetup registers an active http tool "webhook:send" granted to
// agent-1 and returns the delegation token + run id for dispatching.
func idemSetup(t *testing.T, h *harness) (string, string) {
	t.Helper()
	tool, err := h.svc.RegisterTool(testCtx, testTenant, adminActor, true, runtime.RegisterToolRequest{
		Name: "webhook", Transport: runtime.ToolTransportHTTP, EndpointOrServer: "https://hooks.example.com",
		OwnerPrincipalID: ownerActor, Region: testRegion,
	})
	if err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}
	action, err := h.svc.RegisterToolAction(testCtx, testTenant, tool.ID, adminActor, true,
		runtime.RegisterToolActionRequest{Action: "send", ReadOnly: true})
	if err != nil {
		t.Fatalf("RegisterToolAction: %v", err)
	}
	if _, err := h.svc.TransitionTool(testCtx, testTenant, tool.ID, adminActor, true,
		runtime.TransitionToolRequest{Lifecycle: runtime.ToolLifecycleActive}); err != nil {
		t.Fatalf("TransitionTool: %v", err)
	}
	if _, err := h.svc.GrantToolAccess(testCtx, testTenant, adminActor, true, runtime.GrantToolRequest{
		AgentID: "agent-1", VersionID: "version-1", ToolID: tool.ID, ActionID: action.ID,
	}); err != nil {
		t.Fatalf("GrantToolAccess: %v", err)
	}
	minted := h.mint(t, "mint-idem", []string{"webhook:send"})
	run := h.createRun(t, minted.Token, "run-idem", runtime.RunActionRequest{ToolName: "webhook", Action: "send", ResourceRef: "*"})
	return minted.Token, run.Run.ID
}

func idemRequest(token, runID string, args map[string]any) runtime.EvaluateActionRequest {
	return runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: runID,
		ToolName: "webhook", Action: "send", ResourceRef: "*",
		Arguments: args,
	}
}

// TestDispatchIdempotencyReplayAfterSuccess: a client retry of an
// already-executed logical mutation (same run/tool/action/args, new
// decision id) must be answered from evidence — no quota consumed, no
// connector call, no second invocation row.
func TestDispatchIdempotencyReplayAfterSuccess(t *testing.T) {
	h := newHarness(t)
	token, runID := idemSetup(t, h)
	meter := &quotaMeter{}
	disp := &recordingDispatcher{}
	h.svc.SetUsageMeter(meter)
	h.svc.SetConnectorDispatcher(disp)
	req := idemRequest(token, runID, map[string]any{"id": "acc-1"})

	first, err := h.svc.DispatchAction(testCtx, testTenant, testRegion, req)
	if err != nil {
		t.Fatalf("DispatchAction: %v", err)
	}
	if first.DispatchMode != "dispatched" {
		t.Fatalf("expected dispatched, got %+v", first)
	}
	if disp.calls != 1 || meter.calls != 1 {
		t.Fatalf("expected 1 call and 1 quota record, got %d/%d", disp.calls, meter.calls)
	}

	second, err := h.svc.DispatchAction(testCtx, testTenant, testRegion, req)
	if err != nil {
		t.Fatalf("DispatchAction retry: %v", err)
	}
	if second.DispatchMode != "replayed" {
		t.Fatalf("expected replayed, got %+v", second)
	}
	if !second.Allowed {
		t.Fatal("replay must be allowed")
	}
	if second.Invocation == nil || second.Invocation.Outcome != runtime.InvocationSuccess {
		t.Fatalf("replay must carry the recorded success evidence, got %+v", second.Invocation)
	}
	if disp.calls != 1 {
		t.Fatalf("the connector must never be called twice for one key, got %d calls", disp.calls)
	}
	if meter.calls != 1 {
		t.Fatalf("replay must not consume quota, got %d quota records", meter.calls)
	}
	invs, err := h.store.ListConnectorInvocations(testCtx, testTenant, "conn-webhook", 10)
	if err != nil {
		t.Fatalf("ListConnectorInvocations: %v", err)
	}
	if len(invs) != 1 {
		t.Fatalf("expected exactly one invocation row, got %d", len(invs))
	}
	if invs[0].IdempotencyKey == "" {
		t.Fatal("invocation must carry the semantic idempotency key")
	}
	if invs[0].IdempotencyKey != second.Invocation.IdempotencyKey {
		t.Fatal("replayed evidence must be the recorded row")
	}
}

// TestDispatchIdempotencyDifferentArgsDispatchAgain: distinct argument
// sets are distinct logical mutations and must each reach the connector.
func TestDispatchIdempotencyDifferentArgsDispatchAgain(t *testing.T) {
	h := newHarness(t)
	token, runID := idemSetup(t, h)
	disp := &recordingDispatcher{}
	h.svc.SetConnectorDispatcher(disp)

	if resp, err := h.svc.DispatchAction(testCtx, testTenant, testRegion,
		idemRequest(token, runID, map[string]any{"id": "acc-1"})); err != nil || resp.DispatchMode != "dispatched" {
		t.Fatalf("first dispatch: %+v err=%v", resp, err)
	}
	if resp, err := h.svc.DispatchAction(testCtx, testTenant, testRegion,
		idemRequest(token, runID, map[string]any{"id": "acc-2"})); err != nil || resp.DispatchMode != "dispatched" {
		t.Fatalf("second dispatch (different args): %+v err=%v", resp, err)
	}
	if disp.calls != 2 {
		t.Fatalf("different args must be separate mutations, got %d calls", disp.calls)
	}
}

// scriptedDispatcher returns results in order, proving a failed attempt
// does not consume the idempotency key.
type scriptedDispatcher struct {
	mu      sync.Mutex
	results []runtime.ConnectorDispatchResult
	calls   int
}

func (d *scriptedDispatcher) Dispatch(_ context.Context, _ runtime.ConnectorDispatchRequest) (runtime.ConnectorDispatchResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.results[0]
	if len(d.results) > 1 {
		d.results = d.results[1:]
	}
	d.calls++
	return r, nil
}

// TestDispatchIdempotencyFailureStaysRetryable: a failed attempt is NOT
// a replayable outcome — the retry is a fresh connector call.
func TestDispatchIdempotencyFailureStaysRetryable(t *testing.T) {
	h := newHarness(t)
	token, runID := idemSetup(t, h)
	disp := &scriptedDispatcher{results: []runtime.ConnectorDispatchResult{
		{Outcome: runtime.InvocationFailure, ErrorCode: "upstream_5xx", StatusCode: 502, DurationMS: 90},
		{Outcome: runtime.InvocationSuccess, StatusCode: 200, ResponseBytes: 64, DurationMS: 40},
	}}
	h.svc.SetConnectorDispatcher(disp)
	req := idemRequest(token, runID, map[string]any{"id": "acc-1"})

	first, err := h.svc.DispatchAction(testCtx, testTenant, testRegion, req)
	if err != nil {
		t.Fatalf("DispatchAction: %v", err)
	}
	if first.DispatchMode != "connector_failed" {
		t.Fatalf("expected connector_failed, got %+v", first)
	}
	second, err := h.svc.DispatchAction(testCtx, testTenant, testRegion, req)
	if err != nil {
		t.Fatalf("DispatchAction retry: %v", err)
	}
	if second.DispatchMode != "dispatched" {
		t.Fatalf("retry after failure must re-call the connector, got %+v", second)
	}
	if disp.calls != 2 {
		t.Fatalf("expected 2 connector calls after a failure, got %d", disp.calls)
	}
}

// TestDispatchIdempotencyConcurrentSameKeySingleCall: concurrent
// dispatches with the same semantic key serialize on the in-process
// lock; the connector is called exactly once and every caller is
// answered (first dispatched, the rest replayed).
func TestDispatchIdempotencyConcurrentSameKeySingleCall(t *testing.T) {
	h := newHarness(t)
	token, runID := idemSetup(t, h)
	disp := &recordingDispatcher{}
	h.svc.SetConnectorDispatcher(disp)
	req := idemRequest(token, runID, map[string]any{"id": "acc-1"})

	const n = 8
	var wg sync.WaitGroup
	modes := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := h.svc.DispatchAction(context.Background(), testTenant, testRegion, req)
			if err == nil {
				modes[i] = resp.DispatchMode
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if modes[i] != "dispatched" && modes[i] != "replayed" {
			t.Fatalf("goroutine %d: unexpected mode %q", i, modes[i])
		}
	}
	dispatched := 0
	replayed := 0
	for _, m := range modes {
		if m == "dispatched" {
			dispatched++
		} else {
			replayed++
		}
	}
	if dispatched != 1 {
		t.Fatalf("exactly one caller may dispatch, got %d", dispatched)
	}
	if replayed != n-1 {
		t.Fatalf("the rest must replay, got %d", replayed)
	}
	if disp.calls != 1 {
		t.Fatalf("connector called %d times for one key", disp.calls)
	}
}

// TestMemoryStoreDedupKeyIndex: the latest invocation wins the key
// index and only non-empty keys are queryable.
func TestMemoryStoreDedupKeyIndex(t *testing.T) {
	h := newHarness(t)
	fail := runtime.ConnectorInvocation{
		TenantID: testTenant, ConnectorID: "conn-1", DecisionID: "decision-1",
		Kind: runtime.InvocationKindAgentAction, Outcome: runtime.InvocationFailure,
		ErrorCode: "upstream_5xx", IdempotencyKey: "key-1",
	}
	ok := runtime.ConnectorInvocation{
		TenantID: testTenant, ConnectorID: "conn-1", DecisionID: "decision-2",
		Kind: runtime.InvocationKindAgentAction, Outcome: runtime.InvocationSuccess,
		IdempotencyKey: "key-1",
	}
	if _, err := h.store.AppendConnectorInvocation(testCtx, fail); err != nil {
		t.Fatalf("append failure: %v", err)
	}
	if _, err := h.store.AppendConnectorInvocation(testCtx, ok); err != nil {
		t.Fatalf("append success: %v", err)
	}
	got, found, err := h.store.GetConnectorInvocationByDedupKey(testCtx, testTenant, "key-1")
	if err != nil {
		t.Fatalf("dedup lookup: %v", err)
	}
	if !found || got.DecisionID != "decision-2" {
		t.Fatalf("expected latest invocation decision-2, got found=%v %+v", found, got)
	}
	if _, found, err := h.store.GetConnectorInvocationByDedupKey(testCtx, testTenant, "key-unknown"); err != nil || found {
		t.Fatalf("unknown key must not be found (found=%v err=%v)", found, err)
	}
	if _, found, err := h.store.GetConnectorInvocationByDedupKey(testCtx, testTenant, ""); err != nil || found {
		t.Fatalf("empty key must query nothing (found=%v err=%v)", found, err)
	}
	// Duplicate success under one key is impossible (decision ids are
	// unique per row): append another invocation with the same key but
	// a different decision id, latest must win.
	newer := ok
	newer.DecisionID = "decision-3"
	newer.OccurredAt = time.Now().UTC()
	if _, err := h.store.AppendConnectorInvocation(testCtx, newer); err != nil {
		t.Fatalf("append newer: %v", err)
	}
	got, found, err = h.store.GetConnectorInvocationByDedupKey(testCtx, testTenant, "key-1")
	if err != nil || !found || got.DecisionID != "decision-3" {
		t.Fatalf("expected decision-3 as latest, got found=%v %+v err=%v", found, got, err)
	}
}
