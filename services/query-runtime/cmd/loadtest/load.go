package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"time"
)

type outcome int

const (
	outcomeAllowed outcome = iota
	outcomeDenied
	outcomeThrottled
	outcomeError
)

type pathStats struct {
	mu        sync.Mutex
	total     int64
	allowed   int64
	denied    int64
	throttled int64
	errs      int64
	latencies []time.Duration
}

func (s *pathStats) record(o outcome, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	switch o {
	case outcomeAllowed:
		s.allowed++
	case outcomeDenied:
		s.denied++
	case outcomeThrottled:
		s.throttled++
	default:
		s.errs++
	}
	s.latencies = append(s.latencies, d)
}

func (s *pathStats) snapshot() (total, allowed, denied, throttled, errs int64, lat []time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total, s.allowed, s.denied, s.throttled, s.errs, s.latencies
}

// loadTest is the -mode=load entrypoint. It verifies the governed
// prerequisites, spins up the internal connector stub for the connector
// path, drives every enabled path concurrently, and emits the report.
func loadTest(c config) error {
	if c.apiKey == "" || c.jwtSecret == "" {
		return errors.New("-apikey and -jwt-secret are required in load mode")
	}
	paths, err := parsePaths(c.paths)
	if err != nil {
		return err
	}
	httpc := &http.Client{Timeout: 30 * time.Second}
	agentID, versionID := "", ""
	if paths["delegation"] || paths["dispatch"] || paths["connector"] {
		if agentID, versionID, err = verifyGovernedPrereqs(httpc, c); err != nil {
			return fmt.Errorf("governed prerequisites: %w (run -mode=setup first)", err)
		}
	}
	connectorName := ""
	var stub *httptest.Server
	if paths["connector"] {
		stub = newConnectorStub()
		defer stub.Close()
		if connectorName, err = setupLoadConnector(httpc, c, agentID, versionID, stub.URL); err != nil {
			return fmt.Errorf("connector path setup: %w", err)
		}
	}

	stats := make(map[string]*pathStats, len(paths))
	for p := range paths {
		stats[p] = &pathStats{}
	}
	order := []string{"query", "delegation", "dispatch", "connector", "evidence"}
	var enabled []string
	for _, p := range order {
		if paths[p] {
			enabled = append(enabled, p)
		}
	}

	started := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	stopAt := time.After(c.duration)
	workers := c.concurrency
	if workers < len(enabled) {
		workers = len(enabled) // at least one worker per enabled path
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		name := enabled[w%len(enabled)]
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			runPathLoop(ctx, c, httpc, name, agentID, connectorName, stats[name])
		}(name)
	}
	<-stopAt
	cancel()
	wg.Wait()
	elapsed := time.Since(started)

	return summarizeAndReport(c, started, elapsed, stats)
}

func parsePaths(s string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		switch p {
		case "query", "delegation", "dispatch", "connector", "evidence":
			out[p] = true
		case "":
		default:
			return nil, fmt.Errorf("unknown load path %q", p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no load paths enabled")
	}
	return out, nil
}

func runPathLoop(ctx context.Context, c config, httpc *http.Client, name, agentID, connectorName string, s *pathStats) {
	var iter int64
	for ctx.Err() == nil {
		var oc outcome
		var d time.Duration
		switch name {
		case "query":
			oc, d = runQuery(httpc, c)
		case "delegation":
			oc, d = runDelegation(httpc, c, agentID, iter)
		case "dispatch":
			oc, d = runDispatch(httpc, c, agentID, c.tool, "search", iter)
		case "connector":
			oc, d = runDispatch(httpc, c, agentID, connectorName, "call", iter)
		case "evidence":
			oc, d = runEvidence(httpc, c)
		}
		iter++
		s.record(oc, d)
	}
}

// runQuery drives POST /v1/query as a random user. A 200 with citations
// is "allowed"; a 200 with no citations is the fail-closed result.
func runQuery(httpc *http.Client, c config) (outcome, time.Duration) {
	uidx := cryptoIndex(c.users)
	tok := mintJWT(c.jwtSecret, userID(uidx))
	start := time.Now()
	status, citations, err := postQuery(httpc, c, tok)
	lat := time.Since(start)
	if err != nil {
		return outcomeError, lat
	}
	switch status {
	case http.StatusTooManyRequests:
		return outcomeThrottled, lat
	case http.StatusOK:
		if citations > 0 {
			return outcomeAllowed, lat
		}
		return outcomeDenied, lat
	default:
		return outcomeError, lat
	}
}

type queryResponse struct {
	Citations []struct {
		DocumentID string `json:"document_id"`
	} `json:"citations"`
}

func postQuery(httpc *http.Client, c config, token string) (int, int, error) {
	j := &jsonClient{httpc: httpc, key: c.apiKey}
	var parsed queryResponse
	status, err := j.do(http.MethodPost, c.runtime+"/v1/query",
		map[string]any{"question": c.question}, &parsed, token, "")
	return status, len(parsed.Citations), err
}

// runDelegation drives the governed path: mint a delegation for the
// subject, open a run, then evaluate one action. The final evaluate
// outcome classifies the path; the measured latency is the whole
// pipeline.
func runDelegation(httpc *http.Client, c config, agentID string, iter int64) (outcome, time.Duration) {
	j := &jsonClient{httpc: httpc, key: c.apiKey}
	assertion := mintJWT(c.jwtSecret, c.owner)
	start := time.Now()
	lat := func() time.Duration { return time.Since(start) }

	var mintResp struct {
		Token string `json:"token"`
	}
	status, err := j.do(http.MethodPost, c.runtime+"/v1/governance/delegations", map[string]any{
		"agent_id": agentID, "subject_principal_id": c.subject, "purpose": "load-testing",
		"permitted_actions": []string{c.tool + ":search"},
	}, &mintResp, assertion, fmt.Sprintf("lt-mint-%d", iter))
	if err != nil || status >= 400 {
		return early(status, err, lat())
	}
	var runResp struct {
		Run struct {
			ID string `json:"id"`
		} `json:"run"`
	}
	status, err = j.do(http.MethodPost, c.runtime+"/v1/governance/runs", map[string]any{
		"delegation_token": mintResp.Token,
		"actions":          []map[string]any{{"tool_name": c.tool, "action": "search", "resource_ref": "*"}},
	}, &runResp, assertion, fmt.Sprintf("lt-run-%d", iter))
	if err != nil || status >= 400 {
		return early(status, err, lat())
	}
	var evalResp struct {
		Allowed bool `json:"allowed"`
	}
	status, err = j.do(http.MethodPost, c.runtime+"/v1/governance/runs/"+runResp.Run.ID+"/evaluate", map[string]any{
		"delegation_token": mintResp.Token, "tool_name": c.tool, "action": "search", "resource_ref": "*",
	}, &evalResp, assertion, fmt.Sprintf("lt-eval-%d", iter))
	if err != nil {
		return outcomeError, lat()
	}
	switch status {
	case http.StatusTooManyRequests:
		return outcomeThrottled, lat()
	case http.StatusOK:
		if evalResp.Allowed {
			return outcomeAllowed, lat()
		}
		return outcomeDenied, lat()
	default:
		return outcomeError, lat()
	}
}

// runDispatch drives mint -> run -> dispatch against the governed tool
// (builtin) or the load-created connector (through the gateway). A
// dispatch_mode of "dispatched" is "allowed"; a denied dispatch is the
// fail-closed result.
func runDispatch(httpc *http.Client, c config, agentID, toolName, action string, iter int64) (outcome, time.Duration) {
	j := &jsonClient{httpc: httpc, key: c.apiKey}
	assertion := mintJWT(c.jwtSecret, c.owner)
	start := time.Now()
	lat := func() time.Duration { return time.Since(start) }

	var mintResp struct {
		Token string `json:"token"`
	}
	status, err := j.do(http.MethodPost, c.runtime+"/v1/governance/delegations", map[string]any{
		"agent_id": agentID, "subject_principal_id": c.subject, "purpose": "load-testing",
		"permitted_actions": []string{toolName + ":" + action},
	}, &mintResp, assertion, fmt.Sprintf("lt-mint-%d-%s", iter, toolName))
	if err != nil || status >= 400 {
		return early(status, err, lat())
	}
	var runResp struct {
		Run struct {
			ID string `json:"id"`
		} `json:"run"`
	}
	status, err = j.do(http.MethodPost, c.runtime+"/v1/governance/runs", map[string]any{
		"delegation_token": mintResp.Token,
		"actions":          []map[string]any{{"tool_name": toolName, "action": action, "resource_ref": "*"}},
	}, &runResp, assertion, fmt.Sprintf("lt-run-%d-%s", iter, toolName))
	if err != nil || status >= 400 {
		return early(status, err, lat())
	}
	var dispatchResp struct {
		Allowed      bool   `json:"allowed"`
		DispatchMode string `json:"dispatch_mode"`
	}
	status, err = j.do(http.MethodPost, c.runtime+"/v1/governance/runs/"+runResp.Run.ID+"/dispatch", map[string]any{
		"delegation_token": mintResp.Token, "tool_name": toolName, "action": action, "resource_ref": "*",
	}, &dispatchResp, assertion, fmt.Sprintf("lt-dispatch-%d-%s", iter, toolName))
	if err != nil {
		return outcomeError, lat()
	}
	switch status {
	case http.StatusTooManyRequests:
		return outcomeThrottled, lat()
	case http.StatusOK:
		if dispatchResp.Allowed {
			return outcomeAllowed, lat()
		}
		return outcomeDenied, lat()
	default:
		return outcomeError, lat()
	}
}

// runEvidence drives GET /v1/governance/evidence reads.
func runEvidence(httpc *http.Client, c config) (outcome, time.Duration) {
	j := &jsonClient{httpc: httpc, key: c.apiKey}
	assertion := mintJWT(c.jwtSecret, c.owner)
	start := time.Now()
	status, err := j.do(http.MethodGet, c.runtime+"/v1/governance/evidence?limit=100", nil,
		&struct {
			Count int `json:"count"`
		}{}, assertion, "")
	lat := time.Since(start)
	if err != nil {
		return outcomeError, lat
	}
	switch status {
	case http.StatusTooManyRequests:
		return outcomeThrottled, lat
	case http.StatusOK:
		return outcomeAllowed, lat
	default:
		return outcomeError, lat
	}
}

func early(status int, err error, lat time.Duration) (outcome, time.Duration) {
	if err != nil {
		return outcomeError, lat
	}
	if status == http.StatusTooManyRequests {
		return outcomeThrottled, lat
	}
	return outcomeError, lat
}

// verifyGovernedPrereqs checks that the setup agent exists with an
// active version and the governed builtin tool exists — the minimum
// the delegation/dispatch paths need.
func verifyGovernedPrereqs(httpc *http.Client, c config) (agentID, versionID string, err error) {
	j := &jsonClient{httpc: httpc, key: c.apiKey}
	var list struct {
		Agents []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"agents"`
	}
	if _, err = j.do(http.MethodGet, c.runtime+"/v1/agents", nil, &list, "", ""); err != nil {
		return "", "", fmt.Errorf("list agents: %w", err)
	}
	for _, a := range list.Agents {
		if a.Name == c.agent {
			agentID = a.ID
			break
		}
	}
	if agentID == "" {
		return "", "", fmt.Errorf("agent %q not found", c.agent)
	}
	if versionID, err = activeVersion(j, c, agentID); err != nil {
		return "", "", err
	}
	if versionID == "" {
		return "", "", fmt.Errorf("agent %q has no active version", c.agent)
	}
	return agentID, versionID, nil
}

// setupLoadConnector registers a nonce connector pointed at the internal
// stub and wires the grant + use relationship the connector path needs.
func setupLoadConnector(httpc *http.Client, c config, agentID, versionID, stubURL string) (string, error) {
	j := &jsonClient{httpc: httpc, key: c.apiKey}
	assertion := mintJWT(c.jwtSecret, c.owner)
	name := fmt.Sprintf("%s_%d_%d", c.connector, os.Getpid(), time.Now().UnixNano()%1_000_000)
	var reg struct {
		Detail struct {
			Connector struct {
				ID string `json:"id"`
			} `json:"connector"`
		} `json:"detail"`
	}
	status, err := j.do(http.MethodPost, c.runtime+"/v1/governance/connectors", map[string]any{
		"name": name, "transport": "http",
		"config":             map[string]any{"url": stubURL, "headers": map[string]string{}},
		"owner_principal_id": c.owner, "region": c.region,
	}, &reg, assertion, "lt-conn-"+name)
	if err != nil || status >= 400 {
		return "", fmt.Errorf("register connector: %w", err)
	}
	connID := reg.Detail.Connector.ID
	if connID == "" {
		return "", errors.New("connector registration returned no connector id")
	}
	if status, err := j.do(http.MethodPost, c.runtime+"/v1/governance/connectors/"+connID+"/activate",
		map[string]any{"reason": "load testing"}, nil, assertion, "lt-conn-act-"+name); err != nil && status != http.StatusConflict {
		return "", fmt.Errorf("activate connector: %w", err)
	}
	toolID, err := connectorToolID(j, c.runtime, name, assertion)
	if err != nil {
		return "", err
	}
	actionID, err := ensureToolAction(j, c.runtime, toolID, "call", assertion)
	if err != nil {
		return "", err
	}
	if err := ensureGrant(j, c, agentID, versionID, toolID, actionID); err != nil {
		return "", err
	}
	if c.relw != nil {
		if err := ensureUseRelationship(c, toolID); err != nil {
			logf("warning: use relationship not written (connector path will fail closed): %v", err)
		}
	}
	return name, nil
}

func connectorToolID(j *jsonClient, runtime, name, assertion string) (string, error) {
	var list struct {
		Tools []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"tools"`
	}
	if _, err := j.do(http.MethodGet, runtime+"/v1/governance/tools", nil, &list, assertion, ""); err != nil {
		return "", fmt.Errorf("list tools: %w", err)
	}
	for _, t := range list.Tools {
		if t.Name == name {
			return t.ID, nil
		}
	}
	return "", fmt.Errorf("connector tool %q not found", name)
}

// newConnectorStub is the internal connector target for the connector
// path: it answers every invocation immediately.
func newConnectorStub() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":"connector-stub-response"}`))
	}))
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// cryptoIndex returns a uniform index in [0, n) drawn from crypto/rand
// (math/rand would make load-test user selection predictable). Degrades
// to a time-seeded value on an entropy read failure.
func cryptoIndex(n int) int {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return time.Now().Nanosecond() % n
	}
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(n))
}
