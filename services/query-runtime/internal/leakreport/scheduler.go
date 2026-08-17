package leakreport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"groundwork/query-runtime/internal/aclsync"
	"groundwork/query-runtime/internal/runtime"
)

// ---------------------------------------------------------------------------
// Cron scheduling
// ---------------------------------------------------------------------------

// Schedule is a parsed LEAK_REPORT_CRON value. Two forms are accepted:
//
//	@every <duration>   fixed interval (e.g. "@every 6h")
//	<min> <hour> <dom> <mon> <dow>   standard 5-field cron (e.g. "0 */6 * * *")
//
// Fields support *, fixed values, */N steps and comma lists.
type Schedule struct {
	interval time.Duration
	fields   *cronFields
}

type cronFields struct {
	min   fieldSet // 0-59
	hour  fieldSet // 0-23
	dom   fieldSet // 1-31
	mon   fieldSet // 1-12
	dow   fieldSet // 0-6 (Sunday=0)
	names []string
}

type fieldSet struct {
	all bool
	set map[int]struct{}
}

func (f fieldSet) contains(v int) bool {
	if f.all {
		return true
	}
	_, ok := f.set[v]
	return ok
}

// ParseSchedule parses a LEAK_REPORT_CRON expression.
func ParseSchedule(expr string) (*Schedule, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, errors.New("leakreport: empty cron expression")
	}
	if strings.HasPrefix(expr, "@every ") {
		d, err := time.ParseDuration(strings.TrimSpace(strings.TrimPrefix(expr, "@every ")))
		if err != nil {
			return nil, fmt.Errorf("leakreport: @every: %w", err)
		}
		if d < time.Minute {
			return nil, errors.New("leakreport: @every interval must be at least 1 minute")
		}
		return &Schedule{interval: d}, nil
	}

	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return nil, fmt.Errorf("leakreport: cron %q must be 5 fields or @every <duration>", expr)
	}
	f := &cronFields{names: parts}
	var err error
	if f.min, err = parseField(parts[0], 0, 59); err != nil {
		return nil, fmt.Errorf("leakreport: minute field: %w", err)
	}
	if f.hour, err = parseField(parts[1], 0, 23); err != nil {
		return nil, fmt.Errorf("leakreport: hour field: %w", err)
	}
	if f.dom, err = parseField(parts[2], 1, 31); err != nil {
		return nil, fmt.Errorf("leakreport: day-of-month field: %w", err)
	}
	if f.mon, err = parseField(parts[3], 1, 12); err != nil {
		return nil, fmt.Errorf("leakreport: month field: %w", err)
	}
	if f.dow, err = parseField(parts[4], 0, 6); err != nil {
		return nil, fmt.Errorf("leakreport: day-of-week field: %w", err)
	}
	return &Schedule{fields: f}, nil
}

// parseField parses a single cron field into a value set. Supports *,
// * /N (step), N, N-M and comma lists.
func parseField(raw string, min, max int) (fieldSet, error) {
	var out fieldSet
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return out, fmt.Errorf("empty item in %q", raw)
		}
		switch {
		case item == "*":
			out.all = true
		case strings.HasPrefix(item, "*/"):
			step, err := strconv.Atoi(strings.TrimPrefix(item, "*/"))
			if err != nil || step <= 0 {
				return out, fmt.Errorf("bad step %q", item)
			}
			if out.set == nil {
				out.set = map[int]struct{}{}
			}
			for v := min; v <= max; v += step {
				out.set[v] = struct{}{}
			}
		case strings.Contains(item, "-"):
			bounds := strings.SplitN(item, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || lo > hi {
				return out, fmt.Errorf("bad range %q", item)
			}
			for v := lo; v <= hi; v++ {
				if v < min || v > max {
					return out, fmt.Errorf("value %d out of range %d-%d in %q", v, min, max, item)
				}
				if out.set == nil {
					out.set = map[int]struct{}{}
				}
				out.set[v] = struct{}{}
			}
		default:
			v, err := strconv.Atoi(item)
			if err != nil || v < min || v > max {
				return out, fmt.Errorf("bad value %q (range %d-%d)", item, min, max)
			}
			if out.set == nil {
				out.set = map[int]struct{}{}
			}
			out.set[v] = struct{}{}
		}
	}
	return out, nil
}

// Next returns the next run time strictly after t.
func (s *Schedule) Next(t time.Time) time.Time {
	if s.interval > 0 {
		return t.Add(s.interval)
	}
	f := s.fields
	base := t.UTC().Truncate(time.Minute).Add(time.Minute)
	// Brute-force minute scan from the next minute; bounded so a
	// pathological expression (e.g. Feb-30) cannot loop forever.
	for i := 0; i < 2*366*24*60; i++ {
		cand := base.Add(time.Duration(i) * time.Minute)
		if f.min.contains(cand.Minute()) &&
			f.hour.contains(cand.Hour()) &&
			f.dom.contains(cand.Day()) &&
			f.mon.contains(int(cand.Month())) &&
			f.dow.contains(int(cand.Weekday())) {
			return cand
		}
	}
	return t
}

// String renders the schedule for logs.
func (s *Schedule) String() string {
	if s.interval > 0 {
		return "@every " + trimDuration(s.interval)
	}
	return strings.Join(s.fields.names, " ")
}

// trimDuration renders 6h0m0s as "6h" and 6h30m0s as "6h30m".
func trimDuration(d time.Duration) string {
	out := d.String()
	for _, suffix := range []string{"0m0s", "0s"} {
		if strings.HasSuffix(out, suffix) {
			out = strings.TrimSuffix(out, suffix)
			break
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Snapshot persistence (leak_report_history)
// ---------------------------------------------------------------------------

const historyLimitMax = 200

// ErrNoSnapshot is returned when a tenant has no recorded snapshot.
var ErrNoSnapshot = errors.New("leakreport: no snapshot")

// Snapshot is one scheduled run of the exposure analysis, persisted for
// Drift diffing. ID is the run id (0 before first Save).
type Snapshot struct {
	ID            int64
	TenantID      string
	RanAt         time.Time
	DocumentCount int
	GroupCount    int
	Findings      []Finding
}

// HistoryStore persists Snapshot runs.
type HistoryStore interface {
	// Save persists snap; returns the assigned run id.
	Save(ctx context.Context, snap Snapshot) (int64, error)
	// Get returns one run by id, or ErrNoSnapshot.
	Get(ctx context.Context, tenantID string, id int64) (Snapshot, error)
	// Latest returns the most recent run, or ErrNoSnapshot.
	Latest(ctx context.Context, tenantID string) (Snapshot, error)
	// List returns up to limit runs newest-first (limit <= 0: 50).
	List(ctx context.Context, tenantID string, limit int) ([]Snapshot, error)
}

// MemoryHistoryStore is the offline/demo store.
type MemoryHistoryStore struct {
	mu     chan struct{} // 1-buffered mutex
	nextID int64
	byKey  map[string]map[int64]Snapshot // tenantID -> id -> snapshot
	order  map[string][]int64            // tenantID -> ids newest-first
}

// NewMemoryHistoryStore builds an empty in-memory history store.
func NewMemoryHistoryStore() *MemoryHistoryStore {
	return &MemoryHistoryStore{
		mu:    make(chan struct{}, 1),
		byKey: map[string]map[int64]Snapshot{},
		order: map[string][]int64{},
	}
}

func (m *MemoryHistoryStore) lock()   { m.mu <- struct{}{} }
func (m *MemoryHistoryStore) unlock() { <-m.mu }

func tenantSnapshotsKey(tenantID string) string { return tenantID }

func (m *MemoryHistoryStore) Save(ctx context.Context, snap Snapshot) (int64, error) {
	m.lock()
	defer m.unlock()
	m.nextID++
	id := m.nextID
	snap.ID = id
	if snap.RanAt.IsZero() {
		snap.RanAt = time.Now()
	}
	if m.byKey[tenantSnapshotsKey(snap.TenantID)] == nil {
		m.byKey[tenantSnapshotsKey(snap.TenantID)] = map[int64]Snapshot{}
	}
	m.byKey[tenantSnapshotsKey(snap.TenantID)][id] = snap
	m.order[tenantSnapshotsKey(snap.TenantID)] = append([]int64{id}, m.order[tenantSnapshotsKey(snap.TenantID)]...)
	return id, nil
}

func (m *MemoryHistoryStore) Get(ctx context.Context, tenantID string, id int64) (Snapshot, error) {
	m.lock()
	defer m.unlock()
	s, ok := m.byKey[tenantSnapshotsKey(tenantID)][id]
	if !ok {
		return Snapshot{}, ErrNoSnapshot
	}
	return s, nil
}

func (m *MemoryHistoryStore) Latest(ctx context.Context, tenantID string) (Snapshot, error) {
	m.lock()
	defer m.unlock()
	ok := m.byKey[tenantSnapshotsKey(tenantID)]
	for _, id := range m.order[tenantSnapshotsKey(tenantID)] {
		if s, found := ok[id]; found {
			return s, nil
		}
	}
	return Snapshot{}, ErrNoSnapshot
}

func (m *MemoryHistoryStore) List(ctx context.Context, tenantID string, limit int) ([]Snapshot, error) {
	if limit <= 0 {
		limit = 50
	}
	m.lock()
	defer m.unlock()
	ok := m.byKey[tenantSnapshotsKey(tenantID)]
	if ok == nil {
		return []Snapshot{}, nil
	}
	out := make([]Snapshot, 0, limit)
	for _, id := range m.order[tenantSnapshotsKey(tenantID)] {
		if s, found := ok[id]; found {
			out = append(out, s)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

var _ HistoryStore = (*MemoryHistoryStore)(nil)

// PostgresHistoryStore is the production store. The table is created by
// migration 031 and defensively bootstrapped here (CREATE TABLE IF NOT
// EXISTS), matching the api_keys pattern in runtime/auth.go.
type PostgresHistoryStore struct {
	db *sql.DB
}

// NewPostgresHistoryStore returns the Postgres-backed history store.
func NewPostgresHistoryStore(db *sql.DB) *PostgresHistoryStore {
	return &PostgresHistoryStore{db: db}
}

// Bootstrap ensures the leak_report_history table and its index exist.
func (p *PostgresHistoryStore) Bootstrap(ctx context.Context) error {
	if _, err := p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS leak_report_history (
			id BIGSERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			ran_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			document_count INTEGER NOT NULL DEFAULT 0,
			group_count INTEGER NOT NULL DEFAULT 0,
			findings_json TEXT NOT NULL DEFAULT '[]',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return err
	}
	_, err := p.db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_leak_report_history_tenant_time
		ON leak_report_history (tenant_id, ran_at DESC)
	`)
	return err
}

func findJSON(findings []Finding) (string, error) {
	if len(findings) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(findings)
	if err != nil {
		return "", fmt.Errorf("findings json: %w", err)
	}
	return string(b), nil
}

func (p *PostgresHistoryStore) Save(ctx context.Context, snap Snapshot) (int64, error) {
	raw, err := findJSON(snap.Findings)
	if err != nil {
		return 0, err
	}
	if snap.RanAt.IsZero() {
		snap.RanAt = time.Now()
	}
	var id int64
	err = p.db.QueryRowContext(ctx, `
		INSERT INTO leak_report_history (tenant_id, ran_at, document_count, group_count, findings_json)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, snap.TenantID, snap.RanAt, snap.DocumentCount, snap.GroupCount, raw).Scan(&id)
	return id, err
}

func scanSnapshot(row interface{ Scan(...any) error }) (Snapshot, error) {
	var s Snapshot
	var raw string
	err := row.Scan(&s.ID, &s.TenantID, &s.RanAt, &s.DocumentCount, &s.GroupCount, &raw)
	if err != nil {
		return Snapshot{}, err
	}
	var findings []Finding
	if err := json.Unmarshal([]byte(raw), &findings); err != nil {
		return Snapshot{}, fmt.Errorf("findings json: %w", err)
	}
	s.Findings = findings
	return s, nil
}

const snapshotColumns = `id, tenant_id, ran_at, document_count, group_count, findings_json`

func (p *PostgresHistoryStore) Get(ctx context.Context, tenantID string, id int64) (Snapshot, error) {
	s, err := scanSnapshot(p.db.QueryRowContext(ctx, `
		SELECT `+snapshotColumns+` FROM leak_report_history
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Snapshot{}, ErrNoSnapshot
		}
		return Snapshot{}, err
	}
	return s, nil
}

func (p *PostgresHistoryStore) Latest(ctx context.Context, tenantID string) (Snapshot, error) {
	s, err := scanSnapshot(p.db.QueryRowContext(ctx, `
		SELECT `+snapshotColumns+` FROM leak_report_history
		WHERE tenant_id = $1
		ORDER BY ran_at DESC, id DESC LIMIT 1
	`, tenantID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Snapshot{}, ErrNoSnapshot
		}
		return Snapshot{}, err
	}
	return s, nil
}

func (p *PostgresHistoryStore) List(ctx context.Context, tenantID string, limit int) ([]Snapshot, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > historyLimitMax {
		limit = historyLimitMax
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+snapshotColumns+` FROM leak_report_history
		WHERE tenant_id = $1
		ORDER BY ran_at DESC, id DESC LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Snapshot, 0)
	for rows.Next() {
		s, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

var _ HistoryStore = (*PostgresHistoryStore)(nil)

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

// SnapshotProvider yields the permission snapshot a scheduled run
// analyzes. It is connector-agnostic (see Package docs).
type SnapshotProvider interface {
	Snapshot(ctx context.Context, tenantID string) (aclsync.PermissionSet, error)
}

// SnapshotFunc adapts a func to SnapshotProvider.
type SnapshotFunc func(ctx context.Context, tenantID string) (aclsync.PermissionSet, error)

func (f SnapshotFunc) Snapshot(ctx context.Context, tenantID string) (aclsync.PermissionSet, error) {
	return f(ctx, tenantID)
}

// RunResult summarizes one scheduled cycle.
type RunResult struct {
	TenantID string
	RunID    int64
	RanAt    time.Time
	Err      error

	Findings int
	New      int
	Resolved int
}

// Scheduler runs the exposure scan on the LEAK_REPORT_CRON cadence,
// persists each Report as a Snapshot, and reports the drift against the
// previous run. Per-tenant failures are reported on the RunResult slice
// as Errors; other tenants still get scanned.
type Scheduler struct {
	schedule *Schedule
	store    HistoryStore
	provider SnapshotProvider
	tenants  []string
	owners   map[string]string
}

// NewScheduler builds a Scheduler from a cron expression. owners feeds
// Analyze (nil = no ownership-based findings).
func NewScheduler(cron string, store HistoryStore, provider SnapshotProvider, tenants []string, owners map[string]string) (*Scheduler, error) {
	sched, err := ParseSchedule(cron)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("leakreport: empty history store")
	}
	if provider == nil {
		return nil, errors.New("leakreport: empty snapshot provider")
	}
	out := make([]string, 0, len(tenants))
	seen := map[string]struct{}{}
	for _, t := range tenants {
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, errors.New("leakreport: scheduler has no tenants")
	}
	return &Scheduler{schedule: sched, store: store, provider: provider, tenants: out, owners: owners}, nil
}

// Schedule exposes the parsed cadence (for logs / tests).
func (s *Scheduler) Schedule() *Schedule { return s.schedule }

// Next returns the next run time after t.
func (s *Scheduler) Next(t time.Time) time.Time { return s.schedule.Next(t) }

// RunOnce runs one scan cycle for every configured tenant and returns
// per-tenant results. A tenant whose snapshot or persistence fails is
// reported in Results with its Err set.
func (s *Scheduler) RunOnce(ctx context.Context) []RunResult {
	results := make([]RunResult, 0, len(s.tenants))
	for _, tenantID := range s.tenants {
		res := RunResult{TenantID: tenantID, RanAt: time.Now().UTC()}

		ps, err := s.provider.Snapshot(ctx, tenantID)
		if err != nil {
			res.Err = fmt.Errorf("snapshot %s: %w", tenantID, err)
			results = append(results, res)
			continue
		}
		report := Analyze(ps, s.owners)

		previous, prevErr := s.store.Latest(ctx, tenantID)
		if prevErr != nil && !errors.Is(prevErr, ErrNoSnapshot) {
			res.Err = fmt.Errorf("latest %s: %w", tenantID, prevErr)
			results = append(results, res)
			continue
		}
		drift := DriftReport{}
		if prevErr == nil {
			drift = Diff(previous.ToReport(), report)
		}

		id, err := s.store.Save(ctx, Snapshot{
			TenantID:      tenantID,
			RanAt:         res.RanAt,
			DocumentCount: report.DocumentCount,
			GroupCount:    report.GroupCount,
			Findings:      report.Findings,
		})
		if err != nil {
			res.Err = fmt.Errorf("save %s: %w", tenantID, err)
			results = append(results, res)
			continue
		}

		res.RunID = id
		res.Findings = len(report.Findings)
		res.New = len(drift.NewFindings)
		res.Resolved = len(drift.ResolvedFindings)
		results = append(results, res)
	}
	return results
}

// ToReport projects a Snapshot back to the Report shape used by Diff.
func (s Snapshot) ToReport() Report {
	return Report{
		TenantID:      s.TenantID,
		DocumentCount: s.DocumentCount,
		GroupCount:    s.GroupCount,
		Findings:      s.Findings,
	}
}

// Run drives the scheduler until ctx is cancelled. Every cycle runs
// with a bounded budget; onError receives non-tenant scan failures.
func (s *Scheduler) Run(ctx context.Context, onError func(error)) {
	if s.schedule.interval > 0 {
		// Interval cadence: run immediately once, then at each
		// multiple thereafter.
		s.runCycle(ctx, onError)
	}
	for {
		next := s.Next(time.Now())
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		timer.Stop()
		s.runCycle(ctx, onError)
	}
}

func (s *Scheduler) runCycle(ctx context.Context, onError func(error)) {
	cycleCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	results := s.RunOnce(cycleCtx)
	for _, res := range results {
		if res.Err != nil {
			if onError != nil {
				onError(res.Err)
			}
			continue
		}
		logLeakCycle(res)
	}
}

// ---------------------------------------------------------------------------
// History read service for the V1 API
// ---------------------------------------------------------------------------

// Humanize turns "cross_department_access" into "Cross department
// access" (mirrors the live leak-report endpoint's title shape).
func Humanize(kind string) string {
	words := strings.Split(kind, "_")
	if len(words) == 0 {
		return kind
	}
	words[0] = strings.ToUpper(words[0][:1]) + words[0][1:]
	return strings.Join(words, " ")
}

func toLeakFindings(findings []Finding) []runtime.LeakFinding {
	out := make([]runtime.LeakFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, runtime.LeakFinding{
			Kind:     string(f.Kind),
			Severity: string(f.Severity),
			Title:    Humanize(string(f.Kind)),
			Detail:   f.Detail,
		})
	}
	return out
}

// HistoryService implements runtime.LeakHistoryService against a
// HistoryStore.
type HistoryService struct {
	store HistoryStore
}

// NewHistoryService builds the read-side history/diff service.
func NewHistoryService(store HistoryStore) *HistoryService {
	return &HistoryService{store: store}
}

// List returns up to limit entries (newest first).
func (s *HistoryService) List(ctx context.Context, tenantID string, limit int) ([]runtime.LeakHistoryEntry, error) {
	snaps, err := s.store.List(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]runtime.LeakHistoryEntry, 0, len(snaps))
	for _, snap := range snaps {
		out = append(out, runtime.LeakHistoryEntry{
			ID:            snap.ID,
			TenantID:      snap.TenantID,
			RanAt:         snap.RanAt,
			DocumentCount: snap.DocumentCount,
			GroupCount:    snap.GroupCount,
			Findings:      toLeakFindings(snap.Findings),
		})
	}
	return out, nil
}

// Diff returns the drift between two stored runs. Zero fromID/toID
// selects the two most recent runs; with only one run it returns
// runtime.ErrLeakHistoryInsufficient.
func (s *HistoryService) Diff(ctx context.Context, tenantID string, fromID, toID int64) (runtime.LeakDriftResult, error) {
	var prev, curr Snapshot
	var err error
	if fromID == 0 && toID == 0 {
		snaps, err := s.store.List(ctx, tenantID, 2)
		if err != nil {
			return runtime.LeakDriftResult{}, err
		}
		if len(snaps) < 2 {
			return runtime.LeakDriftResult{}, runtime.ErrLeakHistoryInsufficient
		}
		curr, prev = snaps[0], snaps[1]
	} else {
		prev, err = s.store.Get(ctx, tenantID, fromID)
		if err != nil {
			return runtime.LeakDriftResult{}, err
		}
		curr, err = s.store.Get(ctx, tenantID, toID)
		if err != nil {
			return runtime.LeakDriftResult{}, err
		}
	}
	drift := Diff(prev.ToReport(), curr.ToReport())
	return runtime.LeakDriftResult{
		TenantID:         tenantID,
		PreviousID:       prev.ID,
		CurrentID:        curr.ID,
		PreviousRanAt:    prev.RanAt,
		CurrentRanAt:     curr.RanAt,
		NewFindings:      toLeakFindings(drift.NewFindings),
		ResolvedFindings: toLeakFindings(drift.ResolvedFindings),
	}, nil
}

func logLeakCycle(res RunResult) {
	log.Printf("leak-report scheduler: tenant=%s run=%d findings=%d new=%d resolved=%d",
		res.TenantID, res.RunID, res.Findings, res.New, res.Resolved)
}

var _ runtime.LeakHistoryService = (*HistoryService)(nil)
