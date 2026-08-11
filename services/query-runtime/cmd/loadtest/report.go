package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// report is the repeatable JSON artifact of a load run. Every field is
// stable so runs can be diffed across builds (see
// docs/load-testing-and-canary.md).
type report struct {
	SchemaVersion int                   `json:"schema_version"`
	GeneratedAt   time.Time             `json:"generated_at"`
	DurationMS    int64                 `json:"duration_ms"`
	Concurrency   int                   `json:"concurrency"`
	Runtime       string                `json:"runtime"`
	Tenant        string                `json:"tenant"`
	Region        string                `json:"region"`
	Users         int                   `json:"users"`
	Question      string                `json:"question"`
	Paths         map[string]pathReport `json:"paths"`
}

type pathReport struct {
	Requests     int64   `json:"requests"`
	ReqPerSec    float64 `json:"req_per_sec"`
	Allowed      int64   `json:"allowed"`
	FailClosed   int64   `json:"fail_closed"`
	Throttled    int64   `json:"throttled"`
	Errors       int64   `json:"errors"`
	LatencyP50MS float64 `json:"latency_p50_ms"`
	LatencyP95MS float64 `json:"latency_p95_ms"`
	LatencyP99MS float64 `json:"latency_p99_ms"`
	LatencyMaxMS float64 `json:"latency_max_ms"`
}

// summarizeAndReport prints the human summary and writes the JSON
// report. -report=- suppresses the file (stdout only).
func summarizeAndReport(c config, started time.Time, elapsed time.Duration, stats map[string]*pathStats) error {
	fmt.Println("=== Groundwork load test ===")
	fmt.Printf("runtime: %s   tenant: %s   region: %s\n", c.runtime, c.tenant, c.region)
	fmt.Printf("users: %d   concurrency: %d   duration: %s\n", c.users, c.concurrency, elapsed.Round(time.Millisecond))

	rep := report{
		SchemaVersion: 1,
		GeneratedAt:   started.UTC(),
		DurationMS:    elapsed.Milliseconds(),
		Concurrency:   c.concurrency,
		Runtime:       c.runtime,
		Tenant:        c.tenant,
		Region:        c.region,
		Users:         c.users,
		Question:      c.question,
		Paths:         map[string]pathReport{},
	}
	for _, name := range []string{"query", "delegation", "dispatch", "connector", "evidence"} {
		s, ok := stats[name]
		if !ok {
			continue
		}
		total, allowed, denied, throttled, errs, lat := s.snapshot()
		sorted := sortedLatencies(lat)
		p50, p95, p99 := pct(sorted, 50), pct(sorted, 95), pct(sorted, 99)
		var max time.Duration
		if len(sorted) > 0 {
			max = sorted[len(sorted)-1].Round(time.Millisecond)
		}
		pr := pathReport{
			Requests:     total,
			ReqPerSec:    float64(total) / elapsed.Seconds(),
			Allowed:      allowed,
			FailClosed:   denied,
			Throttled:    throttled,
			Errors:       errs,
			LatencyP50MS: float64(p50.Milliseconds()),
			LatencyP95MS: float64(p95.Milliseconds()),
			LatencyP99MS: float64(p99.Milliseconds()),
			LatencyMaxMS: float64(max.Milliseconds()),
		}
		rep.Paths[name] = pr

		deniedPct := 0.0
		if total > 0 {
			deniedPct = 100 * float64(denied) / float64(total)
		}
		fmt.Printf("\npath %s:\n", name)
		fmt.Printf("  requests: %d (%.1f req/s)\n", total, pr.ReqPerSec)
		fmt.Printf("  allowed: %d   fail-closed: %d (%.1f%%)   throttled: %d   errors: %d\n",
			allowed, denied, deniedPct, throttled, errs)
		fmt.Printf("  latency p50: %s   p95: %s   p99: %s   max: %s\n", p50, p95, p99, max)
	}

	if c.report == "-" {
		return nil
	}
	target := c.report
	if target == "" {
		target = "loadtest-report-" + started.UTC().Format("20060102T150405Z") + ".json"
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	log.Printf("report written to %s", target)
	return nil
}
