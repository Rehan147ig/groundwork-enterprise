// Package firewall implements the Zero-Trust Context Firewall: the
// filter chain applied to retrieved chunks BEFORE they reach the LLM.
//
// Three stages run per chunk:
//
//  1. PII / PHI redaction — mask SSNs, credit-card numbers (Luhn
//     verified), phone numbers, emails, and secret material (API keys,
//     AWS access keys, bearer tokens) inside chunk text. The raw
//     context never reaches the model.
//
//  2. Indirect prompt-injection scan — detect adversarial instructions
//     hidden in retrieved document text (instruction override, system
//     prompt theft, jailbreak markers, encoded payloads). In "block"
//     mode the chunk is excluded from the context; in "redact" mode the
//     suspicious spans are stripped and the chunk is retained but
//     flagged. Either way the outcome is recorded on the trace.
//
//  3. Provenance watermark — every chunk delivered to the model carries
//     an HMAC-SHA256 signature over (tenant, chunk id, text), so a
//     downstream leak can be traced back to the exact chunk (and the
//     text verified against tampering via VerifyWatermark).
package firewall

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Mode selects how the firewall treats detected injections.
type Mode string

const (
	// ModeOff disables the firewall entirely (default).
	ModeOff Mode = "off"
	// ModeRedact redacts PII and strips suspicious spans, keeping the chunk.
	ModeRedact Mode = "redact"
	// ModeBlock excludes chunks with detected injections from the context
	// (fail closed) and redacts PII on the rest.
	ModeBlock Mode = "block"
)

// ErrFirewallUnavailable is returned when a firewall is required but
// not configured.
var ErrFirewallUnavailable = errors.New("firewall unavailable")

// Report summarizes one sanitize pass over the candidate set.
type Report struct {
	TenantID         string `json:"tenant_id"`
	ChunksExamined   int    `json:"chunks_examined"`
	ChunksRedacted   int    `json:"chunks_redacted"`
	Redactions       int    `json:"redactions"`
	InjectionHits    int    `json:"injection_hits"`
	InjectionBlocked int    `json:"injection_blocked"`
	Watermarked      int    `json:"watermarked"`
}

// Redaction describes one masked span.
type Redaction struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// ScannerReport describes the injection-scan outcome for one chunk.
type ScannerReport struct {
	Detected   bool     `json:"detected"`
	Severity   string   `json:"severity,omitempty"`
	Categories []string `json:"categories,omitempty"`
}

// ContextFirewall runs the three-stage filter chain over candidates.
type ContextFirewall struct {
	mode         Mode
	redactor     *Redactor
	scanner      *InjectionScanner
	watermarkKey []byte
	// OnReport, when set, is invoked after every sanitize pass with the
	// cumulative report (used to feed Prometheus metrics).
	OnReport func(*Report)
}

// New builds a firewall in the given mode. watermarkKey signs chunk
// provenance; when empty, watermarking is skipped.
func New(mode Mode, watermarkKey string) *ContextFirewall {
	return &ContextFirewall{
		mode:         mode,
		redactor:     NewRedactor(),
		scanner:      NewInjectionScanner(),
		watermarkKey: []byte(watermarkKey),
	}
}

// Enabled reports whether any stage will run.
func (f *ContextFirewall) Enabled() bool {
	return f != nil && f.mode != ModeOff
}

// Sanitize applies the filter chain to candidates. The returned slice
// has the same length as input in redact mode; in block mode chunks
// with detected injections are dropped. PII spans are replaced with
// [REDACTED_<KIND>] markers. Every surviving chunk gets a provenance
// watermark (when a key is configured).
func (f *ContextFirewall) Sanitize(ctx context.Context, tenantID string, candidates []Candidate) ([]Candidate, *Report, error) {
	if f == nil || f.mode == ModeOff {
		return candidates, nil, nil
	}
	report := &Report{TenantID: tenantID, ChunksExamined: len(candidates)}
	out := make([]Candidate, 0, len(candidates))
	for i := range candidates {
		item := candidates[i]
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		redactions := f.redactor.Redact(&item.Text)
		if len(redactions) > 0 {
			report.ChunksRedacted++
			report.Redactions += len(redactions)
		}
		scan := f.scanner.Scan(item.Text)
		if scan.Detected {
			report.InjectionHits++
			if f.mode == ModeBlock {
				report.InjectionBlocked++
				continue // fail closed: the chunk never reaches the model
			}
			item.Text = f.scanner.Strip(item.Text)
		}
		if f.watermarkKey != nil && len(f.watermarkKey) > 0 {
			item.Watermark = f.Watermark(tenantID, item.ChunkID, item.Text)
			report.Watermarked++
		}
		out = append(out, item)
	}
	if f.OnReport != nil {
		f.OnReport(report)
	}
	return out, report, nil
}

// Watermark signs (tenant, chunk id, text) with the firewall's key.
func (f *ContextFirewall) Watermark(tenantID, chunkID, text string) string {
	if f == nil || len(f.watermarkKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, f.watermarkKey)
	fmt.Fprintf(mac, "%s\x00%s\x00%s", tenantID, chunkID, text)
	return "gwv1:" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWatermark recomputes the watermark for a chunk and reports
// whether it matches. Used for provenance checks on delivered context.
func (f *ContextFirewall) VerifyWatermark(tenantID, chunkID, text, watermark string) bool {
	if f == nil || len(f.watermarkKey) == 0 {
		return false
	}
	return hmac.Equal([]byte(watermark), []byte(f.Watermark(tenantID, chunkID, text)))
}

// Candidate is the slice element the firewall operates on. It mirrors
// the engine's chunk payload with the mutable text field the chain
// rewrites.
type Candidate struct {
	TenantID   string
	Region     string
	DocumentID string
	ChunkID    string
	ChunkHash  string
	Page       int
	Offset     int
	Text       string
	Score      float64
	Freshness  float64
	Watermark  string
}

// ---- Stage 1: PII redaction ----

// Redactor masks PII and secret material in text.
type Redactor struct {
	patterns []pattern
}

type pattern struct {
	kind string
	re   *regexp.Regexp
	luhn bool
}

// NewRedactor builds the default redactor. Masking replaces the match
// with [REDACTED_<KIND>] (credit cards additionally verify Luhn so
// ordinary digit runs are not flagged).
func NewRedactor() *Redactor {
	return &Redactor{patterns: []pattern{
		{kind: "SSN", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
		{kind: "PHONE", re: regexp.MustCompile(`\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b`)},
		{kind: "EMAIL", re: regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)},
		{kind: "AWS_KEY", re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
		{kind: "API_KEY", re: regexp.MustCompile(`\b(gw_live_[a-f0-9]{8}_[a-f0-9]{48}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`)},
		{kind: "BEARER", re: regexp.MustCompile(`\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b`)},
		{kind: "PASSWORD", re: regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token)\s*[:=]\s*[^\s,;]+`)},
		{kind: "CREDIT_CARD", re: regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`), luhn: true},
	}}
}

// Redact replaces every detected span with a [REDACTED_<KIND>] marker
// and returns the redactions performed.
func (r *Redactor) Redact(text *string) []Redaction {
	var out []Redaction
	for _, p := range r.patterns {
		loc := p.re.FindAllStringIndex(*text, -1)
		if len(loc) == 0 {
			continue
		}
		var kept int
		for _, span := range loc {
			if p.luhn && !luhnValid(digitsOnly((*text)[span[0]:span[1]])) {
				continue
			}
			mask := "[REDACTED_" + p.kind + "]"
			*text = (*text)[:span[0]+kept] + mask + (*text)[span[1]+kept:]
			kept += len(mask) - (span[1] - span[0])
			out = append(out, Redaction{Kind: p.kind})
		}
	}
	return out
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// luhnValid verifies a digit string against the Luhn checksum.
func luhnValid(digits string) bool {
	if len(digits) < 13 {
		return false
	}
	var sum int
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// ---- Stage 2: indirect prompt-injection scanner ----

// Severity levels for detected injections.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
)

// InjectionScanner detects adversarial instructions embedded in
// retrieved document text. Detection is conservative: rules fire on
// unambiguous instruction-override / jailbreak / exfiltration language.
type InjectionScanner struct {
	rules []rule
}

type rule struct {
	category string
	severity string
	re       *regexp.Regexp
}

// NewInjectionScanner builds the default rule set.
func NewInjectionScanner() *InjectionScanner {
	return &InjectionScanner{rules: []rule{
		{category: "instruction_override", severity: SeverityHigh,
			re: regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override|bypass|ignore all)\b.{0,40}\b(previous|prior|above|earlier)\b.{0,40}\b(instructions?|prompts?|directions?|rules?|system)\b`)},
		{category: "instruction_override", severity: SeverityHigh,
			re: regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\b.{0,40}\b(everything|all|your instructions|the system prompt)\b`)},
		{category: "system_prompt_theft", severity: SeverityHigh,
			re: regexp.MustCompile(`(?i)\b(print|repeat|reveal|disclose|show|output|leak)\b.{0,40}\b(system prompt|your instructions|initial instructions|your rules)\b`)},
		{category: "jailbreak", severity: SeverityHigh,
			re: regexp.MustCompile(`(?i)\b(do anything now|dan mode|jailbreak|developer mode|free mode|unfiltered mode|superior mode)\b`)},
		{category: "role_reversal", severity: SeverityMedium,
			re: regexp.MustCompile(`(?i)\b(you are now|pretend you are|act as if you are|imagine you are)\b.{0,60}\b(no rules|no restrictions|unrestricted|without limits)\b`)},
		{category: "exfiltration", severity: SeverityMedium,
			re: regexp.MustCompile(`(?i)\b(send|post|upload|exfiltrate)\b.{0,60}\b(everything|the full text|all contents|all data|the document)\b.{0,60}\b(url|webhook|endpoint|server|http)\b`)},
		{category: "delimited_override", severity: SeverityMedium,
			re: regexp.MustCompile(`(?is)\b(start|begin|prefix|suffix)\b.{0,20}\b(instruction|prompt|command)\b.{0,80}(new|fake|different)`)},
		{category: "encoded_payload", severity: SeverityLow,
			re: regexp.MustCompile(`\b(?:[A-Za-z0-9+/]{80,}={0,2}|[a-f0-9]{80,})\b`)},
	}}
}

// Scan reports whether the text contains injection signals.
func (s *InjectionScanner) Scan(text string) ScannerReport {
	report := ScannerReport{}
	for _, r := range s.rules {
		if r.re.MatchString(text) {
			report.Detected = true
			report.Categories = append(report.Categories, r.category)
			if report.Severity == "" || severityRank(r.severity) > severityRank(report.Severity) {
				report.Severity = r.severity
			}
		}
	}
	return report
}

// Strip removes the matched injection spans from the text (redact
// mode). The text is kept but the adversarial material is dropped.
func (s *InjectionScanner) Strip(text string) string {
	for _, r := range s.rules {
		text = r.re.ReplaceAllString(text, "[FILTERED]")
	}
	return text
}

func severityRank(level string) int {
	switch level {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	default:
		return 1
	}
}
