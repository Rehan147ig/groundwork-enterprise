import { NextResponse } from "next/server";
import { sanitizeRichText } from "@/lib/sanitize";

// Leak Report. The analysis lives in the runtime (internal/leakreport, run
// today via cmd/leak-report). When the runtime exposes GET /v1/leak-report,
// proxy it here. Until then this returns the curated Acme findings — the
// same ones the leakreport package produces for the mock org — so the view
// is demoable. Wiring the live endpoint is a one-step follow-up (a Go
// handler that runs github.Connector.Snapshot -> leakreport.Analyze).
//
// Every `detail` value passes through sanitizeRichText before leaving this
// route: the console later renders it as HTML, so anything the runtime or
// a connector embeds in a finding is reduced to <code>…</code> at most.
// Demo data is served only when GROUNDWORK_DEMO_MODE=true; otherwise a
// cold backend is a hard 503 rather than fabricated findings.

type Finding = { kind: string; severity: "high" | "medium" | "low"; title: string; detail: string };

const DEMO_FINDINGS: Finding[] = [
  { kind: "cross_department_access", severity: "high", title: "Cross-department access", detail: "<code>engineering-team</code> can view <code>gh:finance-budget</code>, which is owned by <code>finance-team</code>." },
  { kind: "excessive_group_access", severity: "high", title: "Excessive group access", detail: "<code>engineering-team</code> can read documents owned by 2 other departments." },
  { kind: "overexposed_document", severity: "medium", title: "Overexposed document", detail: "<code>gh:finance-budget</code> is viewable by 2 groups: finance-team, engineering-team." },
];

function sanitizedFindings(findings: Finding[]): Finding[] {
  return findings.map((f) => ({ ...f, detail: sanitizeRichText(f.detail ?? "") }));
}

export async function GET() {
  const runtimeUrl = process.env.QUERY_RUNTIME_URL ?? "";
  const apiKey = process.env.GROUNDWORK_API_KEY ?? "";
  if (runtimeUrl && apiKey) {
    try {
      // Live: runtime runs github.Connector.Snapshot -> leakreport.Analyze.
      const res = await fetch(`${runtimeUrl}/v1/leak-report`, {
        headers: { "X-Groundwork-API-Key": apiKey },
        cache: "no-store",
      });
      if (res.ok) {
        const data = await res.json();
        const findings: Finding[] = (data.findings ?? []).map((f: Record<string, string>) => ({
          kind: f.kind,
          severity: (f.severity as Finding["severity"]) ?? "low",
          title: f.title ?? f.kind,
          detail: f.detail ?? "",
        }));
        return NextResponse.json({ source: "live", findings: sanitizedFindings(findings) });
      }
    } catch {
      /* fall through to demo */
    }
  }
  if (process.env.GROUNDWORK_DEMO_MODE !== "true") {
    return NextResponse.json({ source: "error", error: "leak_report_unavailable" }, { status: 503 });
  }
  return NextResponse.json({ source: "demo", findings: sanitizedFindings(DEMO_FINDINGS) });
}