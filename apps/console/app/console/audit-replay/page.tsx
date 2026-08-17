"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { useEffect, useState } from "react";
import {
  Shield,
  Microscope,
  Zap,
  Users,
  Clock,
  CheckCircle,
  Ban,
} from "lucide-react";

type AuditEvent = {
  step: "l1-cache" | "rebac" | "pii-scan" | "decision";
  timestamp: string;
  passed: boolean;
  details?: string;
};

const INITIAL_EVENTS: AuditEvent[] = [
  { step: "l1-cache", timestamp: "2026-06-10T14:30:00Z", passed: true, details: "Cache hit: chunk served from L1, latency ~2ms" },
  { step: "rebac", timestamp: "2026-06-10T14:30:00Z", passed: true, details: "SpiceDB ReBAC: user has executive-team#member → viewer path" },
  { step: "pii-scan", timestamp: "2026-06-10T14:30:00Z", passed: false, details: "PII scan: SSN pattern detected in chunk content, redaction applied" },
  { step: "decision", timestamp: "2026-06-10T14:30:00Z", passed: false, details: "Final decision: DENIED — PII redaction required before grant" },
];

type AuditReplayProps = {
  events?: AuditEvent[];
};

export default function AuditReplay({ events }: AuditReplayProps = {}) {
  const [timelineEvents, setTimelineEvents] = useState<AuditEvent[]>(
    events || INITIAL_EVENTS,
  );

  useEffect(() => {
    // Simulate interactive replay — advance one step at a time
    let index = 0;
    const interval = setInterval(() => {
      setTimelineEvents((prev) => {
        if (index >= prev.length) return prev;
        const next = [...prev];
        next[index].passed = true;
        next[index].details = next[index].details + " ✅";
        index++;
        return next;
      });
    }, 1200);

    return () => clearInterval(interval);
  }, []);

  const statusColor = (passed: boolean) => (passed ? "rgb(34 197 94)" : "rgb(239 68 68)");

  return (
    <div className="p-6">
      <h2 className="text-xl font-semibold mb-6">Audit Replay — Chunk Evaluation Timeline</h2>

      <div className="space-y-4">
        {timelineEvents.map((ev, i) => (
          <div key={i} className="p-4 rounded-lg border" style={{ borderColor: "var(--callout-border)" }}>
            <div className="flex items-center justify-between mb-2">
              <span className="font-medium">{ev.step.replace(/-/g, " ")}</span>
              <span className="text-sm font-normal" style={{ color: statusColor(ev.passed) }}>
                {ev.passed ? "PASS" : "BLOCK"}
              </span>
            </div>
            <p className="text-sm text-muted-foreground">{ev.timestamp}</p>
            {ev.details && (
              <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>
                {ev.details}
              </p>
            )}
          </div>
        ))}
      </div>

      <div className="mt-8 p-4 rounded-lg" style={{ background: "var(--card)", border: "1px solid var(--callout-border)" }}>
        <h3 className="font-medium mb-3">Evaluation Flow</h3>
        <div className="grid grid-cols-4 gap-2">
          <div>
            <Shield width={20} height={20} className="text-primary-500" />
            L1 Cache
          </div>
          <div>
            <Users width={20} height={20} className="text-primary-500" />
            SpiceDB ReBAC
          </div>
          <div>
            <Microscope width={20} height={20} className="text-primary-500" />
            Context Firewall PII Scan
          </div>
          <div>
            <Zap width={20} height={20} className="text-primary-500" />
            Final Decision
          </div>
        </div>
      </div>
    </div>
  );
}