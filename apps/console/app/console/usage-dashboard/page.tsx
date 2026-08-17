"use client";

import {
  BarChart,
  Bar,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  Line,
  PieChart,
  Pie,
  Cell,
  Label,
} from "recharts";
import { useEffect, useState } from "react";

type UsageMetric = {
  name: string;
  queries_per_min: number;
  pii_redactions_total: number;
  quota_consumption_pct: number;
  timestamp: string;
};

const MOCK_METRICS: UsageMetric[] = [
  { name: "00:00", queries_per_min: 12, pii_redactions_total: 3, quota_consumption_pct: 4.5, timestamp: "2026-06-10T00:00:00Z" },
  { name: "01:00", queries_per_min: 8, pii_redactions_total: 2, quota_consumption_pct: 3.2, timestamp: "2026-06-10T01:00:00Z" },
  { name: "02:00", queries_per_min: 15, pii_redactions_total: 5, quota_consumption_pct: 5.1, timestamp: "2026-06-10T02:00:00Z" },
  { name: "03:00", queries_per_min: 22, pii_redactions_total: 7, quota_consumption_pct: 6.8, timestamp: "2026-06-10T03:00:00Z" },
  { name: "04:00", queries_per_min: 18, pii_redactions_total: 4, quota_consumption_pct: 5.9, timestamp: "2026-06-10T04:00:00Z" },
  { name: "05:00", queries_per_min: 25, pii_redactions_total: 9, quota_consumption_pct: 8.3, timestamp: "2026-06-10T05:00:00Z" },
  { name: "06:00", queries_per_min: 31, pii_redactions_total: 12, quota_consumption_pct: 9.7, timestamp: "2026-06-10T06:00:00Z" },
  { name: "07:00", queries_per_min: 38, pii_redactions_total: 15, quota_consumption_pct: 11.2, timestamp: "2026-06-10T07:00:00Z" },
  { name: "08:00", queries_per_min: 42, pii_redactions_total: 18, quota_consumption_pct: 12.5, timestamp: "2026-06-10T08:00:00Z" },
  { name: "09:00", queries_per_min: 35, pii_redactions_total: 14, quota_consumption_pct: 10.8, timestamp: "2026-06-10T09:00:00Z" },
  { name: "10:00", queries_per_min: 28, pii_redactions_total: 10, quota_consumption_pct: 9.4, timestamp: "2026-06-10T10:00:00Z" },
  { name: "11:00", queries_per_min: 22, pii_redactions_total: 7, quota_consumption_pct: 7.9, timestamp: "2026-06-10T11:00:00Z" },
  { name: "12:00", queries_per_min: 19, pii_redactions_total: 6, quota_consumption_pct: 6.2, timestamp: "2026-06-10T12:00:00Z" },
  { name: "13:00", queries_per_min: 15, pii_redactions_total: 4, quota_consumption_pct: 4.8, timestamp: "2026-06-10T13:00:00Z" },
  { name: "14:00", queries_per_min: 11, pii_redactions_total: 3, quota_consumption_pct: 3.5, timestamp: "2026-06-10T14:00:00Z" },
  { name: "15:00", queries_per_min: 9, pii_redactions_total: 2, quota_consumption_pct: 2.1, timestamp: "2026-06-10T15:00:00Z" },
  { name: "16:00", queries_per_min: 7, pii_redactions_total: 1, quota_consumption_pct: 1.3, timestamp: "2026-06-10T16:00:00Z" },
  { name: "17:00", queries_per_min: 5, pii_redactions_total: 1, quota_consumption_pct: 0.9, timestamp: "2026-06-10T17:00:00Z" },
  { name: "18:00", queries_per_min: 3, pii_redactions_total: 1, quota_consumption_pct: 0.5, timestamp: "2026-06-10T18:00:00Z" },
  { name: "19:00", queries_per_min: 2, pii_redactions_total: 0, quota_consumption_pct: 0.2, timestamp: "2026-06-10T19:00:00Z" },
  { name: "20:00", queries_per_min: 1, pii_redactions_total: 0, quota_consumption_pct: 0.1, timestamp: "2026-06-10T20:00:00Z" },
  { name: "21:00", queries_per_min: 1, pii_redactions_total: 0, quota_consumption_pct: 0.1, timestamp: "2026-06-10T21:00:00Z" },
  { name: "22:00", queries_per_min: 1, pii_redactions_total: 0, quota_consumption_pct: 0.1, timestamp: "2026-06-10T22:00:00Z" },
  { name: "23:00", queries_per_min: 1, pii_redactions_total: 0, quota_consumption_pct: 0.1, timestamp: "2026-06-10T23:00:00Z" },
];

type UsageDashboardProps = {
  metrics?: UsageMetric[];
};

export default function UsageDashboard({ metrics }: UsageDashboardProps = {}) {
  const [chartMetrics, setChartMetrics] = useState<UsageMetric[]>(
    metrics || MOCK_METRICS,
  );

  return (
    <div className="p-6">
      <h2 className="text-xl font-semibold mb-6">Usage Dashboard</h2>

      <ResponsiveContainer width="100%" height={400}>
        <PieChart data={chartMetrics} margin={{ top: 20, right: 30, left: 0, bottom: 0 }}>
          <Pie
            dataKey="quota_consumption_pct"
            fill="#8884d8"
            label={<Label fontSize={12} />}
          >
            {chartMetrics.map((entry, index) => (
              <Cell key={index} fill={`hsl(${index * 360 / chartMetrics.length}, 70%, 60%)`} />
            ))}
          </Pie>
          <Legend verticalAlign="top" height={80} />
        </PieChart>
      </ResponsiveContainer>

      <div className="grid grid-cols-2 gap-4 mt-6">
        <BarChart
          data={chartMetrics}
          margin={{ top: 20, right: 30, left: 0, bottom: 0 }}
          layout="vertical"
        >
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" angle={-45} />
          <YAxis />
          <Tooltip />
          <Legend />
          <Bar dataKey="queries_per_min" name="Queries/min" fill="#8884d8" />
          <Bar dataKey="pii_redactions_total" name="PII Redactions" fill="#f472b6" />
        </BarChart>
      </div>

      <div className="grid grid-cols-2 gap-4 mt-6">
        <BarChart
          data={chartMetrics}
          margin={{ top: 20, right: 30, left: 0, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" angle={-45} />
          <YAxis />
          <Tooltip />
          <Legend />
          <Area
            type="monotone"
            dataKey="quota_consumption_pct"
            name="Quota Consumption %"
            fill="#3b82f6"
            stroke="#3b82f6"
            fillOpacity={0.3}
          />
          <Line type="monotone" dataKey="quota_consumption_pct" stroke="#3b82f6" activeDot={{ r: 8 }} />
          <YAxis domain={[0, 100]} />
          <XAxis dataKey="name" angle={-45} />
          <Tooltip />
          <Legend />
        </BarChart>
      </div>

      <div className="mt-6 pt-6 border-t" style={{ borderColor: "var(--callout-border)" }}>
        <p className="text-sm text-muted-foreground">
          Data shown is meterized usage per hour. Quota consumption is calculated against
          the tenant's allocated daily quota. Redactions apply to PII patterns (SSN, credit
          cards, health records) automatically blocked by the Context Firewall.
        </p>
      </div>
    </div>
  );
}