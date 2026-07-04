/**
 * pages/Analytics.jsx
 * ====================
 * Security posture analytics — risk score trends, severity distribution
 * over time, MITRE ATT&CK coverage, and recurring-issue breakdown.
 *
 * Backed by GET /api/v1/analytics/{risk-trend, mitre-coverage,
 * alert-type-breakdown, scan-stats} — all read main.py's own scan
 * history (ScanRun/FindingRecord), the same source Dashboard and Scan
 * History already use.
 *
 * Sections
 * --------
 *  1. Stat row       — total/completed/failed scans, success rate
 *  2. Risk trend      — avg/max risk score per scan (line chart)
 *  3. Severity trend   — Critical/High/Medium/Low/Info per scan (stacked bars)
 *  4. MITRE coverage   — finding counts by ATT&CK technique (horizontal bars)
 *  5. Alert breakdown  — finding counts by alert type, coloured by that
 *                        type's worst severity seen (horizontal bars)
 *
 * UX rules applied (matching Dashboard.jsx / ScanHistory.jsx conventions)
 * -------------------------------------------------------------------
 * - Skeleton placeholders while loading, not a blank page.
 * - A single unified empty state when there's no scan data at all yet,
 *   rather than four separate half-empty-looking charts.
 * - Chart colours reuse the exact severity hex values from
 *   tailwind.config.js's `severity.*` tokens (Recharts needs raw colour
 *   values, not Tailwind class names — so these stay manually in sync
 *   with that file; if the design tokens ever change, update both).
 */

import { useState, useEffect, useCallback } from 'react'
import {
  LineChart, Line, BarChart, Bar, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import {
  getRiskTrend,
  getMitreCoverage,
  getAlertTypeBreakdown,
  getScanStats,
} from '../api/client'

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

// Mirrors tailwind.config.js's `severity.*.border` tokens — the most
// saturated of the three shades per band, which reads clearly as a
// chart fill (the `.bg` shades are pale, meant for badge backgrounds).
const SEVERITY_COLORS = {
  Critical: '#F87171',
  High:     '#FB923C',
  Medium:   '#FACC15',
  Low:      '#60A5FA',
  Info:     '#9CA3AF',
}

const AXIS_TICK_STYLE   = { fontSize: 12, fill: '#6b7280' }
const TOOLTIP_STYLE     = { borderRadius: 8, fontSize: 12, border: '1px solid #e5e7eb' }

const formatDate = (iso) =>
  new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Card wrapper shared by every chart section — header + empty/content switch. */
function ChartCard({ title, subtitle, isEmpty, emptyMessage, children }) {
  return (
    <div className="rounded-xl border bg-white shadow-sm p-5">
      <div className="mb-4">
        <h2 className="text-base font-semibold text-gray-800">{title}</h2>
        {subtitle && <p className="text-xs text-gray-400 mt-0.5">{subtitle}</p>}
      </div>
      {isEmpty ? (
        <div className="flex items-center justify-center h-40 text-sm text-gray-400">
          {emptyMessage}
        </div>
      ) : (
        children
      )}
    </div>
  )
}

function ChartSkeleton({ height = 280 }) {
  return <div className="skeleton rounded-xl" style={{ height }} />
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export default function Analytics() {
  const [riskTrend,      setRiskTrend]      = useState([])
  const [mitreCoverage,  setMitreCoverage]  = useState([])
  const [alertBreakdown, setAlertBreakdown] = useState([])
  const [scanStats,      setScanStats]      = useState(null)
  const [loading,        setLoading]        = useState(true)
  const [error,          setError]          = useState(null)

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [trend, mitre, alerts, stats] = await Promise.all([
        getRiskTrend(30),
        getMitreCoverage(),
        getAlertTypeBreakdown(),
        getScanStats(),
      ])
      setRiskTrend(trend)
      setMitreCoverage(mitre)
      setAlertBreakdown(alerts)
      setScanStats(stats)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchData() }, [fetchData])

  // Chart data needs a short, readable X-axis label — derived once here
  // rather than inside JSX, so it's not recomputed per-render per-point.
  const trendData = riskTrend.map((point) => ({
    ...point,
    label: formatDate(point.started_at),
  }))

  const topMitre  = mitreCoverage.slice(0, 10)
  const topAlerts = alertBreakdown.slice(0, 10)

  // ---------------------------------------------------------------------------
  // Page header (shared by every render path below)
  // ---------------------------------------------------------------------------
  const header = (
    <div className="flex items-center justify-between">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Security Analytics</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Risk trends, MITRE ATT&amp;CK coverage, and recurring issues across all scans
        </p>
      </div>
      <button
        onClick={fetchData}
        className="text-sm text-blue-600 hover:text-blue-800"
      >
        ↻ Refresh
      </button>
    </div>
  )

  // ---------------------------------------------------------------------------
  // Loading state
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="p-6 max-w-6xl mx-auto space-y-6">
        {header}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => <div key={i} className="skeleton h-20 rounded-xl" />)}
        </div>
        <ChartSkeleton />
        <ChartSkeleton />
        <div className="grid lg:grid-cols-2 gap-6">
          <ChartSkeleton height={300} />
          <ChartSkeleton height={300} />
        </div>
      </div>
    )
  }

  // ---------------------------------------------------------------------------
  // Error state
  // ---------------------------------------------------------------------------
  if (error) {
    return (
      <div className="p-6 max-w-6xl mx-auto space-y-6">
        {header}
        <div className="rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700">
          <strong>Error:</strong> {error}
        </div>
      </div>
    )
  }

  // ---------------------------------------------------------------------------
  // No scan data at all yet — one unified empty state, not four
  // separately-empty-looking charts.
  // ---------------------------------------------------------------------------
  if (scanStats && scanStats.total_scans === 0) {
    return (
      <div className="p-6 max-w-6xl mx-auto space-y-6">
        {header}
        <div className="rounded-xl border border-dashed border-gray-300 bg-gray-50
                        p-12 text-center">
          <p className="text-gray-400 text-sm">No scan data yet.</p>
          <p className="text-gray-400 text-xs mt-1">
            Run your first scan from the Dashboard to see analytics here.
          </p>
        </div>
      </div>
    )
  }

  // ---------------------------------------------------------------------------
  // Main content
  // ---------------------------------------------------------------------------
  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {header}

      {/* ── Stat row ── */}
      {scanStats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Total Scans',  value: scanStats.total_scans },
            { label: 'Completed',    value: scanStats.completed_scans },
            { label: 'Failed',       value: scanStats.failed_scans },
            { label: 'Success Rate', value: `${scanStats.success_rate_pct}%` },
          ].map(({ label, value }) => (
            <div key={label} className="rounded-xl border bg-white p-4 text-center shadow-sm">
              <p className="text-2xl font-bold text-gray-800">{value}</p>
              <p className="text-xs text-gray-500 mt-1">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* ── Risk score trend ── */}
      <ChartCard
        title="Risk Score Trend"
        subtitle="Average and peak risk score per scan, most recent 30"
        isEmpty={trendData.length === 0}
        emptyMessage="No completed scans yet."
      >
        <ResponsiveContainer width="100%" height={280}>
          <LineChart data={trendData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis dataKey="label" tick={AXIS_TICK_STYLE} />
            <YAxis tick={AXIS_TICK_STYLE} domain={[0, 100]} allowDecimals={false} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Line
              type="monotone" dataKey="avg_risk_score" name="Avg Risk Score"
              stroke="#2563EB" strokeWidth={2} dot={{ r: 3 }}
            />
            <Line
              type="monotone" dataKey="max_risk_score" name="Max Risk Score"
              stroke="#DC2626" strokeWidth={2} strokeDasharray="4 3" dot={{ r: 3 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </ChartCard>

      {/* ── Severity distribution trend ── */}
      <ChartCard
        title="Severity Distribution Trend"
        subtitle="Findings per severity band, per scan"
        isEmpty={trendData.length === 0}
        emptyMessage="No completed scans yet."
      >
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={trendData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis dataKey="label" tick={AXIS_TICK_STYLE} />
            <YAxis tick={AXIS_TICK_STYLE} allowDecimals={false} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Bar dataKey="critical_count" name="Critical" stackId="sev" fill={SEVERITY_COLORS.Critical} />
            <Bar dataKey="high_count"     name="High"     stackId="sev" fill={SEVERITY_COLORS.High} />
            <Bar dataKey="medium_count"   name="Medium"   stackId="sev" fill={SEVERITY_COLORS.Medium} />
            <Bar dataKey="low_count"      name="Low"      stackId="sev" fill={SEVERITY_COLORS.Low} />
            <Bar dataKey="info_count"     name="Info"     stackId="sev" fill={SEVERITY_COLORS.Info} />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      {/* ── MITRE coverage + Alert type breakdown ── */}
      <div className="grid lg:grid-cols-2 gap-6">
        <ChartCard
          title="MITRE ATT&CK Coverage"
          subtitle="Findings by technique, top 10"
          isEmpty={topMitre.length === 0}
          emptyMessage="No MITRE-mapped findings yet."
        >
          <ResponsiveContainer width="100%" height={Math.max(220, topMitre.length * 36)}>
            <BarChart
              data={topMitre} layout="vertical"
              margin={{ top: 5, right: 24, left: 10, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" horizontal={false} />
              <XAxis type="number" allowDecimals={false} tick={AXIS_TICK_STYLE} />
              <YAxis
                type="category" dataKey="mitre_technique" width={90}
                tick={{ fontSize: 11, fill: '#374151' }}
              />
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                formatter={(value, _name, props) => [value, props.payload.mitre_tactic || 'Findings']}
              />
              <Bar dataKey="finding_count" name="Findings" fill="#2563EB" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard
          title="Recurring Issues"
          subtitle="Findings by alert type, coloured by worst severity seen"
          isEmpty={topAlerts.length === 0}
          emptyMessage="No findings yet."
        >
          <ResponsiveContainer width="100%" height={Math.max(220, topAlerts.length * 36)}>
            <BarChart
              data={topAlerts} layout="vertical"
              margin={{ top: 5, right: 24, left: 10, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" horizontal={false} />
              <XAxis type="number" allowDecimals={false} tick={AXIS_TICK_STYLE} />
              <YAxis
                type="category" dataKey="alert_type" width={150}
                tick={{ fontSize: 11, fill: '#374151' }}
              />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="finding_count" name="Findings" radius={[0, 4, 4, 0]}>
                {topAlerts.map((entry, idx) => (
                  <Cell key={idx} fill={SEVERITY_COLORS[entry.highest_severity] ?? SEVERITY_COLORS.Info} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>
    </div>
  )
}