/**
 * pages/Dashboard.jsx
 * ====================
 * Landing page. Shows the overall security posture at a glance.
 *
 * Sections
 * --------
 *  1. Header + ScanTrigger button
 *  2. Summary cards  — one per severity band (Critical / High / Medium / Low / Info)
 *  3. Unacknowledged banner — prominent if any critical/high are unresolved
 *  4. Latest findings list  — top 10 from the most recent scan
 *  5. AI Executive Report   — rendered via AiReportPanel (collapsible)
 *
 * UX rules applied
 * ----------------
 * - Loading skeletons replace cards while data fetches (no blank flash).
 * - Empty state is explicit and helpful ("No scans run yet — click Run Scan Now").
 * - Severity cards are clickable → navigate to Findings filtered by that band.
 * - Error message is inline and specific (not just "Something went wrong").
 * - onApiStatus callback lets App.jsx update the sidebar connection indicator.
 */

import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { getDashboard, getScanFindings, getScanStatus } from '../api/client'
import ScanTrigger    from '../components/ScanTrigger'
import SeverityBadge  from '../components/SeverityBadge'
import FindingCard    from '../components/FindingCard'
import AiReportPanel  from '../components/AiReportPanel'

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Single severity summary card */
function SeverityCard({ label, count, colour, onClick }) {
  const colours = {
    red:    'border-red-200    bg-red-50    text-red-700',
    orange: 'border-orange-200 bg-orange-50 text-orange-700',
    yellow: 'border-yellow-200 bg-yellow-50 text-yellow-700',
    blue:   'border-blue-200   bg-blue-50   text-blue-700',
    gray:   'border-gray-200   bg-gray-50   text-gray-500',
  }
  return (
    <button
      onClick={onClick}
      className={`rounded-xl border p-5 text-left w-full transition-shadow
                  hover:shadow-md active:scale-95 ${colours[colour]}`}
    >
      <p className="text-3xl font-bold">{count}</p>
      <p className="text-sm font-medium mt-1">{label}</p>
      <p className="text-xs opacity-60 mt-0.5">Click to view →</p>
    </button>
  )
}

/** Skeleton placeholder while loading */
function CardSkeleton() {
  return <div className="skeleton h-28 rounded-xl" />
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export default function Dashboard({ onApiStatus }) {
  const navigate = useNavigate()

  const [summary,      setSummary]      = useState(null)
  const [findings,     setFindings]     = useState([])
  const [aiReport,     setAiReport]     = useState(null)
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState(null)
  const [lastScanId,   setLastScanId]   = useState(null)

  // Fetch dashboard summary + latest findings
  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const dash = await getDashboard()
      setSummary(dash)
      onApiStatus?.(true)

      if (dash.last_scan_id) {
        setLastScanId(dash.last_scan_id)
        const f = await getScanFindings(dash.last_scan_id)
        setFindings(f.slice(0, 10))           // show top 10 on dashboard

        // Fetch AI report from the scan status record
        const scanData = await getScanStatus(dash.last_scan_id)
        setAiReport(scanData.ai_report || null)
      }
    } catch (err) {
      setError(err.message)
      onApiStatus?.(false)
    } finally {
      setLoading(false)
    }
  }, [onApiStatus])

  useEffect(() => { fetchData() }, [fetchData])

  // Called by ScanTrigger when a scan finishes
  const handleScanComplete = (scanData) => {
    setLastScanId(scanData.id)
    fetchData()
  }

  // ---------------------------------------------------------------------------
  // Render helpers
  // ---------------------------------------------------------------------------
  const renderCards = () => {
    if (loading) {
      return [1,2,3,4,5].map(i => <CardSkeleton key={i} />)
    }
    if (!summary) return null

    const cards = [
      { label: 'Critical', count: summary.critical_count, colour: 'red'    },
      { label: 'High',     count: summary.high_count,     colour: 'orange' },
      { label: 'Medium',   count: summary.medium_count,   colour: 'yellow' },
      { label: 'Low',      count: summary.low_count,      colour: 'blue'   },
      { label: 'Info',     count: summary.info_count,     colour: 'gray'   },
    ]
    return cards.map(({ label, count, colour }) => (
      <SeverityCard
        key={label}
        label={label}
        count={count}
        colour={colour}
        onClick={() => navigate(`/findings?severity=${label}`)}
      />
    ))
  }

  // ---------------------------------------------------------------------------
  // Main render
  // ---------------------------------------------------------------------------
  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">

      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {summary?.last_scan_at
              ? `Last scan: ${new Date(summary.last_scan_at).toLocaleString()}`
              : 'No scans run yet'}
            {summary && ` · ${summary.total_scans_run} scan(s) total`}
          </p>
        </div>
        <ScanTrigger onScanComplete={handleScanComplete} />
      </div>

      {/* ── Error banner ── */}
      {error && (
        <div className="rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* ── Severity summary cards ── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {renderCards()}
      </div>

      {/* ── Unacknowledged alert banner ── */}
      {!loading && summary && summary.unacknowledged_count > 0 && (
        <div className="rounded-lg bg-orange-50 border border-orange-200 px-4 py-3
                        flex items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-sm text-orange-800">
            <span>⚠️</span>
            <span>
              <strong>{summary.unacknowledged_count}</strong> unacknowledged finding
              {summary.unacknowledged_count !== 1 ? 's' : ''} require analyst review.
            </span>
          </div>
          <button
            onClick={() => navigate('/findings')}
            className="text-xs px-3 py-1.5 rounded bg-orange-600 text-white
                       hover:bg-orange-700 transition-colors whitespace-nowrap"
          >
            Review now →
          </button>
        </div>
      )}

      {/* ── Stats row ── */}
      {!loading && summary && (
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: 'Total Findings',       value: summary.total_findings },
            { label: 'Unacknowledged',        value: summary.unacknowledged_count },
            { label: 'Scans Run',             value: summary.total_scans_run },
          ].map(({ label, value }) => (
            <div key={label} className="rounded-xl border bg-white p-4 text-center shadow-sm">
              <p className="text-2xl font-bold text-gray-800">{value}</p>
              <p className="text-xs text-gray-500 mt-1">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* ── AI Report ── */}
      {!loading && <AiReportPanel report={aiReport} showEmpty={true} />}

      {/* ── Latest findings ── */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-base font-semibold text-gray-800">
            Latest Findings
            {findings.length > 0 && (
              <span className="ml-2 text-xs font-normal text-gray-400">
                (top {findings.length} by risk score)
              </span>
            )}
          </h2>
          {findings.length > 0 && (
            <button
              onClick={() => navigate('/findings')}
              className="text-xs text-blue-600 hover:text-blue-800"
            >
              View all →
            </button>
          )}
        </div>

        {loading && (
          <div className="space-y-3">
            {[1,2,3].map(i => <div key={i} className="skeleton h-16 rounded-lg" />)}
          </div>
        )}

        {!loading && findings.length === 0 && (
          <div className="rounded-xl border border-dashed border-gray-300 bg-gray-50
                          p-10 text-center">
            <p className="text-gray-400 text-sm">No findings yet.</p>
            <p className="text-gray-400 text-xs mt-1">
              Click <strong>Run Scan Now</strong> to start your first scan.
            </p>
          </div>
        )}

        {!loading && findings.length > 0 && (
          <div className="space-y-3">
            {findings.map(f => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}