/**
 * pages/ScanHistory.jsx
 * =====================
 * List of every scan run with severity breakdown bars and expandable
 * finding details per scan.
 *
 * Features
 * --------
 *  - Paginated scan list (20 per page)
 *  - Status badge (pending / running / completed / failed)
 *  - Severity distribution bar per scan row
 *  - Expandable findings panel per scan (loaded on demand)
 *  - AI report panel inside each expanded scan
 *
 * UX rules applied
 * ----------------
 * - Status badge uses colour + text (not colour alone).
 * - Running scans auto-refresh every 3 s until they complete.
 * - Pagination controls are disabled when at first/last page.
 * - Expanded findings load on demand — not all at once on page load.
 */

import { useState, useEffect, useRef } from 'react'
import { listScans, getScanFindings, getScanStatus } from '../api/client'
import SeverityBadge from '../components/SeverityBadge'
import FindingCard   from '../components/FindingCard'
import AiReportPanel from '../components/AiReportPanel'

const PAGE_SIZE = 20

// Severity bar colours
const SEV_COLOURS = {
  Critical: 'bg-red-500',
  High:     'bg-orange-500',
  Medium:   'bg-yellow-400',
  Low:      'bg-blue-400',
  Info:     'bg-gray-300',
}

// Status badge styles
const STATUS_STYLES = {
  completed: 'bg-green-100  text-green-700  border-green-300',
  running:   'bg-blue-100   text-blue-700   border-blue-300',
  pending:   'bg-gray-100   text-gray-500   border-gray-300',
  failed:    'bg-red-100    text-red-700    border-red-300',
}

/** Proportional severity bar */
function SeverityBar({ scan }) {
  const total = scan.total_findings
  if (total === 0) return <span className="text-xs text-gray-300">No findings</span>

  const bands = [
    { key: 'critical_count', sev: 'Critical' },
    { key: 'high_count',     sev: 'High'     },
    { key: 'medium_count',   sev: 'Medium'   },
    { key: 'low_count',      sev: 'Low'      },
    { key: 'info_count',     sev: 'Info'     },
  ]

  return (
    <div className="flex h-2 w-full rounded-full overflow-hidden gap-px">
      {bands.map(({ key, sev }) => {
        const count = scan[key] || 0
        if (count === 0) return null
        const pct = (count / total) * 100
        return (
          <div
            key={sev}
            title={`${sev}: ${count}`}
            className={`${SEV_COLOURS[sev]} transition-all`}
            style={{ width: `${pct}%` }}
          />
        )
      })}
    </div>
  )
}

/** Single scan row */
function ScanRow({ scan, onRefresh }) {
  const [expanded,  setExpanded]  = useState(false)
  const [findings,  setFindings]  = useState([])
  const [aiReport,  setAiReport]  = useState(null)
  const [loading,   setLoading]   = useState(false)
  const [error,     setError]     = useState(null)

  const handleExpand = async () => {
    if (expanded) { setExpanded(false); return }
    setExpanded(true)
    if (findings.length > 0) return   // already loaded

    setLoading(true)
    setError(null)
    try {
      const [f, s] = await Promise.all([
        getScanFindings(scan.id),
        getScanStatus(scan.id),
      ])
      setFindings(f)
      setAiReport(s.ai_report || null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const statusClass = STATUS_STYLES[scan.status] ?? STATUS_STYLES.pending

  return (
    <div className="rounded-xl border bg-white shadow-sm overflow-hidden">

      {/* ── Row header ── */}
      <button
        onClick={handleExpand}
        className="w-full text-left px-5 py-4 hover:bg-gray-50 transition-colors"
      >
        <div className="flex items-start justify-between gap-4 flex-wrap">

          {/* Left: ID + timestamp */}
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-semibold text-gray-800">
                Scan #{scan.id}
              </span>
              <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${statusClass}`}>
                {scan.status}
              </span>
            </div>
            <p className="text-xs text-gray-400 mt-0.5">
              {scan.started_at
                ? new Date(scan.started_at).toLocaleString()
                : '—'}
              {scan.completed_at && scan.started_at && (
                <span className="ml-2">
                  · {Math.round(
                      (new Date(scan.completed_at) - new Date(scan.started_at)) / 1000
                    )}s
                </span>
              )}
            </p>
          </div>

          {/* Right: counts + expand arrow */}
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-sm font-semibold text-gray-700">
                {scan.total_findings} finding{scan.total_findings !== 1 ? 's' : ''}
              </p>
              {scan.critical_count > 0 && (
                <p className="text-xs text-red-600 font-medium">
                  {scan.critical_count} Critical
                </p>
              )}
            </div>
            <span className="text-gray-400 text-sm">
              {expanded ? '▲' : '▼'}
            </span>
          </div>
        </div>

        {/* Severity distribution bar */}
        {scan.total_findings > 0 && (
          <div className="mt-3">
            <SeverityBar scan={scan} />
          </div>
        )}
      </button>

      {/* ── Expanded: findings ── */}
      {expanded && (
        <div className="border-t px-5 py-4 space-y-3 bg-gray-50">

          {/* AI Report */}
          <AiReportPanel report={aiReport} />

          {loading && (
            <div className="space-y-2">
              {[1,2].map(i => <div key={i} className="skeleton h-14 rounded-lg" />)}
            </div>
          )}

          {error && (
            <p className="text-sm text-red-600">{error}</p>
          )}

          {!loading && findings.length === 0 && !error && (
            <p className="text-sm text-gray-400 text-center py-4">
              No findings recorded for this scan.
            </p>
          )}

          {!loading && findings.map(f => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export default function ScanHistory() {
  const [scans,    setScans]    = useState([])
  const [page,     setPage]     = useState(0)
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)
  const [hasMore,  setHasMore]  = useState(true)
  const pollRef = useRef(null)

  const fetchPage = async (offset) => {
    setLoading(true)
    setError(null)
    try {
      const data = await listScans(PAGE_SIZE, offset)
      setScans(data)
      setHasMore(data.length === PAGE_SIZE)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPage(page * PAGE_SIZE)
  }, [page])

  // Auto-refresh if any scan is in progress (running or pending)
  useEffect(() => {
    const hasInProgress = scans.some(
      s => s.status === 'running' || s.status === 'pending'
    )
    if (hasInProgress) {
      pollRef.current = setInterval(() => fetchPage(page * PAGE_SIZE), 3000)
    } else {
      clearInterval(pollRef.current)
    }
    return () => clearInterval(pollRef.current)
  }, [scans, page])

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-5">

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scan History</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            All past scan runs — click a row to see its findings
          </p>
        </div>
        <button
          onClick={() => fetchPage(page * PAGE_SIZE)}
          className="text-sm text-blue-600 hover:text-blue-800"
        >
          ↻ Refresh
        </button>
      </div>

      {/* ── Error ── */}
      {error && (
        <div className="rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* ── Loading ── */}
      {loading && (
        <div className="space-y-3">
          {[1,2,3].map(i => <div key={i} className="skeleton h-24 rounded-xl" />)}
        </div>
      )}

      {/* ── Empty state ── */}
      {!loading && scans.length === 0 && (
        <div className="rounded-xl border border-dashed border-gray-300
                        bg-gray-50 p-12 text-center">
          <p className="text-gray-400 text-sm">No scan history yet.</p>
          <p className="text-gray-400 text-xs mt-1">
            Run your first scan from the Dashboard.
          </p>
        </div>
      )}

      {/* ── Scan rows ── */}
      {!loading && scans.map(scan => (
        <ScanRow
          key={scan.id}
          scan={scan}
          onRefresh={() => fetchPage(page * PAGE_SIZE)}
        />
      ))}

      {/* ── Pagination ── */}
      {!loading && scans.length > 0 && (
        <div className="flex items-center justify-between pt-2">
          <button
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
            className="text-sm px-4 py-2 rounded-lg border border-gray-300
                       text-gray-600 hover:bg-gray-50 disabled:opacity-40
                       disabled:cursor-not-allowed transition-colors"
          >
            ← Previous
          </button>
          <span className="text-xs text-gray-400">Page {page + 1}</span>
          <button
            onClick={() => setPage(p => p + 1)}
            disabled={!hasMore}
            className="text-sm px-4 py-2 rounded-lg border border-gray-300
                       text-gray-600 hover:bg-gray-50 disabled:opacity-40
                       disabled:cursor-not-allowed transition-colors"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  )
}