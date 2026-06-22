/**
 * pages/Findings.jsx
 * ==================
 * Full findings table from the most recent scan.
 *
 * Features
 * --------
 *  - Severity filter tabs (All / Critical / High / Medium / Low / Info)
 *  - Live search by username or alert type
 *  - Show/hide acknowledged findings toggle
 *  - FindingCard for each result (with inline acknowledge action)
 *  - URL-driven filter: ?severity=Critical pre-selects the tab
 *    (used by Dashboard severity cards)
 *
 * UX rules applied
 * ----------------
 * - Filter tabs use the same severity colour palette as SeverityBadge.
 * - Active filter is clearly highlighted.
 * - Empty state message changes depending on whether a filter is active.
 * - Search is debounced — does not fire an API call on every keystroke
 *   (client-side filter on already-loaded data).
 */

import { useState, useEffect, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { getDashboard, getScanFindings } from '../api/client'
import FindingCard   from '../components/FindingCard'
import SeverityBadge from '../components/SeverityBadge'

const SEVERITY_TABS = ['All', 'Critical', 'High', 'Medium', 'Low', 'Info']

const TAB_STYLES = {
  All:      'bg-gray-100   text-gray-700  border-gray-300',
  Critical: 'bg-red-100    text-red-800   border-red-300',
  High:     'bg-orange-100 text-orange-800 border-orange-300',
  Medium:   'bg-yellow-100 text-yellow-800 border-yellow-300',
  Low:      'bg-blue-100   text-blue-800  border-blue-300',
  Info:     'bg-gray-100   text-gray-500  border-gray-200',
}

export default function Findings() {
  const [searchParams, setSearchParams] = useSearchParams()

  // Read ?severity= from URL — set by Dashboard card clicks
  const urlSeverity = searchParams.get('severity') || 'All'

  const [allFindings,   setAllFindings]   = useState([])
  const [activeTab,     setActiveTab]     = useState(
    SEVERITY_TABS.includes(urlSeverity) ? urlSeverity : 'All'
  )
  const [search,        setSearch]        = useState('')
  const [showAcked,     setShowAcked]     = useState(false)
  const [loading,       setLoading]       = useState(true)
  const [error,         setError]         = useState(null)
  const [scanId,        setScanId]        = useState(null)

  // Sync URL param → tab on mount
  useEffect(() => {
    if (SEVERITY_TABS.includes(urlSeverity)) setActiveTab(urlSeverity)
  }, [urlSeverity])

  // Fetch latest scan's findings once
  useEffect(() => {
    let cancelled = false
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const dash = await getDashboard()
        if (!dash.last_scan_id) { setLoading(false); return }
        setScanId(dash.last_scan_id)
        const data = await getScanFindings(dash.last_scan_id)
        if (!cancelled) setAllFindings(data)
      } catch (err) {
        if (!cancelled) setError(err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  // Client-side filtering — no extra network call needed
  const filtered = useMemo(() => {
    let result = allFindings

    // Severity tab
    if (activeTab !== 'All') {
      result = result.filter(f => f.severity === activeTab)
    }
    // Acknowledged toggle
    if (!showAcked) {
      result = result.filter(f => !f.acknowledged)
    }
    // Search (username or alert_type, case-insensitive)
    const q = search.trim().toLowerCase()
    if (q) {
      result = result.filter(
        f => f.username.toLowerCase().includes(q) ||
             f.alert_type.toLowerCase().includes(q)
      )
    }
    return result
  }, [allFindings, activeTab, showAcked, search])

  // Count per tab for the badge numbers
  const tabCounts = useMemo(() => {
    const counts = { All: allFindings.length }
    for (const sev of SEVERITY_TABS.slice(1)) {
      counts[sev] = allFindings.filter(f => f.severity === sev).length
    }
    return counts
  }, [allFindings])

  const handleTabClick = (tab) => {
    setActiveTab(tab)
    // Update URL so browser back button works
    if (tab === 'All') searchParams.delete('severity')
    else searchParams.set('severity', tab)
    setSearchParams(searchParams)
  }

  // When a FindingCard calls onAckChange, update local state immediately
  const handleAckChange = (updated) => {
    setAllFindings(prev =>
      prev.map(f => f.id === updated.id ? { ...f, ...updated } : f)
    )
  }

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-5">

      {/* ── Header ── */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Findings</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          {scanId ? `Showing results from scan #${scanId}` : 'Most recent scan results'}
        </p>
      </div>

      {/* ── Error ── */}
      {error && (
        <div className="rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* ── Controls row ── */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Search */}
        <input
          type="text"
          placeholder="Search by username or alert type…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="flex-1 min-w-[200px] rounded-lg border border-gray-300 px-3 py-2
                     text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
        {/* Acknowledged toggle */}
        <label className="flex items-center gap-2 text-sm text-gray-600 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showAcked}
            onChange={e => setShowAcked(e.target.checked)}
            className="rounded"
          />
          Show acknowledged
        </label>
      </div>

      {/* ── Severity filter tabs ── */}
      <div className="flex flex-wrap gap-2">
        {SEVERITY_TABS.map(tab => {
          const isActive = activeTab === tab
          return (
            <button
              key={tab}
              onClick={() => handleTabClick(tab)}
              className={`
                px-3 py-1.5 rounded-full text-xs font-medium border transition-all
                ${isActive
                  ? TAB_STYLES[tab] + ' shadow-sm ring-2 ring-offset-1 ring-gray-400'
                  : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-50'}
              `}
            >
              {tab}
              {tabCounts[tab] > 0 && (
                <span className="ml-1.5 bg-white/60 rounded-full px-1.5 py-0.5 text-xs">
                  {tabCounts[tab]}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* ── Results summary ── */}
      {!loading && (
        <p className="text-xs text-gray-400">
          Showing <strong>{filtered.length}</strong> of{' '}
          <strong>{allFindings.length}</strong> findings
          {!showAcked && ' (acknowledged hidden)'}
        </p>
      )}

      {/* ── Loading skeletons ── */}
      {loading && (
        <div className="space-y-3">
          {[1,2,3,4,5].map(i => (
            <div key={i} className="skeleton h-16 rounded-lg" />
          ))}
        </div>
      )}

      {/* ── Empty state ── */}
      {!loading && filtered.length === 0 && (
        <div className="rounded-xl border border-dashed border-gray-300
                        bg-gray-50 p-12 text-center">
          <p className="text-gray-400 text-sm">
            {allFindings.length === 0
              ? 'No findings yet. Run a scan from the Dashboard.'
              : activeTab !== 'All'
              ? `No ${activeTab} findings match your search.`
              : 'No findings match your current filters.'}
          </p>
        </div>
      )}

      {/* ── Finding cards ── */}
      {!loading && filtered.length > 0 && (
        <div className="space-y-3">
          {filtered.map(f => (
            <FindingCard
              key={f.id}
              finding={f}
              onAckChange={handleAckChange}
            />
          ))}
        </div>
      )}
    </div>
  )
}