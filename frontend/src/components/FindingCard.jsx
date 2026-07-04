/**
 * components/FindingCard.jsx
 * ===========================
 * Renders a single security finding: severity, alert type, risk score,
 * description, SLA, and an inline acknowledge / undo action.
 *
 * Props
 * -----
 * finding     : FindingResponse — { id, username, alert_type, severity,
 *                                    risk_score, detail, sla, acknowledged,
 *                                    ack_note, ack_at }
 * onAckChange : (updated: object) => void
 *               Called with the server response after an ack/unack action
 *               so the parent list can merge the change without refetching.
 *
 * UX rules applied
 * -----------------
 * - Acknowledged findings are visually de-emphasised (reduced opacity,
 *   muted border) to cut down on alert fatigue while staying visible.
 * - The acknowledge action shows a busy state and disables itself while
 *   the request is in flight; errors surface inline, not silently.
 */

import { useState } from 'react'
import { acknowledgeFinding, unacknowledgeFinding } from '../api/client'
import SeverityBadge from './SeverityBadge'

/** @param {{ finding: object, onAckChange?: (updated: object) => void }} props */
export default function FindingCard({ finding, onAckChange }) {
  const [note,  setNote]  = useState('')
  const [busy,  setBusy]  = useState(false)
  const [error, setError] = useState(null)

  const handleAcknowledge = async () => {
    setBusy(true)
    setError(null)
    try {
      const updated = await acknowledgeFinding(finding.id, note.trim() || null)
      onAckChange?.(updated)
      setNote('')
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const handleUndo = async () => {
    setBusy(true)
    setError(null)
    try {
      const updated = await unacknowledgeFinding(finding.id)
      onAckChange?.(updated)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      className={`rounded-xl border p-4 transition-opacity ${
        finding.acknowledged
          ? 'border-gray-200 bg-gray-50 opacity-60'
          : 'border-gray-200 bg-white shadow-sm'
      }`}
    >
      {/* ── Header row ── */}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={finding.severity} size="sm" />
          <span className="text-sm font-semibold text-gray-900">
            {finding.alert_type}
          </span>
          <span className="text-xs text-gray-400">· {finding.username}</span>
        </div>
        <div className="flex items-center gap-3 text-xs text-gray-400 shrink-0">
          <span>Risk {finding.risk_score}</span>
          <span className="text-orange-500">{finding.sla}</span>
        </div>
      </div>

      {/* ── MITRE ATT&CK reference (only shown when a technique is mapped —
            behavioural signals like Off-Hours Login have none, by design) ── */}
      {finding.mitre_technique && (
        <p className="text-[11px] text-purple-600 font-medium mt-1.5">
          🎯 {finding.mitre_technique} — {finding.mitre_tactic}
        </p>
      )}

      {/* ── Detail ── */}
      <p className="text-sm text-gray-600 mt-2 leading-relaxed">
        {finding.detail}
      </p>

      {/* ── Inline error ── */}
      {error && <p className="text-xs text-red-600 mt-2">{error}</p>}

      {/* ── Acknowledge / Acknowledged state ── */}
      {finding.acknowledged ? (
        <div className="flex items-center justify-between gap-3 mt-3 pt-3 border-t border-gray-200">
          <div className="text-xs text-gray-500">
            <span className="text-green-600 font-medium">✓ Acknowledged</span>
            {finding.ack_note && <span className="ml-2">— {finding.ack_note}</span>}
            {finding.ack_at && (
              <span className="ml-2 text-gray-400">
                ({new Date(finding.ack_at).toLocaleString()})
              </span>
            )}
          </div>
          <button
            onClick={handleUndo}
            disabled={busy}
            className="text-xs text-blue-600 hover:text-blue-800 disabled:opacity-50 whitespace-nowrap"
          >
            {busy ? 'Undoing…' : 'Undo'}
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-2 mt-3 pt-3 border-t border-gray-100">
          <input
            type="text"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Optional note…"
            maxLength={500}
            className="flex-1 min-w-[120px] text-xs rounded-md border border-gray-300
                       px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <button
            onClick={handleAcknowledge}
            disabled={busy}
            className="text-xs font-medium px-3 py-1.5 rounded-md bg-blue-600 text-white
                       hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap"
          >
            {busy ? 'Saving…' : 'Acknowledge'}
          </button>
        </div>
      )}
    </div>
  )
}