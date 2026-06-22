/**
 * components/AiReportPanel.jsx
 * =============================
 * Renders the Ollama AI executive report when available.
 *
 * Props
 * -----
 * report    : string | null  — the AI report text
 * showEmpty : boolean        — if false (default), renders nothing when
 *                              report is null. Set to true on Dashboard
 *                              to show the "start Ollama" hint.
 */

import { useState } from 'react'

/** @param {{ report: string|null, showEmpty?: boolean }} props */
export default function AiReportPanel({ report, showEmpty = false }) {
  const [open, setOpen] = useState(false)

  // No report — only show empty state if explicitly requested
  if (!report) {
    if (!showEmpty) return null
    return (
      <div className="rounded-lg border border-dashed border-gray-300 bg-gray-50 p-5 text-center">
        <p className="text-sm text-gray-400">
          AI executive report not available for this scan.
        </p>
        <p className="text-xs text-gray-400 mt-1">
          Start Ollama with{' '}
          <code className="bg-gray-100 px-1 rounded">ollama serve</code>{' '}
          to enable AI reports.
        </p>
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-purple-200 bg-purple-50">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 text-left"
      >
        <span className="flex items-center gap-2 text-sm font-semibold text-purple-800">
          <span>🤖</span> AI Executive Report
        </span>
        <span className="text-purple-500 text-xs">
          {open ? '▲ Collapse' : '▼ Expand'}
        </span>
      </button>

      {open && (
        <div className="border-t border-purple-200 px-4 py-4">
          <pre className="text-sm text-gray-800 whitespace-pre-wrap font-sans leading-relaxed">
            {report}
          </pre>
        </div>
      )}
    </div>
  )
}