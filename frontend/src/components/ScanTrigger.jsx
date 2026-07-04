/**
 * components/ScanTrigger.jsx
 * ==========================
 * "Run Scan Now" button that:
 *   1. POSTs to /api/v1/scans to start a background scan.
 *   2. Polls /api/v1/scans/{id}/status every 2 seconds.
 *   3. Calls onScanComplete(scanData) when the scan finishes.
 *   4. Shows a spinner and disables itself while a scan is in progress.
 *
 * UX rules applied
 * ----------------
 * - System status is always visible: "Scanning… (8s)" keeps the user informed.
 * - The button is disabled during scan to prevent double-submission.
 * - Error state is surfaced inline — not silently swallowed.
 * - onScanComplete callback allows the parent (Dashboard) to refresh data.
 */

import { useState, useEffect, useRef } from 'react'
import { triggerScan, getScanStatus } from '../api/client'

/**
 * @param {{ onScanComplete: (scan: object) => void }} props
 */
export default function ScanTrigger({ onScanComplete }) {
  const [scanning,  setScanning]  = useState(false)
  const [elapsed,   setElapsed]   = useState(0)
  const [error,     setError]     = useState(null)
  const pollRef   = useRef(null)
  const timerRef  = useRef(null)

  // Cleanup on unmount
  useEffect(() => () => {
    clearInterval(pollRef.current)
    clearInterval(timerRef.current)
  }, [])

  const startScan = async () => {
    setScanning(true)
    setElapsed(0)
    setError(null)

    // Elapsed time counter — shows user the scan is progressing
    timerRef.current = setInterval(() => setElapsed((s) => s + 1), 1000)

    try {
      const scan = await triggerScan()

      // Poll until completed or failed
      pollRef.current = setInterval(async () => {
        try {
          const status = await getScanStatus(scan.id)
          if (status.status === 'completed' || status.status === 'failed') {
            clearInterval(pollRef.current)
            clearInterval(timerRef.current)
            setScanning(false)
            if (status.status === 'failed') {
              setError(status.error_message || 'Scan failed.')
            } else {
              onScanComplete?.(status)
            }
          }
        } catch (pollErr) {
          clearInterval(pollRef.current)
          clearInterval(timerRef.current)
          setScanning(false)
          setError(pollErr.message)
        }
      }, 2000)

    } catch (err) {
      clearInterval(timerRef.current)
      setScanning(false)
      setError(err.message)
    }
  }

  return (
    <div className="flex items-center gap-3">
      <button
        onClick={startScan}
        disabled={scanning}
        className={`
          inline-flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-sm
          transition-all shadow-sm
          ${scanning
            ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
            : 'bg-blue-600 text-white hover:bg-blue-700 active:scale-95'}
        `}
      >
        {scanning ? (
          <>
            {/* Spinner */}
            <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10"
                      stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor"
                    d="M4 12a8 8 0 018-8v8H4z" />
            </svg>
            Scanning… ({elapsed}s)
          </>
        ) : (
          <>
            {/* Shield icon */}
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24"
                 stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round"
                    d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0
                       013.598 6 11.98 11.98 0 003 9.749c0 5.592 3.824
                       10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21
                       -2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
            Run Scan Now
          </>
        )}
      </button>

      {error && (
        <p className="text-sm text-red-600 bg-red-50 border border-red-200
                      rounded px-3 py-1.5">
          {error}
        </p>
      )}
    </div>
  )
}