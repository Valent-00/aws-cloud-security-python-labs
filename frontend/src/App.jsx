/**
 * App.jsx
 * =======
 * Root component. Owns the navigation sidebar and React Router route
 * definitions. Every page component is lazy-loaded so the initial
 * bundle stays small (code splitting — performance best practice).
 *
 * UX rules applied
 * ----------------
 * - Active nav link is highlighted so the user always knows where they are.
 * - Layout is fixed sidebar + scrollable main — standard dashboard pattern.
 * - Backend connection error is surfaced in a top banner visible on every page.
 */

import { useState, useEffect, Suspense, lazy } from 'react'
import { BrowserRouter, NavLink, Routes, Route, Navigate } from 'react-router-dom'
import { getDashboard } from './api/client'

// Lazy-load pages — each becomes a separate JS chunk
const Dashboard    = lazy(() => import('./pages/Dashboard'))
const Findings     = lazy(() => import('./pages/Findings'))
const UserDetail   = lazy(() => import('./pages/UserDetail'))
const ScanHistory  = lazy(() => import('./pages/ScanHistory'))

// ---------------------------------------------------------------------------
// Nav link style helper — active vs inactive state
// ---------------------------------------------------------------------------
const navClass = ({ isActive }) =>
  [
    'flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors',
    isActive
      ? 'bg-blue-700 text-white'
      : 'text-blue-100 hover:bg-blue-700/60 hover:text-white',
  ].join(' ')

// ---------------------------------------------------------------------------
// Page-level loading skeleton shown while a lazy chunk is fetching
// ---------------------------------------------------------------------------
function PageSkeleton() {
  return (
    <div className="p-8 space-y-4 animate-pulse">
      <div className="skeleton h-8 w-48 rounded" />
      <div className="skeleton h-4 w-72 rounded" />
      <div className="grid grid-cols-4 gap-4 mt-6">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="skeleton h-28 rounded-xl" />
        ))}
      </div>
      <div className="skeleton h-64 rounded-xl mt-4" />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Backend connection banner — shown when the API is unreachable
// ---------------------------------------------------------------------------
function ConnectionBanner({ reachable }) {
  if (reachable !== false) return null
  return (
    <div className="bg-red-600 text-white text-sm px-4 py-2 flex items-center gap-2">
      <span>⚠</span>
      <span>
        Cannot reach the backend API at{' '}
        <code className="bg-red-700 px-1 rounded">localhost:8000</code>.
        Make sure FastAPI is running:{' '}
        <code className="bg-red-700 px-1 rounded">uvicorn main:app --reload --port 8000</code>
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main App
// ---------------------------------------------------------------------------
export default function App() {
  const [apiReachable, setApiReachable] = useState(null) // null=unknown, true, false

  // Probe backend once on mount — shows/hides the connection banner
  useEffect(() => {
    getDashboard()
      .then(() => setApiReachable(true))
      .catch(() => setApiReachable(false))
  }, [])

  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden bg-gray-50">

        {/* ── Sidebar navigation ── */}
        <aside className="w-56 shrink-0 bg-blue-800 flex flex-col">

          {/* Logo / brand */}
          <div className="px-5 py-5 border-b border-blue-700">
            <div className="flex items-center gap-2">
              <span className="text-2xl">🛡️</span>
              <div>
                <p className="text-white font-bold text-sm leading-tight">IAM Scanner</p>
                <p className="text-blue-300 text-xs">Security Dashboard</p>
              </div>
            </div>
          </div>

          {/* Nav links */}
          <nav className="flex-1 px-3 py-4 space-y-1">
            <NavLink to="/dashboard"   className={navClass}>
              <span>📊</span> Dashboard
            </NavLink>
            <NavLink to="/findings"    className={navClass}>
              <span>🔍</span> Findings
            </NavLink>
            <NavLink to="/users"       className={navClass}>
              <span>👤</span> Users
            </NavLink>
            <NavLink to="/history"     className={navClass}>
              <span>🕐</span> Scan History
            </NavLink>
          </nav>

          {/* Footer */}
          <div className="px-5 py-4 border-t border-blue-700">
            <p className="text-blue-400 text-xs">v2.0.0 · IAM Scanner</p>
            <p className="text-blue-500 text-xs mt-0.5">
              Backend:{' '}
              <span className={apiReachable === false ? 'text-red-400' : 'text-green-400'}>
                {apiReachable === null ? '…' : apiReachable ? 'Connected' : 'Offline'}
              </span>
            </p>
          </div>
        </aside>

        {/* ── Main content ── */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* Connection warning banner */}
          <ConnectionBanner reachable={apiReachable} />

          {/* Scrollable page area */}
          <main className="flex-1 overflow-y-auto">
            <Suspense fallback={<PageSkeleton />}>
              <Routes>
                <Route path="/"          element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard onApiStatus={setApiReachable} />} />
                <Route path="/findings"  element={<Findings />} />
                <Route path="/users"     element={<UserDetail />} />
                <Route path="/history"   element={<ScanHistory />} />
                {/* Catch-all → redirect home */}
                <Route path="*"          element={<Navigate to="/dashboard" replace />} />
              </Routes>
            </Suspense>
          </main>
        </div>
      </div>
    </BrowserRouter>
  )
}