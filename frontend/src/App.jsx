/**
 * App.jsx
 * =======
 * Root component. Owns the navigation sidebar and React Router route
 * definitions. Every page component is lazy-loaded so the initial
 * bundle stays small (code splitting — performance best practice).
 *
 * Security fix — session hydration (Fix #1 follow-through)
 * -----------------------------------------------------------
 * Previously: `useState(getSession())` read a locally-cached
 * { username, role } from localStorage on mount and trusted it blindly —
 * it never actually asked the backend whether the session cookie was
 * still valid. A cleared/expired cookie with a stale localStorage entry
 * would show the dashboard, then 401 on the first real API call.
 *
 * Now: on mount, we call getMe() (GET /api/v1/auth/me), which reads the
 * httpOnly cookie server-side and either confirms the session or 401s.
 * Only a confirmed 200 puts the user past the login screen. This is the
 * one required change on the frontend for Fix #1 to be end-to-end —
 * client.js and Login.jsx already assumed this pattern.
 *
 * UX rules applied
 * ----------------
 * - Active nav link is highlighted so the user always knows where they are.
 * - Layout is fixed sidebar + scrollable main — standard dashboard pattern.
 * - Backend connection error is surfaced in a top banner visible on every page.
 * - A brief full-screen loading state covers the /auth/me round trip so the
 *   login screen never flashes for an already-authenticated user on refresh.
 */

import { useState, useEffect, Suspense, lazy } from 'react'
import { BrowserRouter, NavLink, Routes, Route, Navigate } from 'react-router-dom'
import { getDashboard, getMe, logout } from './api/client'
import Login from './pages/Login'

// Lazy-load pages — each becomes a separate JS chunk
const Dashboard    = lazy(() => import('./pages/Dashboard'))
const Findings     = lazy(() => import('./pages/Findings'))
const UserDetail   = lazy(() => import('./pages/UserDetail'))
const ScanHistory  = lazy(() => import('./pages/ScanHistory'))
const Analytics    = lazy(() => import('./pages/Analytics'))
const AwsReports   = lazy(() => import('./pages/AwsReports'))

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
// Full-screen skeleton shown while GET /auth/me is in flight on mount —
// prevents a flash of the Login screen for an already-authenticated user.
// ---------------------------------------------------------------------------
function SessionCheckSkeleton() {
  return (
    <div className="h-screen w-screen flex items-center justify-center bg-gray-50">
      <div className="flex flex-col items-center gap-3">
        <span className="text-3xl">🛡️</span>
        <p className="text-sm text-gray-400">Checking session…</p>
      </div>
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
  const [session, setSession] = useState(null)          // null until confirmed by /auth/me
  const [checkingSession, setCheckingSession] = useState(true)
  const [apiReachable, setApiReachable] = useState(null) // null=unknown, true, false

  // On mount: validate the httpOnly cookie against the backend instead of
  // trusting whatever was last cached in localStorage.
  useEffect(() => {
    getMe()
      .then((data) => setSession(data))
      .catch(() => setSession(null))
      .finally(() => setCheckingSession(false))
  }, [])

  // If any API call comes back 401 (expired/invalid cookie), client.js
  // clears the stored display session and fires this event — drop back
  // to Login immediately rather than waiting for a manual refresh.
  useEffect(() => {
    const handleUnauthorized = () => setSession(null)
    window.addEventListener('auth:unauthorized', handleUnauthorized)
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized)
  }, [])

  // Probe backend once we have a session — shows/hides the connection banner
  useEffect(() => {
    if (!session) return
    getDashboard()
      .then(() => setApiReachable(true))
      .catch(() => setApiReachable(false))
  }, [session])

  const handleLogout = async () => {
    await logout()
    setSession(null)
  }

  // Still waiting on the initial /auth/me round trip — avoid flashing Login.
  if (checkingSession) {
    return <SessionCheckSkeleton />
  }

  // No confirmed session → show the login screen, nothing else.
  if (!session) {
    return <Login onLoggedIn={setSession} />
  }

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
            <NavLink to="/analytics"   className={navClass}>
              <span>📈</span> Analytics
            </NavLink>
            <NavLink to="/aws-reports" className={navClass}>
              <span>☁️</span> AWS Reports
            </NavLink>
          </nav>

          {/* Footer */}
          <div className="px-5 py-4 border-t border-blue-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-white text-xs font-medium">{session.username}</p>
                <p className="text-blue-400 text-xs capitalize">{session.role}</p>
              </div>
              <button
                onClick={handleLogout}
                className="text-blue-300 hover:text-white text-xs font-medium"
              >
                Log out
              </button>
            </div>
            <p className="text-blue-500 text-xs mt-2">
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
                <Route path="/analytics" element={<Analytics />} />
                <Route path="/aws-reports" element={<AwsReports />} />
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