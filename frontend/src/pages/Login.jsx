/**
 * pages/Login.jsx
 * ================
 * Standalone login screen — rendered instead of the sidebar layout
 * whenever there is no active session.
 *
 * There is deliberately no "Sign up" link here. Accounts are provisioned
 * out-of-band via `python scripts/create_analyst.py` — see auth.py on the
 * backend for the full rationale (a SOC tool shouldn't let anyone
 * self-enroll as an analyst).
 *
 * Props
 * -----
 * onLoggedIn : ({ username, role }) => void
 *              Called with the session info after a successful login.
 */

import { useState } from 'react'
import { login } from '../api/client'

export default function Login({ onLoggedIn }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy]         = useState(false)
  const [error, setError]       = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const session = await login(username.trim(), password)
      onLoggedIn(session)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-sm">

        {/* Brand */}
        <div className="flex flex-col items-center mb-6">
          <span className="text-4xl mb-2">🛡️</span>
          <h1 className="text-lg font-bold text-gray-900">IAM Scanner</h1>
          <p className="text-sm text-gray-500">Sign in to the Security Dashboard</p>
        </div>

        {/* Login card */}
        <form
          onSubmit={handleSubmit}
          className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 space-y-4"
        >
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              required
              className="w-full text-sm rounded-md border border-gray-300 px-3 py-2
                         focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full text-sm rounded-md border border-gray-300 px-3 py-2
                         focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
          </div>

          {error && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full text-sm font-medium px-4 py-2.5 rounded-lg bg-blue-700 text-white
                       hover:bg-blue-800 disabled:opacity-50 transition-colors"
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="text-xs text-gray-400 text-center mt-4">
          No account? Ask an admin to run{' '}
          <code className="bg-gray-100 px-1 rounded">scripts/create_analyst.py</code>.
        </p>
      </div>
    </div>
  )
}