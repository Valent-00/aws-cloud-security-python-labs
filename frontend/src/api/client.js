/**
 * api/client.js
 * =============
 * Centralised Axios instance and all API call functions.
 *
 * Security — Fix #1 (JWT no longer stored in localStorage)
 * ---------------------------------------------------------
 * The JWT is now held exclusively in an httpOnly cookie set by the
 * backend login route. This means:
 *   * JavaScript (including any XSS payload) can NEVER read the token.
 *   * The browser sends the cookie automatically on every same-origin
 *     request — no manual Authorization header attachment needed.
 *   * localStorage only stores { username, role } — display-only data
 *     that carries no authentication power on its own.
 *
 * Session hydration
 * -----------------
 * On page load, App.jsx calls getMe() to hit GET /api/v1/auth/me.
 * If the cookie is present and valid, the backend returns { username, role }.
 * If the cookie is absent or expired, it returns 401 → App.jsx shows Login.
 * This replaces the old pattern of reading the JWT from localStorage.
 *
 * Logout
 * ------
 * logout() calls POST /api/v1/auth/logout on the backend, which clears
 * the httpOnly cookie server-side. The client cannot clear an httpOnly
 * cookie via JavaScript — this is the correct pattern.
 */

import axios from 'axios'

// ---------------------------------------------------------------------------
// Session storage — display-only data (NO token stored here)
// The JWT lives exclusively in the httpOnly cookie managed by the browser.
// ---------------------------------------------------------------------------
const SESSION_KEY = 'iam_scanner_session'   // { username, role } — no token

/**
 * Read the display session from localStorage.
 * Returns null if no session exists or parsing fails.
 * This does NOT indicate whether the auth cookie is valid —
 * use getMe() for that.
 */
export const getSession = () => {
  try {
    const raw = localStorage.getItem(SESSION_KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

const _setSession = (session) => {
  // Only store display-safe fields — never the token.
  const { username, role } = session
  localStorage.setItem(SESSION_KEY, JSON.stringify({ username, role }))
}

export const clearSession = () => {
  localStorage.removeItem(SESSION_KEY)
}

export const isLoggedIn = () => getSession() !== null

// ---------------------------------------------------------------------------
// Axios instance
// ---------------------------------------------------------------------------
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '',
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
  // Fix #1: withCredentials = true tells the browser to include the
  // httpOnly cookie on every cross-origin request (e.g. Vite dev proxy).
  // Without this, the browser would silently drop the cookie.
  withCredentials: true,
})

// Response interceptor — normalise errors and handle 401 globally.
// NOTE: No request interceptor needed — the browser attaches the cookie
// automatically. Manual Authorization header injection is removed.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Cookie expired or invalid — clear display session and redirect.
      clearSession()
      window.dispatchEvent(new Event('auth:unauthorized'))
    }
    const message =
      error.response?.data?.detail ||
      error.message ||
      'An unexpected error occurred.'
    return Promise.reject(new Error(message))
  }
)

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/**
 * Log in: sends credentials to the backend, which sets the httpOnly cookie
 * and returns { username, role }. We store only the display fields locally.
 *
 * @param {string} username
 * @param {string} password
 * @returns {Promise<{ username: string, role: string }>}
 */
export const login = (username, password) =>
  api.post('/api/v1/auth/login', { username, password }).then((r) => {
    // r.data = { username, role } — NO token in the response body.
    // The httpOnly cookie was set automatically by the Set-Cookie header.
    _setSession(r.data)
    return r.data
  })

/**
 * Verify the current session by calling /auth/me.
 * Returns { username, role } if the cookie is valid, throws on 401.
 * Used by App.jsx on page load to hydrate session state without
 * reading the token (which is now inaccessible to JS).
 *
 * @returns {Promise<{ username: string, role: string }>}
 */
export const getMe = () =>
  api.get('/api/v1/auth/me').then((r) => {
    _setSession(r.data)
    return r.data
  })

/**
 * Log out: asks the backend to clear the httpOnly cookie, then removes
 * the local display session. Never try to clear an httpOnly cookie from
 * JS — it won't work and the server call is the correct pattern.
 *
 * @returns {Promise<void>}
 */
export const logout = () =>
  api.post('/api/v1/auth/logout')
     .catch(() => {})   // swallow errors — always clear local state
     .finally(() => clearSession())

// ---------------------------------------------------------------------------
// API functions — one per backend endpoint
// ---------------------------------------------------------------------------

/** Trigger a new scan. Returns { id, status: 'pending', ... } */
export const triggerScan = () =>
  api.post('/api/v1/scans').then((r) => r.data)

/** List recent scan runs. */
export const listScans = (limit = 20, offset = 0) =>
  api.get('/api/v1/scans', { params: { limit, offset } }).then((r) => r.data)

/** Poll a scan's status by ID. */
export const getScanStatus = (scanId) =>
  api.get(`/api/v1/scans/${scanId}/status`).then((r) => r.data)

/** Get all findings for a specific scan, with optional severity filter. */
export const getScanFindings = (scanId, severity = null) =>
  api
    .get(`/api/v1/scans/${scanId}/findings`, {
      params: severity ? { severity } : {},
    })
    .then((r) => r.data)

/** Get the dashboard summary (severity counts, last scan info). */
export const getDashboard = () =>
  api.get('/api/v1/dashboard').then((r) => r.data)

/** Get per-user finding summaries. */
export const listUsers = () =>
  api.get('/api/v1/users').then((r) => r.data)

/** Get all findings for one user. */
export const getUserFindings = (username) =>
  api.get(`/api/v1/users/${username}/findings`).then((r) => r.data)

/** Acknowledge a finding with an optional analyst note. */
export const acknowledgeFinding = (findingId, note = null) =>
  api
    .patch(`/api/v1/findings/${findingId}/acknowledge`, { note })
    .then((r) => r.data)

/** Remove acknowledgement from a finding. */
export const unacknowledgeFinding = (findingId) =>
  api.delete(`/api/v1/findings/${findingId}/acknowledge`).then((r) => r.data)

// ---------------------------------------------------------------------------
// Analytics
// ---------------------------------------------------------------------------

/** Per-scan risk score trend (avg/max + severity counts), oldest first. */
export const getRiskTrend = (limit = 30) =>
  api.get('/api/v1/analytics/risk-trend', { params: { limit } }).then((r) => r.data)

/** Finding counts grouped by MITRE ATT&CK tactic/technique. */
export const getMitreCoverage = (scanId = null) =>
  api
    .get('/api/v1/analytics/mitre-coverage', {
      params: scanId ? { scan_id: scanId } : {},
    })
    .then((r) => r.data)

/** Finding counts grouped by alert type, with each type's highest severity. */
export const getAlertTypeBreakdown = (scanId = null) =>
  api
    .get('/api/v1/analytics/alert-type-breakdown', {
      params: scanId ? { scan_id: scanId } : {},
    })
    .then((r) => r.data)

/** High-level scan run statistics — totals, success rate, avg findings/scan. */
export const getScanStats = () =>
  api.get('/api/v1/analytics/scan-stats').then((r) => r.data)

// S3 reports produced by the scheduled AWS Lambda.
export const listS3Reports = (maxResults = 50) =>
  api.get('/api/v1/s3-reports', { params: { max_results: maxResults } }).then((r) => r.data)

export const getS3Report = (key) =>
  api
    .get(`/api/v1/s3-reports/${key.split('/').map(encodeURIComponent).join('/')}`)
    .then((r) => r.data)