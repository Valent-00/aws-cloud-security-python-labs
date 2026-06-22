/**
 * api/client.js
 * =============
 * Centralised Axios instance and all API call functions.
 *
 * Why centralise?
 * ---------------
 * If the backend URL or an endpoint path changes, you fix it in ONE place.
 * Components never import axios directly — they import from this file.
 *
 * Base URL is read from the Vite environment variable VITE_API_BASE_URL.
 * In development, Vite's proxy handles /api → localhost:8000 automatically,
 * so the base URL can be left as an empty string.
 */

import axios from 'axios'

// ---------------------------------------------------------------------------
// Axios instance
// ---------------------------------------------------------------------------
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '',
  timeout: 30_000,   // 30 s — scans can take a few seconds
  headers: { 'Content-Type': 'application/json' },
})

// Response interceptor — normalise error shape for all callers
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const message =
      error.response?.data?.detail ||
      error.message ||
      'An unexpected error occurred.'
    return Promise.reject(new Error(message))
  }
)

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