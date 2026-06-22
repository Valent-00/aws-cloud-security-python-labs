/**
 * pages/UserDetail.jsx
 * ====================
 * Two-panel layout:
 *   Left  — User list sorted by highest severity
 *   Right — All findings for the selected user
 *
 * UX rules applied
 * ----------------
 * - Selected user is highlighted in the list (clear visual feedback).
 * - Highest severity badge is shown next to each username so an analyst
 *   can triage at a glance without opening each row.
 * - Right panel shows a helpful empty state when no user is selected.
 * - Finding count and acknowledged ratio are shown per user.
 * - Progressive disclosure: list first, detail on selection.
 */

import { useState, useEffect } from 'react'
import { listUsers, getUserFindings } from '../api/client'
import SeverityBadge from '../components/SeverityBadge'
import FindingCard   from '../components/FindingCard'

export default function UserDetail() {
  const [users,          setUsers]          = useState([])
  const [selectedUser,   setSelectedUser]   = useState(null)
  const [userFindings,   setUserFindings]   = useState([])
  const [loadingUsers,   setLoadingUsers]   = useState(true)
  const [loadingDetail,  setLoadingDetail]  = useState(false)
  const [usersError,     setUsersError]     = useState(null)
  const [detailError,    setDetailError]    = useState(null)

  // Load user list on mount
  useEffect(() => {
    let cancelled = false
    const load = async () => {
      setLoadingUsers(true)
      setUsersError(null)
      try {
        const data = await listUsers()
        if (!cancelled) setUsers(data)
      } catch (err) {
        if (!cancelled) setUsersError(err.message)
      } finally {
        if (!cancelled) setLoadingUsers(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  // Load findings when a user is selected
  const handleSelectUser = async (username) => {
    setSelectedUser(username)
    setUserFindings([])
    setDetailError(null)
    setLoadingDetail(true)
    try {
      const data = await getUserFindings(username)
      setUserFindings(data)
    } catch (err) {
      setDetailError(err.message)
    } finally {
      setLoadingDetail(false)
    }
  }

  // Update local finding state when analyst acknowledges inline
  const handleAckChange = (updated) => {
    setUserFindings(prev =>
      prev.map(f => f.id === updated.id ? { ...f, ...updated } : f)
    )
  }

  // Severity dot colour for the list
  const dotColour = (sev) => ({
    Critical: 'bg-red-500',
    High:     'bg-orange-500',
    Medium:   'bg-yellow-400',
    Low:      'bg-blue-400',
    Info:     'bg-gray-300',
  }[sev] ?? 'bg-gray-300')

  return (
    <div className="flex h-full">

      {/* ── Left panel: user list ── */}
      <div className="w-64 shrink-0 border-r bg-white flex flex-col">
        <div className="px-4 py-4 border-b">
          <h1 className="text-base font-bold text-gray-900">Users</h1>
          <p className="text-xs text-gray-400 mt-0.5">Select a user to view findings</p>
        </div>

        <div className="flex-1 overflow-y-auto">

          {loadingUsers && (
            <div className="p-4 space-y-3">
              {[1,2,3,4,5].map(i => (
                <div key={i} className="skeleton h-14 rounded-lg" />
              ))}
            </div>
          )}

          {usersError && (
            <div className="p-4 text-xs text-red-600">{usersError}</div>
          )}

          {!loadingUsers && users.length === 0 && (
            <div className="p-4 text-xs text-gray-400 text-center">
              No users found. Run a scan first.
            </div>
          )}

          {!loadingUsers && users.map(user => (
            <button
              key={user.username}
              onClick={() => handleSelectUser(user.username)}
              className={`
                w-full text-left px-4 py-3 border-b transition-colors
                ${selectedUser === user.username
                  ? 'bg-blue-50 border-l-4 border-l-blue-500'
                  : 'hover:bg-gray-50 border-l-4 border-l-transparent'}
              `}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium text-gray-800 truncate">
                  {user.username}
                </span>
                <SeverityBadge severity={user.highest_severity} size="sm" />
              </div>
              <div className="flex items-center gap-2 mt-1">
                <span className={`w-2 h-2 rounded-full shrink-0 ${dotColour(user.highest_severity)}`} />
                <span className="text-xs text-gray-400">
                  {user.finding_count} finding{user.finding_count !== 1 ? 's' : ''}
                  {user.unacknowledged > 0 && (
                    <span className="text-orange-500 ml-1">
                      · {user.unacknowledged} unreviewed
                    </span>
                  )}
                </span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* ── Right panel: findings detail ── */}
      <div className="flex-1 overflow-y-auto p-6">

        {/* No user selected */}
        {!selectedUser && (
          <div className="h-full flex flex-col items-center justify-center text-center">
            <span className="text-5xl mb-4">👤</span>
            <p className="text-gray-400 text-sm">Select a user from the list</p>
            <p className="text-gray-300 text-xs mt-1">to see their security findings</p>
          </div>
        )}

        {/* User selected — show findings */}
        {selectedUser && (
          <div className="max-w-3xl space-y-4">

            {/* Detail header */}
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-gray-900">{selectedUser}</h2>
                <p className="text-xs text-gray-400 mt-0.5">
                  {userFindings.length} finding{userFindings.length !== 1 ? 's' : ''} across all scans
                </p>
              </div>
              {userFindings.length > 0 && (
                <SeverityBadge
                  severity={userFindings[0].severity}
                  size="md"
                />
              )}
            </div>

            {/* Loading */}
            {loadingDetail && (
              <div className="space-y-3">
                {[1,2,3].map(i => (
                  <div key={i} className="skeleton h-16 rounded-lg" />
                ))}
              </div>
            )}

            {/* Error */}
            {detailError && (
              <div className="rounded-lg bg-red-50 border border-red-200 p-4
                              text-sm text-red-700">
                {detailError}
              </div>
            )}

            {/* No findings */}
            {!loadingDetail && !detailError && userFindings.length === 0 && (
              <div className="rounded-xl border border-dashed border-gray-300
                              bg-gray-50 p-10 text-center">
                <p className="text-gray-400 text-sm">No findings for this user.</p>
              </div>
            )}

            {/* Finding cards */}
            {!loadingDetail && userFindings.map(f => (
              <FindingCard
                key={f.id}
                finding={f}
                onAckChange={handleAckChange}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}