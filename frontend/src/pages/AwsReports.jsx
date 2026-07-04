import { useEffect, useState } from 'react'
import { getS3Report, listS3Reports } from '../api/client'
import SeverityBadge from '../components/SeverityBadge'

export default function AwsReports() {
  const [reports, setReports] = useState([])
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const loadReports = async () => {
    setLoading(true)
    setError(null)
    try {
      const items = await listS3Reports()
      setReports(items)
      if (items.length) setSelected(await getS3Report(items[0].key))
      else setSelected(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadReports() }, [])

  const selectReport = async (key) => {
    setLoading(true)
    setError(null)
    try { setSelected(await getS3Report(key)) }
    catch (err) { setError(err.message) }
    finally { setLoading(false) }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">AWS S3 Reports</h1>
          <p className="text-sm text-gray-500">Real reports written by the AWS Lambda scanner</p>
        </div>
        <button onClick={loadReports} className="text-sm text-blue-600 hover:text-blue-800">↻ Refresh</button>
      </div>

      {error && <div className="rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700">{error}</div>}
      {!loading && reports.length === 0 && !error && (
        <div className="rounded-xl border border-dashed p-10 text-center text-sm text-gray-500">
          No S3 reports found. Check REPORT_BUCKET and the backend's AWS credentials.
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-[20rem_1fr]">
        <div className="space-y-2">
          {reports.map((report) => (
            <button key={report.key} onClick={() => selectReport(report.key)}
              className="w-full rounded-lg border bg-white p-3 text-left hover:border-blue-400">
              <p className="text-sm font-medium text-gray-800">{new Date(report.last_modified).toLocaleString()}</p>
              <p className="mt-1 truncate text-xs text-gray-400" title={report.key}>{report.key}</p>
            </button>
          ))}
        </div>

        {selected && (
          <div className="rounded-xl border bg-white p-5 shadow-sm">
            <div className="flex flex-wrap justify-between gap-3 border-b pb-4">
              <div>
                <h2 className="font-semibold text-gray-900">{selected.report_type}</h2>
                <p className="text-xs text-gray-500">Account {selected.aws_account_id} · {selected.aws_region || 'global'}</p>
              </div>
              <p className="text-sm font-semibold">{selected.total_findings} findings</p>
            </div>
            <div className="mt-4 space-y-3">
              {selected.findings.map((finding, index) => (
                <div key={finding.fingerprint || index} className="rounded-lg border p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="font-medium text-gray-800">{finding.alert_type}</p>
                      <p className="text-xs text-gray-500">{finding.username}</p>
                    </div>
                    <SeverityBadge severity={finding.severity} />
                  </div>
                  {finding.detail && <p className="mt-2 text-sm text-gray-600">{finding.detail}</p>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
      {loading && <p className="text-sm text-gray-500">Loading AWS reports…</p>}
    </div>
  )
}
