/**
 * components/SeverityBadge.jsx
 * =============================
 * Small coloured pill that labels a finding's severity band.
 *
 * Props
 * -----
 * severity : 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
 * size     : 'sm' | 'md'   (default 'md')
 *
 * Uses the shared `severity.*` colour tokens defined in tailwind.config.js
 * so the dashboard cards, filter tabs, and finding cards all stay visually
 * consistent with one another.
 */

const COLOUR_CLASSES = {
  Critical: 'bg-severity-critical-bg text-severity-critical-text border-severity-critical-border',
  High:     'bg-severity-high-bg     text-severity-high-text     border-severity-high-border',
  Medium:   'bg-severity-medium-bg   text-severity-medium-text   border-severity-medium-border',
  Low:      'bg-severity-low-bg      text-severity-low-text      border-severity-low-border',
  Info:     'bg-severity-info-bg     text-severity-info-text     border-severity-info-border',
}

const SIZE_CLASSES = {
  sm: 'text-[11px] px-2 py-0.5',
  md: 'text-xs px-2.5 py-1',
}

/** @param {{ severity: string, size?: 'sm'|'md' }} props */
export default function SeverityBadge({ severity, size = 'md' }) {
  const colours = COLOUR_CLASSES[severity] ?? COLOUR_CLASSES.Info
  const sizing  = SIZE_CLASSES[size]       ?? SIZE_CLASSES.md

  return (
    <span
      className={`inline-flex items-center rounded-full border font-semibold
                  whitespace-nowrap ${colours} ${sizing}`}
    >
      {severity}
    </span>
  )
}