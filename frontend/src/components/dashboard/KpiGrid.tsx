import type { FlowSummary } from '@/types'
import { KpiCard } from './KpiCard'

interface KpiGridProps {
  summary: FlowSummary | null
  loading?: boolean
}

export function KpiGrid({ summary, loading }: KpiGridProps) {
  const isLoading = loading || !summary

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
      <KpiCard
        title="Total Flows"
        value={summary?.totalFlows ?? 0}
        loading={isLoading}
      />
      <KpiCard
        title="Active Threats"
        value={summary?.activeThreats ?? 0}
        loading={isLoading}
      />
      <KpiCard
        title="Benign %"
        value={summary ? `${summary.benignPercent.toFixed(1)}%` : '—'}
        loading={isLoading}
      />
    </div>
  )
}
