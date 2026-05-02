import { useEffect, useMemo, useRef, useState } from 'react'
import { KpiGrid } from '@/components/dashboard/KpiGrid'
import { TrafficDonut } from '@/components/dashboard/TrafficDonut'
import { ThreatTimeline } from '@/components/dashboard/ThreatTimeline'
import { ProtocolBarChart } from '@/components/dashboard/ProtocolBarChart'
import { TcpFlagRadar } from '@/components/dashboard/TcpFlagRadar'
import { TopSourceIps } from '@/components/dashboard/TopSourceIps'
import { FlowTable } from '@/components/dashboard/FlowTable'
import { AlertFeed } from '@/components/dashboard/AlertFeed'
import { ScanPanel } from '@/components/scan/ScanPanel'
import { Skeleton } from '@/components/ui/Skeleton'
import { useScanStore } from '@/store/scanStore'
import type { NetworkFlow } from '@/types'

interface TimelinePoint {
  timestamp: string
  benign: number
  spoofing: number
  recon: number
  bruteForce: number
}

const MAX_TIMELINE_POINTS = 80
const MIN_TIMELINE_INTERVAL_MS = 200

function computeFlagData(flows: NetworkFlow[]) {
  if (flows.length === 0) return []
  const sum = (key: keyof NetworkFlow) =>
    flows.reduce((acc, f) => acc + (Number(f[key]) || 0), 0)

  const raw = {
    FIN: sum('finFlagNumber'),
    SYN: sum('synFlagNumber'),
    RST: sum('rstFlagNumber'),
    PSH: sum('pshFlagNumber'),
    ACK: sum('ackFlagNumber'),
    URG: sum('urgFlagNumber'),
    ECE: sum('eceFlagNumber'),
    CWR: sum('cwrFlagNumber'),
  }

  const max = Math.max(...Object.values(raw), 1)
  if (max <= 0) {
    return Object.keys(raw).map((flag) => ({ flag, value: 0 }))
  }
  return Object.entries(raw).map(([flag, total]) => ({
    flag,
    value: parseFloat((total / max).toFixed(3)),
  }))
}

export function DashboardPage() {
  const status = useScanStore((s) => s.status)
  const flowSummary = useScanStore((s) => s.flowSummary)
  const liveFlows = useScanStore((s) => s.liveFlows)

  const [timelineData, setTimelineData] = useState<TimelinePoint[]>([])
  const frozenRef = useRef(false)
  const lastPushRef = useRef(0)

  // Push a timeline point on every flowSummary update while scanning, throttled
  // to MIN_TIMELINE_INTERVAL_MS so high-rate batches don't overwhelm recharts.
  // Freeze on completion so the final chart stays put.
  useEffect(() => {
    if (status === 'completed' || status === 'error') {
      frozenRef.current = true
      return
    }
    if (status !== 'scanning') return
    frozenRef.current = false
    if (!flowSummary) return

    const now = Date.now()
    if (now - lastPushRef.current < MIN_TIMELINE_INTERVAL_MS) return
    lastPushRef.current = now

    setTimelineData((prev) => {
      const point: TimelinePoint = {
        timestamp: new Date().toISOString(),
        benign: flowSummary.benignCount,
        spoofing: flowSummary.spoofingCount,
        recon: flowSummary.reconCount,
        bruteForce: flowSummary.bruteForceCount,
      }
      return [...prev, point].slice(-MAX_TIMELINE_POINTS)
    })
  }, [status, flowSummary])

  const flagData = useMemo(() => computeFlagData(liveFlows), [liveFlows])
  const isScanning = status === 'scanning'
  const hasData = flowSummary !== null

  return (
    <main className="min-h-screen bg-surface-base p-6 text-content-primary">
      <div className="mx-auto max-w-7xl space-y-6">

        {/* Section 1 — Scan panel */}
        <ScanPanel />

        {/* Section 2 — KPI grid */}
        <KpiGrid summary={flowSummary} loading={isScanning && !hasData} />

        {/* Section 3 — Donut + Alert feed */}
        <div className="grid gap-4 md:grid-cols-2">
          <section className="rounded-md border border-border bg-surface-raised p-4">
            <h2 className="mb-2 text-sm font-semibold">Traffic breakdown</h2>
            {isScanning && !hasData
              ? <Skeleton className="h-72 w-full rounded-md" />
              : <TrafficDonut summary={flowSummary} />}
          </section>
          <AlertFeed />
        </div>

        {/* Section 4 — Threat timeline */}
        <section className="rounded-md border border-border bg-surface-raised p-4">
          <h2 className="mb-2 text-sm font-semibold">Threat timeline</h2>
          {isScanning && timelineData.length === 0
            ? <Skeleton className="h-72 w-full rounded-md" />
            : <ThreatTimeline timelineData={timelineData} />}
        </section>

        {/* Section 5 — Protocol / Radar / Top IPs */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <section className="rounded-md border border-border bg-surface-raised p-4">
            <h2 className="mb-2 text-sm font-semibold">Protocols</h2>
            {isScanning && !hasData
              ? <Skeleton className="h-64 w-full rounded-md" />
              : <ProtocolBarChart protocolCounts={flowSummary?.protocolCounts ?? {}} />}
          </section>
          <section className="rounded-md border border-border bg-surface-raised p-4">
            <h2 className="mb-2 text-sm font-semibold">TCP flags</h2>
            {isScanning && liveFlows.length === 0
              ? <Skeleton className="h-80 w-full rounded-md" />
              : <TcpFlagRadar flagData={flagData} />}
          </section>
          <section className="rounded-md border border-border bg-surface-raised p-4">
            <h2 className="mb-2 text-sm font-semibold">Top source IPs</h2>
            {isScanning && !hasData
              ? <Skeleton className="h-64 w-full rounded-md" />
              : <TopSourceIps topIps={flowSummary?.topSourceIps ?? []} />}
          </section>
        </div>

        {/* Section 6 — Flow table */}
        <section className="rounded-md border border-border bg-surface-raised p-4">
          <h2 className="mb-2 text-sm font-semibold">Flows</h2>
          <FlowTable flows={liveFlows} loading={isScanning && liveFlows.length === 0} />
        </section>

      </div>
    </main>
  )
}
