import { useScanStore } from '@/store/scanStore'
import { useStartScan } from '@/hooks/useStartScan'
import { useStopScan } from '@/hooks/useStopScan'
import { StatusPill } from '@/components/ui/StatusPill'
import { Button } from '@/components/ui/Button'
import { InterfaceSelector } from './InterfaceSelector'
import type { ScanStatus } from '@/types'

const STATUS_PILL_MAP: Record<ScanStatus, 'scanning' | 'idle' | 'error' | 'starting'> = {
  idle: 'idle',
  starting: 'starting',
  scanning: 'scanning',
  stopping: 'starting',
  completed: 'idle',
  error: 'error',
}

export function RealtimePanel() {
  const { status, sessionId, selectedInterface, liveFlows, setInterface } = useScanStore()
  const startScan = useStartScan()
  const stopScan = useStopScan()

  const isScanning = status === 'scanning'
  const inTransition = status === 'starting' || status === 'stopping'

  const handleStart = () => {
    if (!selectedInterface) return
    startScan.mutate(selectedInterface)
  }

  const handleStop = () => {
    if (!sessionId) return
    stopScan.mutate(sessionId)
  }

  return (
    <div className="flex flex-col gap-4">
      <InterfaceSelector
        value={selectedInterface}
        onChange={setInterface}
        disabled={isScanning || inTransition}
      />

      <div className="flex items-center gap-3">
        <StatusPill status={STATUS_PILL_MAP[status]} />
        {isScanning ? (
          <Button
            variant="secondary"
            onClick={handleStop}
            disabled={inTransition || stopScan.isPending}
          >
            {stopScan.isPending ? 'Stopping…' : 'Stop Scan'}
          </Button>
        ) : (
          <Button
            variant="primary"
            onClick={handleStart}
            disabled={!selectedInterface || inTransition || startScan.isPending}
          >
            {startScan.isPending ? 'Starting…' : 'Start Scan'}
          </Button>
        )}
        {isScanning && (
          <span className="text-sm text-content-secondary">
            {liveFlows.length} flows captured
          </span>
        )}
      </div>
    </div>
  )
}
