import { useMutation } from '@tanstack/react-query'
import { stopScan } from '@/services/scanService'
import { useScanStore } from '@/store/scanStore'
import { useUiStore } from '@/store/uiStore'

export function useStopScan() {
  const { setStatus } = useScanStore()
  const { pushToast } = useUiStore()

  return useMutation({
    mutationFn: (sessionId: string) => stopScan(sessionId),

    onMutate: () => {
      setStatus('stopping')
    },

    onSuccess: (data) => {
      // Keep liveFlows / flowSummary on screen so the user can review.
      // The next useStartScan call clears them via resetScan() in onMutate.
      setStatus('completed')
      pushToast({
        message: `Scan complete: ${data.total_flows} flows, ${data.threat_count} threats`,
        severity: 'info',
      })
    },

    onError: (err) => {
      setStatus('error')
      pushToast({
        message: err instanceof Error ? err.message : 'Failed to stop scan',
        severity: 'critical',
      })
    },
  })
}
