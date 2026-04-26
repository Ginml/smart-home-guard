import { useMutation } from '@tanstack/react-query'
import { startScan } from '@/services/scanService'
import { useScanStore } from '@/store/scanStore'
import { useUiStore } from '@/store/uiStore'

export function useStartScan() {
  const { setStatus, setSessionId, setMode, resetScan } = useScanStore()
  const { pushToast } = useUiStore()

  return useMutation({
    mutationFn: (iface: string) => startScan(iface),

    onMutate: () => {
      // Clear any prior session's flows before the new one starts streaming.
      resetScan()
      setMode('realtime')
      setStatus('starting')
    },

    onSuccess: (data) => {
      setSessionId(data.session_id)
      setStatus('scanning')
    },

    onError: (err) => {
      setStatus('error')
      pushToast({
        message: err instanceof Error ? err.message : 'Failed to start scan',
        severity: 'critical',
      })
    },
  })
}
