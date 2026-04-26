import { useQuery } from '@tanstack/react-query'
import { getInterfaces, type NetworkInterface } from '@/services/scanService'

export type { NetworkInterface }

export function useInterfaces() {
  return useQuery<NetworkInterface[]>({
    queryKey: ['scan-interfaces'],
    queryFn: getInterfaces,
    staleTime: 60_000,
    retry: 1,
    refetchOnWindowFocus: false,
  })
}
