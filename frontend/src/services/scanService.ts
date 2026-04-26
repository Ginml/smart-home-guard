import { api } from './api'
import { supabase } from '@/lib/supabase'

export interface NetworkInterface {
  name: string
  description: string
}

export interface StartScanResponse {
  session_id: string
  status: string
}

export interface StopScanResponse {
  session_id: string
  total_flows: number
  threat_count: number
  ended_at: string | null
  error: string | null
}

export async function getInterfaces(): Promise<NetworkInterface[]> {
  const response = await api.get<NetworkInterface[]>('/api/scan/interfaces')
  return response.data
}

export async function startScan(iface: string): Promise<StartScanResponse> {
  const { data: userData } = await supabase.auth.getUser()
  const userId = userData.user?.id
  if (!userId) {
    throw new Error('Not authenticated')
  }
  const response = await api.post<StartScanResponse>('/api/scan/start', {
    interface: iface,
    user_id: userId,
  })
  return response.data
}

export async function stopScan(sessionId: string): Promise<StopScanResponse> {
  const response = await api.post<StopScanResponse>('/api/scan/stop', {
    session_id: sessionId,
  })
  return response.data
}
