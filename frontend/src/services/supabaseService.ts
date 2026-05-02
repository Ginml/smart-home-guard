import { supabase } from '@/lib/supabase'
import type { ScanSession, ScanMode, ScanStatus, UserPreferences, NetworkFlow } from '@/types'
import { normalizeFlow } from '@/utils/flowNormalizer'

function normalizeScanSession(row: Record<string, unknown>): ScanSession {
  return {
    id: row.id as string,
    userId: row.user_id as string,
    mode: row.mode as ScanMode,
    status: row.status as ScanStatus,
    interfaceName: row.interface_name as string | undefined,
    pcapFileName: row.pcap_file_name as string | undefined,
    pcapFileSizeBytes: row.pcap_file_size_bytes as number | undefined,
    startedAt: row.started_at as string,
    endedAt: row.ended_at as string | undefined,
    totalFlows: (row.total_flows as number) ?? 0,
    threatCount: (row.threat_count as number) ?? 0,
    summary: row.summary_json as ScanSession['summary'],
  }
}

export async function getScanSessions(
  userId: string,
  page: number,
  pageSize = 20,
): Promise<{ data: ScanSession[]; count: number }> {
  const from = page * pageSize
  const { data, count, error } = await supabase
    .from('scan_sessions')
    .select('*', { count: 'exact' })
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .range(from, from + pageSize - 1)
  if (error) throw error
  return { data: (data ?? []).map(normalizeScanSession), count: count ?? 0 }
}

export async function getFlowEvents(
  sessionId: string,
  page: number,
  pageSize = 50,
): Promise<{ data: NetworkFlow[]; count: number }> {
  const from = page * pageSize
  const { data, count, error } = await supabase
    .from('flow_events')
    .select('*', { count: 'exact' })
    .eq('session_id', sessionId)
    .order('captured_at', { ascending: false })
    .range(from, from + pageSize - 1)
  if (error) throw error
  return {
    data: (data ?? []).map((row) => normalizeFlow(row as Record<string, unknown>)),
    count: count ?? 0,
  }
}

export async function getUserPreferences(userId: string): Promise<UserPreferences> {
  const { data, error } = await supabase
    .from('user_preferences')
    .select('*')
    .eq('user_id', userId)
    .maybeSingle()
  if (error) throw error
  return {
    userId,
    username: (data?.username as string | null) ?? undefined,
    notifyCritical: (data?.notify_critical as boolean) ?? true,
    notifyHigh: (data?.notify_high as boolean) ?? true,
    notifyMedium: (data?.notify_medium as boolean) ?? false,
    emailAlerts: (data?.email_alerts as boolean) ?? false,
    defaultScanMode: ((data?.default_scan_mode as string) ?? 'pcap') as ScanMode,
    updatedAt: (data?.updated_at as string) ?? new Date().toISOString(),
  }
}

export async function updateUserPreferences(
  userId: string,
  prefs: Partial<Omit<UserPreferences, 'userId' | 'updatedAt'>>,
): Promise<void> {
  const update: Record<string, unknown> = {
    user_id: userId,
    updated_at: new Date().toISOString(),
  }
  if (prefs.username !== undefined) update.username = prefs.username
  if (prefs.notifyCritical !== undefined) update.notify_critical = prefs.notifyCritical
  if (prefs.notifyHigh !== undefined) update.notify_high = prefs.notifyHigh
  if (prefs.notifyMedium !== undefined) update.notify_medium = prefs.notifyMedium
  if (prefs.emailAlerts !== undefined) update.email_alerts = prefs.emailAlerts
  if (prefs.defaultScanMode !== undefined) update.default_scan_mode = prefs.defaultScanMode
  const { error } = await supabase
    .from('user_preferences')
    .upsert(update, { onConflict: 'user_id' })
  if (error) throw error
}
