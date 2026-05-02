import type { ClassLabel, AlertSeverity } from '@/types'

export const CLASS_COLORS: Record<ClassLabel, string> = {
  Benign: '#22c55e',
  Spoofing: '#f97316',
  Recon: '#eab308',
  BruteForce: '#ef4444',
}

export const SEVERITY_COLORS: Record<AlertSeverity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  info: '#3b82f6',
}

export const CATEGORY_SEVERITY: Record<ClassLabel, AlertSeverity> = {
  Benign: 'info',
  Recon: 'medium',
  Spoofing: 'high',
  BruteForce: 'critical',
}

export const PROTOCOLS = [
  'MQTT',
  'CoAP',
  'HTTP',
  'HTTPS',
  'SSH',
  'DNS',
  'TCP',
  'UDP',
  'ARP',
  'ICMP',
  'IGMP',
] as const

export const IOT_PROTOCOLS: ReadonlyArray<(typeof PROTOCOLS)[number]> = ['MQTT', 'CoAP']

// Offline test-set accuracy from notebooks/random_forest_added_brute.ipynb.
// Update whenever the model is retrained.
export const MODEL_INFO = {
  name: 'LightGBM',
  classes: 4,
  accuracy: '93.06%',
} as const

export const QUERY_KEYS = {
  scanHistory: (userId: string) => ['scan-history', userId] as const,
  scanSession: (sessionId: string) => ['scan-session', sessionId] as const,
  flowHistory: (sessionId: string, page: number) =>
    ['flow-history', sessionId, page] as const,
}
