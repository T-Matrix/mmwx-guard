export type Status = {
  setup: boolean
  authenticated: boolean
  admin: string
  name: string
  version: string
}

export type SourceCount = { ip: string; connections: number; dropped?: number }
export type Telemetry = {
  collected_at: string
  cpu_usage?: number
  load_1: number
  load_5: number
  memory_used: number
  memory_total: number
  sockets: { total: number; established: number; syn_recv: number; syn_sent: number; time_wait: number }
  conntrack: number
  conntrack_max: number
  dropped_total: number
  protected: boolean
  policy_revision: number
  top_sources: SourceCount[]
}

export type Agent = {
  id: string
  name: string
  status: 'online' | 'offline'
  ip_address: string
  os: string
  arch: string
  version: string
  last_seen: string
  policy_id?: number
  policy_name?: string
  policy_revision?: number
  telemetry?: Telemetry
}

export type PortRule = {
  port: number
  per_ip_rate: number
  per_ip_burst: number
  aggregate_rate: number
  aggregate_burst: number
  enabled: boolean
}

export type Policy = {
  id: number
  revision: number
  name: string
  enabled: boolean
  ports: PortRule[]
  global: { rate: number; burst: number; exempt_ports: number[]; enabled: boolean }
  trusted_cidrs: string[]
  syn_sent_timeout: number
  syn_recv_timeout: number
  updated_at?: string
}

export type EventItem = {
  id: number
  level: 'info' | 'warning' | 'error'
  kind: string
  agent_id?: string
  message: string
  created_at: string
}

export type UpdateInfo = {
  current_version: string
  latest_version: string
  update_available: boolean
  published_at?: string
  release_url: string
  repository: string
  status: { state: string; version?: string; message: string; updated_at?: string }
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: `HTTP ${response.status}` }))
    throw new Error(body.error || `HTTP ${response.status}`)
  }
  if (response.status === 204) return undefined as T
  return response.json()
}
