/**
 * Admin operation audit log API.
 *
 * The audit log is admin-only (not exposed to end users). It records
 * management-plane operations with masked header credentials and redacted
 * request bodies. Entries cannot be deleted individually; the whole log can
 * only be cleared with a fresh TOTP verification.
 */

import { apiClient } from '../client'
import type { PaginatedResponse } from '@/types'

export interface AuditLog {
  id: number
  created_at: string
  actor_user_id?: number
  actor_email: string
  actor_role: string
  auth_method: string
  credential_masked: string
  action: string
  method: string
  path: string
  request_id: string
  client_ip: string
  user_agent: string
  request_body?: string
  status_code: number
  latency_ms: number
  extra?: Record<string, any>
}

export interface AuditLogQuery {
  page?: number
  page_size?: number
  start_time?: string
  end_time?: string
  actor_user_id?: number
  actor_email?: string
  auth_method?: string
  action?: string
  method?: string
  client_ip?: string
  success?: string
  q?: string
}

export type AuditLogListResponse = PaginatedResponse<AuditLog>

export interface IPBlock {
  id: number
  client_ip: string
  reason: string
  source: 'automatic' | 'manual'
  failure_count: number
  strike_count: number
  expires_at: string | null
  revoked_at: string | null
  active: boolean
}

export interface IPBlockList {
  items: IPBlock[]
  total: number
  page: number
  page_size: number
  config: {
    detection_enabled: boolean
    enabled: boolean
    short_threshold: number
    short_window_seconds: number
    long_threshold: number
    long_window_seconds: number
    initial_block_seconds: number
    repeat_block_seconds: number
    permanent_after: number
  }
}

export interface IPAnomaly {
  id: number
  client_ip: string
  reason: string
  short_failures: number
  long_failures: number
  short_window_seconds: number
  long_window_seconds: number
  user_id: number | null
  user_email: string
  api_key_id: number | null
  peer_ip: string
  client_ip_source: string
  method: string
  route: string
  first_detected_at: string
  last_detected_at: string
  dismissed_at: string | null
  block_id: number | null
  blocked: boolean
}

export interface IPAnomalyQuery {
  page: number
  status: 'pending' | 'dismissed' | 'blocked' | 'all'
  client_ip?: string
  user_id?: string
}

export interface IPAnomalyList {
  items: IPAnomaly[]
  total: number
  page: number
  page_size: number
  config: IPBlockList['config']
}

/** 分页读取达到阈值的可疑来源，身份字段不包含攻击者填写的账号名。 */
export async function listIPAnomalies(query: IPAnomalyQuery): Promise<IPAnomalyList> {
  const { data } = await apiClient.get('/admin/audit-logs/ip-anomalies', { params: { ...query, page_size: 20 } })
  return data
}

/** 忽略已有摘要并清空旧失败计数，后续新异常仍会重新检测。 */
export async function dismissIPAnomaly(id: number): Promise<void> {
  await apiClient.post(`/admin/audit-logs/ip-anomalies/${id}/dismiss`)
}

/** 分页读取 IP 封禁名单和当前防护配置。 */
export async function listIPBlocks(page: number, activeOnly: boolean): Promise<IPBlockList> {
  const { data } = await apiClient.get('/admin/audit-logs/ip-blocks', {
    params: { page, page_size: 20, active_only: activeOnly }
  })
  return data
}

/** 保存临时或永久封禁；时长为零表示永久。 */
export async function blockIP(clientIp: string, reason: string, durationSeconds: number): Promise<IPBlock> {
  const { data } = await apiClient.post('/admin/audit-logs/ip-blocks', {
    client_ip: clientIp, reason, duration_seconds: durationSeconds
  })
  return data
}

/** 解除封禁并清除该 IP 的旧失败窗口。 */
export async function unblockIP(id: number): Promise<void> {
  await apiClient.delete(`/admin/audit-logs/ip-blocks/${id}`)
}

/**
 * List audit logs (paginated, filterable).
 */
export async function list(params: AuditLogQuery): Promise<AuditLogListResponse> {
  const { data } = await apiClient.get('/admin/audit-logs', { params })
  return data
}

/**
 * Get a single audit log entry (includes the redacted request body).
 */
export async function get(id: number): Promise<AuditLog> {
  const { data } = await apiClient.get(`/admin/audit-logs/${id}`)
  return data
}

/**
 * Clear all audit logs. Requires a fresh TOTP code (verified server-side);
 * unavailable when 2FA is not enabled for the operator.
 * @param totpCode - current 6-digit TOTP code
 */
export async function clear(totpCode: string): Promise<{ deleted: number }> {
  const { data } = await apiClient.post('/admin/audit-logs/clear', { totp_code: totpCode })
  return data
}

export const auditAPI = {
  list,
  get,
  clear,
  listIPBlocks,
  blockIP,
  unblockIP,
  listIPAnomalies,
  dismissIPAnomaly
}

export default auditAPI
