<template>
  <div class="space-y-4">
    <p class="text-sm text-gray-500 dark:text-gray-400">{{ t('admin.audit.ipAnomalies.hint') }}</p>
    <form class="grid grid-cols-1 gap-3 sm:grid-cols-2" @submit.prevent="applyFilters">
      <div><label class="input-label">{{ t('admin.audit.ipAnomalies.status') }}</label>
        <select v-model="status" class="input" :disabled="busy" @change="applyFilters">
          <option value="pending">{{ t('admin.audit.ipAnomalies.pending') }}</option>
          <option value="blocked">{{ t('admin.audit.ipProtection.blocked') }}</option>
          <option value="dismissed">{{ t('admin.audit.ipAnomalies.dismissed') }}</option>
          <option value="all">{{ t('admin.audit.filters.all') }}</option>
        </select>
      </div>
      <div><label class="input-label">{{ t('admin.audit.filters.clientIp') }}</label>
        <input v-model.trim="ipFilter" class="input" :disabled="busy" :placeholder="t('admin.audit.ipAnomalies.ipPlaceholder')" />
      </div>
      <div><label class="input-label">{{ t('admin.audit.ipAnomalies.userId') }}</label>
        <input v-model.trim="userFilter" class="input" inputmode="numeric" pattern="[1-9][0-9]*" :disabled="busy" />
      </div>
      <div class="flex items-end gap-2"><button type="submit" class="btn btn-secondary" :disabled="busy">{{ t('common.search') }}</button>
        <button type="button" class="btn btn-secondary" :disabled="busy || loading" @click="load">{{ t('common.refresh') }}</button>
      </div>
    </form>
    <div class="flex flex-wrap items-center gap-3 text-sm">
      <label>{{ t('admin.audit.ipProtection.duration') }}:
        <select v-model.number="duration" class="input ml-2 w-auto" :disabled="busy">
          <option :value="1800">{{ t('admin.audit.ipProtection.thirtyMinutes') }}</option>
          <option :value="86400">{{ t('admin.audit.ipProtection.oneDay') }}</option>
          <option :value="0">{{ t('admin.audit.ipProtection.permanent') }}</option>
        </select>
      </label>
      <span class="text-gray-500">{{ t('admin.audit.ipAnomalies.total', { count: total }) }}</span>
    </div>
    <p v-if="error" role="alert" class="text-sm text-red-600 dark:text-red-400">{{ error }}</p>
    <p v-if="loading" class="py-4 text-center text-sm text-gray-500">{{ t('common.loading') }}</p>
    <div v-else class="space-y-3">
      <p v-if="!items.length" class="py-4 text-center text-sm text-gray-500">{{ t('admin.audit.ipAnomalies.empty') }}</p>
      <div v-for="item in items" :key="item.id" class="space-y-2 rounded-xl border border-gray-200 p-3 text-sm dark:border-dark-700">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class="break-all font-mono font-semibold">{{ item.client_ip }}</span>
          <span class="text-xs text-gray-500">{{ item.blocked ? t('admin.audit.ipProtection.blocked') : item.dismissed_at ? t('admin.audit.ipAnomalies.dismissed') : t('admin.audit.ipAnomalies.pending') }}</span>
        </div>
        <p>{{ reasonLabel(item.reason) }}</p>
        <p class="text-xs text-gray-500 dark:text-gray-400">{{ t('admin.audit.ipAnomalies.counts', { short: item.short_failures, shortMinutes: item.short_window_seconds / 60, long: item.long_failures, longHours: item.long_window_seconds / 3600 }) }}</p>
        <p class="break-all text-xs text-gray-500 dark:text-gray-400">
          {{ t('admin.audit.ipAnomalies.relatedUser') }}:
          {{ item.user_id ? `${item.user_email || ''} #${item.user_id}` : t('admin.audit.ipAnomalies.unidentified') }}
          <span v-if="item.api_key_id"> · Key #{{ item.api_key_id }}</span>
        </p>
        <p class="break-all font-mono text-xs text-gray-500">{{ item.method }} {{ item.route }}</p>
        <p class="break-all text-xs text-gray-500">{{ t('admin.audit.detail.peerIp') }}: {{ item.peer_ip || '—' }} · {{ t('admin.audit.detail.clientIpSource') }}: {{ item.client_ip_source || '—' }}</p>
        <p class="text-xs text-gray-500">{{ t('admin.audit.ipAnomalies.firstSeen') }}: {{ new Date(item.first_detected_at).toLocaleString() }}</p>
        <p class="text-xs text-gray-500">{{ t('admin.audit.ipAnomalies.lastSeen') }}: {{ new Date(item.last_detected_at).toLocaleString() }}</p>
        <div v-if="!item.blocked" class="flex flex-wrap gap-2">
          <button class="btn btn-danger" :disabled="busy" @click="requestBlock(item)">{{ t('admin.audit.ipProtection.block') }}</button>
          <button v-if="!item.dismissed_at" class="btn btn-secondary" :disabled="busy" @click="dismissTarget = item">{{ t('admin.audit.ipAnomalies.dismiss') }}</button>
        </div>
      </div>
    </div>
    <p class="text-xs text-gray-500 dark:text-gray-400">{{ t('admin.audit.ipAnomalies.snapshotHint') }}</p>
    <Pagination v-if="total > 0" :total="total" :page="page" :page-size="20" :show-page-size-selector="false" @update:page="changePage" />
    <ConfirmDialog :show="!!dismissTarget" :title="t('admin.audit.ipAnomalies.dismiss')" :message="t('admin.audit.ipAnomalies.dismissConfirm', { ip: dismissTarget?.client_ip })" @confirm="dismiss" @cancel="dismissTarget = null" />
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { auditAPI, type IPAnomaly, type IPAnomalyQuery, type IPBlockList } from '@/api/admin/audit'
import Pagination from '@/components/common/Pagination.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { extractApiErrorMessage } from '@/utils/apiError'
import { useAppStore } from '@/stores'

const emit = defineEmits<{
  block: [request: { clientIp: string; reason: string; duration: number }]
  config: [value: IPBlockList['config']]
  busy: [value: boolean]
  changed: []
}>()
const { t, te } = useI18n()
const appStore = useAppStore()
const items = ref<IPAnomaly[]>([])
const status = ref<IPAnomalyQuery['status']>('pending')
const ipFilter = ref('')
const userFilter = ref('')
const appliedFilters = ref<Omit<IPAnomalyQuery, 'page'>>({ status: 'pending' })
const page = ref(1)
const total = ref(0)
const duration = ref(1800)
const error = ref('')
const loading = ref(false)
const busy = ref(false)
const dismissTarget = ref<IPAnomaly | null>(null)
let generation = 0
let timer: ReturnType<typeof setInterval> | undefined

/** 仅在列表可见时刷新摘要，操作与确认期间停止轮询。 */
onMounted(() => {
  void load()
  timer = setInterval(() => {
    if (document.visibilityState === 'visible' && !loading.value && !busy.value && !dismissTarget.value && !error.value) void load()
  }, 15000)
})
onUnmounted(() => { generation++; if (timer) clearInterval(timer) })

/** 优先显示可读异常原因，未知原因保留服务端分类标识。 */
function reasonLabel(reason: string): string {
  const key = `admin.audit.ipAnomalies.reasons.${reason}`
  return te(key) ? t(key) : reason
}

/** 获取筛选后的摘要，过期响应不会覆盖最新列表。 */
async function load() {
  const current = ++generation
  loading.value = true
  error.value = ''
  try {
    const result = await auditAPI.listIPAnomalies({ ...appliedFilters.value, page: page.value })
    if (current !== generation) return
    items.value = result.items
    total.value = result.total
    emit('config', result.config)
  } catch (err: unknown) {
    if (current === generation) error.value = extractApiErrorMessage(err, t('admin.audit.ipProtection.failed'))
  } finally { if (current === generation) loading.value = false }
}

/** 更换条件时重新读取第一页，避免沿用旧页码。 */
function applyFilters() {
  if (busy.value) return
  appliedFilters.value = { status: status.value, client_ip: ipFilter.value || undefined, user_id: userFilter.value || undefined }
  page.value = 1
  void load()
}
/** 分页操作在名单变更期间保持禁用。 */
function changePage(value: number) { if (busy.value) return; page.value = value; void load() }
/** 带入 IP、原因和时长，复用现有封禁确认与管理员保护。 */
function requestBlock(item: IPAnomaly) {
  if (busy.value) return
  emit('block', { clientIp: item.client_ip, reason: t('admin.audit.ipAnomalies.suggestedReason', { reason: reasonLabel(item.reason) }).slice(0, 128), duration: duration.value })
}
/** 忽略成功后以服务器状态刷新，失败时保留原列表。 */
async function dismiss() {
  if (busy.value || !dismissTarget.value) return
  const id = dismissTarget.value.id
  dismissTarget.value = null
  // 作废操作前的查询，防止迟到响应覆盖操作结果或清除错误提示。
  generation++
  loading.value = false
  error.value = ''
  busy.value = true
  emit('busy', true)
  try {
    await auditAPI.dismissIPAnomaly(id)
    appStore.showSuccess(t('admin.audit.ipAnomalies.dismissedSuccess'))
    emit('changed')
    page.value = 1
    await load()
  } catch (err: unknown) { error.value = extractApiErrorMessage(err, t('admin.audit.ipProtection.failed')) }
  finally { busy.value = false; emit('busy', false) }
}
</script>
