<template>
  <BaseDialog :show="show" :title="tab === 'anomalies' ? t('admin.audit.ipAnomalies.title') : t('admin.audit.ipProtection.title')" width="wide" @close="close">
    <div class="space-y-5 py-2">
      <p class="text-sm text-gray-500 dark:text-gray-400">{{ t('admin.audit.ipProtection.scopeHint') }}</p>
      <div v-if="config" class="rounded-xl bg-gray-50 p-3 text-sm dark:bg-dark-900">
        <p>{{ t('admin.audit.ipAnomalies.detectionStatus') }}: {{ config.detection_enabled ? t('common.enabled') : t('common.disabled') }}</p>
        <p>{{ t('admin.audit.ipProtection.autoStatus') }}: {{ config.enabled ? t('common.enabled') : t('common.disabled') }}</p>
        <p>{{ t('admin.audit.ipProtection.rules', { short: config.short_threshold, shortMinutes: config.short_window_seconds / 60, long: config.long_threshold, longHours: config.long_window_seconds / 3600 }) }}</p>
        <p>{{ t('admin.audit.ipProtection.penalties', { initialMinutes: config.initial_block_seconds / 60, repeatHours: config.repeat_block_seconds / 3600 }) }}</p>
        <p>{{ config.permanent_after > 0 ? t('admin.audit.ipProtection.autoPermanent', { count: config.permanent_after }) : t('admin.audit.ipProtection.noAutoPermanent') }}</p>
        <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.audit.ipProtection.configHint') }}</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button type="button" :class="tab === 'anomalies' ? 'btn btn-primary' : 'btn btn-secondary'" :disabled="busy" @click="tab = 'anomalies'">{{ t('admin.audit.ipAnomalies.title') }}</button>
        <button type="button" :class="tab === 'blocks' ? 'btn btn-primary' : 'btn btn-secondary'" :disabled="busy" @click="tab = 'blocks'">{{ t('admin.audit.ipProtection.title') }}</button>
      </div>
      <p v-if="error" role="alert" class="text-sm text-red-600 dark:text-red-400">{{ error }}</p>
      <div v-if="tab === 'blocks'" class="space-y-5">
        <form class="grid grid-cols-1 gap-3 sm:grid-cols-2" @submit.prevent="requestBlock">
          <div>
            <label class="input-label">{{ t('admin.audit.filters.clientIp') }}</label>
            <input v-model.trim="address" class="input" required :disabled="busy" autocomplete="off" />
          </div>
          <div>
            <label class="input-label">{{ t('admin.audit.ipProtection.duration') }}</label>
            <select v-model.number="duration" class="input" :disabled="busy">
              <option :value="1800">{{ t('admin.audit.ipProtection.thirtyMinutes') }}</option>
              <option :value="86400">{{ t('admin.audit.ipProtection.oneDay') }}</option>
              <option :value="0">{{ t('admin.audit.ipProtection.permanent') }}</option>
            </select>
          </div>
          <div class="sm:col-span-2">
            <label class="input-label">{{ t('admin.audit.ipProtection.reason') }}</label>
            <input v-model.trim="reason" class="input" required maxlength="128" :disabled="busy" />
          </div>
          <div class="sm:col-span-2">
            <button class="btn btn-danger" type="submit" :disabled="busy || !address || !reason">
              {{ busy ? t('common.loading') : t('admin.audit.ipProtection.block') }}
            </button>
          </div>
        </form>
        <div class="flex flex-wrap items-center justify-between gap-3">
          <label class="flex items-center gap-2 text-sm">
            <input v-model="activeOnly" type="checkbox" :disabled="busy" @change="changeFilter" />
            {{ t('admin.audit.ipProtection.activeOnly') }}
          </label>
          <button class="btn btn-secondary" :disabled="loading || busy" @click="load">{{ t('common.refresh') }}</button>
        </div>
        <div v-if="loading" class="py-6 text-center text-sm text-gray-500">{{ t('common.loading') }}</div>
        <div v-else class="space-y-3">
          <p v-if="items.length === 0" class="py-4 text-center text-sm text-gray-500">{{ t('admin.audit.ipProtection.empty') }}</p>
          <div v-for="item in items" :key="item.id" class="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-gray-200 p-3 dark:border-dark-700">
            <div class="min-w-0 space-y-1 text-sm">
              <p class="break-all font-mono font-medium">{{ item.client_ip }}</p>
              <p class="break-all text-gray-500 dark:text-gray-400">{{ item.reason }}</p>
              <p class="text-xs text-gray-500 dark:text-gray-400">
                {{ t(`admin.audit.ipProtection.${item.source}`) }} · {{ item.active ? t('admin.audit.ipProtection.blocked') : t('admin.audit.ipProtection.inactive') }}
              </p>
              <p class="text-xs text-gray-500 dark:text-gray-400">
                {{ t('admin.audit.ipProtection.expires') }}: {{ item.expires_at ? new Date(item.expires_at).toLocaleString() : t('admin.audit.ipProtection.permanent') }}
                · {{ t('admin.audit.ipProtection.counts', { failures: item.failure_count, strikes: item.strike_count }) }}
              </p>
            </div>
            <button v-if="item.active" class="btn btn-secondary" :disabled="busy" @click="unblockTarget = item">
              {{ t('admin.audit.ipProtection.unblock') }}
            </button>
          </div>
        </div>
        <Pagination v-if="total > 0" :total="total" :page="page" :page-size="20" :show-page-size-selector="false" @update:page="changePage" />
      </div>
      <IPAnomalyList v-if="show && tab === 'anomalies'" @block="blockAnomaly" @config="config = $event" @busy="busy = $event" @changed="emit('changed')" />
    </div>
    <template #footer><button class="btn btn-secondary" :disabled="busy" @click="close">{{ t('common.close') }}</button></template>
  </BaseDialog>
  <ConfirmDialog :show="confirmBlock" :title="t('admin.audit.ipProtection.block')" :message="t('admin.audit.ipProtection.blockConfirm', { ip: address, duration: durationLabel })" danger @confirm="saveBlock" @cancel="confirmBlock = false" />
  <ConfirmDialog :show="!!unblockTarget" :title="t('admin.audit.ipProtection.unblock')" :message="t('admin.audit.ipProtection.unblockConfirm', { ip: unblockTarget?.client_ip })" @confirm="removeBlock" @cancel="unblockTarget = null" />
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { auditAPI, type IPBlock, type IPBlockList } from '@/api/admin/audit'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import Pagination from '@/components/common/Pagination.vue'
import { useAppStore } from '@/stores'
import { extractApiErrorMessage } from '@/utils/apiError'
import IPAnomalyList from './IPAnomalyList.vue'

const props = withDefaults(defineProps<{ show: boolean; initialIp: string; initialTab?: 'blocks' | 'anomalies' }>(), { initialTab: 'blocks' })
const emit = defineEmits<{ close: []; changed: [] }>()
const { t } = useI18n()
const appStore = useAppStore()
const address = ref('')
const reason = ref('')
const duration = ref(1800)
const durationLabel = computed(() => duration.value === 0 ? t('admin.audit.ipProtection.permanent') : duration.value === 1800 ? t('admin.audit.ipProtection.thirtyMinutes') : t('admin.audit.ipProtection.oneDay'))
const items = ref<IPBlock[]>([])
const config = ref<IPBlockList['config'] | null>(null)
const total = ref(0)
const page = ref(1)
const activeOnly = ref(true)
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const tab = ref<'blocks' | 'anomalies'>('blocks')
const confirmBlock = ref(false)
const unblockTarget = ref<IPBlock | null>(null)
let loadGeneration = 0

/** 打开时重置操作表单，避免沿用上一次选中的 IP。 */
watch(() => props.show, (show) => {
  if (!show) { loadGeneration++; return }
  error.value = ''
  address.value = props.initialIp
  reason.value = ''
  duration.value = 1800
  page.value = 1
  confirmBlock.value = false
  unblockTarget.value = null
  tab.value = props.initialTab
  if (tab.value === 'blocks') void load()
})

/** 返回封禁名单时重新获取当前状态。 */
watch(tab, (value) => { if (props.show && value === 'blocks') { page.value = 1; void load() } })

/** 可疑列表的封禁操作沿用现有确认表单，不另设绕过管理员校验的入口。 */
function blockAnomaly(request: { clientIp: string; reason: string; duration: number }) {
  if (busy.value) return
  address.value = request.clientIp
  reason.value = request.reason
  duration.value = request.duration
  tab.value = 'blocks'
  confirmBlock.value = true
}

/** 加载名单，忽略关闭弹窗或翻页后过期的响应。 */
async function load() {
  const generation = ++loadGeneration
  loading.value = true
  error.value = ''
  try {
    const result = await auditAPI.listIPBlocks(page.value, activeOnly.value)
    if (generation !== loadGeneration) return
    items.value = result.items
    total.value = result.total
    config.value = result.config
  } catch (err: unknown) {
    if (generation === loadGeneration) error.value = extractApiErrorMessage(err, t('admin.audit.ipProtection.failed'))
  } finally {
    if (generation === loadGeneration) loading.value = false
  }
}

/** 切换页码并读取对应名单。 */
function changePage(value: number) { if (busy.value) return; page.value = value; void load() }
/** 过滤条件变更后从第一页读取。 */
function changeFilter() { page.value = 1; void load() }
/** 操作进行中保持弹窗可见，避免隐藏服务端失败。 */
function close() {
  if (busy.value) return
  if (confirmBlock.value || unblockTarget.value) { confirmBlock.value = false; unblockTarget.value = null; return }
  emit('close')
}
/** 提交前显示目标 IP，避免误选日志来源。 */
function requestBlock() { if (!busy.value) confirmBlock.value = true }

/** 保存封禁并刷新名单，服务端失败时保留表单供管理员修正。 */
async function saveBlock() {
  if (busy.value) return
  confirmBlock.value = false
  loadGeneration++
  loading.value = false
  busy.value = true
  error.value = ''
  try {
    await auditAPI.blockIP(address.value, reason.value, duration.value)
    appStore.showSuccess(t('admin.audit.ipProtection.saved'))
    emit('changed')
    page.value = 1
    await load()
  } catch (err: unknown) { error.value = extractApiErrorMessage(err, t('admin.audit.ipProtection.failed')) }
  finally { busy.value = false }
}

/** 解封后重新读取服务器状态，不在请求失败时乐观删除条目。 */
async function removeBlock() {
  if (busy.value || !unblockTarget.value) return
  const id = unblockTarget.value.id
  unblockTarget.value = null
  loadGeneration++
  loading.value = false
  busy.value = true
  error.value = ''
  try {
    await auditAPI.unblockIP(id)
    appStore.showSuccess(t('admin.audit.ipProtection.unblocked'))
    emit('changed')
    page.value = 1
    await load()
  } catch (err: unknown) { error.value = extractApiErrorMessage(err, t('admin.audit.ipProtection.failed')) }
  finally { busy.value = false }
}
</script>
