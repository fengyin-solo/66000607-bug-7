<template>
  <div class="history">
    <h2>审计历史</h2>
    <div v-if="history.length === 0" class="empty">暂无审计记录</div>
    <div class="history-list">
      <div v-for="item in history" :key="item.id" class="history-card">
        <div class="history-row">
          <div class="history-file">{{ item.filename }}</div>
          <div class="history-count">发现漏洞 {{ item.vulnerabilities.length }} 个</div>
          <div class="history-score" :class="item.score >= 70 ? 'high' : item.score >= 40 ? 'medium' : 'low'">{{ item.score }}分</div>
          <div class="history-time">{{ formatTime(item.timestamp) }}</div>
          <button class="btn-sm" @click="toggle(item.id)">{{ expandedId === item.id ? "收起" : "查看详情" }}</button>
        </div>
        <div v-if="expandedId === item.id" class="history-detail">
          <div v-if="item.vulnerabilities.length === 0" class="detail-empty">未发现漏洞</div>
          <div v-for="(v, i) in item.vulnerabilities" :key="`${v.type}-${v.line}-${i}`" class="detail-row">
            <span class="detail-type">{{ v.type }}</span>
            <span class="detail-line">第 {{ v.line }} 行</span>
            <span class="detail-severity" :class="v.severity">{{ v.severity }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from "vue"
import { useAuditStore } from "@/store"

const store = useAuditStore()
const history = computed(() => store.results)
const expandedId = ref<string | null>(null)

onMounted(() => {
  store.fetchHistory()
})

function toggle(id: string) {
  expandedId.value = expandedId.value === id ? null : id
}

function formatTime(ts: string) {
  return ts ? ts.replace("T", " ").slice(0, 19) : ""
}
</script>

<style scoped>
.history { max-width: 800px; }
.empty { background: white; border-radius: 12px; padding: 2rem; text-align: center; color: #6b7280; }
.history-list { display: flex; flex-direction: column; gap: 1rem; }
.history-card { background: white; border-radius: 12px; padding: 1.25rem; }
.history-row { display: flex; align-items: center; gap: 1rem; }
.history-file { flex: 1; font-weight: 600; }
.history-count { color: #374151; font-size: 0.875rem; }
.history-score { padding: 0.25rem 0.75rem; border-radius: 8px; font-weight: 600; font-size: 0.875rem; }
.history-score.high { background: #d1fae5; color: #065f46; }
.history-score.medium { background: #fef3c7; color: #92400e; }
.history-score.low { background: #fee2e2; color: #991b1b; }
.history-time { color: #6b7280; font-size: 0.875rem; }
.btn-sm { background: #e5e7eb; border: none; padding: 0.25rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
.history-detail { margin-top: 1rem; border-top: 1px solid #f3f4f6; padding-top: 1rem; }
.detail-empty { color: #6b7280; font-size: 0.875rem; }
.detail-row { display: flex; align-items: center; gap: 1rem; padding: 0.375rem 0; font-size: 0.875rem; }
.detail-type { flex: 1; color: #374151; }
.detail-line { color: #7c3aed; font-family: monospace; font-size: 0.75rem; }
.detail-severity { padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; background: #f3f4f6; color: #374151; }
.detail-severity.critical { background: #fee2e2; color: #dc2626; }
.detail-severity.high { background: #fef3c7; color: #d97706; }
.detail-severity.medium { background: #dbeafe; color: #1d4ed8; }
</style>
