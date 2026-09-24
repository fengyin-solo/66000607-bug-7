<template>
  <div class="history">
    <h2>审计历史</h2>
    <div v-if="loading" class="history-tip">加载中…</div>
    <div v-else-if="history.length === 0" class="history-tip">暂无审计记录，去「合约审计」页提交一份合约吧。</div>
    <div v-else class="history-list">
      <div v-for="item in history" :key="item.id" class="history-card">
        <div class="history-main">
          <div class="history-file">{{ item.filename }}</div>
          <div class="history-meta">
            <span>漏洞 {{ item.vulnerabilities.length }} 条</span>
            <span class="history-time">{{ formatTime(item.timestamp) }}</span>
          </div>
        </div>
        <div class="history-score" :class="item.score >= 70 ? 'high' : item.score >= 40 ? 'medium' : 'low'">{{ item.score }}分</div>
        <button class="btn-sm" @click="viewDetail(item)">查看详情</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue"
import { useRouter } from "vue-router"
import { useAuditStore, type AuditResult } from "@/store"

const router = useRouter()
const store = useAuditStore()
const loading = ref(true)
const history = ref<AuditResult[]>([])

function formatTime(ts: string) {
  return ts.replace("T", " ").slice(0, 16)
}

function viewDetail(item: AuditResult) {
  // 详情由审计页统一渲染，走同一个入口保证结论一致
  router.push({ path: "/", query: { id: item.id } })
}

onMounted(async () => {
  loading.value = true
  try {
    history.value = await store.fetchHistory()
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.history { max-width: 800px; }
.history-tip { color: #6b7280; padding: 2rem; text-align: center; }
.history-list { display: flex; flex-direction: column; gap: 1rem; }
.history-card { background: white; border-radius: 12px; padding: 1.25rem; display: flex; align-items: center; gap: 1rem; }
.history-main { flex: 1; }
.history-file { font-weight: 600; margin-bottom: 0.25rem; }
.history-meta { display: flex; gap: 1rem; color: #6b7280; font-size: 0.875rem; }
.history-score { padding: 0.25rem 0.75rem; border-radius: 8px; font-weight: 600; font-size: 0.875rem; }
.history-score.high { background: #d1fae5; color: #065f46; }
.history-score.medium { background: #fef3c7; color: #92400e; }
.history-score.low { background: #fee2e2; color: #991b1b; }
.history-time { color: #6b7280; font-size: 0.875rem; }
.btn-sm { background: #e5e7eb; border: none; padding: 0.25rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
</style>
