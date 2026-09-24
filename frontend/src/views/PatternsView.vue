<template>
  <div class="patterns">
    <h2>漏洞模式库</h2>
    <div v-if="loading" class="patterns-tip">加载中…</div>
    <div v-else class="pattern-grid">
      <div v-for="(p, idx) in patterns" :key="p.type + idx" class="pattern-card">
        <div class="pattern-name">{{ p.type }}</div>
        <div class="pattern-severity" :class="p.severity">{{ p.severity }}</div>
        <div class="pattern-desc">{{ p.description }}</div>
        <div class="pattern-regex">正则: <code>{{ p.pattern }}</code></div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue"
import { useAuditStore } from "@/store"

const store = useAuditStore()
const patterns = ref<any[]>([])
const loading = ref(true)

onMounted(async () => {
  try {
    await store.fetchPatterns()
    patterns.value = store.patterns
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.patterns { max-width: 1000px; }
.patterns-tip { color: #6b7280; padding: 2rem; text-align: center; }
.pattern-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
.pattern-card { background: white; border-radius: 12px; padding: 1.25rem; }
.pattern-name { font-weight: 600; margin-bottom: 0.5rem; }
.pattern-severity { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; margin-bottom: 0.75rem; }
.pattern-severity.critical { background: #fee2e2; color: #dc2626; }
.pattern-severity.high { background: #fef3c7; color: #d97706; }
.pattern-severity.medium { background: #dbeafe; color: #1d4ed8; }
.pattern-desc { color: #374151; font-size: 0.875rem; margin-bottom: 0.75rem; }
.pattern-regex { font-size: 0.75rem; color: #6b7280; }
.pattern-regex code { background: #f3f4f6; padding: 0.125rem 0.375rem; border-radius: 4px; font-family: monospace; }
</style>
