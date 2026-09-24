<template>
  <div class="gas">
    <h2>Gas 消耗分析</h2>
    <div v-if="results.length > 0" class="gas-toolbar">
      <label>选择合约：</label>
      <select v-model="selectedId" class="contract-select">
        <option v-for="r in results" :key="r.id" :value="r.id">{{ r.filename }}（{{ r.score }}分）</option>
      </select>
    </div>
    <div v-if="gasIssues.length === 0" class="gas-empty">
      暂无已审计合约的 Gas 数据，请先在「合约审计」页完成一次审计。
    </div>
    <template v-else>
      <div ref="gasChart" class="chart-container"></div>
      <div class="gas-issues">
        <h3>优化建议（{{ gasIssues.length }}）</h3>
        <div v-for="g in gasIssues" :key="g.id" class="gas-item">
          <span class="gas-fn">{{ g.functionName }}</span>
          <span class="gas-detail">{{ g.currentGas }} → {{ g.optimizedGas }}（{{ Math.round((1-g.optimizedGas/g.currentGas)*100) }}% 节省）</span>
          <span class="gas-suggest">{{ g.suggestion }}</span>
        </div>
      </div>
    </template>
    <div class="gas-tips">
      <h3>Gas优化技巧</h3>
      <ul>
        <li>使用 <code>calldata</code> 代替 <code>memory</code> 存储函数参数</li>
        <li>使用 <code>short-circuit</code> 逻辑减少不必要的计算</li>
        <li>避免在循环中读取存储变量，缓存到内存</li>
        <li>使用事件而非存储来记录历史数据</li>
        <li>合理使用 <code>unchecked</code> 块跳过溢出检查</li>
      </ul>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from "vue"
import * as echarts from "echarts"
import { useAuditStore } from "@/store"

const store = useAuditStore()
const gasChart = ref<HTMLElement | null>(null)
let chart: echarts.ECharts | null = null
const selectedId = ref<string>("")

const results = computed(() => store.results)
const selected = computed(() => results.value.find(r => r.id === selectedId.value) || null)
const gasIssues = computed(() => selected.value?.gasIssues ?? [])

function renderChart() {
  if (!chart) return
  if (gasIssues.value.length === 0) {
    chart.clear()
    return
  }
  chart.setOption({
    title: { text: `${selected.value?.filename ?? ""} 各函数Gas消耗对比`, left: "center" },
    tooltip: {},
    xAxis: { type: "category", data: gasIssues.value.map(g => g.functionName) },
    yAxis: { type: "value", name: "Gas" },
    series: [{
      type: "bar",
      data: gasIssues.value.map(g => ({
        value: g.currentGas,
        itemStyle: { color: "#8b5cf6" }
      }))
    }]
  }, true)
}

watch([gasIssues, selectedId], async () => {
  await nextTick()
  if (gasChart.value && !chart) {
    chart = echarts.init(gasChart.value)
  }
  renderChart()
}, { deep: true })

onMounted(async () => {
  // 进入页面先与后端同步各合约最新结论，保证这里看到的和审计页一致
  await store.fetchHistory()
  selectedId.value = store.currentResult?.id || results.value[0]?.id || ""
  await nextTick()
  if (gasChart.value) {
    chart = echarts.init(gasChart.value)
    renderChart()
  }
})

onUnmounted(() => { chart?.dispose() })
</script>

<style scoped>
.gas { max-width: 1000px; }
.gas-toolbar { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; }
.contract-select { padding: 0.5rem 0.75rem; border: 1px solid #d1d5db; border-radius: 8px; background: white; }
.gas-empty { background: white; border-radius: 12px; padding: 2rem; text-align: center; color: #6b7280; margin-bottom: 2rem; }
.chart-container { height: 400px; background: white; border-radius: 12px; padding: 1rem; margin-bottom: 1rem; }
.gas-issues { background: white; border-radius: 12px; padding: 1.25rem; margin-bottom: 2rem; }
.gas-issues h3 { margin-bottom: 0.75rem; }
.gas-item { display: flex; gap: 1rem; align-items: baseline; padding: 0.5rem 0; border-bottom: 1px solid #f3f4f6; font-size: 0.875rem; }
.gas-item:last-child { border-bottom: none; }
.gas-fn { font-weight: 600; color: #7c3aed; min-width: 120px; }
.gas-detail { color: #059669; min-width: 200px; }
.gas-suggest { color: #6b7280; }
.gas-tips { background: white; border-radius: 12px; padding: 1.5rem; }
.gas-tips h3 { margin-bottom: 1rem; }
.gas-tips ul { list-style: none; }
.gas-tips li { padding: 0.5rem 0; color: #374151; border-bottom: 1px solid #f3f4f6; }
.gas-tips li:last-child { border-bottom: none; }
.gas-tips code { background: #f3f4f6; padding: 0.125rem 0.375rem; border-radius: 4px; font-family: monospace; color: #7c3aed; }
</style>
