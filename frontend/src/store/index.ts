import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'

export interface AuditResult {
  id: string
  filename: string
  score: number
  vulnerabilities: Vulnerability[]
  gasIssues: GasIssue[]
  code?: string
  timestamp: string
}

export interface Vulnerability {
  id: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  line: number
  description: string
  suggestion: string
  code?: string
}

export interface GasIssue {
  id: string
  functionName: string
  currentGas: number
  optimizedGas: number
  suggestion: string
}

interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}

export const useAuditStore = defineStore('audit', () => {
  const results = ref<AuditResult[]>([])
  const currentResult = ref<AuditResult | null>(null)
  const patterns = ref<any[]>([])

  async function uploadAndAudit(code: string, filename: string) {
    const res = await axios.post<ApiResponse<AuditResult>>('/api/audit', { code, filename })
    const result = res.data.data
    currentResult.value = result
    // 同一份合约（同 id）重复审计时用新结论替换旧记录，避免列表里残留上一次的条数/评分
    const idx = results.value.findIndex(r => r.id === result.id)
    if (idx === -1) {
      results.value.unshift(result)
    } else {
      results.value.splice(idx, 1, result)
    }
    return result
  }

  async function fetchHistory() {
    const res = await axios.get<ApiResponse<AuditResult[]>>('/api/history')
    results.value = res.data.data
    return results.value
  }

  async function fetchAudit(id: string) {
    const res = await axios.get<ApiResponse<AuditResult>>(`/api/audit/${id}`)
    currentResult.value = res.data.data
    return res.data.data
  }

  async function fetchPatterns() {
    const res = await axios.get<ApiResponse<any[]>>('/api/patterns')
    patterns.value = res.data.data
  }

  return { results, currentResult, patterns, uploadAndAudit, fetchHistory, fetchAudit, fetchPatterns }
})
