import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import type { ApiResponse } from '@/types'

export interface AuditResult {
  id: string
  filename: string
  score: number
  vulnerabilities: Vulnerability[]
  gasIssues: GasIssue[]
  timestamp: string
}

export interface Vulnerability {
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  line: number
  description: string
  suggestion: string
  code?: string
}

export interface GasIssue {
  functionName: string
  currentGas: number
  optimizedGas: number
  suggestion: string
}

export const useAuditStore = defineStore('audit', () => {
  const results = ref<AuditResult[]>([])
  const currentResult = ref<AuditResult | null>(null)
  const patterns = ref<any[]>([])

  async function uploadAndAudit(code: string, filename: string) {
    const res = await axios.post<ApiResponse<AuditResult>>('/api/audit', { code, filename })
    const data = res.data.data
    currentResult.value = data
    // Same contract (same id/filename) gets its record replaced, not duplicated
    const idx = results.value.findIndex(r => r.id === data.id || r.filename === data.filename)
    if (idx >= 0) results.value.splice(idx, 1)
    results.value.unshift(data)
    return data
  }

  async function fetchHistory() {
    const res = await axios.get<ApiResponse<AuditResult[]>>('/api/history')
    results.value = res.data.data
  }

  async function fetchPatterns() {
    const res = await axios.get<ApiResponse<any[]>>('/api/patterns')
    patterns.value = res.data.data
  }

  return { results, currentResult, patterns, uploadAndAudit, fetchHistory, fetchPatterns }
})