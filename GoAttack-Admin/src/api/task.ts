import axios from 'axios'
import { getToken } from '@/utils/auth'

// 扫描选项接口
export interface ScanOptions {
  // 主机探测
  enable_host_discovery: boolean // 是否开启主机存活探测（ICMP）

  // 端口扫描
  ports: string // 端口范围
  enable_service_det: boolean // 是否进行服务识别
  enable_port_scan?: boolean // 是否进行端口扫描（自定义扫描用）
  enable_udp_scan?: boolean // 是否进行 UDP 扫描
  udp_ports?: string // UDP 扫描端口范围

  // 认证攻击
  enable_weak_password: boolean // 是否进行弱口令猜解

  // Web 扫描
  enable_subdomain_enum: boolean // 是否进行子域名枚举
  enable_dir_scan: boolean // 是否进行目录扫描
  enable_web_fingerprint?: boolean // 是否进行Web指纹识别（自定义扫描用）
  enable_poc_verify?: boolean // 是否进行POC漏洞验证（自定义扫描用）
  enable_full_poc_verify?: boolean // 是否进行全量POC验证（不依赖指纹）

  // 反连服务
  enable_reverse: boolean // 是否启用反连服务

  // 其他选项
  threads: number // 并发线程数
  timeout: number // 超时时间（秒）
  advanced: string // 高级选项（JSON字符串）
  scheduled_time?: string // 定时扫描时间
  blacklist_ports?: string // 端口黑名单
  blacklist_hosts?: string // 资产黑名单
}

// 任务接口
export interface Task {
  id?: number
  name: string
  target: string
  type: string // 扫描类型：port, web, vuln
  description?: string
  scan_options: ScanOptions
  status?: string
  progress?: number
  creator?: string
  result?: string
  created_at?: string
  updated_at?: string
  started_at?: string
  completed_at?: string
}

export interface ScanTask {
  id: number
  name: string
  targets: string
  status: string
  created_at: string
}

// 创建任务请求
export interface CreateTaskRequest {
  name: string
  target: string
  type: string
  description?: string
  scan_options: ScanOptions
}

// 创建任务
export function createTask(data: CreateTaskRequest) {
  return axios.post('/api/task/create', data)
}

// 获取任务列表
export function getTaskList(params?: { page?: number; pageSize?: number; name?: string; status?: string; type?: string }) {
  return axios.get('/api/task/list', { params })
}

// 获取任务详情
export function getTaskDetail(id: number) {
  return axios.get(`/api/task/${id}`)
}

// 启动任务
export function startTask(id: number) {
  return axios.post(`/api/task/${id}/start`)
}

// 停止任务
export function stopTask(id: number) {
  return axios.post(`/api/task/${id}/stop`)
}

// 删除任务
export function deleteTask(id: number) {
  return axios.delete(`/api/task/${id}`)
}

// 获取任务统计
export function getTaskStats() {
  return axios.get('/api/task/stats')
}

export function getTopPorts() {
  return axios.get('/api/task/ports/top1000')
}

// 获取任务扫描结果 (资产测绘)
export function getTaskResults(id: number) {
  return axios.get(`/api/task/${id}/results`)
}

// 获取任务发现的漏洞
export function getTaskVulnerabilities(id: number) {
  return axios.get(`/api/task/${id}/vulnerabilities`)
}

// 获取任务实时进度
export function getTaskProgress(id: number) {
  return axios.get(`/api/task/${id}/progress`)
}

// 导出为PDF
export function exportPdf(htmlStr: string) {
  const token = getToken()
  return axios.post(
    '/api/task/export-pdf',
    { html: htmlStr },
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      responseType: 'blob',
      timeout: 60000,
    }
  )
}
