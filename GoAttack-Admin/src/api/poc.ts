import axios, { AxiosPromise } from 'axios'

// 标准API响应格式（后端返回）
export interface ApiResponse<T = any> {
  code: number
  msg: string
  data: T
}

// 由于 axios 拦截器会解包响应（return res 而不是 response），
// 实际 API 函数返回的是 data 字段的内容
export type UnwrappedResponse<T> = Promise<{ data: T }>

// POC模板接口
export interface PocTemplate {
  id: number
  template_id: string
  name: string
  category: string
  severity: string
  tags: string[]
  cve_id: string
  cnvd_id: string
  protocol: string
  author: string
  is_active: boolean
  verified: boolean
  created_at: string
  template_content?: string
}

// POC模板列表数据
export interface PocTemplateListData {
  list: PocTemplate[]
  total: number
  page: number
  page_size: number
}

// 获取POC模板列表
export function getPocTemplateList(params?: {
  page?: number
  pageSize?: number
  name?: string
  category?: string
  severity?: string
  cve_id?: string
  cnvd_id?: string
  protocol?: string
  is_active?: boolean
  sort?: string
  order?: string
}): UnwrappedResponse<PocTemplateListData> {
  return axios.get('/api/poc/templates', { params }) as any
}

// 获取POC模板详情
export function getPocTemplateDetail(id: number): UnwrappedResponse<PocTemplate> {
  return axios.get(`/api/poc/templates/${id}`) as any
}

// 搜索POC模板
export function searchPocTemplates(params?: {
  keyword?: string
  page?: number
  pageSize?: number
}): UnwrappedResponse<PocTemplateListData> {
  return axios.get('/api/poc/templates/search', { params }) as any
}

// 获取POC统计信息
export function getPocTemplateStats(): UnwrappedResponse<any> {
  return axios.get('/api/poc/templates/stats') as any
}

// 更新POC模板
export function updatePocTemplate(
  id: number,
  data: {
    is_active?: boolean
    verified?: boolean
    template_content?: string
  }
): UnwrappedResponse<any> {
  return axios.put(`/api/poc/templates/${id}`, data) as any
}

// 删除POC模板
export function deletePocTemplate(id: number): UnwrappedResponse<any> {
  return axios.delete(`/api/poc/templates/${id}`) as any
}

// 批量删除POC
export function batchDeletePocs(ids: number[]): UnwrappedResponse<any> {
  return axios.delete('/api/poc/batch-delete', { data: { ids } }) as any
}

// 扫描并导入POC模板
export function scanAndImportPocs(data: { path: string }): UnwrappedResponse<{ total_files: number; valid_files: number }> {
  return axios.post('/api/poc/scan-import', data) as any
}

// 前端上传压缩包或批量文件导入POC
export function uploadDirectoryPocs(data: FormData): UnwrappedResponse<{ total_files: number; valid_files: number }> {
  return axios.post('/api/poc/upload-directory', data, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    // 大规模批量导入场景需要更长处理时间（30分钟）
    timeout: 1800000,
  }) as any
}

// 保存手动输入的POC模板
export function saveManualPoc(data: { content: string }): UnwrappedResponse<{
  id: number
  name: string
  location: string
}> {
  return axios.post('/api/poc/manual-import/save', data) as any
}

// HTTP请求包转YAML模板请求参数
export interface ConvertHTTPToYamlRequest {
  raw_http: string
  poc_name?: string
  severity?: string
  description?: string
  author?: string
  match_type?: string // status/word/regex
  match_value?: string
}

// HTTP请求包转YAML模板响应
export interface ConvertHTTPToYamlResponse {
  yaml_content: string
  parsed_info: {
    method: string
    path: string
    host: string
    headers_count: number
    has_body: boolean
  }
}

// HTTP请求包转换为Nuclei YAML模板
export function convertHTTPToYaml(data: ConvertHTTPToYamlRequest): UnwrappedResponse<ConvertHTTPToYamlResponse> {
  return axios.post('/api/poc/convert-http', data) as any
}

// POC 验证结果
export interface PocVerifyResult {
  template_id: string
  template_name: string
  target: string
  matched: boolean
  severity: string
  description: string
  matched_at?: string
  request?: string
  response?: string
  extracted_data?: Record<string, any>
  error?: string
  timestamp: string
}

// POC 验证请求
export interface PocVerifyRequest {
  target: string
  targets?: string[]
  poc_ids: number[]
  result_id?: number
  variables?: Record<string, string>
}

// POC 验证响应
export interface PocVerifyResponse {
  results: PocVerifyResult[]
  total: number
}

// 执行 POC 验证
export function verifyPoc(data: PocVerifyRequest): UnwrappedResponse<PocVerifyResponse> {
  return axios.post('/api/poc/verify', data) as any
}

// POC 验证结果历史记录接口
export interface PocVerifyResultRecord {
  id: number
  target: string
  poc_id: number
  template_id: string
  template_name: string
  matched: boolean
  severity: string
  description: string
  request: string
  response: string
  matched_at: string
  extracted_data?: Record<string, any>
  error?: string
  verified_by: string
  verified_at: string
}

// POC 验证结果列表数据
export interface PocVerifyResultListData {
  list: PocVerifyResultRecord[]
  total: number
  page: number
  page_size: number
}

// 获取 POC 验证结果列表
export function getPocVerifyResults(params?: {
  page?: number
  pageSize?: number
  target?: string
  poc_id?: number
  template_id?: string
  matched?: boolean
  severity?: string
}): UnwrappedResponse<PocVerifyResultListData> {
  return axios.get('/api/poc/verify-results', { params }) as any
}

// 获取 POC 验证结果详情
export function getPocVerifyResultDetail(id: number): UnwrappedResponse<PocVerifyResultRecord> {
  return axios.get(`/api/poc/verify-results/${id}`) as any
}

// 删除 POC 验证结果
export function deletePocVerifyResult(id: number): UnwrappedResponse<any> {
  return axios.delete(`/api/poc/verify-results/${id}`) as any
}

// 批量删除 POC 验证结果
export function batchDeletePocVerifyResults(ids: number[]): UnwrappedResponse<any> {
  return axios.delete('/api/poc/verify-results/batch', { data: { ids } }) as any
}

// 清空所有 POC 验证结果
export function clearPocVerifyResults(): UnwrappedResponse<any> {
  return axios.delete('/api/poc/verify-results/clear') as any
}
