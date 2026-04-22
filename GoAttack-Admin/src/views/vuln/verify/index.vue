<template>
  <div class="container">
    <Breadcrumb :items="['menu.vuln', 'menu.vuln.verify']" />
    <a-space direction="vertical" :size="16" fill>
      <a-card class="general-card" title="POC 验证">
        <template #extra>
          <a-space>
            <a-button @click="resetForm">重置</a-button>
            <a-button type="primary" :loading="verifying" @click="handleVerify">
              <template #icon><icon-play-arrow /></template>
              开始验证
            </a-button>
          </a-space>
        </template>
        <a-form :model="form" layout="vertical">
          <a-row :gutter="24">
            <a-col :span="24">
              <a-form-item field="target" label="扫描目标" required help="支持 IP、域名或 URL（支持多个目标，换行分隔）">
                <a-textarea
                  v-model="form.target"
                  placeholder="请输入目标IP或域名，支持多个目标（换行分隔）&#10;例如:&#10;192.168.1.1&#10;http://example.com:8080&#10;domain.com"
                  :auto-size="{ minRows: 5, maxRows: 10 }"
                  size="large"
                />
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="24">
            <a-col :span="12">
              <a-form-item field="pocIds" label="选择 POC" required>
                <a-select
                  v-model="form.pocIds"
                  multiple
                  placeholder="可多选 POC 进行验证"
                  allow-search
                  :loading="pocsLoading"
                  @search="handlePocSearch"
                >
                  <a-option v-for="item in pocList" :key="item.id" :value="item.id">
                    {{ item.name }}
                    <template #suffix>
                      <a-tag :color="getSeverityColor(item.severity)" size="small">
                        {{ item.severity }}
                      </a-tag>
                    </template>
                  </a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="模板变量" field="variables" help="用于替换模板中的变量，如 {{username}}">
                <a-space direction="vertical" style="width: 100%">
                  <div v-for="(item, index) in form.variableList" :key="index" style="display: flex; gap: 10px; align-items: center">
                    <a-input v-model="item.key" placeholder="变量名 (如 username)" style="width: 200px" />
                    <span style="font-weight: bold">=</span>
                    <a-input v-model="item.value" placeholder="变量值 (如 admin)" style="flex: 1" />
                    <a-button type="text" status="danger" @click="removeVariable(index)">
                      <template #icon><icon-delete /></template>
                    </a-button>
                  </div>
                  <a-button type="dashed" long @click="addVariable">
                    <template #icon><icon-plus /></template>
                    添加变量
                  </a-button>
                </a-space>
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </a-card>

      <a-card class="general-card" title="验证结果">
        <template #extra>
          <a-button type="text" status="danger" @click="clearResults">
            <template #icon><icon-delete /></template>
            清空结果
          </a-button>
        </template>
        <a-table :data="results" :loading="verifying" :pagination="{ pageSize: 10 }">
          <template #columns>
            <a-table-column title="POC 名称" data-index="pocName" :width="250" />
            <a-table-column title="扫描目标" data-index="target" :width="200" />
            <a-table-column title="验证状态" data-index="status">
              <template #cell="{ record }">
                <a-tag :color="getStatusColor(record.status)">
                  <template #icon>
                    <icon-sync v-if="record.status === 'verifying'" spin />
                    <icon-check-circle v-else-if="record.status === 'success' || record.status === 'vulnerable'" />
                    <icon-close-circle v-else />
                  </template>
                  {{ getStatusText(record.status) }}
                </a-tag>
              </template>
            </a-table-column>
            <a-table-column title="风险等级" data-index="severity">
              <template #cell="{ record }">
                <a-tag v-if="record.severity" :color="getSeverityColor(record.severity)">
                  {{ record.severity }}
                </a-tag>
                <span v-else>-</span>
              </template>
            </a-table-column>
            <a-table-column title="验证时间" data-index="timestamp">
              <template #cell="{ record }">
                {{ record.timestamp ? new Date(record.timestamp).toLocaleString() : '-' }}
              </template>
            </a-table-column>
            <a-table-column title="结果详情" data-index="detail">
              <template #cell="{ record }">
                <a-typography-text :type="record.status === 'vulnerable' ? 'danger' : 'secondary'">
                  {{ record.detail }}
                </a-typography-text>
              </template>
            </a-table-column>
            <a-table-column title="操作" :width="180" align="center">
              <template #cell="{ record }">
                <a-space>
                  <a-button type="text" size="small" @click="showDetail(record)">
                    <template #icon><icon-eye /></template>
                    查看详情
                  </a-button>
                  <a-button type="text" size="small" @click="retryVerify(record)">
                    <template #icon><icon-refresh /></template>
                    重新验证
                  </a-button>
                </a-space>
              </template>
            </a-table-column>
          </template>
        </a-table>
      </a-card>

      <!-- 详情抽屉 -->
      <a-drawer v-model:visible="detailVisible" title="验证详情" :width="1000" unmount-on-close>
        <a-space direction="vertical" :size="16" fill v-if="currentDetail">
          <a-descriptions :column="2" bordered>
            <a-descriptions-item label="POC 名称" :span="2">{{ currentDetail.pocName }}</a-descriptions-item>
            <a-descriptions-item label="模板ID">{{ currentDetail.templateId || '-' }}</a-descriptions-item>
            <a-descriptions-item label="扫描目标">{{ currentDetail.target }}</a-descriptions-item>
            <a-descriptions-item label="验证状态">
              <a-tag :color="getStatusColor(currentDetail.status)">
                {{ getStatusText(currentDetail.status) }}
              </a-tag>
            </a-descriptions-item>
            <a-descriptions-item label="风险等级">
              <a-tag v-if="currentDetail.severity" :color="getSeverityColor(currentDetail.severity)">
                {{ currentDetail.severity }}
              </a-tag>
            </a-descriptions-item>
            <a-descriptions-item label="详情说明" :span="2">
              {{ currentDetail.detail }}
            </a-descriptions-item>
          </a-descriptions>

          <a-card title="请求与响应" class="request-response-card">
            <div v-for="(packet, index) in packetList" :key="index" class="packet-wrapper">
              <a-divider v-if="index > 0" orientation="center" style="margin: 12px 0; color: var(--color-text-3); font-size: 12px">
                交互 {{ index + 1 }}
              </a-divider>
              <a-row :gutter="16" class="packet-row">
                <a-col :span="12" class="packet-col">
                  <div class="packet-container">
                    <div class="packet-header">
                      <span>请求包 {{ packetList.length > 1 ? `#${index + 1}` : '' }}</span>
                    </div>
                    <pre class="packet-content">{{ packet.req }}</pre>
                  </div>
                </a-col>
                <a-col :span="12" class="packet-col">
                  <div class="packet-container">
                    <div class="packet-header">
                      <span>响应包 {{ packetList.length > 1 ? `#${index + 1}` : '' }}</span>
                    </div>
                    <pre class="packet-content">{{ packet.res }}</pre>
                  </div>
                </a-col>
              </a-row>
            </div>
          </a-card>

          <a-card title="提取数据" v-if="currentDetail.extractedData">
            <pre class="json-content">{{ JSON.stringify(currentDetail.extractedData, null, 2) }}</pre>
          </a-card>
        </a-space>
        <template #footer>
          <a-space>
            <a-button type="primary" @click="currentDetail && retryVerify(currentDetail)">
              <template #icon><icon-refresh /></template>
              重新验证
            </a-button>
            <a-button @click="detailVisible = false">关闭</a-button>
          </a-space>
        </template>
      </a-drawer>
    </a-space>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted, watch, computed } from 'vue'
import { useRoute } from 'vue-router'
import { Message, Modal } from '@arco-design/web-vue'
import {
  IconPlayArrow,
  IconDelete,
  IconSync,
  IconCheckCircle,
  IconCloseCircle,
  IconEye,
  IconRefresh,
  IconPlus,
} from '@arco-design/web-vue/es/icon'
import {
  getPocTemplateList,
  getPocTemplateDetail,
  verifyPoc,
  getPocVerifyResults,
  searchPocTemplates,
  clearPocVerifyResults,
  PocTemplate,
  PocVerifyResultRecord,
} from '@/api/poc'

interface PocDisplayResult {
  id?: number
  pocName: string
  target: string
  status: string
  severity: string
  detail: string
  request: string
  response: string
  extractedData?: any
  timestamp: string
  templateId: string
}

const route = useRoute()
const PREFILL_TARGETS_KEY = 'goattack_poc_targets'
const form = reactive({
  target: '',
  pocIds: [] as number[],
  variableList: [] as { key: string; value: string }[],
})

const addVariable = () => {
  form.variableList.push({ key: '', value: '' })
}

const removeVariable = (index: number) => {
  form.variableList.splice(index, 1)
}

const pocList = ref<PocTemplate[]>([])
const pocsLoading = ref(false)
const verifying = ref(false)
const results = ref<PocDisplayResult[]>([])
const detailVisible = ref(false)
const currentDetail = ref<PocDisplayResult | null>(null)

// 计算属性：解析请求和响应包列表
const packetList = computed(() => {
  if (!currentDetail.value) return []
  const { request, response } = currentDetail.value

  try {
    // 尝试解析 JSON 格式的多包数据
    if (request && request.trim().startsWith('[')) {
      const reqs = JSON.parse(request)
      // 响应可能是 JSON 数组，也可能是空字符串
      let resps: string[] = []
      if (response && response.trim().startsWith('[')) {
        resps = JSON.parse(response)
      }

      if (Array.isArray(reqs)) {
        return reqs.map((req: string, i: number) => ({
          req: req || '无请求数据',
          res: resps[i] || '无响应数据',
        }))
      }
    }
  } catch (e) {
    // 解析失败，回退到普通显示
  }

  // 默认单包显示
  return [
    {
      req: request || '无请求数据',
      res: response || '无响应数据',
    },
  ]
})

let searchTimeout: ReturnType<typeof setTimeout> | null = null // 搜索防抖计时器

// 提取YAML中的变量
const extractVariablesFromYaml = (content: string) => {
  if (!content) return []
  const vars: { key: string; value: string }[] = []
  const lines = content.split('\n')
  let inVariables = false
  let baseIndent = -1

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]
    if (!line.trim().startsWith('#')) {
      if (!inVariables) {
        if (line.trim() === 'variables:') {
          inVariables = true
          baseIndent = line.search(/\S/)
        }
      } else {
        const currentIndent = line.search(/\S/)
        if (currentIndent !== -1) {
          if (currentIndent <= baseIndent) {
            break // 退出变量块
          }

          const match = line.match(/^\s*([a-zA-Z0-9_-]+):/)
          if (match) {
            vars.push({ key: match[1], value: '' })
          }
        }
      }
    }
  }
  return vars
}

// 监听 POC 选择变化，自动加载变量
watch(
  () => form.pocIds,
  async (newIds) => {
    if (newIds.length === 1) {
      try {
        const id = newIds[0]
        const res = await getPocTemplateDetail(id)
        if (res.data && res.data.template_content) {
          const vars = extractVariablesFromYaml(res.data.template_content)
          form.variableList = vars
        }
      } catch {
        // console.error('加载POC详情失败', err)
      }
    } else {
      // 多选或未选时不显示自动变量，或者可以清空
      form.variableList = []
    }
  }
)

// 获取所有激活的 POC
const fetchPocs = async (name?: string) => {
  pocsLoading.value = true
  try {
    // 如果有搜索关键词，使用搜索API（可以搜索到所有POC）
    if (name && name.trim()) {
      const res = await searchPocTemplates({
        keyword: name,
        pageSize: 200, // 搜索时返回更多结果
      })
      pocList.value = res.data.list
    } else {
      // 无搜索词时，默认加载激活的POC
      const res = await getPocTemplateList({
        pageSize: 200, // 增加默认加载数量
        is_active: true,
      })
      pocList.value = res.data.list
    }
  } catch (err) {
    Message.error('获取 POC 列表失败')
  } finally {
    pocsLoading.value = false
  }
}

// 将英文severity转换为中文
const getSeverityText = (severity: string) => {
  const map: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
    safe: '安全',
  }
  return map[severity?.toLowerCase()] || severity || '未知'
}

// 加载历史验证结果
const loadHistoryResults = async () => {
  try {
    const res = await getPocVerifyResults({
      page: 1,
      pageSize: 20, // 加载最近20条历史记录
    })

    if (res.data.list && res.data.list.length > 0) {
      //  转换历史记录为结果格式
      const historyResults = res.data.list.map((record: PocVerifyResultRecord) => ({
        id: record.id,
        pocName: record.template_name || record.template_id,
        target: record.target,
        status: record.matched ? 'vulnerable' : 'success',
        severity: record.matched ? getSeverityText(record.severity || 'info') : '安全', // 匹配成功显示中文severity，未匹配显示安全
        detail: record.matched ? `扫描完成，发现 ${record.template_name || record.template_id} 漏洞` : '扫描完成，未发现该漏洞特征',
        request: record.request,
        response: record.response,
        extractedData: record.extracted_data,
        timestamp: record.verified_at,
        templateId: record.template_id,
      }))
      results.value = historyResults
    }
  } catch {
    // console.error('加载历史记录失败:', err)
  }
}

const handlePocSearch = (value: string) => {
  // 防抖搜索，避免频繁请求
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
  searchTimeout = setTimeout(() => {
    fetchPocs(value)
  }, 300)
}

const getSeverityColor = (severity: string) => {
  const map: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'blue',
    info: 'gray',
    safe: 'green',
    严重: 'red',
    高危: 'orange',
    中危: 'gold',
    低危: 'blue',
    安全: 'green',
  }
  return map[severity?.toLowerCase()] || 'gray'
}

const getStatusColor = (status: string) => {
  const map: Record<string, string> = {
    verifying: 'arcoblue',
    success: 'green',
    vulnerable: 'red',
    error: 'gray',
  }
  return map[status] || 'gray'
}

const getStatusText = (status: string) => {
  const map: Record<string, string> = {
    verifying: '正在验证',
    success: '扫描完成',
    vulnerable: '发现漏洞',
    error: '扫描失败',
  }
  return map[status] || '未知'
}

const resetForm = () => {
  form.target = ''
  form.pocIds = []
  form.variableList = []
}

const parseTargets = (value: string) => {
  return Array.from(
    new Set(
      value
        .split(/[\r\n,，;；]+/)
        .map((item) => item.trim())
        .filter((item) => item)
    )
  )
}

const handleVerify = async (arg?: number | Event) => {
  const targets = parseTargets(form.target)
  if (targets.length === 0) {
    Message.warning('请输入扫描目标')
    return
  }
  if (form.pocIds.length === 0) {
    Message.warning('请选择至少一个 POC')
    return
  }

  const resultId = typeof arg === 'number' ? arg : undefined
  verifying.value = true

  try {
    const variables: Record<string, string> = {}
    form.variableList.forEach((item) => {
      if (item.key) variables[item.key] = item.value
    })

    // 调用后端 API 执行验证
    const payload: any = {
      target: targets[0],
      poc_ids: form.pocIds,
      result_id: resultId,
      variables,
    }
    if (!resultId && targets.length > 1) {
      payload.targets = targets
    }

    const res = await verifyPoc(payload)

    // 处理验证结果
    const apiResults = res.data.results || []

    // 转换结果格式
    const convertedResults = apiResults.map((result: any) => ({
      id: result.id || resultId || undefined, // 使用后端返回的ID，或者传入的ID
      pocName: result.template_name || result.template_id,
      target: result.target,
      status: result.matched ? 'vulnerable' : 'success',
      severity: result.matched ? getSeverityText(result.severity || 'info') : '安全',
      detail: result.matched ? `扫描完成，发现 ${result.template_name || result.template_id} 漏洞` : '扫描完成，未发现该漏洞特征',
      request: result.request,
      response: result.response,
      extractedData: result.extracted_data,
      timestamp: result.timestamp,
      templateId: result.template_id,
    }))

    if (resultId) {
      // 更新现有记录
      const index = results.value.findIndex((r) => r.id === resultId)
      if (index !== -1 && convertedResults.length > 0) {
        // 保留原有ID和其他未更新字段（如果有）
        results.value[index] = { ...results.value[index], ...convertedResults[0] }
      }
    } else {
      // 添加新记录
      results.value = [...convertedResults, ...results.value]
    }

    // 统计匹配结果
    const matchedCount = convertedResults.filter((r: any) => r.status === 'vulnerable').length

    if (matchedCount > 0) {
      Message.warning(`验证完成：发现 ${matchedCount} 个漏洞`)
    } else {
      Message.success('验证完成：未发现漏洞')
    }
  } catch (err) {
    const error = err as Error
    Message.error(`验证失败: ${error.message || '未知错误'}`)
  } finally {
    verifying.value = false
  }
}

const clearResults = async () => {
  if (results.value.length === 0) {
    Message.warning('没有可清空的结果')
    return
  }

  try {
    // 确认删除
    Modal.warning({
      title: '确认清空',
      content: '确定要清空所有验证结果吗？此操作将从数据库中永久删除全部历史记录，不可恢复！',
      okText: '确定清空',
      cancelText: '取消',
      onOk: async () => {
        try {
          // 调用后端全量清空 API
          await clearPocVerifyResults()
          Message.success('验证结果已全部清空')
          // 清空前端显示
          results.value = []
        } catch (err) {
          const error = err as Error
          Message.error(`删除失败: ${error.message || '未知错误'}`)
        }
      },
    })
  } catch (err) {
    const error = err as Error
    Message.error(`操作失败: ${error.message || '未知错误'}`)
  }
}

const showDetail = (record: PocDisplayResult) => {
  currentDetail.value = record
  detailVisible.value = true
}

const retryVerify = async (record: PocDisplayResult) => {
  if (!record.target) {
    Message.warning('无效的验证目标')
    return
  }

  try {
    // 先尝试从已加载的列表中查找
    let poc = pocList.value.find((p) => p.template_id === record.templateId)

    // 如果未找到，通过API搜索
    if (!poc && record.templateId) {
      const searchRes = await searchPocTemplates({
        keyword: record.templateId,
        pageSize: 10,
      })

      if (searchRes.data.list && searchRes.data.list.length > 0) {
        poc = searchRes.data.list.find((p) => p.template_id === record.templateId)
      }
    }

    if (!poc) {
      Message.warning(`未找到POC模板: ${record.templateId || record.pocName}`)
      return
    }

    // 重新设置表单并执行验证
    form.target = record.target
    form.pocIds = [poc.id]
    detailVisible.value = false
    await handleVerify(record.id)
  } catch {
    Message.error('查找POC模板失败')
    // console.error(err)
  }
}

onMounted(async () => {
  await fetchPocs()
  await loadHistoryResults() // 加载历史记录

  const savedTargets = sessionStorage.getItem(PREFILL_TARGETS_KEY)
  if (savedTargets) {
    if (!form.target) {
      form.target = savedTargets
    }
    sessionStorage.removeItem(PREFILL_TARGETS_KEY)
  }

  // 处理从 POC 列表跳转过来的批量验证请求
  if (route.query.pocIds) {
    const ids = (route.query.pocIds as string).split(',').map(Number)
    form.pocIds = ids
  }
})
</script>

<style scoped lang="less">
.container {
  padding: 0 20px 20px 20px;
}

.general-card {
  border-radius: 4px;
  border: none;
  & > .arco-card-header {
    height: auto;
    padding: 20px;
    border: none;
  }
  & > .arco-card-body {
    padding: 0 20px 20px 20px;
  }
}

.packet-container {
  border: 1px solid var(--color-border-2);
  border-radius: 4px;
  overflow: hidden;
  height: 400px; // 稍微减小每个包的高度，适应多包展示
  display: flex;
  flex-direction: column;
}

.packet-header {
  background: var(--color-fill-2);
  padding: 8px 12px;
  font-weight: 500;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--color-border-2);
  flex-shrink: 0; // 不缩小
}

.packet-content {
  margin: 0;
  padding: 12px;
  background: var(--color-bg-1);
  font-family: 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.6;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
  flex: 1; // 占满剩余空间
  height: 100%; // 占满高度
}

.packet-row {
  height: 400px; // 与 container 高度一致
}

.packet-wrapper {
  margin-bottom: 16px;
  &:last-child {
    margin-bottom: 0;
  }
}

.packet-col {
  height: 100%;
}

.request-response-card {
  :deep(.arco-card-body) {
    padding: 0;
  }
}

.json-content {
  margin: 0;
  padding: 12px;
  background: var(--color-bg-1);
  font-family: 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.6;
  max-height: 300px;
  overflow: auto;
  border: 1px solid var(--color-border-2);
  border-radius: 4px;
}
</style>
