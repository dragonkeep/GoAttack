<template>
  <div class="container">
    <Breadcrumb :items="['menu.task', 'menu.task.list']" />
    <a-card class="general-card" :title="$t('menu.task.list')">
      <!-- 顶部操作栏 -->
      <template #extra>
        <a-space>
          <a-button v-if="!batchMode" @click="toggleBatchMode">
            <template #icon>
              <icon-check-square />
            </template>
            批量操作
          </a-button>
          <template v-else>
            <a-tag color="blue">已选择 {{ selectedKeys.length }} 项</a-tag>
            <a-popconfirm content="确认删除选中的任务吗？" @ok="handleBatchDelete">
              <a-button status="danger" :disabled="selectedKeys.length === 0">
                <template #icon>
                  <icon-delete />
                </template>
                批量删除
              </a-button>
            </a-popconfirm>
            <a-button @click="cancelBatchMode">取消</a-button>
          </template>
        </a-space>
      </template>

      <a-row>
        <a-col :flex="1">
          <a-form :model="formModel" :label-col-props="{ span: 6 }" :wrapper-col-props="{ span: 18 }" label-align="left">
            <a-row :gutter="16">
              <a-col :span="8">
                <a-form-item field="name" label="任务名称">
                  <a-input v-model="formModel.name" placeholder="搜索任务名称" />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="type" label="扫描类型">
                  <a-select v-model="formModel.type" placeholder="请选择扫描类型" allow-clear>
                    <a-option value="full">全量扫描</a-option>
                    <a-option value="quick">快速扫描</a-option>
                    <a-option value="custom">自定义扫描</a-option>
                    <a-option value="alive">存活扫描（旧）</a-option>
                    <a-option value="port">端口扫描（旧）</a-option>
                    <a-option value="web">Web扫描（旧）</a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="status" label="状态">
                  <a-select v-model="formModel.status" placeholder="请选择状态" allow-clear>
                    <a-option value="pending">{{ $t('task.status.pending') }}</a-option>
                    <a-option value="running">{{ $t('task.status.running') }}</a-option>
                    <a-option value="completed">{{ $t('task.status.completed') }}</a-option>
                    <a-option value="stopped">{{ $t('task.status.stopped') }}</a-option>
                    <a-option value="error">{{ $t('task.status.error') }}</a-option>
                    <a-option value="failed">{{ $t('task.status.failed') }}</a-option>
                  </a-select>
                </a-form-item>
              </a-col>
            </a-row>
          </a-form>
        </a-col>
        <a-divider style="height: 84px" direction="vertical" />
        <a-col :flex="'86px'" style="text-align: right">
          <a-space direction="vertical" :size="18">
            <a-button type="primary" @click="() => fetchData()">
              <template #icon>
                <icon-search />
              </template>
              查询
            </a-button>
            <a-button @click="reset">
              <template #icon>
                <icon-refresh />
              </template>
              重置
            </a-button>
          </a-space>
        </a-col>
      </a-row>
      <a-divider style="margin-top: 0" />
      <a-table
        row-key="id"
        :loading="loading"
        :pagination="pagination"
        :columns="columns"
        :data="renderData"
        :bordered="false"
        :row-selection="batchMode ? rowSelection : undefined"
        v-model:selectedKeys="selectedKeys"
        size="medium"
        @page-change="onPageChange"
        @sorter-change="onSortChange"
      >
        <template #scanType="{ record }">
          <a-tag :color="getScanTypeColor(record.type)">
            {{ getScanTypeName(record.type) }}
          </a-tag>
        </template>
        <template #status="{ record }">
          <a-tag :color="getStatusColor(record.status)">
            {{ $t(`task.status.${record.status}`) }}
          </a-tag>
        </template>
        <template #createdAt="{ record }">
          {{ formatDateTime(record.created_at) }}
        </template>
        <template #operations="{ record }">
          <a-space>
            <!-- 启动/重新扫描按钮 -->
            <a-button
              v-if="['pending', 'error', 'failed'].includes(record.status)"
              type="text"
              status="success"
              @click="handleStart(record.id)"
            >
              开始扫描
            </a-button>
            <a-button v-else-if="record.status === 'stopped'" type="text" @click="handleContinue(record.id)">继续扫描</a-button>
            <a-button
              v-else-if="['finished', 'completed'].includes(record.status)"
              type="text"
              status="success"
              @click="handleStart(record.id)"
            >
              重新扫描
            </a-button>
            <a-button v-if="record.status === 'running'" type="text" status="warning" @click="handleStop(record.id)">停止扫描</a-button>
            <a-button type="text" @click="handleView(record.id)">查看详情</a-button>

            <!-- 导出报告下拉
            <a-dropdown @select="(val: string) => handleExportReport(val, record.id)">
              <a-button type="text">报告</a-button>
              <template #content>
                <a-doption value="preview">报告预览</a-doption>
                <a-doption value="pdf">导出 PDF</a-doption>
                <a-doption value="html">导出 HTML</a-doption>
              </template>
            </a-dropdown> -->

            <a-popconfirm content="确认删除该任务及其结果吗？" @ok="handleDelete(record.id)">
              <a-button type="text" status="danger">删除</a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </a-table>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted, onUnmounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { Message } from '@arco-design/web-vue'
import { getTaskList, startTask, stopTask, deleteTask, ScanTask } from '@/api/task'
import { Pagination } from '@/types/global'

defineOptions({ name: 'TaskList' })

const router = useRouter()
const loading = ref(false)
const renderData = ref<ScanTask[]>([])
const batchMode = ref(false)
const selectedKeys = ref<number[]>([])

const formModel = reactive({
  name: '',
  type: '',
  status: '',
})

const pagination = reactive<Pagination>({
  current: 1,
  pageSize: 10,
  total: 0,
})

// 排序状态
const sortState = reactive({
  id: '' as '' | 'ascend' | 'descend',
  created_at: '' as '' | 'ascend' | 'descend',
})

const columns = computed(() => [
  {
    title: 'ID',
    dataIndex: 'id',
    width: 70,
    sortable: {
      sortDirections: ['ascend', 'descend'],
      sorter: true,
      sortOrder: sortState.id || undefined,
    },
  },
  {
    title: '任务名称',
    dataIndex: 'name',
    width: 150,
    ellipsis: true,
    tooltip: true,
  },
  {
    title: '扫描目标',
    dataIndex: 'target',
    width: 200,
    ellipsis: true,
    tooltip: true,
  },
  {
    title: '扫描类型',
    slotName: 'scanType',
    width: 110,
  },
  { title: '状态', slotName: 'status', width: 100 },
  {
    title: '创建时间',
    dataIndex: 'created_at',
    slotName: 'createdAt',
    width: 160,
    sortable: {
      sortDirections: ['ascend', 'descend'],
      sorter: true,
      sortOrder: sortState.created_at || undefined,
    },
  },
  { title: '操作', slotName: 'operations', fixed: 'right', width: 220 },
])

const rowSelection = {
  type: 'checkbox' as const,
  showCheckedAll: true,
}

const toggleBatchMode = () => {
  batchMode.value = true
  selectedKeys.value = []
}

const cancelBatchMode = () => {
  batchMode.value = false
  selectedKeys.value = []
}

const parseChinaDate = (dateStr: string) => {
  if (!dateStr) return null
  const normalized = String(dateStr).trim()
  if (!normalized) return null

  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$/.test(normalized)) {
    const withT = normalized.replace(' ', 'T')
    const dt = new Date(`${withT}+08:00`)
    return Number.isNaN(dt.getTime()) ? null : dt
  }

  const dt = new Date(normalized)
  return Number.isNaN(dt.getTime()) ? null : dt
}

const formatDateTime = (dateStr: string) => {
  if (!dateStr) return '-'
  const date = parseChinaDate(dateStr)
  if (!date) return '-'
  const formatter = new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
  return formatter.format(date).replace(/\//g, '-')
}

const getScanTypeName = (type: string) => {
  const typeMap: Record<string, string> = {
    full: '全量扫描',
    quick: '快速扫描',
    custom: '自定义扫描',
    alive: '存活扫描',
    port: '端口扫描',
    vuln: '漏洞扫描',
    web: 'Web扫描',
  }
  return typeMap[type] || type || '未知'
}

const getScanTypeColor = (type: string) => {
  const colorMap: Record<string, string> = {
    full: 'orange',
    quick: 'green',
    custom: 'purple',
    alive: 'blue',
    port: 'cyan',
    vuln: 'red',
    web: 'arcoblue',
  }
  return colorMap[type] || 'gray'
}

const applySorting = (data: ScanTask[]) => {
  const sorted = [...data]

  if (sortState.id) {
    sorted.sort((a, b) => {
      return sortState.id === 'ascend' ? a.id - b.id : b.id - a.id
    })
  }

  if (sortState.created_at) {
    sorted.sort((a, b) => {
      const dateA = parseChinaDate(a.created_at)?.getTime() || 0
      const dateB = parseChinaDate(b.created_at)?.getTime() || 0
      return sortState.created_at === 'ascend' ? dateA - dateB : dateB - dateA
    })
  }

  return sorted
}

const fetchData = async (silent = false) => {
  if (!silent) loading.value = true
  try {
    const { data } = await getTaskList({
      page: pagination.current,
      pageSize: pagination.pageSize,
      ...formModel,
    })
    renderData.value = data.list
    pagination.total = data.total

    // 本地排序
    if (sortState.id || sortState.created_at) {
      renderData.value = applySorting(renderData.value)
    }
  } catch (err: any) {
    if (!silent) Message.error(err.message || '获取任务列表失败')
  } finally {
    if (!silent) loading.value = false
  }
}

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    pending: 'gray',
    running: 'arcoblue',
    finished: 'green',
    completed: 'green',
    stopped: 'orange',
    error: 'red',
    failed: 'red',
  }
  return colors[status] || 'gray'
}

const onPageChange = (current: number) => {
  pagination.current = current
  fetchData()
}

const onSortChange = (dataIndex: string, direction: string) => {
  // 重置其他列的排序
  if (dataIndex === 'id') {
    sortState.created_at = ''
    sortState.id = direction as '' | 'ascend' | 'descend'
  } else if (dataIndex === 'created_at') {
    sortState.id = ''
    sortState.created_at = direction as '' | 'ascend' | 'descend'
  }

  // 应用排序
  renderData.value = applySorting(renderData.value)
}

const reset = () => {
  formModel.name = ''
  formModel.type = ''
  formModel.status = ''
  sortState.id = ''
  sortState.created_at = ''
  fetchData()
}

const handleStart = async (id: number) => {
  try {
    await startTask(id)
    Message.success('任务已启动')
    fetchData()
  } catch (err: any) {
    Message.error(err.message || '启动失败')
  }
}

const handleStop = async (id: number) => {
  try {
    await stopTask(id)
    Message.success('任务已停止')
    fetchData()
  } catch (err: any) {
    Message.error(err.message || '操作失败')
  }
}

const handleContinue = async (id: number) => {
  try {
    await startTask(id)
    Message.success('任务已继续')
    fetchData()
  } catch (err: any) {
    Message.error(err.message || '操作失败')
  }
}

const handleDelete = async (id: number) => {
  try {
    await deleteTask(id)
    Message.success('删除成功')
    fetchData()
  } catch (err: any) {
    Message.error(err.message || '删除失败')
  }
}

const handleBatchDelete = async () => {
  if (selectedKeys.value.length === 0) {
    Message.warning('请先选择要删除的任务')
    return
  }

  try {
    loading.value = true
    const promises = selectedKeys.value.map((id) => deleteTask(id))
    await Promise.all(promises)
    Message.success(`成功删除 ${selectedKeys.value.length} 个任务`)
    selectedKeys.value = []
    batchMode.value = false
    fetchData()
  } catch (err: any) {
    Message.error(err.message || '批量删除失败')
  } finally {
    loading.value = false
  }
}

const handleView = (id: number) => {
  router.push({ name: 'ScanResult', query: { taskId: id.toString() } })
}

const handleExportReport = (type: string, id: number) => {
  if (type === 'preview') {
    router.push({
      name: 'ReportDetail',
      query: { taskId: id.toString() },
    })
    return
  }

  Message.loading({ content: `正在生成 ${type.toUpperCase()} 报告...`, duration: 1500 })
  setTimeout(() => {
    Message.success(`${type.toUpperCase()} 报告导出成功`)
  }, 1600)
}

let timer: ReturnType<typeof setInterval> | null = null

const startPolling = () => {
  if (timer) return
  timer = setInterval(() => {
    fetchData(true)
  }, 3000)
}

const stopPolling = () => {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
}

onMounted(() => {
  fetchData()
  startPolling()
})

onUnmounted(() => {
  stopPolling()
})
</script>

<style scoped lang="less">
.container {
  padding: 0 20px 20px 20px;
}
</style>
