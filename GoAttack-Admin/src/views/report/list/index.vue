<template>
  <div class="container">
    <Breadcrumb :items="['menu.report', 'menu.report.list']" />
    <a-card class="general-card" title="报告管理">
      <template #extra>
        <a-space>
          <a-select v-model="filterType" placeholder="扫描类型" allow-clear style="width: 130px" @change="fetchData">
            <a-option value="full">全量扫描</a-option>
            <a-option value="port">端口扫描</a-option>
            <a-option value="vuln">漏洞扫描</a-option>
            <a-option value="web">Web扫描</a-option>
          </a-select>
          <a-button @click="fetchData">
            <template #icon><icon-refresh /></template>
            刷新
          </a-button>
        </a-space>
      </template>

      <a-table
        :data="reportList"
        :loading="loading"
        :pagination="{ pageSize: 15, showTotal: true }"
        row-key="id"
        :bordered="false"
        size="medium"
      >
        <template #columns>
          <a-table-column title="ID" data-index="id" :width="70" />
          <a-table-column title="任务名称" data-index="name" :ellipsis="true" :tooltip="true" :width="200" />
          <a-table-column title="扫描目标" data-index="target" :ellipsis="true" :tooltip="true" :width="200" />
          <a-table-column title="扫描类型" :width="120">
            <template #cell="{ record }">
              <a-tag :color="getScanTypeColor(record.type)">{{ getScanTypeName(record.type) }}</a-tag>
            </template>
          </a-table-column>
          <a-table-column title="状态" :width="100">
            <template #cell="{ record }">
              <a-badge :status="record.status === 'completed' || record.status === 'finished' ? 'success' : 'normal'" :text="getStatusText(record.status)" />
            </template>
          </a-table-column>
          <a-table-column title="开始时间" :width="170">
            <template #cell="{ record }">{{ formatDateTime(record.started_at || record.created_at) }}</template>
          </a-table-column>
          <a-table-column title="完成时间" :width="170">
            <template #cell="{ record }">{{ formatDateTime(record.completed_at) }}</template>
          </a-table-column>
          <a-table-column title="操作" align="center" :width="200" fixed="right">
            <template #cell="{ record }">
              <a-space>
                <a-button type="text" size="small" @click="viewReport(record.id)">
                  <template #icon><icon-file /></template>
                  查看报告
                </a-button>
                <a-dropdown @select="(val: any) => handleExportFromList(val, record.id)">
                  <a-button type="text" size="small">
                    <template #icon><icon-download /></template>
                    导出
                    <template #suffix><icon-down /></template>
                  </a-button>
                  <template #content>
                    <a-doption value="html">导出 HTML</a-doption>
                    <a-doption value="pdf">导出 PDF</a-doption>
                  </template>
                </a-dropdown>
              </a-space>
            </template>
          </a-table-column>
        </template>
      </a-table>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { Message } from '@arco-design/web-vue'
import { IconRefresh, IconFile, IconDownload, IconDown } from '@arco-design/web-vue/es/icon'
import { getTaskList } from '@/api/task'

const router = useRouter()
const loading = ref(false)
const reportList = ref<any[]>([])
const filterType = ref('')

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
  const d = parseChinaDate(dateStr)
  if (!d) return '-'
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(d)
}

const getScanTypeName = (type: string) => {
  const map: Record<string, string> = { alive: '存活扫描', port: '端口扫描', full: '全量扫描', vuln: '漏洞扫描', web: 'Web扫描' }
  return map[type] || type || '-'
}

const getScanTypeColor = (type: string) => {
  const colorMap: Record<string, string> = { alive: 'blue', port: 'purple', full: 'orange', vuln: 'red', web: 'green' }
  return colorMap[type] || 'gray'
}

const getStatusText = (status: string) => {
  const map: Record<string, string> = {
    completed: '已完成', finished: '已完成', running: '运行中',
    pending: '等待中', stopped: '已停止', failed: '失败', error: '出错',
  }
  return map[status] || status
}

const fetchData = async () => {
  loading.value = true
  try {
    const { data } = await getTaskList({ pageSize: 200, type: filterType.value || undefined })
    reportList.value = (data.list || [])
  } catch (err: any) {
    Message.error(err.message || '获取报告列表失败')
  } finally {
    loading.value = false
  }
}

const viewReport = (id: number) => {
  router.push({ name: 'ReportDetail', query: { taskId: id.toString() } })
}

const handleExportFromList = (type: string, id: number) => {
  router.push({ name: 'ReportDetail', query: { taskId: id.toString(), export: type } })
}

onMounted(fetchData)
</script>

<style scoped lang="less">
.container {
  padding: 0 20px 20px 20px;
}
</style>
