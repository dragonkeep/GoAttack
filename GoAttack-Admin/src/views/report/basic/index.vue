<template>
  <div class="container">
    <Breadcrumb :items="['menu.report', 'menu.report.detail']" />

    <div v-if="loading" class="loading-center">
      <a-spin size="large" tip="正在加载报告数据..." />
    </div>

    <template v-else>
      <!-- 报告头部 -->
      <a-card class="general-card report-header-card">
        <div class="report-header">
          <div class="header-left">
            <div class="report-title">
              <icon-file :size="24" style="margin-right: 10px; color: var(--color-primary-6)" />
              <a-typography-title :heading="5" style="margin: 0">安全扫描报告 — {{ reportData.taskName }}</a-typography-title>
            </div>
            <div class="header-meta">
              <a-space :size="24">
                <span>
                  <icon-calendar />
                  扫描开始: {{ reportData.startTime }}
                </span>
                <span>
                  <icon-clock-circle />
                  耗时: {{ reportData.duration }}
                </span>
                <span>
                  <a-badge
                    :status="reportData.status === 'completed' || reportData.status === 'finished' ? 'success' : 'normal'"
                    :text="getStatusText(reportData.status)"
                  />
                </span>
              </a-space>
            </div>
          </div>
          <div class="header-right">
            <a-space>
              <a-button @click="router.back()">
                <template #icon><icon-left /></template>
                返回列表
              </a-button>
              <a-dropdown @select="handleExport">
                <a-button type="primary">
                  <template #icon><icon-export /></template>
                  导出报告
                  <template #suffix><icon-down /></template>
                </a-button>
                <template #content>
                  <a-doption value="html">
                    <template #icon><icon-code /></template>
                    导出 HTML (.html)
                  </a-doption>
                  <a-doption value="pdf">
                    <template #icon><icon-file /></template>
                    导出 PDF (打印)
                  </a-doption>
                </template>
              </a-dropdown>
            </a-space>
          </div>
        </div>
      </a-card>

      <!-- 统计概览 -->
      <a-row :gutter="16" style="margin-top: 16px">
        <a-col :span="6">
          <a-card class="stat-card">
            <a-statistic
              title="发现资产"
              :value="reportData.stats.assets"
              :value-from="0"
              animation
              show-group-separator
              style="--color: var(--color-primary-6)"
            >
              <template #prefix><icon-computer :size="20" style="color: var(--color-primary-6)" /></template>
              <template #suffix>条</template>
            </a-statistic>
          </a-card>
        </a-col>
        <a-col :span="6">
          <a-card class="stat-card">
            <a-statistic title="开放端口" :value="reportData.stats.ports" :value-from="0" animation show-group-separator>
              <template #prefix><icon-wifi :size="20" style="color: #7816ff" /></template>
              <template #suffix>个</template>
            </a-statistic>
          </a-card>
        </a-col>
        <a-col :span="6">
          <a-card class="stat-card">
            <a-statistic title="Web 指纹" :value="reportData.stats.webApps" :value-from="0" animation>
              <template #prefix><icon-apps :size="20" style="color: #16baaa" /></template>
              <template #suffix>条</template>
            </a-statistic>
          </a-card>
        </a-col>
        <a-col :span="6">
          <a-card class="stat-card danger-card">
            <a-statistic title="发现漏洞" :value="reportData.stats.vulnerabilities" :value-from="0" animation>
              <template #prefix><icon-bug :size="20" style="color: #f53f3f" /></template>
              <template #suffix>个</template>
            </a-statistic>
          </a-card>
        </a-col>
      </a-row>

      <!-- 漏洞分布 + 任务详情 -->
      <a-row :gutter="16" style="margin-top: 16px">
        <a-col :span="9">
          <a-card class="general-card" title="漏洞危害等级分布">
            <div class="severity-chart">
              <div v-for="item in severityDist" :key="item.label" class="severity-row">
                <div class="severity-label">
                  <a-badge :color="item.color" :text="item.label" />
                </div>
                <div class="severity-bar-wrap">
                  <div class="severity-bar" :style="{ width: Math.min(item.percent, 100) + '%', backgroundColor: item.color }" />
                </div>
                <div class="severity-count">
                  <a-tag :color="item.tagColor" size="small">{{ item.count }}</a-tag>
                </div>
              </div>
              <div v-if="reportData.stats.vulnerabilities === 0" class="no-vuln">
                <icon-check-circle :size="40" style="color: #16baaa" />
                <div>未发现漏洞</div>
              </div>
            </div>
          </a-card>
        </a-col>
        <a-col :span="15">
          <a-card class="general-card" title="扫描配置详情">
            <a-descriptions :column="2" bordered size="medium">
              <a-descriptions-item label="任务名称">{{ reportData.taskName }}</a-descriptions-item>
              <a-descriptions-item label="扫描类型">{{ reportData.taskType }}</a-descriptions-item>
              <a-descriptions-item label="扫描目标" :span="2">
                <a-typography-text copyable>{{ reportData.target }}</a-typography-text>
              </a-descriptions-item>
              <a-descriptions-item label="端口范围">{{ reportData.ports }}</a-descriptions-item>
              <a-descriptions-item label="并发线程">{{ reportData.concurrency || '-' }}</a-descriptions-item>
              <a-descriptions-item label="开始时间">{{ reportData.startTime }}</a-descriptions-item>
              <a-descriptions-item label="完成时间">{{ reportData.endTime }}</a-descriptions-item>
              <a-descriptions-item label="扫描历时">{{ reportData.duration }}</a-descriptions-item>
              <a-descriptions-item label="当前状态">
                <a-badge
                  :status="reportData.status === 'completed' || reportData.status === 'finished' ? 'success' : 'normal'"
                  :text="getStatusText(reportData.status)"
                />
              </a-descriptions-item>
            </a-descriptions>
          </a-card>
        </a-col>
      </a-row>

      <!-- 开放端口服务列表 -->
      <a-card class="general-card" title="开放端口与服务" style="margin-top: 16px">
        <template #extra>
          <a-tag color="purple">共 {{ portList.length }} 条</a-tag>
        </template>
        <a-table :data="portList" :pagination="{ pageSize: 10, showTotal: true }" size="medium" :bordered="false">
          <template #columns>
            <a-table-column title="IP / 主机" data-index="ip" :width="160" />
            <a-table-column title="端口" data-index="port" :width="90">
              <template #cell="{ record }">
                <a-tag color="blue" size="small">{{ record.port }}</a-tag>
              </template>
            </a-table-column>
            <a-table-column title="协议" data-index="protocol" :width="80" />
            <a-table-column title="服务" data-index="service" :width="130" />
            <a-table-column title="产品" data-index="product" :ellipsis="true" :tooltip="true" />
            <a-table-column title="版本号" data-index="version" :width="150" :ellipsis="true" :tooltip="true" />
            <a-table-column title="状态" :width="90">
              <template #cell="{ record }">
                <a-badge status="success" :text="record.state || 'open'" />
              </template>
            </a-table-column>
          </template>
        </a-table>
      </a-card>

      <!-- Web 指纹 -->
      <a-card class="general-card" title="Web 指纹识别结果" style="margin-top: 16px">
        <template #extra>
          <a-tag color="cyan">共 {{ webList.length }} 条</a-tag>
        </template>
        <a-table :data="webList" :pagination="{ pageSize: 10, showTotal: true }" size="medium" :bordered="false">
          <template #columns>
            <a-table-column title="URL" :width="260" :ellipsis="true" :tooltip="true">
              <template #cell="{ record }">
                <a-link :href="record.url" target="_blank">{{ record.url }}</a-link>
              </template>
            </a-table-column>
            <a-table-column title="网站标题" data-index="title" :ellipsis="true" :tooltip="true" />
            <a-table-column title="状态码" :width="90">
              <template #cell="{ record }">
                <a-tag :color="record.status_code >= 400 ? 'red' : record.status_code >= 300 ? 'blue' : 'green'" size="small">
                  {{ record.status_code }}
                </a-tag>
              </template>
            </a-table-column>
            <a-table-column title="服务" data-index="server" :width="160" :ellipsis="true" />
            <a-table-column title="技术栈" :width="220">
              <template #cell="{ record }">
                <a-space wrap>
                  <a-tag v-for="tech in (record.technologies || []).slice(0, 4)" :key="tech" color="arcoblue" size="small">
                    {{ tech }}
                  </a-tag>
                </a-space>
              </template>
            </a-table-column>
          </template>
        </a-table>
      </a-card>

      <!-- 漏洞清单 -->
      <a-card class="general-card" title="漏洞详情清单" style="margin-top: 16px">
        <template #extra>
          <a-tag color="red">共 {{ vulnList.length }} 个</a-tag>
        </template>
        <a-table :data="vulnList" :pagination="{ pageSize: 10, showTotal: true }" size="medium" :bordered="false">
          <template #columns>
            <a-table-column title="漏洞名称" :width="260" :ellipsis="true" :tooltip="true">
              <template #cell="{ record }">
                <span style="font-weight: 500">{{ record.name }}</span>
              </template>
            </a-table-column>
            <a-table-column title="目标" data-index="target" :width="250" :ellipsis="true" :tooltip="true" />
            <a-table-column title="危害等级" :width="100">
              <template #cell="{ record }">
                <a-tag :color="getSeverityColor(record.severity)" size="small">{{ record.severity }}</a-tag>
              </template>
            </a-table-column>
            <a-table-column title="CVE / CNVD" :width="160">
              <template #cell="{ record }">
                <span v-if="record.cve">
                  <a-link :href="`https://nvd.nist.gov/vuln/detail/${record.cve}`" target="_blank">{{ record.cve }}</a-link>
                </span>
                <span v-else-if="record.cnvd">{{ record.cnvd }}</span>
                <span v-else class="text-placeholder">-</span>
              </template>
            </a-table-column>
            <a-table-column title="验证结果" :width="100">
              <template #cell="{ record }">
                <a-badge :status="record.verified ? 'danger' : 'normal'" :text="record.verified ? '已确认' : '疑似'" />
              </template>
            </a-table-column>
            <a-table-column title="发现时间" :width="160">
              <template #cell="{ record }">{{ record.time }}</template>
            </a-table-column>
          </template>
        </a-table>
      </a-card>

      <!-- 报告底部签名 -->
      <a-card class="general-card report-footer" style="margin-top: 16px">
        <div class="footer-content">
          <icon-check-circle :size="20" style="margin-right: 8px; color: var(--color-primary-6)" />
          <span>本报告由 GoAttack 安全扫描系统自动生成 · {{ formatNowChina() }}</span>
        </div>
      </a-card>
    </template>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Message } from '@arco-design/web-vue'
import {
  IconCalendar,
  IconClockCircle,
  IconExport,
  IconDown,
  IconApps,
  IconLeft,
  IconCode,
  IconFile,
  IconBug,
  IconCheckCircle,
  IconComputer,
  IconWifi,
} from '@arco-design/web-vue/es/icon'
import { getTaskDetail, getTaskResults, getTaskVulnerabilities, exportPdf } from '@/api/task'

const route = useRoute()
const router = useRouter()
const taskId = computed(() => route.query.taskId as string)
const loading = ref(true)

const reportData = reactive({
  taskName: '加载中...',
  target: '-',
  taskType: '-',
  startTime: '-',
  endTime: '-',
  duration: '-',
  status: '',
  ports: '-',
  concurrency: 0,
  stats: { assets: 0, ports: 0, vulnerabilities: 0, webApps: 0, highRisk: 0 },
})

const severityDist = ref([
  { label: '严重 (Critical)', count: 0, percent: 0, color: '#8E0000', tagColor: 'red' },
  { label: '高危 (High)', count: 0, percent: 0, color: '#F53F3F', tagColor: 'orangered' },
  { label: '中危 (Medium)', count: 0, percent: 0, color: '#F7BA1E', tagColor: 'gold' },
  { label: '低危 (Low)', count: 0, percent: 0, color: '#3491FA', tagColor: 'blue' },
  { label: '信息 (Info)', count: 0, percent: 0, color: '#86909C', tagColor: 'gray' },
])

const portList = ref<any[]>([])
const webList = ref<any[]>([])
const vulnList = ref<any[]>([])

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

const formatChinaDateTime = (date: Date) => {
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date)
}

const formatNowChina = () => formatChinaDateTime(new Date())

const formatDateTime = (dateStr: string) => {
  if (!dateStr) return '-'
  const d = parseChinaDate(dateStr)
  if (!d) return '-'
  return formatChinaDateTime(d)
}

const formatDuration = (start: string, end: string) => {
  if (!start) return '-'
  const startDate = parseChinaDate(start)
  if (!startDate) return '-'
  const endDate = end ? parseChinaDate(end) : new Date()
  const s = startDate.getTime()
  const e = endDate ? endDate.getTime() : Date.now()
  const sec = Math.floor((e - s) / 1000)
  if (sec < 0) return '0 秒'
  if (sec < 60) return `${sec} 秒`
  const m = Math.floor(sec / 60)
  if (m < 60) return `${m} 分 ${sec % 60} 秒`
  const h = Math.floor(m / 60)
  return `${h} 小时 ${m % 60} 分`
}

const getStatusText = (status: string) => {
  const map: Record<string, string> = {
    completed: '已完成',
    finished: '已完成',
    running: '运行中',
    pending: '等待中',
    stopped: '已停止',
    failed: '失败',
    error: '出错',
  }
  return map[status] || status
}

const getSeverityColor = (severity: string) => {
  const colorMap: Record<string, string> = {
    严重: 'red',
    critical: 'red',
    高危: 'orangered',
    high: 'orangered',
    中危: 'gold',
    medium: 'gold',
    低危: 'blue',
    low: 'blue',
    信息: 'gray',
    info: 'gray',
  }
  return colorMap[severity?.toLowerCase()] || colorMap[severity] || 'gray'
}

const getSeverityText = (s: string) => {
  const map: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
  return map[s?.toLowerCase()] || s || '未知'
}

// 辅助函数：获取 web 状态码 badge class
function getWebBadgeClass(statusCode: number): string {
  if (statusCode >= 400) return 'badge-red'
  if (statusCode >= 300) return 'badge-blue'
  return 'badge-green'
}

// 辅助函数：获取漏洞 badge class
function getVulnBadgeClass(severity: string): string {
  if (severity === '严重') return 'badge-darkred'
  if (severity === '高危') return 'badge-red'
  if (severity === '中危') return 'badge-yellow'
  return 'badge-blue'
}

// 生成 HTML 报告字符串
function buildHTMLReport(): string {
  const escHtml = (s: string) =>
    String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
  const portRows = portList.value
    .map(
      (p) =>
        `<tr><td>${escHtml(p.ip)}</td><td style="color:#3491FA;font-weight:600">${p.port}</td><td>${escHtml(p.protocol)}</td><td>${escHtml(p.service)}</td><td>${escHtml(p.product)}</td><td>${escHtml(p.version)}</td><td><span class="badge badge-green">open</span></td></tr>`
    )
    .join('')
  const webRows = webList.value
    .map((w) => {
      const wBadge = getWebBadgeClass(w.status_code)
      return `<tr><td><a href="${escHtml(w.url)}" target="_blank">${escHtml(w.url)}</a></td><td>${escHtml(w.title)}</td><td><span class="badge ${wBadge}">${w.status_code || '-'}</span></td><td>${escHtml(w.server)}</td><td>${(w.technologies || []).join(', ')}</td></tr>`
    })
    .join('')
  const vulnRows = vulnList.value
    .map((v) => {
      const vBadge = getVulnBadgeClass(v.severity)
      return `<tr><td>${escHtml(v.name)}</td><td>${escHtml(v.target)}</td><td><span class="badge ${vBadge}">${escHtml(v.severity)}</span></td><td>${v.cve || v.cnvd || '-'}</td><td>${escHtml(v.time)}</td></tr>`
    })
    .join('')

  // eslint-disable-next-line no-useless-escape
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<title>安全扫描报告 - ${escHtml(reportData.taskName)}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:#f2f3f5;color:#1d2129;font-size:14px;line-height:1.5; -webkit-print-color-adjust: exact; print-color-adjust: exact;}
.page{max-width:1000px;margin:0 auto;padding:40px;background:#fff;}
.report-cover{background:linear-gradient(135deg,#0052D9 0%,#002B70 100%);color:#fff;padding:48px;border-radius:12px;margin-bottom:32px;box-shadow:0 8px 20px rgba(0,82,217,0.15);page-break-inside:avoid;break-inside:avoid;}
.report-cover h1{font-size:32px;margin-bottom:12px;display:flex;align-items:center;gap:12px;}
.report-cover .meta{padding-top:24px;border-top:1px solid rgba(255,255,255,0.1);display:grid;grid-template-columns:repeat(2,1fr);row-gap:16px;font-size:14px;letter-spacing:0.5px;}
.section{background:#fff;border:1px solid #e5e6eb;border-radius:8px;padding:32px;margin-bottom:24px;page-break-inside:avoid;break-inside:avoid;}
.section-title{font-size:18px;font-weight:600;color:#1d2129;margin-bottom:24px;padding-left:12px;border-left:4px solid #0052D9;line-height:1.2;}
.stat-row{display:flex;gap:20px;margin-bottom:24px;page-break-inside:avoid;break-inside:avoid;}
.stat-box{flex:1;background:#f7f8fa;border-radius:8px;padding:24px;text-align:center;border:1px solid #e5e6eb;}
.stat-box .val{font-size:36px;font-weight:700;color:var(--c);font-family:system-ui,-apple-system;}
.stat-box .lbl{font-size:14px;color:#4e5969;margin-top:8px;font-weight:500;}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;border:1px solid #e5e6eb;border-radius:8px;overflow:hidden;}
th{background:#f7f8fa;padding:12px 16px;text-align:left;font-weight:600;color:#1d2129;border-bottom:1px solid #e5e6eb;}
td{padding:12px 16px;border-bottom:1px solid #f0f0f0;vertical-align:top;word-break:break-all;}
tr:last-child td{border-bottom:none;}
tr{page-break-inside:avoid;break-inside:avoid;}
.badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:500;line-height:1.5}
.badge-green{background:#d8f3e5;color:#00b42a}
.badge-blue{background:#e8f4fd;color:#3491fa}
.badge-yellow{background:#fef5e3;color:#f7ba1e}
.badge-red{background:#fde8e8;color:#f53f3f}
.badge-darkred{background:#ffd6d6;color:#8e0000}
.severity-bar{height:12px;background:#e5e6eb;border-radius:6px;overflow:hidden;margin:0 12px;flex:1}
.severity-fill{height:100%;border-radius:6px;transition:width .5s}
.sev-row{display:flex;align-items:center;margin-bottom:12px;font-size:13px}
.sev-label{width:140px;color:#4e5969;font-weight:500;}
.sev-count{width:50px;text-align:right;font-weight:600;color:#1d2129;}
.footer{text-align:center;color:#86909c;font-size:12px;padding:24px 0 16px;border-top:1px solid #e5e6eb;margin-top:32px;page-break-inside:avoid;break-inside:avoid;}
a{color:#3491fa;text-decoration:none}
</style>
</head>
<body>
<div class="page">
  <div class="report-cover">
    <h1>&#127697;&#65039; 安全扫描报告</h1>
    <h2 style="font-size:20px;margin-top:8px;font-weight:400">${escHtml(reportData.taskName)}</h2>
    <div class="meta">
      <span>&#128197; 扫描开始: ${escHtml(reportData.startTime)}</span>
      <span>&#9201; 耗时: ${escHtml(reportData.duration)}</span>
      <span>&#127919; 目标: ${escHtml(reportData.target)}</span>
      <span>&#128204; 类型: ${escHtml(reportData.taskType)}</span>
    </div>
  </div>

  <div class="section">
    <div class="section-title">📊 扫描概览</div>
    <div class="stat-row">
      <div class="stat-box" style="--c:#3491fa"><div class="val">${reportData.stats.assets}</div><div class="lbl">发现资产</div></div>
      <div class="stat-box" style="--c:#7816ff"><div class="val">${reportData.stats.ports}</div><div class="lbl">开放端口</div></div>
      <div class="stat-box" style="--c:#16baaa"><div class="val">${reportData.stats.webApps}</div><div class="lbl">Web 指纹</div></div>
      <div class="stat-box" style="--c:#f53f3f"><div class="val">${reportData.stats.vulnerabilities}</div><div class="lbl">发现漏洞</div></div>
    </div>
    <div style="margin-top:16px">
      ${severityDist.value
        .map(
          (s) => `
      <div class="sev-row">
        <div class="sev-label">${s.label}</div>
        <div class="severity-bar"><div class="severity-fill" style="width:${Math.min(s.percent, 100)}%;background:${s.color}"></div></div>
        <div class="sev-count">${s.count}</div>
      </div>`
        )
        .join('')}
    </div>
  </div>

  ${
    portRows
      ? `<div class="section">
    <div class="section-title">开放端口与服务 (${portList.value.length} 条)</div>
    <table><thead><tr><th>IP / 主机</th><th>端口</th><th>协议</th><th>服务</th><th>产品</th><th>版本</th><th>状态</th></tr></thead>
    <tbody>${portRows}</tbody></table>
  </div>`
      : ''
  }

  ${
    webRows
      ? `<div class="section">
    <div class="section-title">Web 指纹识别 (${webList.value.length} 条)</div>
    <table><thead><tr><th>URL</th><th>网站标题</th><th>状态码</th><th>服务端</th><th>技术栈</th></tr></thead>
    <tbody>${webRows}</tbody></table>
  </div>`
      : ''
  }

  ${
    vulnRows
      ? `<div class="section">
    <div class="section-title">漏洞详情清单 (${vulnList.value.length} 个)</div>
    <table><thead><tr><th>漏洞名称</th><th>目标</th><th>危害等级</th><th>CVE/CNVD</th><th>发现时间</th></tr></thead>
    <tbody>${vulnRows}</tbody></table>
  </div>`
      : ''
  }

  <div class="footer">本报告由 GoAttack 安全扫描系统自动生成 &nbsp;&middot;&nbsp; ${formatNowChina()}</div>
</div>
</body></html>`
}

async function handleExport(val: string) {
  if (val === 'html') {
    const html = buildHTMLReport()
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `report-${taskId.value}-${Date.now()}.html`
    a.click()
    URL.revokeObjectURL(url)
    Message.success('HTML 报告已导出')
  } else if (val === 'pdf') {
    Message.info('正在由服务器生成高清 PDF，该操作可能需要十几秒...')
    // 采用后端 Headless Chrome 渲染保证完美的格式一致性
    const html = buildHTMLReport()
    try {
      const resp = await exportPdf(html)
      // 使用 Blob 处理文件下载
      const blob = new Blob([resp.data], { type: 'application/pdf' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `report-${taskId.value}-${Date.now()}.pdf`
      a.click()
      URL.revokeObjectURL(url)
      Message.success('PDF 报告已直接导出')
    } catch (err) {
      Message.error('PDF 生成失败，请确保后台服务端支持 Chromedp')
      console.error(err)
    }
  } else {
    Message.info(`${val.toUpperCase()} 格式暂不支持`)
  }
}

const fetchData = async () => {
  if (!taskId.value) {
    loading.value = false
    return
  }
  loading.value = true
  try {
    const [detailRes, resultsRes, vulnRes] = await Promise.all([
      getTaskDetail(Number(taskId.value)),
      getTaskResults(Number(taskId.value)),
      getTaskVulnerabilities(Number(taskId.value)),
    ])

    const detail = detailRes.data
    reportData.taskName = detail.name || `任务 #${detail.id}`
    reportData.target = detail.target || '-'
    reportData.status = detail.status || ''
    const typeMap: Record<string, string> = {
      port: '端口扫描与服务探测',
      vuln: '漏洞扫描',
      alive: '存活资产探测',
      full: '全量扫描',
      web: 'Web指纹识别',
    }
    reportData.taskType = typeMap[detail.type] || detail.type || '未知'
    reportData.startTime = formatDateTime(detail.started_at || detail.created_at)
    reportData.endTime = formatDateTime(detail.completed_at)
    reportData.duration = formatDuration(detail.started_at || detail.created_at, detail.completed_at)
    try {
      const opts = JSON.parse(detail.options || '{}')
      reportData.ports = opts.port_range || opts.ports || '1-65535 (默认)'
      reportData.concurrency = opts.threads || 0
    } catch {
      reportData.ports = '默认'
    }

    // 解析资产结果
    const assets: any[] = resultsRes.data || []
    reportData.stats.assets = assets.length

    // 提取端口
    const ports: any[] = []
    const webs: any[] = []
    assets.forEach((asset: any) => {
      const ip = asset.asset?.value || '-'
      const openPorts: any[] = asset.detail?.ports || []
      openPorts.forEach((p: any) => {
        const services: any[] = p.services || p.service_info || []
        if (services.length > 0) {
          services.forEach((s: any) => {
            ports.push({
              ip,
              port: p.Port || p.port,
              protocol: p.Protocol || p.protocol || 'tcp',
              service: s.Name || s.service || s.name || '-',
              product: s.Product || s.product || '-',
              version: s.Version || s.version || '-',
              state: p.State || p.state || 'open',
            })
          })
        } else {
          ports.push({
            ip,
            port: p.Port || p.port,
            protocol: p.Protocol || p.protocol || 'tcp',
            service: '-',
            product: '-',
            version: '-',
            state: p.State || p.state || 'open',
          })
        }
      })
      const fingerprints: any[] = asset.detail?.fingerprints || []
      fingerprints.forEach((fp: any) => {
        webs.push({
          ip,
          url: fp.url || `http://${ip}`,
          title: fp.title || '-',
          status_code: fp.status_code,
          server: fp.server || '-',
          technologies: fp.technologies || [],
        })
      })
    })

    portList.value = ports
    webList.value = webs
    reportData.stats.ports = ports.length
    reportData.stats.webApps = webs.length

    // 漏洞
    const vulns: any[] = vulnRes.data || []
    vulnList.value = vulns.map((v: any) => ({
      name: v.name,
      target: v.target,
      severity: getSeverityText(v.severity),
      cve: v.cve,
      cnvd: v.cnvd,
      verified: v.verified,
      time: formatDateTime(v.created_at),
    }))
    reportData.stats.vulnerabilities = vulns.length

    const sDist = { crit: 0, high: 0, med: 0, low: 0, info: 0 }
    vulns.forEach((v: any) => {
      const s = v.severity?.toLowerCase()
      if (s === 'critical' || s === '严重') sDist.crit += 1
      else if (s === 'high' || s === '高危') sDist.high += 1
      else if (s === 'medium' || s === '中危') sDist.med += 1
      else if (s === 'info') sDist.info += 1
      else sDist.low += 1
    })
    reportData.stats.highRisk = sDist.crit + sDist.high
    const total = vulns.length || 1
    severityDist.value[0].count = sDist.crit
    severityDist.value[0].percent = (sDist.crit / total) * 100
    severityDist.value[1].count = sDist.high
    severityDist.value[1].percent = (sDist.high / total) * 100
    severityDist.value[2].count = sDist.med
    severityDist.value[2].percent = (sDist.med / total) * 100
    severityDist.value[3].count = sDist.low
    severityDist.value[3].percent = (sDist.low / total) * 100
    severityDist.value[4].count = sDist.info
    severityDist.value[4].percent = (sDist.info / total) * 100
  } catch (err) {
    Message.error('获取报告数据失败，请检查任务ID是否正确')
  } finally {
    loading.value = false
    // 如果带 export 参数则自动导出
    const exportType = route.query.export as string
    if (exportType) {
      setTimeout(() => {
        handleExport(exportType)
      }, 500)
    }
  }
}

onMounted(fetchData)
</script>

<style scoped lang="less">
.container {
  padding: 0 20px 20px 20px;
}

.loading-center {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 400px;
}

.report-header-card {
  .report-header {
    display: flex;
    justify-content: space-between;
    align-items: center;

    .report-title {
      display: flex;
      align-items: center;
      font-size: 18px;
    }

    .header-meta {
      margin-top: 10px;
      color: var(--color-text-3);
      font-size: 13px;
    }
  }
}

.stat-card {
  background: var(--color-fill-2);
  border: none;
  border-radius: 8px;
  padding: 8px 0;

  &.danger-card :deep(.arco-statistic-value) {
    color: #f53f3f;
  }
}

.severity-chart {
  padding: 8px 0;

  .severity-row {
    display: flex;
    align-items: center;
    margin-bottom: 14px;

    .severity-label {
      width: 160px;
      font-size: 13px;
    }

    .severity-bar-wrap {
      flex: 1;
      height: 10px;
      background: var(--color-fill-3);
      border-radius: 5px;
      margin: 0 12px;
      overflow: hidden;

      .severity-bar {
        height: 100%;
        border-radius: 5px;
        transition: width 0.6s ease;
      }
    }

    .severity-count {
      width: 50px;
      text-align: right;
    }
  }

  .no-vuln {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 140px;
    color: var(--color-text-3);
    gap: 12px;
    font-size: 14px;
  }
}

.report-footer .footer-content {
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--color-text-3);
  font-size: 13px;
  padding: 4px 0;
}

.text-placeholder {
  color: var(--color-text-4);
}

:deep(.arco-descriptions-item-label) {
  width: 100px;
}
</style>
