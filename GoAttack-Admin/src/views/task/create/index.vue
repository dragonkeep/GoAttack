<template>
  <div class="container">
    <Breadcrumb :items="['menu.task', 'menu.task.create']" />
    <a-card class="general-card" title="创建扫描任务">
      <a-form ref="formRef" :model="formData" layout="vertical" @submit="handleSubmit">
        <!-- 基础信息 -->
        <a-row :gutter="16">
          <a-col :span="12">
            <a-form-item
              field="name"
              label="任务名称"
              :rules="[{ required: true, message: '请输入任务名称' }]"
            >
              <a-input v-model="formData.name" placeholder="请输入任务名称" size="large" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item
              field="type"
              label="扫描类型"
              :rules="[{ required: true, message: '请选择扫描类型' }]"
            >
              <a-select v-model="formData.type" placeholder="请选择扫描类型" size="large">
                <a-option value="full">全量扫描</a-option>
                <a-option value="quick">快速扫描</a-option>
                <a-option value="custom">自定义扫描</a-option>
              </a-select>
            </a-form-item>
          </a-col>
        </a-row>

        <!-- 扫描类型说明 -->
        <a-row :gutter="16" style="margin-bottom: 12px">
          <a-col :span="24">
            <a-alert
              v-if="formData.type === 'full'"
              type="info"
              :show-icon="true"
            >全量扫描：主机存活探测 → TCP/UDP 端口扫描（TOP1000）→ 弱口令验证 → Web 目录扫描 → 子域名枚举 → Web 指纹识别 → POC 漏洞验证</a-alert>
            <a-alert
              v-else-if="formData.type === 'quick'"
              type="success"
              :show-icon="true"
            >快速扫描：主机存活探测 → TCP 端口扫描（TOP1000）→ 弱口令验证 → Web 指纹识别 → POC 漏洞验证</a-alert>
            <a-alert
              v-else-if="formData.type === 'custom'"
              type="warning"
              :show-icon="true"
            >自定义扫描：根据下方勾选项自定义扫描内容，灵活配置各扫描模块</a-alert>
          </a-col>
        </a-row>

        <!-- 扫描目标 -->
        <a-row :gutter="16">
          <a-col :span="24">
            <a-form-item
              field="target"
              label="扫描目标"
              :rules="[{ required: true, message: '请输入扫描目标' }]"
            >
              <a-textarea
                v-model="formData.target"
                placeholder="请输入目标 IP 或域名，支持多个目标（换行分隔）&#10;例如：&#10;192.168.1.0/24&#10;http://example.com:8080&#10;domain.com"
                :auto-size="{ minRows: 5, maxRows: 10 }"
                size="large"
              />
            </a-form-item>
          </a-col>
        </a-row>

        <!-- ── 全量扫描：可调整的附加模块 ── -->
        <template v-if="formData.type === 'full'">
          <a-divider orientation="left">扫描模块（默认全开，可按需关闭）</a-divider>
          <a-row :gutter="16">
            <a-col :span="8">
              <a-form-item>
                <template #label>
                  <span>
                    目录扫描
                    <a-tooltip position="top">
                      <template #content>
                        <div style="max-width: 360px; line-height: 1.6">
                          目录扫描依赖 gobuster 插件。<br />
                          请先在插件管理中启用 gobuster，否则该选项会被禁用。
                        </div>
                      </template>
                      <icon-question-circle
                        style="margin-left: 4px; color: var(--color-text-3); cursor: help"
                      />
                    </a-tooltip>
                  </span>
                </template>
                <a-checkbox v-model="scanOptions.enable_dir_scan" :disabled="!isGobusterEnabled">
                  启用 Web 目录/文件扫描
                  <span
                    v-if="!isGobusterEnabled"
                    style="color: red; font-size: 12px; margin-left: 4px"
                  >(需开启 gobuster 插件)</span>
                </a-checkbox>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item>
                <template #label>
                  <span>
                    子域名枚举
                    <a-tooltip position="top">
                      <template #content>
                        <div style="max-width: 360px; line-height: 1.6">
                          子域名枚举依赖 gobuster 插件。<br />
                          请先在插件管理中启用 gobuster，否则该选项会被禁用。
                        </div>
                      </template>
                      <icon-question-circle
                        style="margin-left: 4px; color: var(--color-text-3); cursor: help"
                      />
                    </a-tooltip>
                  </span>
                </template>
                <a-checkbox v-model="scanOptions.enable_subdomain_enum" :disabled="!isGobusterEnabled">
                  启用子域名枚举扫描
                  <span
                    v-if="!isGobusterEnabled"
                    style="color: red; font-size: 12px; margin-left: 4px"
                  >(需开启 gobuster 插件)</span>
                </a-checkbox>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item>
                <template #label>
                  <span>
                    弱口令检测
                    <a-tooltip position="top">
                      <template #content>
                        <div style="max-width: 360px; line-height: 1.6">
                          开启后，对 mysql、rdp、ssh 等服务进行弱口令爆破检测。
                        </div>
                      </template>
                      <icon-question-circle
                        style="margin-left: 4px; color: var(--color-text-3); cursor: help"
                      />
                    </a-tooltip>
                  </span>
                </template>
                <a-checkbox v-model="scanOptions.enable_weak_password">
                  启用服务弱口令暴力破解
                </a-checkbox>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item label="UDP 端口扫描">
                <a-checkbox v-model="scanOptions.enable_udp_scan">
                  启用 UDP 端口扫描（需 root 权限）
                </a-checkbox>
              </a-form-item>
            </a-col>
          </a-row>
        </template>

        <!-- ── 自定义扫描：逐模块勾选 ── -->
        <template v-if="formData.type === 'custom'">
          <a-divider orientation="left">扫描模块</a-divider>
          <a-row :gutter="16">
            <a-col :span="8">
              <a-form-item label="主机探测">
                <a-checkbox v-model="scanOptions.enable_host_discovery">
                  开启主机存活探测（ICMP Ping）
                </a-checkbox>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item label="端口扫描">
                <a-checkbox v-model="scanOptions.enable_port_scan">
                  开启 TCP 端口扫描
                </a-checkbox>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item label="UDP 扫描">
                <a-checkbox v-model="scanOptions.enable_udp_scan">
                  开启 UDP 端口扫描
                </a-checkbox>
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="8">
              <a-form-item label="Web 指纹识别">
                <a-checkbox v-model="scanOptions.enable_web_fingerprint">
                  开启 Web 指纹识别
                </a-checkbox>
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="8">
              <a-form-item>
                <template #label>
                  <span>
                    POC 漏洞验证
                    <a-tooltip position="top">
                      <template #content>
                        <div style="max-width: 420px; line-height: 1.6">
                          默认模式下，POC 验证会基于 Web 指纹识别结果进行匹配验证。<br />
                          开启全量 POC 后，将不再依赖指纹识别，而是对目标遍历全部已启用 HTTP 类 POC。
                        </div>
                      </template>
                      <icon-question-circle
                        style="margin-left: 4px; color: var(--color-text-3); cursor: help"
                      />
                    </a-tooltip>
                  </span>
                </template>
                <a-checkbox v-model="scanOptions.enable_poc_verify">
                  开启 POC 漏洞验证
                </a-checkbox>
              </a-form-item>
            </a-col>
      <a-col :span="8">
        <a-form-item>
        <template #label>
          <span>
          全量 POC 验证
          <a-tooltip position="top">
            <template #content>
            <div style="max-width: 460px; line-height: 1.6">
              启用后将不依赖 Web 指纹匹配，而是对扫描目标遍历所有已启用 HTTP 类 POC 模板进行验证。
              适用于未知指纹、指纹缺失或希望做深度覆盖的场景。
              该模式任务耗时和请求量会明显增加，建议优先用于高价值目标，并合理控制目标范围与并发。
            </div>
            </template>
            <icon-question-circle
            style="margin-left: 4px; color: var(--color-text-3); cursor: help"
            />
          </a-tooltip>
          </span>
        </template>
        <a-checkbox
          v-model="scanOptions.enable_full_poc_verify"
          :disabled="!scanOptions.enable_poc_verify"
        >
          开启全量 POC 模式
        </a-checkbox>
        </a-form-item>
      </a-col>
            <a-col :span="8">
              <a-form-item>
                <template #label>
                  <span>
                    目录扫描
                    <a-tooltip position="top">
                      <template #content>
                        <div style="max-width: 360px; line-height: 1.6">
                          目录扫描依赖 gobuster 插件。<br />
                          请先在插件管理中启用 gobuster，否则该选项会被禁用。
                        </div>
                      </template>
                      <icon-question-circle
                        style="margin-left: 4px; color: var(--color-text-3); cursor: help"
                      />
                    </a-tooltip>
                  </span>
                </template>
                <a-checkbox v-model="scanOptions.enable_dir_scan" :disabled="!isGobusterEnabled">
                  启用 Web 目录/文件扫描
                  <span
                    v-if="!isGobusterEnabled"
                    style="color: red; font-size: 12px; margin-left: 4px"
                  >(需开启 gobuster 插件)</span>
                </a-checkbox>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item>
                <template #label>
                  <span>
                    子域名枚举
                    <a-tooltip position="top">
                      <template #content>
                        <div style="max-width: 360px; line-height: 1.6">
                          子域名枚举依赖 gobuster 插件。<br />
                          请先在插件管理中启用 gobuster，否则该选项会被禁用。
                        </div>
                      </template>
                      <icon-question-circle
                        style="margin-left: 4px; color: var(--color-text-3); cursor: help"
                      />
                    </a-tooltip>
                  </span>
                </template>
                <a-checkbox
                  v-model="scanOptions.enable_subdomain_enum"
                  :disabled="!isGobusterEnabled"
                >
                  启用子域名枚举扫描
                  <span
                    v-if="!isGobusterEnabled"
                    style="color: red; font-size: 12px; margin-left: 4px"
                  >(需开启 gobuster 插件)</span>
                </a-checkbox>
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="16">
            <a-col :span="8">
              <a-form-item>
                <template #label>
                  <span>
                    弱口令检测
                    <a-tooltip position="top">
                      <template #content>
                        <div style="max-width: 360px; line-height: 1.6">
                          主要对 mysql、rdp、ssh 等服务进行弱口令爆破检测。
                        </div>
                      </template>
                      <icon-question-circle
                        style="margin-left: 4px; color: var(--color-text-3); cursor: help"
                      />
                    </a-tooltip>
                  </span>
                </template>
                <a-checkbox v-model="scanOptions.enable_weak_password">
                  启用服务弱口令暴力破解
                </a-checkbox>
              </a-form-item>
            </a-col>
          </a-row>
        </template>

        <!-- ── 扫描参数 ── -->
        <a-divider orientation="left">扫描参数</a-divider>
        <a-row :gutter="16">
          <a-col :span="6">
            <a-form-item field="scan_options.ports">
              <template #label>
                <span>
                  TCP 端口范围
                  <a-tooltip position="top">
                    <template #content>
                      <div style="max-width: 420px; line-height: 1.6">
                        支持以下写法：<br />
                        1) top1000（扫描常见端口）<br />
                        2) 80,443,8080（多个端口用英文逗号分隔）<br />
                        3) 1-10000 或 1-65535（连续端口范围）<br />
                        4) 22,80,443,8000-8100（可混合单端口和范围）
                      </div>
                    </template>
                    <icon-question-circle
                      style="margin-left: 4px; color: var(--color-text-3); cursor: help"
                    />
                  </a-tooltip>
                </span>
              </template>
              <a-input
                v-model="scanOptions.ports"
                placeholder="例如: top1000 或 80,443,8080"
                autocomplete="off"
              />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item field="scan_options.udp_ports">
              <template #label>
                <span>
                  UDP 端口范围
                  <a-tooltip position="top">
                    <template #content>
                      <div style="max-width: 420px; line-height: 1.6">
                        支持以下写法：<br />
                        1) udptop100（扫描常见 UDP 端口）<br />
                        2) 53,67,68,123,161（多个端口用英文逗号分隔）<br />
                        3) 1-10000 或 1-65535（连续端口范围）<br />
                        4) 53,123,161,5000-5100（可混合单端口和范围）
                      </div>
                    </template>
                    <icon-question-circle
                      style="margin-left: 4px; color: var(--color-text-3); cursor: help"
                    />
                  </a-tooltip>
                </span>
              </template>
              <a-input
                v-model="scanOptions.udp_ports"
                placeholder="例如: udptop100 或 53,161"
                autocomplete="off"
                :disabled="!scanOptions.enable_udp_scan"
              />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item field="scan_options.threads" label="并发线程">
              <a-input-number
                v-model="scanOptions.threads"
                :min="1"
                :max="500"
                placeholder="线程数"
                style="width: 100%"
              />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item field="scan_options.timeout" label="超时时间（秒）">
              <a-input-number
                v-model="scanOptions.timeout"
                :min="1"
                :max="3600"
                placeholder="超时"
                style="width: 100%"
              />
            </a-form-item>
          </a-col>
        </a-row>

        <a-divider />

        <a-row>
          <a-col :span="24" style="text-align: right">
            <a-space>
              <a-button @click="showAdvancedOptions">高级选项</a-button>
              <a-button @click="resetForm">重置</a-button>
              <a-button type="primary" html-type="submit" :loading="loading" size="large">
                创建任务
              </a-button>
            </a-space>
          </a-col>
        </a-row>
      </a-form>
    </a-card>

    <!-- 高级选项对话框 -->
    <a-modal v-model:visible="advancedVisible" title="高级选项" @ok="advancedVisible = false">
      <a-form layout="vertical">
        <a-form-item label="定时任务扫描">
          <a-date-picker
            v-model="scanOptions.scheduled_time"
            show-time
            format="YYYY-MM-DD HH:mm:ss"
            placeholder="选择任务开始时间，留空则立即执行"
            style="width: 100%"
          />
        </a-form-item>
        <a-form-item label="黑名单端口">
          <a-input
            v-model="scanOptions.blacklist_ports"
            placeholder="例如: 22,3306"
            autocomplete="off"
          />
        </a-form-item>
        <a-form-item label="黑名单资产 (IP/域名)">
          <a-textarea
            v-model="scanOptions.blacklist_hosts"
            placeholder="每行一个资产，或者以逗号分隔，例如:&#10;192.168.1.1&#10;example.com"
            :auto-size="{ minRows: 2, maxRows: 5 }"
          />
        </a-form-item>
        <a-form-item label="高级配置 (JSON)">
          <a-textarea
            v-model="scanOptions.advanced"
            placeholder='例如: {"custom_headers": {"User-Agent": "Custom"}}'
            :auto-size="{ minRows: 3, maxRows: 5 }"
          />
        </a-form-item>
      </a-form>
      <template #footer>
        <a-button @click="advancedVisible = false">关闭</a-button>
      </template>
    </a-modal>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, watch, onMounted } from 'vue'
import { Message } from '@arco-design/web-vue'
import { IconQuestionCircle } from '@arco-design/web-vue/es/icon'
import { useRouter } from 'vue-router'
import { createTask, getTopPorts, type ScanOptions, type CreateTaskRequest } from '@/api/task'
import { getPluginList } from '@/api/plugin'

defineOptions({ name: 'TaskCreate' })

const router = useRouter()
const loading = ref(false)
const advancedVisible = ref(false)
const PREFILL_TARGETS_KEY = 'goattack_task_targets'
const topPorts = ref('')
const isGobusterEnabled = ref(false)

// 表单数据
const formData = reactive({
  name: '',
  target: '',
  type: 'full',
})

// 扫描选项
const scanOptions = reactive<ScanOptions>({
  enable_host_discovery: true,
  ports: 'top1000',
  enable_service_det: true,
  enable_weak_password: true,
  enable_subdomain_enum: false,
  enable_dir_scan: false,
  enable_poc_verify: true,
  enable_full_poc_verify: false,
  enable_port_scan: true,
  enable_udp_scan: true,
  udp_ports: 'udptop100',
  enable_web_fingerprint: true,
  enable_reverse: false,
  threads: 20,
  timeout: 10,
  advanced: '',
  scheduled_time: '',
  blacklist_ports: '',
  blacklist_hosts: '',
})

/** 全量扫描默认值 */
const applyFullDefaults = () => {
  scanOptions.enable_host_discovery = true
  scanOptions.enable_port_scan = true
  scanOptions.enable_web_fingerprint = true
  scanOptions.enable_poc_verify = true
  scanOptions.enable_full_poc_verify = false
  scanOptions.enable_weak_password = true
  scanOptions.enable_subdomain_enum = isGobusterEnabled.value
  scanOptions.enable_dir_scan = isGobusterEnabled.value
  scanOptions.enable_udp_scan = true
  scanOptions.udp_ports = 'udptop100'
  scanOptions.enable_reverse = false
  if (topPorts.value) {
    scanOptions.ports = topPorts.value
  }
}

/** 快速扫描默认值（固定，无需调整） */
const applyQuickDefaults = () => {
  scanOptions.enable_host_discovery = true
  scanOptions.enable_port_scan = true
  scanOptions.enable_web_fingerprint = true
  scanOptions.enable_poc_verify = true
  scanOptions.enable_full_poc_verify = false
  scanOptions.enable_dir_scan = false
  scanOptions.enable_subdomain_enum = false
  scanOptions.enable_weak_password = true
  scanOptions.enable_udp_scan = false
  scanOptions.udp_ports = 'udptop100'
  if (topPorts.value) {
    scanOptions.ports = topPorts.value
  }
}

/** 自定义扫描默认值（开启常用模块，用户可手动调整） */
const applyCustomDefaults = () => {
  scanOptions.enable_host_discovery = false
  scanOptions.enable_port_scan = false
  scanOptions.enable_web_fingerprint = false
  scanOptions.enable_poc_verify = false
  scanOptions.enable_full_poc_verify = false
  scanOptions.enable_dir_scan = false
  scanOptions.enable_subdomain_enum = false
  scanOptions.enable_weak_password = false
  scanOptions.enable_udp_scan = false
  scanOptions.udp_ports = 'udptop100'
  if (topPorts.value) {
    scanOptions.ports = topPorts.value
  }
}

// 监听扫描类型变化，自动填充对应默认值
watch(
  () => formData.type,
  (newType) => {
    if (newType === 'full') applyFullDefaults()
    else if (newType === 'quick') applyQuickDefaults()
    else if (newType === 'custom') applyCustomDefaults()
  }
)

watch(
  () => scanOptions.enable_poc_verify,
  (enabled) => {
    if (!enabled) {
    scanOptions.enable_full_poc_verify = false
    }
  }
)

onMounted(async () => {
  // 恢复跳转前预填充的目标
  const savedTargets = sessionStorage.getItem(PREFILL_TARGETS_KEY)
  if (savedTargets && !formData.target) {
    formData.target = savedTargets
    sessionStorage.removeItem(PREFILL_TARGETS_KEY)
  }

  // 查询 gobuster 插件状态
  try {
    const { data } = await getPluginList({ name: 'gobuster' })
    isGobusterEnabled.value = data && data.length > 0 ? data[0].enabled : false
  } catch {
    isGobusterEnabled.value = false
  }

  // 加载 TOP1000 端口列表
  try {
    const res = await getTopPorts()
    topPorts.value = res.data?.data?.ports || ''
  } catch {
    // 保持默认 top1000 字符串
  }

  // 应用初始默认值
  applyFullDefaults()
})

const showAdvancedOptions = () => {
  advancedVisible.value = true
}

const handleSubmit = async () => {
  loading.value = true
  try {
    const data: CreateTaskRequest = {
      name: formData.name,
      target: formData.target,
      type: formData.type,
      scan_options: { ...scanOptions },
    }
    await createTask(data)
    Message.success('任务创建成功！')
    setTimeout(() => router.push('/task/list'), 1000)
  } catch (error: any) {
    Message.error(error.response?.data?.msg || error.message || '创建任务失败')
  } finally {
    loading.value = false
  }
}

const resetForm = () => {
  formData.name = ''
  formData.target = ''
  formData.type = 'full'
  applyFullDefaults()
  scanOptions.threads = 20
  scanOptions.timeout = 10
  scanOptions.advanced = ''
  scanOptions.scheduled_time = ''
  scanOptions.blacklist_ports = ''
  scanOptions.blacklist_hosts = ''
}
</script>

<style scoped lang="less">
.container {
  padding: 0 20px 20px 20px;
}

.general-card {
  margin-top: 20px;
}
</style>
