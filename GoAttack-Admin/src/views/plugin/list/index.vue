<template>
  <div class="container">
    <Breadcrumb :items="['menu.plugin', 'menu.plugin.list']" />
    <a-card class="general-card" :title="$t('menu.plugin.list')">
      <a-row>
        <a-col :flex="1">
          <a-form :model="formModel" :label-col-props="{ span: 6 }" :wrapper-col-props="{ span: 18 }" label-align="left">
            <a-row :gutter="16">
              <a-col :span="8">
                <a-form-item field="name" label="插件名称">
                  <a-input v-model="formModel.name" placeholder="搜索插件名称" />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="type" label="插件类型">
                  <a-select v-model="formModel.type" placeholder="请选择类型" allow-clear>
                    <a-option value="scanner">扫描器</a-option>
                    <a-option value="fingerprint">指纹库</a-option>
                    <a-option value="exploit">利用工具</a-option>
                  </a-select>
                </a-form-item>
              </a-col>
            </a-row>
          </a-form>
        </a-col>
        <a-divider style="height: 32px" direction="vertical" />
        <a-col :flex="'86px'" style="text-align: right">
          <a-space :size="10">
            <a-button type="primary" @click="fetchData">
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
      <a-divider style="margin-top: 10px" />
      <a-table
        row-key="id"
        :loading="loading"
        :pagination="pagination"
        :columns="columns"
        :data="renderData"
        :bordered="false"
        size="medium"
      >
        <template #status="{ record }">
          <a-switch v-model="record.enabled" @change="(val) => handleStatusChange(record, val)" />
        </template>
        <template #operations="{ record }">
          <a-space>
            <a-button type="text" @click="openSettings(record)">设置</a-button>
          </a-space>
        </template>
      </a-table>
    </a-card>

    <!-- 设置弹窗 -->
    <a-modal v-model:visible="configVisible" title="插件配置" @ok="handleConfigSubmit" @cancel="configVisible = false">
      <a-form :model="currentConfig" layout="vertical">
        <template v-if="isGobusterPlugin()">
          <a-form-item field="dns_dict" label="子域名字典">
            <a-select v-model="currentConfig.dns_dict" placeholder="请选择子域名字典">
              <a-option v-for="opt in dnsDictOptions" :key="opt.value" :value="opt.value">{{ opt.label }}</a-option>
            </a-select>
          </a-form-item>
          <a-form-item field="dir_dict" label="目录扫描字典">
            <a-select v-model="currentConfig.dir_dict" placeholder="请选择目录字典">
              <a-option v-for="opt in dictOptions" :key="opt.value" :value="opt.value">{{ opt.label }}</a-option>
            </a-select>
          </a-form-item>
          <a-form-item field="threads" label="线程数">
            <a-input-number v-model="currentConfig.threads" placeholder="默认 10" :min="1" :max="200" />
          </a-form-item>
          <a-form-item field="timeout" label="超时时间">
            <a-input v-model="currentConfig.timeout" placeholder="例如: 5s, 10s" />
          </a-form-item>
          <a-form-item field="status_codes" label="HTTP 状态码 (仅目录扫描)">
            <a-input v-model="currentConfig.status_codes" placeholder="例如: 200,204,301,302,307,401,403" />
          </a-form-item>
        </template>

        <template v-else-if="isOSSScannerPlugin()">
          <div class="oss-switch-group">
            <div class="oss-switch-item">
              <div class="oss-switch-text">
                <div class="oss-switch-title">文件上传探测</div>
                <div class="oss-switch-desc">使用小型 txt 测试文件验证是否可匿名上传。</div>
              </div>
              <a-switch v-model="currentConfig.enable_upload_probe" />
            </div>

            <div class="oss-switch-item">
              <div class="oss-switch-text">
                <div class="oss-switch-title">对象覆盖探测</div>
                <div class="oss-switch-desc">使用 PUT 请求尝试覆盖同一路径对象并验证是否生效。</div>
              </div>
              <a-switch
                v-model="currentConfig.enable_overwrite_probe"
                :disabled="!currentConfig.enable_upload_probe"
              />
            </div>
          </div>
        </template>

        <template v-else>
          <a-form-item>
            <div style="color: var(--color-text-3)">当前插件暂无可视化配置项。</div>
          </a-form-item>
        </template>
      </a-form>
    </a-modal>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted } from 'vue'
import { Message } from '@arco-design/web-vue'
import { getPluginList, updatePluginStatus, updatePluginConfig } from '@/api/plugin'

const loading = ref(false)
const renderData = ref<any[]>([])
const configVisible = ref(false)
const currentPlugin = ref<any>(null)
const currentConfig = reactive({
  dir_dict: '',
  dns_dict: '',
  threads: 10,
  timeout: '5s',
  status_codes: '200,204,301,302,307,401,403',
  enable_upload_probe: true,
  enable_overwrite_probe: false,
})

const dictOptions = ref<{ label: string; value: string }[]>([])
const dnsDictOptions = ref<{ label: string; value: string }[]>([])

function isGobusterPlugin(plugin = currentPlugin.value) {
  return plugin?.name === 'gobuster'
}

function isOSSScannerPlugin(plugin = currentPlugin.value) {
  return plugin?.name === 'oss_scaner'
}

const fetchDicts = async () => {
  try {
    const { getDictList } = await import('@/api/dict')
    const res = await getDictList()
    const dicts = res.data || []

    dictOptions.value = dicts
      .filter((d: any) => d.category !== '子域名字典')
      .map((d: any) => ({
        label: `${d.name} (${d.type === 'preset' ? '预设' : '自定义'})`,
        value: d.name,
      }))

    dnsDictOptions.value = dicts
      .filter((d: any) => d.category === '子域名字典' || d.category === '其他字典')
      .map((d: any) => ({
        label: `${d.name} (${d.type === 'preset' ? '预设' : '自定义'})`,
        value: d.name,
      }))
  } catch (err) {
    Message.error('获取字典失败')
  }
}

const formModel = reactive({
  name: '',
  type: '',
})

const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
})

const columns = [
  { title: '插件名称', dataIndex: 'name' },
  { title: '版本', dataIndex: 'version', width: 120 },
  { title: '类型', dataIndex: 'type', width: 120 },
  { title: '状态', slotName: 'status', width: 100 },
  { title: '描述', dataIndex: 'description', ellipsis: true },
  { title: '操作', slotName: 'operations', fixed: 'right', width: 160 },
]

const fetchData = async () => {
  loading.value = true
  try {
    const { data } = await getPluginList(formModel)
    renderData.value = data || []
    pagination.total = renderData.value.length
  } catch (err) {
    Message.error('获取插件列表失败')
  } finally {
    loading.value = false
  }
}

const handleStatusChange = async (record: any, val: boolean | string | number) => {
  try {
    await updatePluginStatus(record.id, Boolean(val))
    Message.success('状态更新成功')
  } catch (err: any) {
    Message.error(err.response?.data?.msg || '状态更新失败')
    record.enabled = !val // revert
  }
}

const openSettings = (record: any) => {
  currentPlugin.value = record

  const gobusterDefaults = {
    dir_dict: dictOptions.value.length > 0 ? dictOptions.value[0].value : '',
    dns_dict: dnsDictOptions.value.length > 0 ? dnsDictOptions.value[0].value : '',
    threads: 10,
    timeout: '5s',
    status_codes: '200,204,301,302,307,401,403',
  }
  const ossDefaults = {
    enable_upload_probe: true,
    enable_overwrite_probe: false,
  }
  let configObj: any = isOSSScannerPlugin(record) ? { ...ossDefaults } : { ...gobusterDefaults }

  if (record.config) {
    try {
      configObj = { ...configObj, ...JSON.parse(record.config) }
      if (typeof configObj.threads === 'string' && configObj.threads !== '') {
        configObj.threads = parseInt(configObj.threads, 10) || 10
      }
    } catch (e) {
      // Ignored string parsing failure
    }
  }
  currentConfig.dir_dict = configObj.dir_dict
  currentConfig.dns_dict = configObj.dns_dict
  currentConfig.threads = configObj.threads
  currentConfig.timeout = configObj.timeout
  currentConfig.status_codes = configObj.status_codes
  currentConfig.enable_upload_probe = Boolean(configObj.enable_upload_probe)
  currentConfig.enable_overwrite_probe = Boolean(configObj.enable_overwrite_probe)

  configVisible.value = true
}

const handleConfigSubmit = async () => {
  if (!currentPlugin.value) return

  let confToSave: any = {}
  if (isGobusterPlugin()) {
    confToSave = {
      dir_dict: currentConfig.dir_dict,
      dns_dict: currentConfig.dns_dict,
      threads: String(currentConfig.threads),
      timeout: currentConfig.timeout,
      status_codes: currentConfig.status_codes,
    }
  } else if (isOSSScannerPlugin()) {
    confToSave = {
      enable_upload_probe: Boolean(currentConfig.enable_upload_probe),
      enable_overwrite_probe: Boolean(currentConfig.enable_upload_probe && currentConfig.enable_overwrite_probe),
    }
  }

  const configStr = JSON.stringify(confToSave)
  try {
    await updatePluginConfig(currentPlugin.value.id, configStr)
    Message.success('配置更新成功')
    configVisible.value = false
    fetchData()
  } catch (err: any) {
    Message.error(err.response?.data?.msg || '配置更新失败')
  }
}

const reset = () => {
  formModel.name = ''
  formModel.type = ''
  fetchData()
}

onMounted(() => {
  fetchData()
  fetchDicts()
})
</script>

<style scoped lang="less">
.container {
  padding: 0 20px 20px 20px;
}

.oss-switch-group {
  display: grid;
  row-gap: 20px;
}

.oss-switch-item {
  display: grid;
  grid-template-columns: 1fr auto;
  column-gap: 16px;
  align-items: center;
}

.oss-switch-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 6px;
}

.oss-switch-desc {
  color: var(--color-text-3);
  font-size: 15px;
  line-height: 1.5;
}
</style>
