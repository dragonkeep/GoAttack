<template>
  <div class="container">
    <Breadcrumb :items="['menu.task', 'menu.task.list', `任务 ${taskId}`]" />
    <a-spin :loading="loading" style="width: 100%">
      <a-card class="general-card" :title="`任务 ${taskInfo.name || taskId} - 扫描结果`">
        <template #extra>
          <a-space>
            <!-- 运行中显示暂停按钮 -->
            <a-button v-if="taskInfo.status === 'running'" type="primary" status="warning" :loading="pauseLoading" @click="handlePause">
              <template #icon>
                <icon-pause />
              </template>
              暂停扫描
            </a-button>

            <!-- 暂停后显示继续和删除按钮 -->
            <template v-if="taskInfo.status === 'stopped' || taskInfo.status === 'paused'">
              <a-button type="primary" :loading="rescanLoading" @click="handleResume">
                <template #icon>
                  <icon-play-arrow />
                </template>
                继续扫描
              </a-button>
              <a-button type="primary" status="danger" :loading="deleteLoading" @click="handleDelete">
                <template #icon>
                  <icon-delete />
                </template>
                删除任务
              </a-button>
            </template>

            <!-- 查看扫描配置按钮 -->
            <a-button @click="showConfig">
              <template #icon>
                <icon-settings />
              </template>
              扫描配置
            </a-button>

            <!-- 导出报告按钮 -->
            <!-- <a-dropdown @select="handleExportReport">
              <a-button type="outline">
                <template #icon>
                  <icon-export />
                </template>
                导出报告
                <template #suffix>
                  <icon-down />
                </template>
              </a-button>
              <template #content>
                <a-doption value="pdf">导出 PDF (.pdf)</a-doption>
                <a-doption value="html">导出 HTML (.html)</a-doption>
                <a-doption value="preview">查看详细报告</a-doption>
              </template>
            </a-dropdown> -->

            <!-- 完成或失败后显示重新扫描 -->
            <a-button
              v-if="taskInfo.status === 'completed' || taskInfo.status === 'failed'"
              type="primary"
              :loading="rescanLoading"
              @click="handleRescan"
            >
              <template #icon>
                <icon-sync />
              </template>
              重新扫描
            </a-button>
          </a-space>
        </template>

        <!-- 任务基本信息 -->
        <a-descriptions :column="2" bordered>
          <a-descriptions-item label="任务名称">{{ taskInfo.name }}</a-descriptions-item>
          <a-descriptions-item label="扫描目标">{{ truncateTarget(taskInfo.target) }}</a-descriptions-item>

          <a-descriptions-item label="任务状态">
            <a-space>
              <a-tag :color="getStatusColor(taskInfo.status)" size="large" bordered>
                <template #icon>
                  <icon-loading v-if="taskInfo.status === 'running'" />
                </template>
                {{ $t(`task.status.${taskInfo.status}`) }}
              </a-tag>
              <span v-if="taskInfo.status === 'running'" class="status-msg">
                {{ taskInfo.message || '系统准备中...' }}
              </span>
            </a-space>
          </a-descriptions-item>
          <a-descriptions-item label="扫描进度">
            <div class="progress-wrapper">
              <a-progress
                :percent="normalizeProgress(taskInfo.progress)"
                :status="taskInfo.status === 'running' ? 'normal' : 'success'"
                animation
                :stroke-width="6"
                style="width: 100%"
              />
              <div v-if="taskInfo.scanned_targets !== undefined && taskInfo.total_targets" class="progress-stats">
                <icon-layers />
                {{ taskInfo.scanned_targets }} / {{ taskInfo.total_targets }} 目标
              </div>
            </div>
          </a-descriptions-item>
          <a-descriptions-item v-if="taskInfo.status === 'running'" label="实时动态" :span="2">
            <a-card size="small" class="realtime-card" :bordered="false">
              <div class="realtime-item">
                <span class="item-label">
                  <icon-location />
                  当前扫描:
                </span>
                <a-typography-text code>{{ taskInfo.current_target || '解析中...' }}</a-typography-text>
              </div>
              <div class="realtime-item">
                <span class="item-label">
                  <icon-check-circle-fill style="color: var(--color-success-6)" />
                  已探测存活:
                </span>
                <span class="found-big">{{ taskInfo.found_assets || 0 }}</span>
              </div>
            </a-card>
          </a-descriptions-item>
          <a-descriptions-item label="扫描时长">{{ formatDuration(taskInfo.started_at, taskInfo.completed_at) }}</a-descriptions-item>
          <a-descriptions-item label="创建时间">{{ formatDateTime(taskInfo.created_at) }}</a-descriptions-item>
        </a-descriptions>

        <!-- 扫描结果区域 -->
        <a-divider />
        <a-tabs default-active-key="assets">
          <!-- 资产测绘标签页 -->
          <a-tab-pane key="assets" title="资产测绘">
            <!-- 针对存活扫描任务的显示逻辑 -->
            <template v-if="taskInfo.type === 'alive'">
              <a-table v-if="aliveHosts && aliveHosts.length > 0" :data="aliveHosts" :pagination="{ pageSize: 20 }" :bordered="true">
                <template #columns>
                  <a-table-column title="目标">
                    <template #cell="{ record }">
                      <span style="font-weight: 600; color: var(--color-text-1)">
                        {{ record.original || record.host || record.ip || '未知' }}
                      </span>
                    </template>
                  </a-table-column>
                  <a-table-column title="IP地址">
                    <template #cell="{ record }">
                      <span v-if="record.ip && record.ip !== record.original" style="color: var(--color-text-2)">
                        {{ record.ip }}
                      </span>
                      <span v-else style="color: var(--color-text-3)">-</span>
                    </template>
                  </a-table-column>
                  <a-table-column title="状态">
                    <template #cell>
                      <a-tag color="green" bordered>存活</a-tag>
                    </template>
                  </a-table-column>
                  <a-table-column title="延迟" data-index="latency" />
                </template>
              </a-table>
              <a-empty v-else description="未发现存活目标" style="margin: 40px 0" />
            </template>

            <!-- 针对常规扫描任务的显示逻辑 (端口/服务) -->
            <template v-else>
              <a-table v-if="hasAssetData" :data="serviceResults" :pagination="{ pageSize: 20 }" :bordered="true">
                <template #columns>
                  <a-table-column title="IP地址" data-index="ip">
                    <template #cell="{ record }">
                      <span style="font-weight: 600">{{ record.ip }}</span>
                    </template>
                  </a-table-column>
                  <a-table-column title="端口" data-index="port">
                    <template #cell="{ record }">
                      <a-tag color="blue">{{ record.port }} / {{ record.protocol || 'tcp' }}</a-tag>
                    </template>
                  </a-table-column>
                  <a-table-column title="服务" data-index="service">
                    <template #cell="{ record }">
                      {{ formatServiceName(record.service) }}
                    </template>
                  </a-table-column>
                  <a-table-column title="版本信息">
                    <template #cell="{ record }">
                      <span v-if="record.product || record.version">{{ record.product }} {{ record.version }}</span>
                      <span v-else style="color: var(--color-text-3)">-</span>
                    </template>
                  </a-table-column>
                  <a-table-column title="可信度" data-index="confidence">
                    <template #cell="{ record }">
                      <a-progress
                        v-if="record.confidence > 0"
                        :percent="record.confidence / 100"
                        :show-text="false"
                        size="mini"
                        style="width: 60px"
                      />
                      <span v-else style="color: var(--color-text-3)">-</span>
                    </template>
                  </a-table-column>
                  <a-table-column title="操作" align="center">
                    <template #cell="{ record }">
                      <a-button type="text" size="small" @click="showPortDetail(record)">查看详情</a-button>
                    </template>
                  </a-table-column>
                </template>
              </a-table>
              <a-empty v-else description="暂无资产数据" style="margin: 40px 0" />
            </template>
          </a-tab-pane>

          <!-- Web指纹标签页 -->
          <a-tab-pane key="fingerprints" title="Web指纹">
            <template v-if="webFingerprints.length > 0">
              <a-table :data="webFingerprints" :pagination="{ pageSize: 10 }" row-key="url" :bordered="true">
                <template #columns>
                  <a-table-column title="URL" data-index="url" :width="220" />
                  <a-table-column title="标题" data-index="title" :ellipsis="true" :tooltip="true" />
                  <a-table-column title="指纹/技术栈" >
                    <template #cell="{ record }">
                      <a-space wrap>
                        <a-tag v-for="tech in record.technologies || []" :key="tech" color="arcoblue" size="small">
                          {{ tech }}
                        </a-tag>
                        <a-tag v-for="fw in record.frameworks || []" :key="fw" color="green" size="small">
                          {{ fw }}
                        </a-tag>
                      </a-space>
                    </template>
                  </a-table-column>
                  <a-table-column title="扫描标注" :width="150">
                    <template #cell="{ record }">
                      <div v-if="record.server && (record.server.includes('目录扫描') || record.server.includes('子域名爆破'))">
                        <a-tag color="purple" size="small">{{ record.server }}</a-tag>
                      </div>
                      <div v-else-if="record.server === 'Web指纹'">
                        <a-tag color="blue" size="small">指纹识别</a-tag>
                      </div>
                      <div v-else>
                        <span style="color: var(--color-text-3)">-</span>
                      </div>
                    </template>
                  </a-table-column>
                  <a-table-column title="响应信息" :width="160">
                    <template #cell="{ record }">
                      <div>
                        <a-tag
                          v-if="record.status_code"
                          :color="record.status_code >= 400 ? 'red' : record.status_code >= 300 ? 'blue' : 'green'"
                          size="small"
                        >
                          {{ record.status_code }}
                        </a-tag>
                        <span
                          style="margin-left: 8px; font-size: 12px; color: var(--color-text-3)"
                          v-if="record.server && !record.server.includes('目录扫描') && !record.server.includes('子域名爆破')"
                        >
                          {{ record.server }}
                        </span>
                      </div>
                    </template>
                  </a-table-column>
                  <a-table-column title="操作" align="center" :width="150">
                    <template #cell="{ record }">
                      <a-space>
                        <a-button type="text" size="small" @click="showWebDetail(record)">详情</a-button>
                        <a-button
                          type="text"
                          size="small"
                          @click="openURL(record.url)"
                        >访问</a-button>
                      </a-space>
                    </template>
                  </a-table-column>
                </template>
              </a-table>
            </template>
            <a-empty v-else description="暂无指纹识别结果" style="margin: 40px 0" />
          </a-tab-pane>

          <!-- 漏洞扫描标签页 -->
          <a-tab-pane key="vulnerabilities" :title="`漏洞详情 ${vulnerabilities.length > 0 ? '(' + vulnerabilities.length + ')' : ''}`">
            <a-empty v-if="vulnerabilities.length === 0" description="暂无漏洞数据" style="margin: 40px 0" />
            <a-table v-else :data="vulnerabilities" :pagination="{ pageSize: 20 }" :bordered="true" row-key="id">
              <template #columns>
                <a-table-column title="漏洞等级" :width="90" align="center">
                  <template #cell="{ record }">
                    <a-tag :color="getSeverityColor(record.severity)" size="small">
                      {{ getSeverityText(record.severity) }}
                    </a-tag>
                  </template>
                </a-table-column>
                <a-table-column title="漏洞名称" :width="400">
                  <template #cell="{ record }">
                    <span style="font-weight: 600">{{ record.name || record.template_id }}</span>
                  </template>
                </a-table-column>
                <a-table-column title="目标" data-index="target" :width="250" />
                <a-table-column title="CVE / CVSS" :width="200">
                  <template #cell="{ record }">
                    <div>
                      <a-tag v-if="record.cve" color="red" size="small">{{ record.cve }}</a-tag>
                      <span v-if="record.cvss > 0" style="margin-left: 6px; font-size: 12px; color: var(--color-text-3)">
                        {{ record.cvss }}
                      </span>
                    </div>
                  </template>
                </a-table-column>
                <a-table-column title="描述" :ellipsis="true" :tooltip="true">
                  <template #cell="{ record }">
                    <span style="color: var(--color-text-2); font-size: 13px">{{ record.description || '-' }}</span>
                  </template>
                </a-table-column>
                <a-table-column title="操作" align="center" :width="80">
                  <template #cell="{ record }">
                    <a-button type="text" size="small" @click="showVulnDetail(record)">详情</a-button>
                  </template>
                </a-table-column>
              </template>
            </a-table>
          </a-tab-pane>

          <!-- 原始输出标签页 -->
          <!-- <a-tab-pane key="raw" title="扫描详情">
            <a-descriptions :column="1" bordered>
              <a-descriptions-item label="任务类型">{{ taskInfo.type }}</a-descriptions-item>
              <a-descriptions-item label="目标数量">{{ assetResults.length }}</a-descriptions-item>
              <a-descriptions-item label="发现漏洞">{{ vulnerabilities.length }}</a-descriptions-item>
            </a-descriptions>
          </a-tab-pane> -->
        </a-tabs>
      </a-card>
    </a-spin>

    <!-- 端口详情弹窗 -->
    <a-modal v-model:visible="detailVisible" title="端口详情" width="700px" :footer="false">
      <a-descriptions :column="2" bordered size="small">
        <a-descriptions-item label="IP地址">{{ currentPort.ip }}</a-descriptions-item>
        <a-descriptions-item label="端口号">{{ currentPort.port }} / {{ currentPort.protocol }}</a-descriptions-item>
        <a-descriptions-item label="服务名称">{{ formatServiceName(currentPort.service) }}</a-descriptions-item>
        <a-descriptions-item label="产品/版本">{{ currentPort.product }} {{ currentPort.version }}</a-descriptions-item>
        <a-descriptions-item label="探测方法">{{ currentPort.method || '-' }}</a-descriptions-item>
        <a-descriptions-item label="识别置信度">
          {{ currentPort.confidence > 0 ? currentPort.confidence + ' / 100' : '-' }}
        </a-descriptions-item>
        <a-descriptions-item v-if="currentPort.os_type" label="操作系统">{{ currentPort.os_type }}</a-descriptions-item>
        <a-descriptions-item v-if="currentPort.device_type" label="设备类型">{{ currentPort.device_type }}</a-descriptions-item>
      </a-descriptions>

      <div v-if="currentPort.banner" class="detail-section">
        <div class="detail-label">Banner 信息:</div>
        <pre class="detail-content">{{ currentPort.banner }}</pre>
      </div>

      <div v-if="currentPort.scripts && Object.keys(currentPort.scripts).length > 0" class="detail-section">
        <div class="detail-label">脚本探测结果:</div>
        <div v-for="(val, key) in currentPort.scripts" :key="key" class="script-item">
          <div class="script-name">{{ key }}:</div>
          <pre class="script-val">{{ val }}</pre>
        </div>
      </div>

      <div v-if="currentPort.cpes && currentPort.cpes.length > 0" class="detail-section">
        <div class="detail-label">CPE 信息:</div>
        <a-space wrap>
          <a-tag v-for="cpe in currentPort.cpes" :key="cpe" color="orange" size="small">{{ cpe }}</a-tag>
        </a-space>
      </div>
    </a-modal>

    <!-- 任务配置详情弹窗 -->
    <a-modal v-model:visible="configVisible" title="扫描配置详情" width="600px" :footer="false">
      <a-descriptions :column="1" bordered size="medium">
        <a-descriptions-item label="任务名称">{{ taskInfo.name }}</a-descriptions-item>
        <a-descriptions-item label="扫描类型">
          <a-tag color="arcoblue">{{ $t(`task.type.${taskInfo.type}`) }}</a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="扫描目标">
          <div style="word-break: break-all; max-height: 100px; overflow-y: auto">
            {{ taskInfo.target }}
          </div>
        </a-descriptions-item>

        <!-- 动态显示 options 中的配置 -->
        <template v-if="taskInfo.type === 'port'">
          <a-descriptions-item label="端口范围">
            <a-tag color="orange">{{ parsedOptions.port_range || parsedOptions.ports || '常用端口' }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="指纹识别">
            <a-tag :color="parsedOptions.enable_fingerprint ? 'green' : 'gray'">
              {{ parsedOptions.enable_fingerprint ? '已开启' : '未开启' }}
            </a-tag>
          </a-descriptions-item>
        </template>

        <a-descriptions-item label="并发线程">{{ parsedOptions.threads || '默认 (25)' }}</a-descriptions-item>
        <a-descriptions-item label="超时时间">{{ parsedOptions.timeout || '默认 (10)' }} 秒</a-descriptions-item>

        <a-descriptions-item v-if="taskInfo.description" label="任务描述">{{ taskInfo.description }}</a-descriptions-item>
      </a-descriptions>

      <div v-if="taskInfo.options && typeof taskInfo.options === 'string'" class="detail-section">
        <div class="detail-label">原始配置 (JSON)</div>
        <div class="detail-content banner-code" style="max-height: 200px; overflow-y: auto">
          {{ taskInfo.options }}
        </div>
      </div>
    </a-modal>

    <!-- Web指纹详情弹窗 -->
    <a-modal v-model:visible="webDetailVisible" title="Web 指纹详细信息" width="800px" :footer="false">
      <a-descriptions :column="2" bordered size="small">
        <a-descriptions-item label="URL" :span="2">
          <a-link :href="currentWebDetail.url" target="_blank">{{ currentWebDetail.url }}</a-link>
        </a-descriptions-item>
        <a-descriptions-item label="网页标题" :span="2">{{ currentWebDetail.title || '-' }}</a-descriptions-item>
        <a-descriptions-item label="状态码">{{ currentWebDetail.status_code }}</a-descriptions-item>
        <a-descriptions-item label="服务端">{{ currentWebDetail.server || '-' }}</a-descriptions-item>
        <a-descriptions-item v-if="currentWebDetail.response_time" label="响应时间">
          {{ currentWebDetail.response_time }} ms
        </a-descriptions-item>
        <a-descriptions-item v-if="currentWebDetail.favicon_hash" label="Favicon Hash">
          {{ currentWebDetail.favicon_hash }}
        </a-descriptions-item>
      </a-descriptions>

      <div class="detail-section">
        <div class="detail-label">识别结果:</div>
        <a-space direction="vertical" style="width: 100%">
          <div v-if="currentWebDetail.frameworks?.length > 0">
            <span style="margin-right: 8px; font-weight: bold">应用框架:</span>
            <a-space wrap>
              <a-tag v-for="fw in currentWebDetail.frameworks" :key="fw" color="green">{{ fw }}</a-tag>
            </a-space>
          </div>
          <div v-if="currentWebDetail.technologies?.length > 0">
            <span style="margin-right: 8px; font-weight: bold">技术组件:</span>
            <a-space wrap>
              <a-tag v-for="tech in currentWebDetail.technologies" :key="tech" color="arcoblue">{{ tech }}</a-tag>
            </a-space>
          </div>
        </a-space>
      </div>

      <div v-if="currentWebDetail.matched_rules?.length > 0" class="detail-section">
        <div class="detail-label">指纹规则详情:</div>
        <a-list size="small">
          <a-list-item v-for="(rule, index) in currentWebDetail.matched_rules" :key="index">
            <template #actions>
              <a-tag color="arcoblue" size="small">已匹配</a-tag>
            </template>
            <a-list-item-meta :title="rule" />
          </a-list-item>
        </a-list>
      </div>

      <div v-if="currentWebDetail.headers && Object.keys(currentWebDetail.headers).length > 0" class="detail-section">
        <div class="detail-label">HTTP 响应头:</div>
        <div class="banner-code" style="background: var(--color-fill-2); padding: 12px; border-radius: 4px">
          <div v-for="(val, key) in currentWebDetail.headers" :key="key" style="margin-bottom: 4px">
            <span style="color: var(--color-primary-light-4); font-weight: bold">{{ key }}:</span>
            {{ val }}
          </div>
        </div>
      </div>
    </a-modal>
  </div>

  <!-- 漏洞详情弹窗 -->
  <a-modal v-model:visible="vulnDetailVisible" :title="currentVuln.name || '漏洞详情'" width="900px" :footer="false">
    <!-- 基本信息 -->
    <a-descriptions :column="2" bordered size="small" style="margin-bottom: 16px">
      <a-descriptions-item label="严重程度">
        <a-tag :color="getSeverityColor(currentVuln.severity)">
          {{ getSeverityText(currentVuln.severity) }}
        </a-tag>
      </a-descriptions-item>
      <a-descriptions-item label="目标">{{ currentVuln.target }}</a-descriptions-item>
      <a-descriptions-item label="CVE编号">
        <a-tag v-if="currentVuln.cve" color="red" size="small">{{ currentVuln.cve }}</a-tag>
        <span v-else style="color: var(--color-text-3)">-</span>
      </a-descriptions-item>
      <a-descriptions-item label="CVSS评分">
        <span v-if="currentVuln.cvss > 0" style="font-weight: bold; color: var(--color-danger-6)">{{ currentVuln.cvss }}</span>
        <span v-else style="color: var(--color-text-3)">-</span>
      </a-descriptions-item>
      <a-descriptions-item label="模板ID" :span="2">{{ currentVuln.template_id || '-' }}</a-descriptions-item>
      <a-descriptions-item v-if="currentVuln.matched_at" label="命中地址" :span="2">
        <a-typography-text code>{{ currentVuln.matched_at }}</a-typography-text>
      </a-descriptions-item>
      <a-descriptions-item v-if="currentVuln.description" label="漏洞描述" :span="2">
        {{ currentVuln.description }}
      </a-descriptions-item>
    </a-descriptions>

    <!-- HTTP 请求包 -->
    <div v-if="currentVuln.evidence_request" class="detail-section">
      <div class="detail-label" style="display: flex; align-items: center; gap: 8px">
        <a-tag color="arcoblue" size="small">HTTP Request</a-tag>
        请求报文
      </div>
      <pre
        class="detail-content"
        style="
          max-height: 300px;
          overflow-y: auto;
          font-size: 12px;
          line-height: 1.6;
          background: var(--color-fill-2);
          padding: 12px;
          border-radius: 4px;
          white-space: pre-wrap;
          word-break: break-all;
        "
        >{{ currentVuln.evidence_request }}</pre
      >
    </div>

    <!-- HTTP 响应包 -->
    <div v-if="currentVuln.evidence_response" class="detail-section">
      <div class="detail-label" style="display: flex; align-items: center; gap: 8px">
        <a-tag color="green" size="small">HTTP Response</a-tag>
        响应报文
      </div>
      <pre
        class="detail-content"
        style="
          max-height: 300px;
          overflow-y: auto;
          font-size: 12px;
          line-height: 1.6;
          background: var(--color-fill-2);
          padding: 12px;
          border-radius: 4px;
          white-space: pre-wrap;
          word-break: break-all;
        "
        >{{ currentVuln.evidence_response }}</pre
      >
    </div>

    <div v-if="parseListField(currentVuln.tags).length > 0" class="detail-section">
      <div class="detail-label">标签</div>
      <a-space wrap>
        <a-tag v-for="tag in parseListField(currentVuln.tags)" :key="tag" color="orange" size="small">{{ tag }}</a-tag>
      </a-space>
    </div>

    <div v-if="parseListField(currentVuln.reference).length > 0" class="detail-section">
      <div class="detail-label">参考链接</div>
      <div v-for="ref in parseListField(currentVuln.reference)" :key="ref">
        <a-link :href="ref" target="_blank" style="font-size: 12px">{{ ref }}</a-link>
      </div>
    </div>

  </a-modal>
</template>

<script lang="ts" setup>
/* eslint-disable no-use-before-define */
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Message } from '@arco-design/web-vue'
import {
  IconSync,
  IconPause,
  IconPlayArrow,
  IconClose,
  IconDelete,
  IconLoading,
  IconLayers,
  IconLocation,
  IconCheckCircleFill,
  IconExport,
  IconDown,
  IconSettings,
} from '@arco-design/web-vue/es/icon'
import { getTaskDetail, startTask, getTaskResults, getTaskVulnerabilities, stopTask, deleteTask, getTaskProgress } from '@/api/task'

defineOptions({ name: 'ScanResult' })

const route = useRoute()
const router = useRouter()
const loading = ref(false)
const rescanLoading = ref(false)
const pauseLoading = ref(false)
const stopLoading = ref(false)
const deleteLoading = ref(false)

const taskId = computed(() => {
  return (route.query.taskId as string) || (route.params.id as string)
})

const taskInfo = ref<any>({})
const assetResults = ref<any[]>([])
const pollTimer = ref<any>(null)

// 计算属性: 提取存活主机
const aliveHosts = computed(() => {
  return assetResults.value
    .filter((item: any) => item.asset?.is_alive)
    .map((item: any) => ({
      original: item.asset?.value || item.detail?.original,
      ip: item.detail?.ip,
      host: item.detail?.host,
      latency: item.detail?.latency,
      status: item.status,
    }))
})

// 计算属性: 提取端口/服务信息
const serviceResults = computed(() => {
  const list: any[] = []
  assetResults.value.forEach((asset: { asset?: { value?: string }; detail?: { ip?: string; services?: any[]; ports?: any[] } }) => {
    // 兼容 detail.services 和 detail.ports 两种结构
    const items = asset.detail?.services || asset.detail?.ports || []
    items.forEach(
      (item: {
        Port?: number
        port?: number
        Protocol?: string
        protocol?: string
        Service?: any
        service?: any
        Name?: string
        name?: string
        Product?: string
        product?: string
        Version?: string
        version?: string
        Confidence?: number
        confidence?: number
        OSType?: string
        os_type?: string
        DeviceType?: string
        device_type?: string
        Banner?: string
        banner?: string
        method?: string
        fingerprint_method?: string
        CPEs?: string[]
        cpes?: string[]
        Scripts?: any
        scripts?: any
        State?: string
        state?: string
        status?: string
      }) => {
        // 兼容 PortResult 和 ServiceInfo 两种可能的结构
        const s = item.Service || item.service || {}
        list.push({
          host: asset.asset?.value,
          ip: asset.detail?.ip || asset.asset?.value,
          port: item.Port || item.port,
          protocol: item.Protocol || item.protocol || 'tcp',
          service: s.Name || s.service || s.name || '-',
          product: s.Product || s.product || '',
          version: s.Version || s.version || '',
          confidence: s.Confidence || s.confidence || 0,
          os_type: s.OSType || s.os_type || '',
          device_type: s.DeviceType || s.device_type || '',
          banner: s.Banner || s.banner || item.banner || '',
          method: item.method || item.fingerprint_method || '',
          cpes: s.CPEs || s.cpes || [],
          scripts: s.Scripts || s.scripts || {},
          status: item.State || item.state || (item.status === 'open' ? 'open' : 'open'),
        })
      }
    )
  })
  return list
})

// 计算属性: 提取Web指纹
const webFingerprints = computed(() => {
  const list: any[] = []
  console.log('[DEBUG] assetResults:', assetResults.value)
  assetResults.value.forEach((asset) => {
    const fingerprints = asset.detail?.fingerprints || []
    console.log('[DEBUG] asset fingerprints:', fingerprints)
    fingerprints.forEach((fp: any) => {
      list.push({
        url: fp.url || asset.asset?.value,
        title: fp.title || '-',
        technologies: fp.technologies || [],
        frameworks: fp.frameworks || [],
        server: fp.server || '-',
        status_code: fp.status_code || '-',
        headers: fp.headers || {},
        favicon_hash: fp.favicon_hash || '',
        response_time: fp.response_time || 0,
        raw: fp, // 原始数据
      })
    })
  })
  console.log('[DEBUG] webFingerprints list:', list)
  return list
})

// 计算属性: 获取所有漏洞详情
const vulnerabilities = ref<any[]>([])

const hasAssetData = computed(() => {
  return assetResults.value.length > 0
})

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    pending: 'gray',
    running: 'arcoblue',
    finished: 'green',
    completed: 'green',
    stopped: 'gray',
    error: 'red',
    failed: 'red',
  }
  return colors[status] || 'gray'
}

const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = {
    critical: 'red',
    high: 'orangered',
    medium: 'orange',
    low: 'gold',
    info: 'blue',
  }
  return colors[severity?.toLowerCase()] || 'gray'
}

const getSeverityText = (severity: string) => {
  const texts: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }
  return texts[severity?.toLowerCase()] || severity
}

const formatServiceName = (service: string) => {
  if (!service || service === '-' || service.toLowerCase() === 'unknown') return '-'
  if (service.length > 5) {
    return service.charAt(0).toUpperCase() + service.slice(1).toLowerCase()
  }
  return service.toUpperCase()
}

const openURL = (url: string) => {
  if (url) {
    window.open(url, '_blank')
  }
}

const truncateTarget = (target: string) => {
  if (!target) return '-'
  if (target.length <= 80) return target
  return `${target.substring(0, 80)}...`
}

const normalizeProgress = (progress: any) => {
  const p = parseFloat(progress)
  if (Number.isNaN(p)) return 0
  // 后端返回的 progress 是 0-100 的整数，统一除以 100 转换为 0-1 的小数
  let result = p / 100
  if (result > 1) result = 1
  if (result < 0) result = 0
  return result
}

const parseChinaDate = (dateStr: string) => {
  if (!dateStr) return null
  const normalized = String(dateStr).trim()
  if (!normalized) return null

  // 后端若返回无时区时间字符串，按中国时区解析，避免出现固定 8 小时偏差。
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

const formatDuration = (start: string, end: string) => {
  if (!start) return '-'
  const startDate = parseChinaDate(start)
  const endDate = end ? parseChinaDate(end) : new Date()

  if (!startDate) return '-'
  const startTime = startDate.getTime()
  const endTime = endDate ? endDate.getTime() : new Date().getTime()

  if (Number.isNaN(startTime)) return '-'

  const durationMs = endTime - startTime
  if (durationMs < 0) return '0s'

  const totalSeconds = Math.floor(durationMs / 1000)
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60

  let result = ''
  if (hours > 0) result += `${hours}h `
  if (minutes > 0 || hours > 0) result += `${minutes}m `
  result += `${seconds}s`

  return result.trim()
}

const parseListField = (raw: unknown): string[] => {
  if (raw === null || raw === undefined) return []
  const text = String(raw).trim()
  if (!text) return []

  try {
    const parsed = JSON.parse(text)
    if (Array.isArray(parsed)) {
      return parsed
        .map((item) => String(item).trim())
        .filter((item) => item.length > 0)
    }
  } catch {
    // not json, fallback to delimiter split
  }

  return text
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
}

function startPolling() {
  if (pollTimer.value) return
  pollTimer.value = setInterval(() => {
    fetchTaskData()
    fetchTaskResults()
    fetchVulnerabilities()
  }, 3000)
}

function stopPolling() {
  if (pollTimer.value) {
    clearInterval(pollTimer.value)
    pollTimer.value = null
  }
}

async function fetchTaskResults() {
  if (!taskId.value) return
  try {
    const { data } = await getTaskResults(Number(taskId.value))
    assetResults.value = data || []
  } catch (err) {
    console.error('Failed to fetch task results', err)
  }
}

// 漏洞详情弹窗
const vulnDetailVisible = ref(false)
const currentVuln = ref<any>({})

function showVulnDetail(vuln: any) {
  currentVuln.value = vuln
  vulnDetailVisible.value = true
}

async function fetchVulnerabilities() {
  if (!taskId.value) return
  try {
    const { data } = await getTaskVulnerabilities(Number(taskId.value))
    // 后端返回 { code, msg, data: [...] }，axios 响应 .data 是外层对象
    vulnerabilities.value = data?.data || data || []
  } catch (err) {
    console.error('Failed to fetch vulnerabilities', err)
  }
}

async function fetchTaskData() {
  if (!taskId.value) return

  // 仅首次加载或状态改变时显示loading
  if (!taskInfo.value.status) loading.value = true

  try {
    // 1. 获取任务基础详情
    const { data: detail } = await getTaskDetail(Number(taskId.value))

    // 2. 如果任务正在运行，尝试获取 Redis 中的实时进度
    if (detail.status === 'running') {
      try {
        const { data: progressData } = await getTaskProgress(Number(taskId.value))
        // 合并实时进度数据
        taskInfo.value = {
          ...detail,
          ...progressData,
          // 确保进度值被正确覆盖（实时进度更准）
          progress: progressData.progress !== undefined ? progressData.progress : detail.progress,
        }
      } catch (e) {
        console.warn('获取实时进度失败，回退到基础详情', e)
        taskInfo.value = detail
      }
    } else {
      // ✅ 任务已完成/失败/停止，直接使用 MySQL 数据，不再合并 Redis
      taskInfo.value = detail

      // ✅ 立即停止轮询，避免继续请求造成数据跳动
      if (pollTimer.value) {
        stopPolling()
      }
    }

    // 如果任务正在运行，启动轮询
    if (taskInfo.value.status === 'running' && !pollTimer.value) {
      startPolling()
    }
  } catch (err: any) {
    Message.error(err.message || '获取任务详情失败')
    stopPolling()
  } finally {
    loading.value = false
  }
}

// 导出报告处理
const handleExportReport = (type: string) => {
  if (type === 'preview') {
    // 跳转到报告详情页 (目前使用 report/basic 作为详情模板)
    router.push({
      path: '/report/basic',
      query: { taskId: taskId.value },
    })
    return
  }

  Message.loading({ content: `正在生成 ${type.toUpperCase()} 报告...`, duration: 1500 })
  setTimeout(() => {
    Message.success(`${type.toUpperCase()} 报告导出成功`)
  }, 1600)
}

async function handlePause() {
  if (!taskId.value) return
  pauseLoading.value = true
  try {
    await stopTask(Number(taskId.value))
    Message.success('已暂停扫描')
    fetchTaskData()
  } catch (err: any) {
    Message.error(err.response?.data?.msg || err.message || '暂停失败')
  } finally {
    pauseLoading.value = false
  }
}

async function handleResume() {
  if (!taskId.value) return
  rescanLoading.value = true
  try {
    await startTask(Number(taskId.value))
    Message.success('已继续扫描')

    // 立即更新本地状态
    taskInfo.value.status = 'running'

    // 确保轮询已启动
    if (!pollTimer.value) {
      startPolling()
    }
  } catch (err: any) {
    Message.error(err.response?.data?.msg || err.message || '继续扫描失败')
  } finally {
    rescanLoading.value = false
  }
}

async function handleStop() {
  if (!taskId.value) return
  stopLoading.value = true
  try {
    await stopTask(Number(taskId.value))
    Message.success('任务已停止')
    fetchTaskData()
  } catch (err: any) {
    Message.error(err.response?.data?.msg || err.message || '停止任务失败')
  } finally {
    stopLoading.value = false
  }
}

async function handleDelete() {
  if (!taskId.value) return
  deleteLoading.value = true
  try {
    await deleteTask(Number(taskId.value))
    Message.success('任务已删除')
    // 删除成功后跳转回任务列表
    window.location.href = '/#/task/list'
  } catch (err: any) {
    Message.error(err.response?.data?.msg || err.message || '删除任务失败')
  } finally {
    deleteLoading.value = false
  }
}

async function handleRescan() {
  if (!taskId.value) return
  rescanLoading.value = true
  try {
    await startTask(Number(taskId.value))
    Message.success('已发起重新扫描')

    // 立即重置本地状态以提供反馈 (乐观 UI 更新)
    const now = new Date().toISOString()
    taskInfo.value = {
      ...taskInfo.value,
      status: 'running',
      progress: 0,
      started_at: now,
      created_at: now,
      completed_at: null,
      message: '准备重新扫描...',
      scanned_targets: 0,
      found_assets: 0,
      current_target: '初始化...',
    }

    // 清空旧的显示数据
    assetResults.value = []
    vulnerabilities.value = []

    // ✅ 不要立即调用 fetchTaskData()，因为后端 DB 更新可能有微小延迟
    // fetchTaskData();
    // fetchTaskResults();
    // fetchVulnerabilities();

    // 确保轮询已启动，下一轮轮询会获取到真正在运行的状态
    if (!pollTimer.value) {
      startPolling()
    }
  } catch (err: any) {
    Message.error(err.response?.data?.msg || err.message || '发起扫描失败')
  } finally {
    rescanLoading.value = false
  }
}

// 端口详情展示
const detailVisible = ref(false)
const currentPort = ref<any>({})

const showPortDetail = (record: any) => {
  currentPort.value = record
  detailVisible.value = true
}

// 状态更新与重新扫描配置
const configVisible = ref(false)
const showConfig = () => {
  configVisible.value = true
}

// Web 指纹详情
const webDetailVisible = ref(false)
const currentWebDetail = ref<any>({})
const showWebDetail = (record: any) => {
  currentWebDetail.value = record
  webDetailVisible.value = true
}

const parsedOptions = computed(() => {
  if (!taskInfo.value.options) return {}
  if (typeof taskInfo.value.options === 'object') return taskInfo.value.options
  try {
    return JSON.parse(taskInfo.value.options)
  } catch (e) {
    return { raw: taskInfo.value.options }
  }
})

onMounted(() => {
  fetchTaskData()
  fetchTaskResults()
  fetchVulnerabilities()
})

onUnmounted(() => {
  stopPolling()
})
</script>

<style scoped lang="less">
.container {
  padding: 0 20px 20px 20px;
}

.raw-output {
  background: var(--color-fill-2);
  padding: 16px;
  border-radius: 4px;
  overflow-x: auto;
  max-height: 600px;
  font-size: 13px;
  line-height: 1.6;
  font-family: 'Courier New', Courier, monospace;
}

.detail-section {
  margin-top: 16px;
}

.detail-label {
  font-weight: 600;
  margin-bottom: 8px;
  color: var(--color-text-1);
}

.detail-content {
  background: var(--color-fill-2);
  padding: 12px;
  border-radius: 4px;
  max-height: 200px;
  overflow-y: auto;
  font-family: monospace;
  font-size: 13px;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
}

.script-item {
  margin-top: 12px;
}

.script-name {
  font-weight: 500;
  color: var(--color-primary-light-4);
  margin-bottom: 4px;
}

.progress-wrapper {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.progress-text {
  font-weight: bold;
  font-size: 14px;
  color: var(--color-text-1);
}

.progress-stats {
  font-size: 12px;
  color: var(--color-text-3);
  display: flex;
  align-items: center;
  gap: 4px;
}

.status-msg {
  font-size: 13px;
  color: var(--color-primary-light-4);
  font-style: italic;
}

.realtime-card {
  background: var(--color-bg-2);
  border: 1px solid var(--color-fill-3);
  border-radius: 8px;
}

.realtime-item {
  display: flex;
  align-items: center;
  margin-bottom: 8px;
  &:last-child {
    margin-bottom: 0;
  }
}

.item-label {
  font-size: 12px;
  color: var(--color-text-3);
  margin-right: 8px;
  display: flex;
  align-items: center;
  gap: 4px;
  width: 100px;
}

.found-big {
  font-size: 18px;
  font-weight: bold;
  color: var(--color-success-6);
  text-shadow: 0 0 8px rgba(var(--success-6), 0.2);
}

.script-val {
  background: var(--color-fill-1);
  padding: 8px;
  border-left: 3px solid var(--color-primary-light-3);
  font-size: 12px;
  white-space: pre-wrap;
  margin: 0;
}
</style>
