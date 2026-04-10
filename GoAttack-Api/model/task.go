package model

import (
	"time"
)

// Task 漏洞扫描任务结构体
type Task struct {
	ID          int    `json:"id"`          // 任务ID
	Name        string `json:"name"`        // 任务名称
	Target      string `json:"target"`      // 扫描目标（URL或IP）
	Type        string `json:"type"`        // 扫描类型：port, web, vuln
	Status      string `json:"status"`      // 任务状态：pending, running, completed, failed
	Progress    int    `json:"progress"`    // 任务进度 (0-100)
	Creator     string `json:"creator"`     // 创建者
	Description string `json:"description"` // 任务描述
	Options     string `json:"options"`     // 扫描选项（JSON格式）
	// 注意：扫描结果现在存储在 asset_scan_result 表中，不再存储在此字段
	CreatedAt   time.Time  `json:"created_at"`   // 创建时间
	UpdatedAt   time.Time  `json:"updated_at"`   // 更新时间
	StartedAt   *time.Time `json:"started_at"`   // 开始时间
	CompletedAt *time.Time `json:"completed_at"` // 完成时间
}

// ScanOptions 扫描选项结构体
type ScanOptions struct {
	// 主机探测
	EnableHostDiscovery bool `json:"enable_host_discovery"` // 是否开启主机存活探测（ICMP）

	// 端口扫描
	Ports            string `json:"ports"`              // 端口范围，如 "1-1000" 或 "80,443,8080"
	EnableServiceDet bool   `json:"enable_service_det"` // 是否进行服务识别
	EnablePortScan   bool   `json:"enable_port_scan"`   // 是否进行 TCP 端口扫描（自定义扫描）
	EnableUDPScan    bool   `json:"enable_udp_scan"`    // 是否进行 UDP 端口扫描（自定义/全量）
	UDPPorts         string `json:"udp_ports"`          // UDP 扫描端口范围

	// 认证攻击
	EnableWeakPassword bool `json:"enable_weak_password"` // 是否进行弱口令猜解

	// Web 扫描
	EnableSubdomainEnum bool `json:"enable_subdomain_enum"` // 是否进行子域名枚举
	EnableDirScan       bool `json:"enable_dir_scan"`       // 是否进行目录扫描
	EnableWebFingerprint bool `json:"enable_web_fingerprint"` // 是否进行 Web 指纹识别（自定义扫描）
	EnablePocVerify      bool `json:"enable_poc_verify"`      // 是否进行 POC 漏洞验证（自定义扫描）
	EnableFullPocVerify  bool `json:"enable_full_poc_verify"` // 是否启用全量 POC 验证（不依赖指纹）

	// 反连服务
	EnableReverse bool `json:"enable_reverse"` // 是否启用反连服务

	// 其他选项
	Threads        int    `json:"threads"`         // 并发线程数
	Timeout        int    `json:"timeout"`         // 超时时间（秒）
	Advanced       string `json:"advanced"`        // 高级选项（JSON字符串）
	ScheduledTime  string `json:"scheduled_time"`  // 定时任务时间，格式："2006-01-02 15:04:05"
	BlacklistPorts string `json:"blacklist_ports"` // 黑名单端口，例如："22,3306"
	BlacklistHosts string `json:"blacklist_hosts"` // 黑名单资产，例如："192.168.1.1,example.com"
}

// CreateTaskRequest 创建任务请求结构体
type CreateTaskRequest struct {
	Name        string      `json:"name" binding:"required"`   // 任务名称
	Target      string      `json:"target" binding:"required"` // 扫描目标
	Type        string      `json:"type" binding:"required"`   // 扫描类型
	Description string      `json:"description"`               // 任务描述
	ScanOptions ScanOptions `json:"scan_options"`              // 扫描选项
}

// TaskListResponse 任务列表响应结构体
type TaskListResponse struct {
	Total int    `json:"total"` // 总任务数
	Tasks []Task `json:"tasks"` // 任务列表
}

// TaskStatusUpdate 任务状态更新结构体
type TaskStatusUpdate struct {
	Status   string `json:"status"`   // 任务状态
	Progress int    `json:"progress"` // 任务进度
	Result   string `json:"result"`   // 扫描结果
}
