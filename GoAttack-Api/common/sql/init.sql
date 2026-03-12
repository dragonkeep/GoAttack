-- GoAttack 漏洞扫描系统数据库初始化脚本
-- 创建时间: 2026-01-19
-- 说明: 该脚本用于首次部署时初始化数据库结构

-- ============================================
-- 1. 用户表 (user)
-- 说明: 存储系统用户信息，包括管理员和普通用户
-- ============================================
CREATE TABLE IF NOT EXISTS `user` (
    `id` INT AUTO_INCREMENT PRIMARY KEY COMMENT '用户ID',
    `username` VARCHAR(50) NOT NULL UNIQUE COMMENT '用户名，唯一',
    `password` VARCHAR(255) NOT NULL COMMENT '密码哈希值（bcrypt）',
    `role` VARCHAR(20) DEFAULT 'user' COMMENT '角色：admin/user',
    `avatar` VARCHAR(500) DEFAULT '' COMMENT '头像URL',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    INDEX `idx_username` (`username`),
    INDEX `idx_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';

-- ============================================
-- 2. 系统设置表 (system_settings)
-- 说明: 存储全局系统配置，包括扫描引擎配置、代理设置等
-- ============================================
CREATE TABLE IF NOT EXISTS `system_settings` (
    `id` INT AUTO_INCREMENT PRIMARY KEY COMMENT '设置ID',
    
    -- 扫描引擎配置
    `network_card` VARCHAR(100) DEFAULT '' COMMENT '网卡接口名称',
    `concurrency` INT DEFAULT 10 COMMENT '并发数',
    `timeout` INT DEFAULT 10 COMMENT '超时时间（秒）',
    `retries` INT DEFAULT 2 COMMENT '重试次数',
    
    -- 代理配置
    `proxy_type` VARCHAR(20) DEFAULT '' COMMENT '代理类型: http/socks5',
    `proxy_url` VARCHAR(255) DEFAULT '' COMMENT '代理地址',
    
    -- 反连平台配置
    `reverse_dnslog_domain` VARCHAR(255) DEFAULT '' COMMENT 'DNSLog域名',
    `reverse_dnslog_api` VARCHAR(255) DEFAULT '' COMMENT 'DNSLog API',
    `reverse_rmi_server` VARCHAR(255) DEFAULT '' COMMENT 'RMI服务器',
    `reverse_ldap_server` VARCHAR(255) DEFAULT '' COMMENT 'LDAP服务器',
    `reverse_http_server` VARCHAR(255) DEFAULT '' COMMENT 'HTTP服务器',
    
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统设置表';

-- 插入默认系统设置
INSERT INTO `system_settings` (
    `network_card`, `concurrency`, `timeout`, `retries`,
    `proxy_type`, `proxy_url`,
    `reverse_dnslog_domain`, `reverse_dnslog_api`,
    `reverse_rmi_server`, `reverse_ldap_server`, `reverse_http_server`
) VALUES (
    '', 10, 10, 2,
    '', '',
    '', '',
    '', '', ''
) ON DUPLICATE KEY UPDATE `id`=`id`;

-- ============================================
-- 2.1 Tools config table (tools)
-- Description: API keys for search engines
-- ============================================
CREATE TABLE IF NOT EXISTS `tools` (
    `id` INT AUTO_INCREMENT PRIMARY KEY COMMENT 'ID',
    `name` VARCHAR(50) NOT NULL UNIQUE COMMENT 'Engine name',
    `api_key` VARCHAR(255) DEFAULT '' COMMENT 'API Key',
    `api_email` VARCHAR(255) DEFAULT '' COMMENT 'API Email',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Created at',
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Updated at'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Tools API config';

INSERT INTO `tools` (`name`, `api_key`, `api_email`) VALUES
    ('hunter', '', ''),
    ('fofa', '', ''),
    ('quake', '', '')
ON DUPLICATE KEY UPDATE `name`=`name`;

-- 插入默认管理员用户
-- 用户名: admin
-- 密码: Qaz@123# (已使用 bcrypt 加密)
INSERT IGNORE INTO `user` (
    `username`,
    `password`,
    `role`,
    `avatar`,
    `created_at`
) VALUES (
    'admin',
    '$2a$10$KwjLTl6X0Jnq/q2CyI6d0.9ucFz3BxNxcJI.wC55LS3b5VH13RPp2',
    'admin',
    '/api/uploads/avatars/admin.jpg',
    '2026-01-13 11:35:59'
);
-- ============================================
-- 3. 任务表 (task)
-- 说明: 存储扫描任务信息和执行状态
-- ============================================
CREATE TABLE IF NOT EXISTS `task` (
    `id` INT AUTO_INCREMENT PRIMARY KEY COMMENT '任务ID',
    `name` VARCHAR(100) NOT NULL COMMENT '任务名称',
    `target` VARCHAR(255) NOT NULL COMMENT '扫描目标（IP/域名/URL/CIDR）',
    `type` VARCHAR(20) NOT NULL COMMENT '扫描类型: alive/port/web/vuln',
    `status` VARCHAR(20) DEFAULT 'pending' COMMENT '任务状态: pending/running/completed/failed/stopped',
    `progress` INT DEFAULT 0 COMMENT '进度百分比（0-100）',
    `creator` VARCHAR(50) NOT NULL COMMENT '创建者用户名',
    
    -- 任务配置与结果
    `description` TEXT COMMENT '任务描述',
    `options` TEXT COMMENT '扫描选项（JSON格式）',
    
    -- 时间戳
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    `started_at` TIMESTAMP NULL COMMENT '开始时间',
    `completed_at` TIMESTAMP NULL COMMENT '完成时间',
    
    -- 索引
    INDEX `idx_creator` (`creator`),
    INDEX `idx_status` (`status`),
    INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='扫描任务表';

-- ============================================
-- 4. 漏洞表 (vulnerability)
-- 说明: 存储扫描发现的漏洞详细信息
-- ============================================
CREATE TABLE IF NOT EXISTS `vulnerability` (
    `id` INT AUTO_INCREMENT PRIMARY KEY COMMENT '漏洞ID',
    `task_id` INT NOT NULL COMMENT '关联任务ID',
    
    -- 目标信息
    `target` VARCHAR(500) NOT NULL COMMENT '漏洞目标URL',
    `ip` VARCHAR(45) COMMENT '目标IP地址',
    `port` INT COMMENT '目标端口',
    `service` VARCHAR(50) COMMENT '服务类型',
    
    -- 漏洞基本信息
    `name` VARCHAR(255) NOT NULL COMMENT '漏洞名称',
    `description` TEXT COMMENT '漏洞描述',
    `severity` VARCHAR(20) NOT NULL COMMENT '严重程度: critical/high/medium/low/info',
    `type` VARCHAR(50) COMMENT '漏洞类型',
    
    -- 漏洞标识
    `cve` VARCHAR(255) COMMENT 'CVE编号',
    `cwe` VARCHAR(255) COMMENT 'CWE编号',
    `cvss` DECIMAL(3,1) COMMENT 'CVSS评分',
    
    -- 模板信息
    `template_id` VARCHAR(255) COMMENT '检测模板ID',
    `template_path` VARCHAR(500) COMMENT '模板路径',
    `author` VARCHAR(255) COMMENT '模板作者',
    `tags` TEXT COMMENT '标签（JSON数组）',
    `reference` TEXT COMMENT '参考链接（JSON数组）',
    
    -- 证据信息
    `evidence_request` LONGTEXT COMMENT '请求内容',
    `evidence_response` LONGTEXT COMMENT '响应内容',
    `matched_at` VARCHAR(500) COMMENT '匹配位置',
    `extracted_data` TEXT COMMENT '提取的数据（JSON）',
    `curl_command` TEXT COMMENT 'CURL复现命令',
    
    -- 附加信息
    `metadata` JSON COMMENT '其他元数据',
    `discovered_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '发现时间',
    
    -- 索引
    INDEX `idx_task_id` (`task_id`),
    INDEX `idx_severity` (`severity`),
    INDEX `idx_target` (`target`(255)),
    INDEX `idx_cve` (`cve`),
    FOREIGN KEY (`task_id`) REFERENCES `task`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='漏洞详情表';




-- ============================================
-- 5. 资产表 (asset)
-- 说明: 存储扫描发现资产信息
-- ============================================
CREATE TABLE IF NOT EXISTS asset (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    value VARCHAR(255) NOT NULL COMMENT 'IP 或域名',
    asset_type VARCHAR(20) NOT NULL COMMENT 'ip / domain',
    is_alive BOOLEAN DEFAULT FALSE,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    UNIQUE KEY uk_value (value)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='资产表';

-- ============================================
-- 5. 资产扫描结果表 (asset_scan_result)
-- 说明: 存储扫描资产结果信息
-- ============================================
CREATE TABLE IF NOT EXISTS  asset_scan_result (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    task_id INT NOT NULL,
    asset_id BIGINT NOT NULL,
    scan_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    result JSON,
    scanned_at DATETIME NOT NULL,

    INDEX idx_task (task_id),
    INDEX idx_asset (asset_id),
    INDEX idx_task_asset (task_id, asset_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='资产扫描结果表';

-- ============================================
-- 6. 端口资产表 (asset_port)
-- 说明: 存储端口扫描发现的开放端口及其服务指纹信息
-- ============================================
CREATE TABLE IF NOT EXISTS `asset_port` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '端口资产ID',
    `task_id` INT NOT NULL COMMENT '关联任务ID',
    `asset_id` BIGINT COMMENT '关联资产ID（可为空）',
    
    -- 目标信息
    `ip` VARCHAR(45) NOT NULL COMMENT 'IP地址',
    `port` INT NOT NULL COMMENT '端口号',
    `protocol` VARCHAR(10) DEFAULT 'tcp' COMMENT '协议类型：tcp/udp',
    `state` VARCHAR(20) DEFAULT 'open' COMMENT '端口状态：open/closed/filtered',
    
    -- 服务信息
    `service_name` VARCHAR(100) COMMENT '服务名称',
    `service_product` VARCHAR(255) COMMENT '产品名称',
    `service_version` VARCHAR(100) COMMENT '服务版本',
    `service_extra_info` TEXT COMMENT '额外信息',
    `service_hostname` VARCHAR(255) COMMENT '服务主机名',
    `service_os_type` VARCHAR(100) COMMENT '操作系统类型',
    `service_device_type` VARCHAR(100) COMMENT '设备类型',
    `service_confidence` INT DEFAULT 0 COMMENT '服务识别置信度（0-100）',
    
    -- 指纹信息
    `banner` TEXT COMMENT 'Banner信息',
    `fingerprint_method` VARCHAR(50) COMMENT '识别方法：nmap-probes/banner/port-guess',
    `raw_response` LONGTEXT COMMENT '原始响应数据',
    
    -- CPE信息
    `cpes` JSON COMMENT 'CPE列表（JSON数组）',
    
    -- 脚本扫描结果
    `scripts` JSON COMMENT 'NSE脚本输出（JSON对象）',
    
    -- 时间戳
    `discovered_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '发现时间',
    `last_seen` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后发现时间',
    
    -- 索引
    INDEX `idx_task_id` (`task_id`),
    INDEX `idx_asset_id` (`asset_id`),
    INDEX `idx_ip` (`ip`),
    INDEX `idx_port` (`port`),
    INDEX `idx_ip_port` (`ip`, `port`),
    INDEX `idx_service` (`service_name`),
    INDEX `idx_discovered_at` (`discovered_at`),
    UNIQUE KEY `uk_ip_port_task` (`ip`, `port`, `task_id`),
    FOREIGN KEY (`task_id`) REFERENCES `task`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`asset_id`) REFERENCES `asset`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='端口资产表';

-- ============================================
-- 7. 仪表盘统计数据表 (dashboard)
-- 说明: 存储仪表盘各项统计数据，用于提升仪表盘加载性能
-- 注意: 此表设计为单行表，始终只保留一条记录
-- ============================================
CREATE TABLE IF NOT EXISTS `dashboard` (
    `id` INT AUTO_INCREMENT PRIMARY KEY COMMENT '统计ID（始终为1）',
    
    -- 核心统计数据
    `total_assets` INT DEFAULT 0 COMMENT '资产总数',
    `total_vulnerabilities` INT DEFAULT 0 COMMENT '漏洞总数',
    `total_tasks` INT DEFAULT 0 COMMENT '任务总数',
    `total_fingerprints` INT DEFAULT 0 COMMENT '指纹总数（已识别的服务）',
    
    -- 漏洞严重程度统计
    `critical_vulns` INT DEFAULT 0 COMMENT '严重漏洞数',
    `high_vulns` INT DEFAULT 0 COMMENT '高危漏洞数',
    `medium_vulns` INT DEFAULT 0 COMMENT '中危漏洞数',
    `low_vulns` INT DEFAULT 0 COMMENT '低危漏洞数',
    `info_vulns` INT DEFAULT 0 COMMENT '信息级漏洞数',
    
    -- 时间戳
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='仪表盘统计数据表';

-- 插入默认统计记录（初始值全为0）
INSERT INTO `dashboard` (
    `id`,
    `total_assets`, `total_vulnerabilities`, `total_tasks`, `total_fingerprints`,
    `critical_vulns`, `high_vulns`, `medium_vulns`, `low_vulns`, `info_vulns`
) VALUES (
    1,
    0, 0, 0, 0,
    0, 0, 0, 0, 0
) ON DUPLICATE KEY UPDATE `id`=`id`;

-- ============================================
-- 8. Web指纹资产表 (asset_web_fingerprints)
-- 说明: 存储Web指纹识别结果，使用wappalyzergo识别的技术栈信息
-- 注意: 此表可以从端口扫描结果自动触发，当发现HTTP/HTTPS服务时进行识别
-- ============================================
CREATE TABLE IF NOT EXISTS `asset_web_fingerprints` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Web指纹ID',
    `task_id` INT NOT NULL COMMENT '关联任务ID',
    `asset_id` BIGINT COMMENT '关联资产ID',
    `port_id` BIGINT COMMENT '关联端口ID（来自asset_port表）',
    
    -- 目标信息
    `url` VARCHAR(500) NOT NULL COMMENT '完整URL',
    `ip` VARCHAR(45) NOT NULL COMMENT 'IP地址',
    `port` INT NOT NULL COMMENT '端口号',
    `protocol` VARCHAR(10) DEFAULT 'http' COMMENT '协议类型：http/https',
    
    -- 响应信息
    `title` VARCHAR(500) COMMENT '网页标题',
    `status_code` INT COMMENT 'HTTP状态码',
    `server` VARCHAR(255) COMMENT 'Server响应头',
    `content_type` VARCHAR(255) COMMENT 'Content-Type',
    `content_length` BIGINT COMMENT '响应体大小（字节）',
    `response_time` INT COMMENT '响应时间（毫秒）',
    
    -- 指纹信息
    `technologies` JSON COMMENT '识别到的技术栈列表 (Wappalyzer)，格式：["Nginx","PHP","WordPress"]',
    `frameworks` JSON COMMENT '识别到的应用框架列表 (GoAttack)，格式：["DVWA","RuoYi"]',
    `matched_rules` JSON COMMENT '匹配到的具体指纹规则信息',
    `favicon_hash` VARCHAR(100) COMMENT 'Favicon哈希值',
    
    -- 详细信息
    `headers` JSON COMMENT 'HTTP响应头（JSON对象）',
    `meta_tags` JSON COMMENT 'Meta标签信息',
    `cookies` JSON COMMENT 'Set-Cookie信息',
    
    -- 附加信息
    `screenshot_path` VARCHAR(500) COMMENT '截图路径（可选）',
    `raw_html_hash` VARCHAR(64) COMMENT 'HTML内容哈希（用于去重）',
    
    -- 时间戳
    `discovered_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '发现时间',
    `last_checked` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后检查时间',
    
    -- 索引
    INDEX `idx_task_id` (`task_id`),
    INDEX `idx_asset_id` (`asset_id`),
    INDEX `idx_port_id` (`port_id`),
    INDEX `idx_url` (`url`(255)),
    INDEX `idx_ip_port` (`ip`, `port`),
    INDEX `idx_status_code` (`status_code`),
    INDEX `idx_discovered_at` (`discovered_at`),
    UNIQUE KEY `uk_task_url` (`task_id`, `url`(255)),
    
    -- 外键约束
    FOREIGN KEY (`task_id`) REFERENCES `task`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`asset_id`) REFERENCES `asset`(`id`) ON DELETE SET NULL,
    FOREIGN KEY (`port_id`) REFERENCES `asset_port`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Web指纹资产表';

-- ============================================
-- 9. POC模板表 (poc_template)
-- 说明: 存储从nuclei-templates扫描出来的POC模板信息
-- 注意: 此表用于POC管理功能，与漏洞扫描功能关联
-- ============================================
CREATE TABLE IF NOT EXISTS `poc_template` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'POC模板ID',
    
    -- 模板基本信息
    `template_id` VARCHAR(255) NOT NULL COMMENT '模板唯一标识（nuclei模板ID）',
    `name` VARCHAR(500) NOT NULL COMMENT 'POC名称',
    `description` TEXT COMMENT 'POC描述',
    `author` VARCHAR(255) COMMENT '作者',
    
    -- 分类信息
    `category` VARCHAR(100) COMMENT '分类：cves/vulnerabilities/exposures/misconfiguration等',
    `severity` VARCHAR(20) NOT NULL COMMENT '严重程度：critical/high/medium/low/info',
    `tags` JSON COMMENT '标签列表（JSON数组）',
    
    -- CVE/CWE/CNVD信息
    `cve_id` VARCHAR(50) COMMENT 'CVE编号（如有）',
    `cnvd_id` VARCHAR(50) COMMENT 'CNVD编号（如有）',
    `cwe_id` VARCHAR(50) COMMENT 'CWE编号（如有）',
    `cvss_score` DECIMAL(3,1) COMMENT 'CVSS评分',
    `cvss_metrics` VARCHAR(200) COMMENT 'CVSS向量',
    
    -- 模板元数据
    `protocol` VARCHAR(50) DEFAULT 'http' COMMENT '协议类型：http/network/dns/ssl等',
    `max_request` INT DEFAULT 1 COMMENT '最大请求数',
    `reference` JSON COMMENT '参考链接（JSON数组）',
    `classification` JSON COMMENT '分类信息（JSON对象）',
    `metadata` JSON COMMENT '其他元数据（JSON对象）',
    
    -- 文件信息
    `file_path` VARCHAR(500) NOT NULL COMMENT '模板文件相对路径',
    `file_hash` VARCHAR(64) COMMENT '文件SHA256哈希值（用于检测变更）',
    `template_content` LONGTEXT COMMENT '模板YAML原始内容',
    
    -- 状态信息
    `is_active` BOOLEAN DEFAULT TRUE COMMENT '是否启用该POC',
    `verified` BOOLEAN DEFAULT FALSE COMMENT '是否已验证',
    
    -- 时间戳
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    `last_scanned_at` TIMESTAMP NULL COMMENT '最后扫描时间',
    
    -- 索引
    INDEX `idx_template_id` (`template_id`),
    INDEX `idx_category` (`category`),
    INDEX `idx_severity` (`severity`),
    INDEX `idx_cve_id` (`cve_id`),
    INDEX `idx_protocol` (`protocol`),
    INDEX `idx_is_active` (`is_active`),
    INDEX `idx_created_at` (`created_at`),
    UNIQUE KEY `uk_template_id` (`template_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='POC模板表';

-- ============================================
-- 10. POC验证结果表 (poc_verify_result)
-- 说明: 存储POC验证的历史记录和详细结果
-- ============================================
CREATE TABLE IF NOT EXISTS `poc_verify_result` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '验证结果ID',
    
    -- 验证基本信息
    `target` VARCHAR(500) NOT NULL COMMENT '验证目标（IP/域名/URL）',
    `poc_id` BIGINT NOT NULL COMMENT '关联的POC模板ID',
    `template_id` VARCHAR(255) NOT NULL COMMENT '模板唯一标识（nuclei模板ID）',
    `template_name` VARCHAR(500) NOT NULL COMMENT 'POC名称',
    
    -- 验证结果
    `matched` BOOLEAN DEFAULT FALSE COMMENT '是否匹配成功',
    `severity` VARCHAR(20) COMMENT '严重程度：critical/high/medium/low/info',
    `description` TEXT COMMENT 'POC描述',
    
    -- 请求和响应详情
    `request` LONGTEXT COMMENT '发送的请求包',
    `response` LONGTEXT COMMENT '返回的响应包',
    `matched_at` VARCHAR(500) COMMENT '匹配位置或URL',
    
    -- 提取的数据
    `extracted_data` JSON COMMENT '提取的数据（JSON）',
    
    -- 错误信息
    `error` TEXT COMMENT '错误信息（如果验证失败）',
    
    -- 执行信息
    `verified_by` VARCHAR(50) COMMENT '验证执行者用户名',
    `verified_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '验证时间',
    
    -- 索引
    INDEX `idx_target` (`target`(255)),
    INDEX `idx_poc_id` (`poc_id`),
    INDEX `idx_template_id` (`template_id`),
    INDEX `idx_matched` (`matched`),
    INDEX `idx_severity` (`severity`),
    INDEX `idx_verified_at` (`verified_at`),
    
    -- 外键约束
    FOREIGN KEY (`poc_id`) REFERENCES `poc_template`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='POC验证结果表';

-- ============================================
-- 11. 字典表 (dict)
-- 说明: 存储字典信息，支持默认字典与导入字典
-- ============================================
CREATE TABLE IF NOT EXISTS `dict` (
    `id` INT AUTO_INCREMENT PRIMARY KEY COMMENT '字典ID',
    `name` VARCHAR(255) NOT NULL UNIQUE COMMENT '字典名称',
    `type` VARCHAR(20) DEFAULT 'preset' COMMENT '类型：preset/custom',
    `category` VARCHAR(50) DEFAULT 'other' COMMENT '分类：password, directory, domain, fuzz等',
    `size` BIGINT DEFAULT 0 COMMENT '文件大小(字节)',
    `lines_cnt` BIGINT DEFAULT 0 COMMENT '文件行数',
    `path` VARCHAR(500) NOT NULL COMMENT '字典保存路径',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='字典表';

-- ============================================
-- 12. 通知已读时间表 (notification_read_time)
-- 说明: 记录每个用户的漏洞通知已读时间戳
--       任何在该时间戳之后发现的漏洞视为"未读"
-- ============================================
CREATE TABLE IF NOT EXISTS `notification_read_time` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE COMMENT '用户名',
    `last_read_at` TIMESTAMP DEFAULT '2000-01-01 00:00:00' COMMENT '上次已读时间',
    `last_cleared_at` TIMESTAMP DEFAULT '2000-01-01 00:00:00' COMMENT '上次清空时间',
    INDEX `idx_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='通知已读时间追踪表';

-- ============================================
-- 13. 插件表 (plugins)
-- 说明: 存储可执行工具插件的配置信息
-- ============================================
CREATE TABLE IF NOT EXISTS `plugins` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(255) UNIQUE COMMENT '插件名称',
  `version` VARCHAR(50) COMMENT '版本号',
  `type` VARCHAR(50) COMMENT '类型',
  `enabled` TINYINT(1) DEFAULT 1 COMMENT '是否启用',
  `description` TEXT COMMENT '描述',
  `path` VARCHAR(255) COMMENT '可执行文件路径',
  `config` TEXT COMMENT '配置信息',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='插件表';

