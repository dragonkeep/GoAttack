package service

import (
	"GoAttack/common/log"
	"GoAttack/common/mysql"
	redisdb "GoAttack/common/redis"
	"GoAttack/model"
	servicecommon "GoAttack/service/common"
	scanhost "GoAttack/service/scan_host"
	scanport "GoAttack/service/scan_port"
	scanweb "GoAttack/service/scan_web"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	// 任务管理器，用于存储正在运行任务的取消函数
	runningTasks = make(map[int]context.CancelFunc)
	tasksMu      sync.RWMutex
)

// RegisterTask 注册任务取消函数
func RegisterTask(id int, cancel context.CancelFunc) {
	tasksMu.Lock()
	defer tasksMu.Unlock()
	runningTasks[id] = cancel
}

// UnregisterTask 注销任务
func UnregisterTask(id int) {
	tasksMu.Lock()
	defer tasksMu.Unlock()
	delete(runningTasks, id)
}

// CancelTask 取消任务执行
func CancelTask(id int) bool {
	tasksMu.Lock()
	defer tasksMu.Unlock()
	if cancel, ok := runningTasks[id]; ok {
		cancel()
		delete(runningTasks, id)
		return true
	}
	return false
}

// sanitizeBanner 清理Banner中的二进制数据，只保留可打印字符
func sanitizeBanner(banner string) string {
	if banner == "" {
		return ""
	}

	// 限制Banner长度
	maxLen := 1000
	if len(banner) > maxLen {
		banner = banner[:maxLen]
	}

	// 清理非打印字符，只保留可打印字符和常见空白字符
	result := make([]rune, 0, len(banner))
	for _, r := range banner {
		// 保留ASCII可打印字符 (32-126) 和常见空白字符 (\t\n\r)
		if (r >= 32 && r <= 126) || r == '\t' || r == '\n' || r == '\r' {
			result = append(result, r)
		} else if r > 126 && r < 0xFFFD {
			// 保留有效的Unicode字符，但跳过替换字符
			result = append(result, r)
		} else {
			// 将不可打印字符替换为点号
			result = append(result, '.')
		}
	}

	return string(result)
}

// ExecuteTask 执行扫描任务
func ExecuteTask(taskID int, target string, taskType string, options string) error {
	log.Info("[服务] 开始执行任务 #%d: %s (类型: %s)", taskID, target, taskType)

	// 创建可取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 注册任务
	RegisterTask(taskID, cancel)
	defer UnregisterTask(taskID)

	// ✅ 重新扫描前清除旧结果
	mysql.ClearTaskResults(taskID)

	// 更新任务状态为running
	_ = mysql.UpdateTaskProgress(taskID, "running", 0)

	if taskType == "full" {
		return ExecuteFullScan(ctx, taskID, target, options)
	}

	// 快速扫描：主机探测 + TCP TOP1000端口 + Web指纹识别 + POC验证
	if taskType == "quick" {
		return ExecuteQuickScan(ctx, taskID, target, options)
	}

	// 自定义扫描：根据选项动态执行各阶段
	if taskType == "custom" {
		return ExecuteCustomScan(ctx, taskID, target, options)
	}

	// 其他扫描类型暂不支持
	errMsg := fmt.Sprintf("不支持的扫描类型: %s", taskType)
	log.Info("[服务] 任务 #%d 失败: %s", taskID, errMsg)
	mysql.UpdateTaskResult(taskID, "failed", 0, fmt.Sprintf(`{"error": "%s"}`, errMsg))
	return fmt.Errorf(errMsg)
}

// ExecuteAliveScan 执行存活扫描任务
func ExecuteAliveScan(ctx context.Context, taskID int, target string, options string) error {
	startTime := time.Now()
	log.Info("[存活扫描] 开始执行任务 #%d: %s", taskID, target)

	// ✨ 清除该任务的旧扫描结果（重新扫描时避免结果累积）
	if err := mysql.ClearTaskResults(taskID); err != nil {
		log.Info("[警告] 清除任务 #%d 旧结果失败: %v", taskID, err)
		// 不阻止扫描继续进行
	} else {
		log.Info("[存活扫描] 已清除任务 #%d 的旧扫描结果", taskID)
	}

	// 解析扫描选项
	timeout := 3 * time.Second
	concurrency := 50

	if options != "" {
		var opts map[string]interface{}
		if err := json.Unmarshal([]byte(options), &opts); err == nil {
			if t, ok := opts["timeout"].(float64); ok {
				timeout = time.Duration(t) * time.Second
			}
			if c, ok := opts["threads"].(float64); ok {
				concurrency = int(c)
			}
		}
	}

	log.Info("[存活扫描] 任务 #%d 配置 - 超时: %v, 并发: %d", taskID, timeout, concurrency)

	// ✅ 重新扫描前清除旧结果
	mysql.ClearTaskResults(taskID)

	// 初始化Redis进度数据
	redisProgress := redisdb.TaskProgress{
		TaskID:         taskID,
		Status:         "running",
		Progress:       0,
		TotalTargets:   0,
		ScannedTargets: 0,
		FoundAssets:    0,
		CurrentTarget:  "",
		StartTime:      startTime,
		Message:        "正在解析目标...",
	}
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// ✨ 创建进度跟踪器，绑定 Redis 更新回调
	progressCallback := func(current, total, found int, currentTarget, message string) {
		redisProgress.ScannedTargets = current
		redisProgress.TotalTargets = total
		redisProgress.FoundAssets = found
		redisProgress.CurrentTarget = currentTarget

		// 计算进度百分比
		if total > 0 {
			redisProgress.Progress = (current * 100) / total
			if redisProgress.Progress > 100 {
				redisProgress.Progress = 100
			}
		}

		// 更新消息
		if message != "" {
			redisProgress.Message = fmt.Sprintf("%s (%d/%d)", message, current, total)
		} else {
			redisProgress.Message = fmt.Sprintf("正在扫描 %d/%d: %s", current, total, currentTarget)
		}

		// 实时更新 Redis
		redisdb.UpdateTaskProgress(taskID, redisProgress)
	}

	tracker := servicecommon.NewProgressTracker(0, progressCallback)

	// 设置更新阈值（每5个目标更新一次，或发现存活主机时立即更新）
	tracker.SetUpdateThreshold(5)

	// 创建扫描服务并注入 Tracker
	service := scanhost.NewScanService(true, timeout, concurrency)
	service.Scanner.Tracker = tracker // ✨ 注入进度跟踪器

	// 执行扫描
	results, err := service.ScanTargets(ctx, target)
	if err != nil {
		// 检查是否是被主动取消的
		status := "failed"
		if err == context.Canceled {
			status = "stopped"
			log.Info("[服务] 存活扫描任务 #%d 已被主动停止", taskID)
		}

		// 更新MySQL和Redis状态
		mysql.UpdateTaskProgress(taskID, status, 0)
		redisProgress.Status = status
		redisProgress.Message = fmt.Sprintf("扫描失败: %v", err)
		redisdb.UpdateTaskProgress(taskID, redisProgress)

		// 延迟清理Redis数据（给前端时间读取最终状态）
		go func() {
			time.Sleep(10 * time.Second)
			redisdb.DeleteTaskProgress(taskID)
		}()

		return fmt.Errorf("存活扫描失败: %v", err)
	}

	// 更新总目标数
	totalHosts := len(results)
	redisProgress.TotalTargets = totalHosts
	redisProgress.Message = fmt.Sprintf("开始扫描 %d 个目标", totalHosts)
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// 统计并保存结果到资产表
	aliveHosts := 0

	for i, result := range results {
		// 更新Redis进度：当前扫描目标和进度
		redisProgress.ScannedTargets = i + 1
		redisProgress.Progress = (redisProgress.ScannedTargets * 100) / redisProgress.TotalTargets
		redisProgress.CurrentTarget = fmt.Sprintf("%v", result.Target.Original)
		redisProgress.Message = fmt.Sprintf("正在扫描 %d/%d: %s", i+1, totalHosts, result.Target.Original)

		// 每10个目标或最后一个目标更新一次Redis（避免过于频繁）
		if (i+1)%10 == 0 || i == totalHosts-1 {
			redisdb.UpdateTaskProgress(taskID, redisProgress)
		}

		// 1. 创建或更新资产
		// 优先使用 IP，如果没有则使用 Host，最后是 Original
		assetValue := result.Target.IP
		if assetValue == "" {
			assetValue = result.Target.Host
			if assetValue == "" {
				assetValue = result.Target.Original
			}
		}

		assetType := "ip"
		if result.Target.Host != "" && result.Target.IP == "" {
			assetType = "domain"
		}

		assetID, err := mysql.CreateOrUpdateAsset(assetValue, assetType, result.HostAlive)
		if err != nil {
			log.Info("[警告] 保存资产 #%s 失败: %v", assetValue, err)
			continue
		}

		// 2. 保存扫描结果
		detail := map[string]interface{}{
			"original": result.Target.Original,
			"host":     result.Target.Host,
			"ip":       result.Target.IP,
			"alive":    result.HostAlive,
			"latency":  result.Latency.String(),
		}
		if result.Error != nil {
			detail["error"] = result.Error.Error()
		}

		resultJSON, _ := json.Marshal(detail)
		status := "failed"
		if result.HostAlive {
			status = "success"
			aliveHosts++
			redisProgress.FoundAssets = aliveHosts // 更新发现的存活主机数
		}

		err = mysql.SaveAssetScanResult(taskID, assetID, "alive", status, string(resultJSON))
		if err != nil {
			log.Info("[警告] 保存资产扫描结果失败: %v", err)
		}
	}

	duration := time.Since(startTime)

	// ✅ 先更新 Redis 最终状态（避免与 MySQL 不一致）
	redisProgress.Status = "completed"
	redisProgress.Progress = 100
	redisProgress.ScannedTargets = totalHosts
	redisProgress.TotalTargets = totalHosts
	redisProgress.FoundAssets = aliveHosts
	redisProgress.Message = fmt.Sprintf("扫描完成: 发现 %d/%d 存活主机", aliveHosts, totalHosts)
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// ✅ 再更新 MySQL 状态为 completed
	err = mysql.UpdateTaskProgress(taskID, "completed", 100)
	if err != nil {
		return fmt.Errorf("更新任务完成状态失败: %v", err)
	}

	// ✅ 延迟清理Redis数据（缩短到10秒，避免长时间数据不一致）
	go func() {
		time.Sleep(10 * time.Second)
		redisdb.DeleteTaskProgress(taskID)
		log.Info("[Redis] 存活扫描任务 #%d 进度数据已清理", taskID)
	}()

	log.Info("[存活扫描] 任务 #%d 完成: %d/%d 主机存活 (耗时: %v)", taskID, aliveHosts, totalHosts, duration)

	return nil
}

// ExecutePortScan 执行端口扫描任务
func ExecutePortScan(ctx context.Context, taskID int, target string, options string) error {
	startTime := time.Now()
	log.Info("[端口扫描] 开始执行任务 #%d: %s", taskID, target)

	// ✨ 清除该任务的旧扫描结果（重新扫描时避免结果累积）
	if err := mysql.ClearTaskResults(taskID); err != nil {
		log.Info("[警告] 清除任务 #%d 旧结果失败: %v", taskID, err)
		// 不阻止扫描继续进行
	} else {
		log.Info("[端口扫描] 已清除任务 #%d 的旧扫描结果", taskID)
	}

	// 解析扫描选项
	timeout := 5 * time.Minute
	concurrency := 50
	portRange := "common"
	enableFingerprint := true

	if options != "" {
		var opts map[string]interface{}
		if err := json.Unmarshal([]byte(options), &opts); err == nil {
			if t, ok := opts["timeout"].(float64); ok {
				timeout = time.Duration(t) * time.Second
			}
			if c, ok := opts["threads"].(float64); ok {
				concurrency = int(c)
			}
			if pr, ok := opts["port_range"].(string); ok && pr != "" {
				portRange = pr
			}
			if ports, ok := opts["ports"].(string); ok && ports != "" {
				portRange = ports
			}
			if ef, ok := opts["enable_fingerprint"].(bool); ok {
				enableFingerprint = ef
			}
		}
	}

	log.Info("[端口扫描] 任务 #%d 配置 - 端口范围: %s, 超时: %v, 并发: %d, 指纹识别: %v",
		taskID, portRange, timeout, concurrency, enableFingerprint)

	// ✅ 重新扫描前清除旧结果
	mysql.ClearTaskResults(taskID)

	// 初始化Redis进度数据
	redisProgress := redisdb.TaskProgress{
		TaskID:         taskID,
		Status:         "running",
		Progress:       0,
		TotalTargets:   0,
		ScannedTargets: 0,
		FoundAssets:    0,
		CurrentTarget:  "",
		StartTime:      startTime,
		Message:        "正在进行端口扫描及指纹识别...",
	}
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// ✨ 创建进度跟踪器，绑定 Redis 更新回调
	portProgressCallback := func(current, total, found int, currentTarget, message string) {
		redisProgress.ScannedTargets = current
		redisProgress.TotalTargets = total
		redisProgress.FoundAssets = found
		redisProgress.CurrentTarget = currentTarget

		// 计算进度百分比
		if total > 0 {
			redisProgress.Progress = (current * 100) / total
			if redisProgress.Progress > 100 {
				redisProgress.Progress = 100
			}
		}

		// 更新消息
		if message != "" {
			redisProgress.Message = fmt.Sprintf("%s (%d/%d)", message, current, total)
		} else {
			redisProgress.Message = fmt.Sprintf("正在扫描 %d/%d: %s", current, total, currentTarget)
		}

		// 实时更新 Redis
		redisdb.UpdateTaskProgress(taskID, redisProgress)
	}

	portTracker := servicecommon.NewProgressTracker(0, portProgressCallback)
	// 端口扫描更新频率可以稍低一些（每3个主机更新一次）
	portTracker.SetUpdateThreshold(3)

	// 创建端口扫描服务并注入 Tracker
	service := scanport.NewPortScanService(timeout, concurrency, enableFingerprint)
	service.ComprehensiveScanner.Tracker = portTracker // ✨ 注入进度跟踪器

	// 执行扫描
	results, err := service.ScanTargets(ctx, target, portRange)
	if err != nil {
		// 检查是否是被主动取消的
		status := "failed"
		if err == context.Canceled {
			status = "stopped"
			log.Info("[服务] 端口扫描任务 #%d 已被主动停止", taskID)
		}

		// 更新MySQL和Redis状态
		mysql.UpdateTaskProgress(taskID, status, 0)
		redisProgress.Status = status
		redisProgress.Message = fmt.Sprintf("端口扫描失败: %v", err)
		redisdb.UpdateTaskProgress(taskID, redisProgress)

		// 延迟清理Redis数据
		go func() {
			time.Sleep(10 * time.Second)
			redisdb.DeleteTaskProgress(taskID)
		}()

		return fmt.Errorf("端口扫描失败: %v", err)
	}

	// 更新总目标数
	totalHosts := len(results)
	redisProgress.TotalTargets = totalHosts
	redisProgress.Message = fmt.Sprintf("扫描完成，正在处理 %d 个主机的结果...", totalHosts)
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// 统计并保存结果到资产表
	hostsWithPorts := 0
	totalOpenPorts := 0

	for i, result := range results {
		// 更新Redis进度：当前处理资产
		redisProgress.ScannedTargets = i + 1
		redisProgress.Progress = (redisProgress.ScannedTargets * 100) / redisProgress.TotalTargets
		if result.Target != nil {
			redisProgress.CurrentTarget = result.Target.Original
		}
		redisProgress.Message = fmt.Sprintf("正在处理结果 %d/%d...", i+1, totalHosts)

		// 每5个记录更新一次Redis
		if (i+1)%5 == 0 || i == totalHosts-1 {
			redisdb.UpdateTaskProgress(taskID, redisProgress)
		}

		if result.ScanResult == nil {
			continue
		}

		// 1. 创建或更新资产
		assetValue := result.ScanResult.IP
		if assetValue == "" && result.Target != nil {
			assetValue = result.Target.IP
			if assetValue == "" {
				assetValue = result.Target.Host
				if assetValue == "" {
					assetValue = result.Target.Original
				}
			}
		}

		if assetValue == "" {
			continue
		}

		assetType := "ip"
		if result.Target != nil && result.Target.Host != "" && result.Target.IP == "" {
			assetType = "domain"
		}

		// 主机有开放端口则认为存活
		isAlive := result.ScanResult.OpenPorts > 0
		if isAlive {
			hostsWithPorts++
			totalOpenPorts += result.ScanResult.OpenPorts
		}

		assetID, err := mysql.CreateOrUpdateAsset(assetValue, assetType, isAlive)
		if err != nil {
			log.Info("[警告] 保存资产 #%s 失败: %v", assetValue, err)
			continue
		}

		// 2. 保存端口扫描结果
		detail := map[string]interface{}{
			"ip":             result.ScanResult.IP,
			"hostname":       result.ScanResult.Hostname,
			"open_ports":     result.ScanResult.OpenPorts,
			"closed_ports":   result.ScanResult.ClosedPorts,
			"filtered_ports": result.ScanResult.FilteredPorts,
			"total_ports":    result.ScanResult.TotalPorts,
			"scan_duration":  result.ScanResult.ScanDuration.String(),
			"ports":          []map[string]interface{}{},
		}

		// 添加操作系统信息
		if result.ScanResult.OS.Name != "" {
			detail["os"] = map[string]interface{}{
				"name":      result.ScanResult.OS.Name,
				"accuracy":  result.ScanResult.OS.Accuracy,
				"os_family": result.ScanResult.OS.OSFamily,
				"vendor":    result.ScanResult.OS.Vendor,
			}
		}

		// 添加端口详细信息
		ports := detail["ports"].([]map[string]interface{})
		for _, port := range result.ScanResult.Ports {
			portInfo := map[string]interface{}{
				"port":     port.Port,
				"protocol": port.Protocol,
				"state":    port.State,
				"service": map[string]interface{}{
					"name":        port.Service.Name,
					"product":     port.Service.Product,
					"version":     port.Service.Version,
					"extra_info":  port.Service.ExtraInfo,
					"os_type":     port.Service.OSType,
					"hostname":    port.Service.Hostname,
					"device_type": port.Service.DeviceType,
					"confidence":  port.Service.Confidence,
					"cpes":        port.Service.CPEs,
				},
			}

			// 添加脚本输出（包括banner）
			if len(port.Service.Scripts) > 0 {
				portInfo["scripts"] = port.Service.Scripts
			}

			ports = append(ports, portInfo)
		}
		detail["ports"] = ports

		// 添加指纹信息
		if len(result.Fingerprints) > 0 {
			fingerprints := []map[string]interface{}{}
			for _, fp := range result.Fingerprints {
				if fp == nil {
					continue
				}
				fingerprintInfo := map[string]interface{}{
					"port":       fp.Port,
					"protocol":   fp.Protocol,
					"service":    fp.Service,
					"product":    fp.Product,
					"version":    fp.Version,
					"banner":     fp.Banner,
					"confidence": fp.Confidence,
					"method":     fp.Method,
				}
				fingerprints = append(fingerprints, fingerprintInfo)
			}
			detail["fingerprints"] = fingerprints
		}

		resultJSON, _ := json.Marshal(detail)
		status := "success"
		if result.Error != nil {
			status = "failed"
			detail["error"] = result.Error.Error()
		}

		err = mysql.SaveAssetScanResult(taskID, assetID, "port", status, string(resultJSON))
		if err != nil {
			log.Info("[警告] 保存端口扫描结果失败: %v", err)
		}

		// 3. 保存每个端口的详细信息到 asset_port 表
		for _, port := range result.ScanResult.Ports {
			assetPort := &model.AssetPort{
				TaskID:   taskID,
				AssetID:  &assetID,
				IP:       result.ScanResult.IP,
				Port:     int(port.Port),
				Protocol: port.Protocol,
				State:    port.State,

				// 服务信息
				ServiceName:       port.Service.Name,
				ServiceProduct:    port.Service.Product,
				ServiceVersion:    port.Service.Version,
				ServiceExtraInfo:  port.Service.ExtraInfo,
				ServiceHostname:   port.Service.Hostname,
				ServiceOSType:     port.Service.OSType,
				ServiceDeviceType: port.Service.DeviceType,
				ServiceConfidence: port.Service.Confidence,

				// CPE信息
				CPEs: port.Service.CPEs,

				// 脚本输出
				Scripts: port.Service.Scripts,
			}

			// 从Scripts中提取Banner和识别方法
			if banner, ok := port.Service.Scripts["banner"]; ok {
				assetPort.Banner = sanitizeBanner(banner)
			}
			if method, ok := port.Service.Scripts["detection_method"]; ok {
				assetPort.FingerprintMethod = method
			}

			// 如果有对应的指纹信息，添加更多细节
			for _, fp := range result.Fingerprints {
				if fp != nil && fp.Port == port.Port {
					if assetPort.Banner == "" {
						assetPort.Banner = sanitizeBanner(fp.Banner)
					}
					if assetPort.FingerprintMethod == "" {
						assetPort.FingerprintMethod = fp.Method
					}
					assetPort.RawResponse = sanitizeBanner(fp.RawResponse)
					break
				}
			}

			// 保存端口信息
			err = mysql.SaveAssetPort(assetPort)
			if err != nil {
				log.Info("[警告] 保存端口 %s:%d 到asset_port表失败: %v", result.ScanResult.IP, port.Port, err)
			}
		}
	}

	duration := time.Since(startTime)

	// ✅ 先更新 Redis 最终状态（避免与 MySQL 不一致）
	redisProgress.Status = "completed"
	redisProgress.Progress = 100
	redisProgress.ScannedTargets = totalHosts
	redisProgress.TotalTargets = totalHosts
	redisProgress.FoundAssets = hostsWithPorts
	redisProgress.Message = fmt.Sprintf("端口扫描完成: 在 %d 个主机上发现 %d 个开放端口", hostsWithPorts, totalOpenPorts)
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// ✅ 再更新 MySQL 状态为 completed
	err = mysql.UpdateTaskProgress(taskID, "completed", 100)
	if err != nil {
		return fmt.Errorf("更新任务完成状态失败: %v", err)
	}

	// ✅ 延迟清理Redis数据（缩短到10秒）
	go func() {
		time.Sleep(10 * time.Second)
		redisdb.DeleteTaskProgress(taskID)
		log.Info("[Redis] 端口扫描任务 #%d 进度数据已清理", taskID)
	}()

	log.Info("[端口扫描] 任务 #%d 完成: %d/%d 主机有开放端口，共发现 %d 个开放端口 (耗时: %v)",
		taskID, hostsWithPorts, totalHosts, totalOpenPorts, duration)

	return nil
}

// ExecuteWebScan 执行 Web 指纹扫描任务
func ExecuteWebScan(ctx context.Context, taskID int, target string, options string) error {
	startTime := time.Now()
	log.Info("[Web扫描] 开始执行任务 #%d: %s", taskID, target)

	// 1. 初始化进度
	_ = mysql.UpdateTaskProgress(taskID, "running", 0)
	redisProgress := redisdb.TaskProgress{
		TaskID:        taskID,
		Status:        "running",
		Progress:      0,
		CurrentTarget: "",
		StartTime:     startTime,
		Message:       "正在初始化 Web 扫描...",
	}
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// 2. 先进行端口扫描 (识别 Web 常用端口)
	redisProgress.Message = "正在探测 Web 开放端口..."
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// 解析扫描选项
	timeout := 10 * time.Second
	concurrency := 25
	portRange := "80,443,8080,8443,8000,8888,3000,5000,9000" // 常用 Web 端口

	if options != "" {
		var opts map[string]interface{}
		if err := json.Unmarshal([]byte(options), &opts); err == nil {
			if t, ok := opts["timeout"].(float64); ok && t > 0 {
				timeout = time.Duration(t) * time.Second
			}
			if c, ok := opts["threads"].(float64); ok && c > 0 {
				concurrency = int(c)
			}
		}
	}

	// 执行快速端口扫描
	portService := scanport.NewPortScanService(timeout, concurrency, true)
	results, err := portService.ScanTargets(ctx, target, portRange)
	if err != nil {
		if err == context.Canceled {
			_ = mysql.UpdateTaskProgress(taskID, "stopped", 0)
			return err
		}
		errMsg := fmt.Sprintf("端口探测失败: %v", err)
		mysql.UpdateTaskResult(taskID, "failed", 0, fmt.Sprintf(`{"error": "%s"}`, errMsg))
		return err
	}

	// 3. 保存端口结果并统计存活情况
	totalHosts := len(results)
	log.Info("[Web扫描] 端口探测完成，共处理 %d 个扫描目标", totalHosts)
	hostsWithWeb := 0
	for _, result := range results {
		if result.ScanResult == nil {
			continue
		}

		assetValue := result.ScanResult.IP
		if assetValue == "" && result.Target != nil {
			assetValue = result.Target.IP
		}
		if assetValue == "" {
			continue
		}

		isAlive := result.ScanResult.OpenPorts > 0
		assetID, _ := mysql.CreateOrUpdateAsset(assetValue, "ip", isAlive)

		if isAlive {
			hostsWithWeb++
			// 保存端口详细信息到 asset_port 表
			for _, port := range result.ScanResult.Ports {
				assetPort := &model.AssetPort{
					TaskID:      taskID,
					AssetID:     &assetID,
					IP:          assetValue,
					Port:        int(port.Port),
					Protocol:    port.Protocol,
					State:       port.State,
					ServiceName: port.Service.Name,
				}
				_ = mysql.SaveAssetPort(assetPort)
			}
		}
	}

	// 4. 进行深度 Web 指纹识别
	redisProgress.Progress = 50
	redisProgress.Message = fmt.Sprintf("端口探测完成，发现 %d 个潜在 Web 服务，开始识别指纹...", hostsWithWeb)
	redisdb.UpdateTaskProgress(taskID, redisProgress)
	_ = mysql.UpdateTaskProgress(taskID, "running", 50)

	// 收集所有扫描过的目标（包含域名/URL等原始信息）
	var scanTargets []*servicecommon.Target
	for _, res := range results {
		if res.Target != nil {
			scanTargets = append(scanTargets, res.Target)
		}
	}

	err = scanweb.ScanWebFingerprintsFromPorts(ctx, taskID, scanTargets)
	if err != nil {
		if err == context.Canceled {
			_ = mysql.UpdateTaskProgress(taskID, "stopped", 50)
			return err
		}
		log.Info("[Web扫描] 指纹识别过程出错: %v", err)
		// 即使出错也继续，因为可能部分识别成功了
	}

	// 5. 扫描完成
	duration := time.Since(startTime)
	redisProgress.Status = "completed"
	redisProgress.Progress = 100
	redisProgress.Message = fmt.Sprintf("Web 扫描完成 (耗时: %v)", duration)
	redisdb.UpdateTaskProgress(taskID, redisProgress)
	_ = mysql.UpdateTaskProgress(taskID, "completed", 100)

	log.Info("[Web扫描] 任务 #%d 执行完毕 (耗时: %v)", taskID, duration)
	return nil
}

// SaveScanResult 保存扫描结果到数据库
func SaveScanResult(result *model.ScanResult, scanType string) error {
	// 1. 保存/更新资产信息
	assetValue := result.Asset.IP
	if assetValue == "" {
		assetValue = result.Asset.Hostname
		if assetValue == "" {
			assetValue = result.Target
		}
	}

	assetType := "ip"
	if result.Asset.Hostname != "" && result.Asset.IP == "" {
		assetType = "domain"
	}

	// 存活状态：如果扫描有结果，通常认为存活
	isAlive := true
	assetID, err := mysql.CreateOrUpdateAsset(assetValue, assetType, isAlive)
	if err != nil {
		log.Info("[警告] 保存资产 #%s 失败: %v", assetValue, err)
	}

	// 2. 保存详细扫描结果到 asset_scan_result
	// 构建资产扫描结果 JSON
	scanDetails := map[string]interface{}{
		"services":     result.Services,
		"fingerprints": result.Fingerprints,
	}
	detailsJSON, _ := json.Marshal(scanDetails)
	err = mysql.SaveAssetScanResult(result.TaskID, assetID, scanType, "success", string(detailsJSON))
	if err != nil {
		log.Info("[警告] 保存资产扫描结果失败: %v", err)
	}

	// 3. 保存所有发现的漏洞
	for _, vuln := range result.Vulnerabilities {
		// 转换为数据库格式
		vulnMap := map[string]interface{}{
			"task_id":           vuln.TaskID,
			"target":            vuln.Target,
			"ip":                vuln.IP,
			"port":              vuln.Port,
			"service":           vuln.Service,
			"name":              vuln.Name,
			"description":       vuln.Description,
			"severity":          vuln.Severity,
			"type":              vuln.Type,
			"cve":               vuln.CVE,
			"cwe":               vuln.CWE,
			"cvss":              vuln.CVSS,
			"template_id":       vuln.TemplateID,
			"template_path":     vuln.TemplatePath,
			"author":            vuln.Author,
			"tags":              strings.Join(vuln.Tags, ","),
			"reference":         strings.Join(vuln.Reference, ","),
			"evidence_request":  vuln.Evidence.Request,
			"evidence_response": vuln.Evidence.Response,
			"matched_at":        vuln.Evidence.MatchedAt,
			"extracted_data":    formatExtractedData(vuln.Evidence.ExtractedData),
			"curl_command":      vuln.Evidence.CurlCommand,
			"metadata":          vuln.Metadata,
			"status":            vuln.Status,
		}

		err := mysql.SaveVulnerability(vulnMap)
		if err != nil {
			log.Info("[警告] 保存漏洞失败: %v", err)
		}
	}

	return nil
}

// formatExtractedData 格式化提取的数据
func formatExtractedData(data map[string]string) string {
	if len(data) == 0 {
		return ""
	}
	jsonData, _ := json.Marshal(data)
	return string(jsonData)
}

// GetTaskVulnerabilities 获取任务的所有漏洞
func GetTaskVulnerabilities(taskID int) ([]model.Vulnerability, error) {
	rows, err := mysql.GetVulnerabilitiesByTaskID(taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	vulnerabilities := make([]model.Vulnerability, 0)

	for rows.Next() {
		var vuln model.Vulnerability
		var tags, reference, extractedData string
		var cvss interface{}

		err := rows.Scan(
			&vuln.ID,
			&vuln.TaskID,
			&vuln.Target,
			&vuln.IP,
			&vuln.Port,
			&vuln.Service,
			&vuln.Name,
			&vuln.Description,
			&vuln.Severity,
			&vuln.Type,
			&vuln.CVE,
			&vuln.CWE,
			&cvss,
			&vuln.TemplateID,
			&vuln.TemplatePath,
			&vuln.Author,
			&tags,
			&reference,
			&vuln.Evidence.Request,
			&vuln.Evidence.Response,
			&vuln.Evidence.MatchedAt,
			&extractedData,
			&vuln.Evidence.CurlCommand,
			&vuln.Metadata,
			&vuln.Status,
			&vuln.CreatedAt,
			&vuln.UpdatedAt,
		)

		if err != nil {
			log.Info("[警告] 解析漏洞数据失败: %v", err)
			continue
		}

		// 处理CVSS分数
		if cvss != nil {
			if cvssFloat, ok := cvss.(float64); ok {
				vuln.CVSS = cvssFloat
			}
		}

		// 解析tags
		if tags != "" {
			vuln.Tags = strings.Split(tags, ",")
		}

		// 解析reference
		if reference != "" {
			vuln.Reference = strings.Split(reference, ",")
		}

		// 解析extracted_data
		if extractedData != "" {
			var data map[string]string
			if err := json.Unmarshal([]byte(extractedData), &data); err == nil {
				vuln.Evidence.ExtractedData = data
			}
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

// GetVulnerabilityStats 获取漏洞统计信息
func GetVulnerabilityStats(taskID int) (map[string]interface{}, error) {
	stats, err := mysql.GetVulnerabilityStats(taskID)
	if err != nil {
		return nil, err
	}

	// 将 map[string]int 转换为 map[string]interface{}
	result := make(map[string]interface{})
	for k, v := range stats {
		result[k] = v
	}

	return result, nil
}
