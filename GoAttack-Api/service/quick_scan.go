package service

import (
	"GoAttack/common/log"
	"GoAttack/common/mysql"
	redisdb "GoAttack/common/redis"
	servicecommon "GoAttack/service/common"
	"GoAttack/service/plugins"
	scanbrute "GoAttack/service/scan_brute"
	scanhost "GoAttack/service/scan_host"
	scanport "GoAttack/service/scan_port"
	scanweb "GoAttack/service/scan_web"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ─────────────────────────────────────────────
//  Quick Scan
// ─────────────────────────────────────────────

type quickScanOptions struct {
	Timeout            time.Duration
	Concurrency        int
	Ports              string
	EnableWeakPassword bool
	BlacklistHosts     string
	BlacklistPorts     string
}

func parseQuickScanOptions(options string) quickScanOptions {
	timeout := 1 * time.Second
	concurrency := 50
	ports := "top1000"
	enableWeakPassword := true
	var blacklistHosts, blacklistPorts string

	if options == "" {
		return quickScanOptions{Timeout: timeout, Concurrency: concurrency, Ports: ports, EnableWeakPassword: enableWeakPassword, BlacklistHosts: blacklistHosts, BlacklistPorts: blacklistPorts}
	}

	var opts map[string]interface{}
	if err := json.Unmarshal([]byte(options), &opts); err != nil {
		return quickScanOptions{Timeout: timeout, Concurrency: concurrency, Ports: ports, EnableWeakPassword: enableWeakPassword, BlacklistHosts: blacklistHosts, BlacklistPorts: blacklistPorts}
	}

	if t, ok := opts["timeout"].(float64); ok && t > 0 {
		timeout = time.Duration(t) * time.Second
	}
	if c, ok := opts["threads"].(float64); ok && c > 0 {
		concurrency = int(c)
	}
	if p, ok := opts["ports"].(string); ok && p != "" {
		ports = p
	}
	if w, ok := opts["enable_weak_password"].(bool); ok {
		enableWeakPassword = w
	}
	if bh, ok := opts["blacklist_hosts"].(string); ok {
		blacklistHosts = bh
	}
	if bp, ok := opts["blacklist_ports"].(string); ok {
		blacklistPorts = bp
	}

	return quickScanOptions{Timeout: timeout, Concurrency: concurrency, Ports: ports, EnableWeakPassword: enableWeakPassword, BlacklistHosts: blacklistHosts, BlacklistPorts: blacklistPorts}
}

// ExecuteQuickScan 快速扫描：主机探测 → TCP TOP1000端口扫描 → Web指纹识别 → POC漏洞验证
func ExecuteQuickScan(ctx context.Context, taskID int, target string, options string) error {
	startTime := time.Now()
	log.Info("[QuickScan] Start task #%d: %s", taskID, target)

	opts := parseQuickScanOptions(options)

	if err := mysql.DeleteVulnerabilitiesByTaskID(taskID); err != nil {
		log.Info("[QuickScan] Warning: failed to clear vulnerabilities for task #%d: %v", taskID, err)
	}

	redisProgress := redisdb.TaskProgress{
		TaskID:        taskID,
		Status:        "running",
		Progress:      0,
		CurrentTarget: target,
		StartTime:     startTime,
		Message:       "Initializing quick scan...",
	}
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// Stage 1: Alive scan
	aliveProgress := func(current, total, found int, currentTarget, message string) {
		redisProgress.ScannedTargets = current
		redisProgress.TotalTargets = total
		redisProgress.FoundAssets = found
		redisProgress.CurrentTarget = currentTarget
		redisProgress.Progress = scaleProgress(current, total, 0, 25)
		if message != "" {
			redisProgress.Message = fmt.Sprintf("Alive scan: %s", message)
		} else {
			redisProgress.Message = fmt.Sprintf("Alive scan %d/%d: %s", current, total, currentTarget)
		}
		redisdb.UpdateTaskProgress(taskID, redisProgress)
	}

	aliveService := scanhost.NewScanService(true, opts.Timeout, opts.Concurrency)
	aliveTracker := servicecommon.NewProgressTracker(0, aliveProgress)
	aliveTracker.SetUpdateThreshold(5)
	aliveService.Scanner.Tracker = aliveTracker
	if opts.BlacklistHosts != "" {
		aliveService.Parser.SetBlacklist(opts.BlacklistHosts)
	}

	aliveResults, err := aliveService.ScanTargets(ctx, target)
	if err != nil {
		return handleQuickScanError(taskID, err, "alive scan failed", &redisProgress)
	}

	aliveCount := saveAliveScanResults(taskID, aliveResults)
	aliveTargets := scanhost.GetAliveTargets(aliveResults)
	redisProgress.Progress = 25
	redisProgress.Message = fmt.Sprintf("Alive scan completed: %d/%d alive", aliveCount, len(aliveResults))
	redisProgress.FoundAssets = aliveCount
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// Stage 2: Port scan (top1000 TCP only)
	// 存活探测已运行且没有发现任何存活主机时，不做端口扫描。
	// 理由：若目标完全无响应（不存在/全部封锁），对其扫描 top1000 端口
	// 每个端口都要等 2 秒超时 × 1000 端口 / 50 并发 ≈ 40 秒，毫无意义。
	// 若用户希望跳过存活探测直接扫端口，应使用自定义扫描并关闭 EnableAliveScan。
	if len(aliveTargets) == 0 {
		log.Info("[QuickScan] Alive scan found no live hosts, skipping port scan and subsequent stages")
		redisProgress.Status = "completed"
		redisProgress.Progress = 100
		redisProgress.Message = "Quick scan completed: no live hosts found"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		if err := mysql.UpdateTaskProgress(taskID, "completed", 100); err != nil {
			return fmt.Errorf("update task status failed: %v", err)
		}
		go func() {
			time.Sleep(10 * time.Second)
			redisdb.DeleteTaskProgress(taskID)
		}()
		log.Info("[QuickScan] Task #%d completed (no live hosts) in %v", taskID, time.Since(startTime))
		return nil
	}

	portTargetStr := buildTargetString(aliveTargets)
	portProgress := func(current, total, found int, currentTarget, message string) {
		redisProgress.ScannedTargets = current
		redisProgress.TotalTargets = total
		redisProgress.FoundAssets = found
		redisProgress.CurrentTarget = currentTarget
		redisProgress.Progress = scaleProgress(current, total, 25, 60)
		if message != "" {
			redisProgress.Message = fmt.Sprintf("Port scan: %s", message)
		} else {
			redisProgress.Message = fmt.Sprintf("Port scan %d/%d: %s", current, total, currentTarget)
		}
		redisdb.UpdateTaskProgress(taskID, redisProgress)
	}

	portService := scanport.NewPortScanService(0, opts.Concurrency, true)
	portTracker := servicecommon.NewProgressTracker(0, portProgress)
	portTracker.SetUpdateThreshold(3)
	portService.ComprehensiveScanner.Tracker = portTracker

	targetPorts := servicecommon.FilterPorts(opts.Ports, opts.BlacklistPorts)

	portResults, err := portService.ScanTargets(ctx, portTargetStr, targetPorts)
	if err != nil {
		return handleQuickScanError(taskID, err, "port scan failed", &redisProgress)
	}

	hostsWithPorts, totalOpenPorts := savePortScanResults(taskID, portResults)
	redisProgress.Progress = 60
	redisProgress.Message = fmt.Sprintf("Port scan completed: %d hosts, %d open ports", hostsWithPorts, totalOpenPorts)
	redisProgress.FoundAssets = hostsWithPorts
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// Stage 3: Web fingerprinting
	scanTargets := extractTargetsFromPortResults(portResults)
	if len(scanTargets) == 0 {
		scanTargets = aliveTargets
	}

	redisProgress.Progress = 65
	redisProgress.Message = "Web fingerprinting in progress..."
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	if err := scanweb.ScanWebFingerprintsFromPorts(ctx, taskID, scanTargets); err != nil {
		log.Info("[QuickScan] Web fingerprinting warning: %v", err)
	}

	redisProgress.Progress = 82
	redisProgress.Message = "Web fingerprinting completed"
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// Stage 4: POC verification
	pocTargets, pocTemplateMap, err := buildPocTargetsFromFingerprints(taskID)
	if err != nil {
		log.Info("[QuickScan] Failed to build POC targets: %v", err)
	} else if len(pocTargets) > 0 {
		if err = runPocVerification(ctx, taskID, pocTargets, pocTemplateMap, &redisProgress); err != nil {
			log.Info("[QuickScan] POC verification warning: %v", err)
		}
	} else {
		redisProgress.Message = "No matched POCs from fingerprints, skip verification"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
	}

	// Stage 5: Weak password brute force
	if opts.EnableWeakPassword {
		redisProgress.Progress = 92
		redisProgress.Message = "Running weak password brute force..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)

		scanbrute.ExecuteBruteForce(ctx, taskID)

		redisProgress.Message = "Weak password brute force completed"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
	}

	// Finalize
	redisProgress.Status = "completed"
	redisProgress.Progress = 100
	redisProgress.Message = "Quick scan completed"
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	if err := mysql.UpdateTaskProgress(taskID, "completed", 100); err != nil {
		return fmt.Errorf("update task status failed: %v", err)
	}

	go func() {
		time.Sleep(10 * time.Second)
		redisdb.DeleteTaskProgress(taskID)
	}()

	log.Info("[QuickScan] Task #%d completed in %v", taskID, time.Since(startTime))
	return nil
}

func handleQuickScanError(taskID int, err error, message string, rp *redisdb.TaskProgress) error {
	return handleFullScanError(taskID, err, message, rp)
}

// ─────────────────────────────────────────────
//  Custom Scan
// ─────────────────────────────────────────────

type customScanOptions struct {
	Timeout              time.Duration
	Concurrency          int
	Ports                string
	EnableAliveScan      bool
	EnablePortScan       bool
	EnableWebFingerprint bool
	EnablePocVerify      bool
	EnableDirScan        bool
	EnableSubdomainEnum  bool
	EnableWeakPassword   bool
	EnableUDPScan        bool
	UDPPorts             string
	BlacklistHosts       string
	BlacklistPorts       string
}

func parseCustomScanOptions(options string) customScanOptions {
	opts := customScanOptions{
		Timeout:              3 * time.Second,
		Concurrency:          50,
		Ports:                "top1000",
		EnableAliveScan:      true,
		EnablePortScan:       true,
		EnableWebFingerprint: true,
		EnablePocVerify:      true,
		EnableDirScan:        false,
		EnableSubdomainEnum:  false,
		EnableWeakPassword:   false,
		EnableUDPScan:        false,
		UDPPorts:             "udptop100",
	}

	if options == "" {
		return opts
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(options), &raw); err != nil {
		return opts
	}

	if t, ok := raw["timeout"].(float64); ok && t > 0 {
		opts.Timeout = time.Duration(t) * time.Second
	}
	if c, ok := raw["threads"].(float64); ok && c > 0 {
		opts.Concurrency = int(c)
	}
	if p, ok := raw["ports"].(string); ok && p != "" {
		opts.Ports = p
	}
	if v, ok := raw["enable_host_discovery"].(bool); ok {
		opts.EnableAliveScan = v
	}
	if v, ok := raw["enable_port_scan"].(bool); ok {
		opts.EnablePortScan = v
	}
	if v, ok := raw["enable_web_fingerprint"].(bool); ok {
		opts.EnableWebFingerprint = v
	}
	if v, ok := raw["enable_poc_verify"].(bool); ok {
		opts.EnablePocVerify = v
	}
	if v, ok := raw["enable_dir_scan"].(bool); ok {
		opts.EnableDirScan = v
	}
	if v, ok := raw["enable_subdomain_enum"].(bool); ok {
		opts.EnableSubdomainEnum = v
	}
	if v, ok := raw["enable_weak_password"].(bool); ok {
		opts.EnableWeakPassword = v
	}
	if v, ok := raw["enable_udp_scan"].(bool); ok {
		opts.EnableUDPScan = v
	}
	if u, ok := raw["udp_ports"].(string); ok && u != "" {
		opts.UDPPorts = u
	}
	if bh, ok := raw["blacklist_hosts"].(string); ok {
		opts.BlacklistHosts = bh
	}
	if bp, ok := raw["blacklist_ports"].(string); ok {
		opts.BlacklistPorts = bp
	}

	return opts
}

// ExecuteCustomScan 自定义扫描：根据选项动态决定执行哪些扫描阶段
func ExecuteCustomScan(ctx context.Context, taskID int, target string, options string) error {
	startTime := time.Now()
	log.Info("[CustomScan] Start task #%d: %s", taskID, target)

	opts := parseCustomScanOptions(options)

	if err := mysql.DeleteVulnerabilitiesByTaskID(taskID); err != nil {
		log.Info("[CustomScan] Warning: failed to clear vulnerabilities for task #%d: %v", taskID, err)
	}

	redisProgress := redisdb.TaskProgress{
		TaskID:        taskID,
		Status:        "running",
		Progress:      0,
		CurrentTarget: target,
		StartTime:     startTime,
		Message:       "Initializing custom scan...",
	}
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// Compute progress scale points dynamically
	stages := countEnabledStages(opts)
	stageWidth := 90 / max(stages, 1)
	stageStart := 0

	// ── Stage: Alive Scan ──
	var aliveTargets []*servicecommon.Target

	if opts.EnableAliveScan {
		redisProgress.Message = "Running alive scan..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)

		aliveProgress := func(current, total, found int, currentTarget, message string) {
			redisProgress.ScannedTargets = current
			redisProgress.TotalTargets = total
			redisProgress.FoundAssets = found
			redisProgress.CurrentTarget = currentTarget
			redisProgress.Progress = scaleProgress(current, total, stageStart, stageStart+stageWidth)
			redisProgress.Message = fmt.Sprintf("Alive scan %d/%d: %s", current, total, currentTarget)
			redisdb.UpdateTaskProgress(taskID, redisProgress)
		}

		aliveService := scanhost.NewScanService(true, opts.Timeout, opts.Concurrency)
		aliveTracker := servicecommon.NewProgressTracker(0, aliveProgress)
		aliveTracker.SetUpdateThreshold(5)
		aliveService.Scanner.Tracker = aliveTracker
		if opts.BlacklistHosts != "" {
			aliveService.Parser.SetBlacklist(opts.BlacklistHosts)
		}

		aliveResults, err := aliveService.ScanTargets(ctx, target)
		if err != nil {
			return handleCustomScanError(taskID, err, "alive scan failed", &redisProgress)
		}

		aliveCount := saveAliveScanResults(taskID, aliveResults)
		aliveTargets = scanhost.GetAliveTargets(aliveResults)
		redisProgress.Progress = stageStart + stageWidth
		redisProgress.Message = fmt.Sprintf("Alive scan completed: %d/%d alive", aliveCount, len(aliveResults))
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		stageStart += stageWidth
	}

	// ── Stage: Port Scan ──
	var portResults []scanport.PortScanServiceResult

	if opts.EnablePortScan {
		var portTargetStr string
		if opts.EnableAliveScan {
			// 开启了存活探测：只对存活主机做端口扫描
			// 若 0 个存活，说明目标全部无响应，跳过端口扫描（及后续阶段）
			if len(aliveTargets) == 0 {
				log.Info("[CustomScan] Alive scan found no live hosts, skipping port scan and subsequent stages")
				redisProgress.Status = "completed"
				redisProgress.Progress = 100
				redisProgress.Message = "Custom scan completed: no live hosts found"
				redisdb.UpdateTaskProgress(taskID, redisProgress)
				if err := mysql.UpdateTaskProgress(taskID, "completed", 100); err != nil {
					return fmt.Errorf("update task status failed: %v", err)
				}
				go func() {
					time.Sleep(10 * time.Second)
					redisdb.DeleteTaskProgress(taskID)
				}()
				log.Info("[CustomScan] Task #%d completed (no live hosts) in %v", taskID, time.Since(startTime))
				return nil
			}
			portTargetStr = buildTargetString(aliveTargets)
		} else {
			// 未开启存活探测：直接对用户给定的所有目标做端口扫描
			portTargetStr = target
		}

		portProgress := func(current, total, found int, currentTarget, message string) {
			redisProgress.ScannedTargets = current
			redisProgress.TotalTargets = total
			redisProgress.FoundAssets = found
			redisProgress.CurrentTarget = currentTarget
			redisProgress.Progress = scaleProgress(current, total, stageStart, stageStart+stageWidth)
			redisProgress.Message = fmt.Sprintf("Port scan %d/%d: %s", current, total, currentTarget)
			redisdb.UpdateTaskProgress(taskID, redisProgress)
		}

		portService := scanport.NewPortScanService(0, opts.Concurrency, true)
		portTracker := servicecommon.NewProgressTracker(0, portProgress)
		portTracker.SetUpdateThreshold(3)
		portService.ComprehensiveScanner.Tracker = portTracker

		var err error
		targetPorts := servicecommon.FilterPorts(opts.Ports, opts.BlacklistPorts)
		portResults, err = portService.ScanTargets(ctx, portTargetStr, targetPorts)
		if err != nil {
			return handleCustomScanError(taskID, err, "port scan failed", &redisProgress)
		}

		hostsWithPorts, totalOpenPorts := savePortScanResults(taskID, portResults)
		redisProgress.Progress = stageStart + stageWidth
		redisProgress.Message = fmt.Sprintf("Port scan completed: %d hosts, %d open ports", hostsWithPorts, totalOpenPorts)
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		stageStart += stageWidth
	}

	// ── Stage: UDP Port Scan ──
	if opts.EnableUDPScan {
		redisProgress.Progress = stageStart
		redisProgress.Message = "Running UDP port scan..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)

		portTargetStr := buildTargetString(aliveTargets)
		if portTargetStr == "" {
			portTargetStr = target
		}

		// If hosts were found in alive target, use them, otherwise we fallback
		// Here we just use the same aliveTargets
		targetUDPPorts := servicecommon.FilterPorts(opts.UDPPorts, opts.BlacklistPorts)
		runUDPScan(ctx, taskID, aliveTargets, targetUDPPorts)

		redisProgress.Progress = stageStart + stageWidth
		redisProgress.Message = "UDP port scan completed"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		stageStart += stageWidth
	}

	// ── Stage: Dir Scan (before fingerprinting) ──
	scanTargets := extractTargetsFromPortResults(portResults)
	if len(scanTargets) == 0 {
		scanTargets = aliveTargets
	}

	if opts.EnableDirScan {
		redisProgress.Message = "Running directory scan..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)

		ipToTargets := make(map[string][]*servicecommon.Target)
		for _, t := range scanTargets {
			if t.IP != "" {
				ipToTargets[t.IP] = append(ipToTargets[t.IP], t)
			}
		}

		rows, err := mysql.GetHTTPPortsByTaskID(taskID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int64
				var ip string
				var port int
				var protocol string
				var serviceName string
				if err := rows.Scan(&id, &ip, &port, &protocol, &serviceName); err == nil {
					hostToUse := ip
					if tList, ok := ipToTargets[ip]; ok && len(tList) > 0 {
						for _, t := range tList {
							if t.Host != "" && t.Host != t.IP {
								hostToUse = t.Host
								break
							}
						}
						if hostToUse == ip {
							hostToUse = tList[0].Host
						}
					}
					scheme := "http"
					if protocol == "https" || port == 443 || port == 8443 {
						scheme = "https"
					}
					targetUrl := fmt.Sprintf("%s://%s:%d", scheme, hostToUse, port)
					_ = plugins.RunGobuster(ctx, taskID, targetUrl, "dir")
				}
			}
		} else {
			for _, t := range scanTargets {
				targetUrl := t.Original
				if t.Port > 0 {
					targetUrl = fmt.Sprintf("%s:%d", t.Host, t.Port)
				} else if targetUrl == "" {
					targetUrl = t.Host
				}
				_ = plugins.RunGobuster(ctx, taskID, targetUrl, "dir")
			}
		}

		redisProgress.Progress = stageStart + stageWidth
		redisProgress.Message = "Directory scan completed"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		stageStart += stageWidth
	}

	// ── Stage: Web Fingerprint ──
	if opts.EnableWebFingerprint {
		redisProgress.Progress = stageStart
		redisProgress.Message = "Web fingerprinting in progress..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)

		if err := scanweb.ScanWebFingerprintsFromPorts(ctx, taskID, scanTargets); err != nil {
			log.Info("[CustomScan] Web fingerprinting warning: %v", err)
		}

		if opts.EnableDirScan {
			if err := scanweb.ScanGobusterDiscoveredURLs(ctx, taskID); err != nil {
				log.Info("[CustomScan] Gobuster path fingerprinting warning: %v", err)
			}
		}

		redisProgress.Progress = stageStart + stageWidth
		redisProgress.Message = "Web fingerprinting completed"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		stageStart += stageWidth
	}

	// ── Stage: POC Verify ──
	if opts.EnablePocVerify {
		pocTargets, pocTemplateMap, err := buildPocTargetsFromFingerprints(taskID)
		if err != nil {
			log.Info("[CustomScan] Failed to build POC targets: %v", err)
		} else if len(pocTargets) > 0 {
			if err = runPocVerification(ctx, taskID, pocTargets, pocTemplateMap, &redisProgress); err != nil {
				log.Info("[CustomScan] POC verification warning: %v", err)
			}
		} else {
			redisProgress.Message = "No matched POCs from fingerprints, skip verification"
			redisdb.UpdateTaskProgress(taskID, redisProgress)
		}
		stageStart += stageWidth
	}

	// ── Stage: Weak Password Brute Force ──
	if opts.EnableWeakPassword {
		redisProgress.Progress = stageStart
		redisProgress.Message = "Running weak password brute force..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)

		scanbrute.ExecuteBruteForce(ctx, taskID)

		redisProgress.Progress = stageStart + stageWidth
		redisProgress.Message = "Weak password brute force completed"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		stageStart += stageWidth
	}

	// ── Stage: Subdomain Enum ──
	if opts.EnableSubdomainEnum {
		redisProgress.Message = "Running subdomain enumeration..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		for _, t := range scanTargets {
			_ = plugins.RunGobuster(ctx, taskID, t.Host, "dns")
		}
		redisProgress.Progress = stageStart + stageWidth
		redisProgress.Message = "Subdomain enumeration completed"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
	}

	// Finalize
	redisProgress.Status = "completed"
	redisProgress.Progress = 100
	redisProgress.Message = "Custom scan completed"
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	if err := mysql.UpdateTaskProgress(taskID, "completed", 100); err != nil {
		return fmt.Errorf("update task status failed: %v", err)
	}

	go func() {
		time.Sleep(10 * time.Second)
		redisdb.DeleteTaskProgress(taskID)
	}()

	log.Info("[CustomScan] Task #%d completed in %v", taskID, time.Since(startTime))
	return nil
}

func handleCustomScanError(taskID int, err error, message string, rp *redisdb.TaskProgress) error {
	return handleFullScanError(taskID, err, message, rp)
}

func countEnabledStages(opts customScanOptions) int {
	count := 0
	if opts.EnableAliveScan {
		count++
	}
	if opts.EnablePortScan {
		count++
	}
	if opts.EnableUDPScan {
		count++
	}
	if opts.EnableDirScan {
		count++
	}
	if opts.EnableWebFingerprint {
		count++
	}
	if opts.EnablePocVerify {
		count++
	}
	if opts.EnableWeakPassword {
		count++
	}
	if opts.EnableSubdomainEnum {
		count++
	}
	return count
}
