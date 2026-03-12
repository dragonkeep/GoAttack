package service

import (
	"GoAttack/common/log"
	"GoAttack/common/mysql"
	redisdb "GoAttack/common/redis"
	"GoAttack/model"
	servicecommon "GoAttack/service/common"
	"GoAttack/service/plugins"
	scanbrute "GoAttack/service/scan_brute"
	scanhost "GoAttack/service/scan_host"
	scanpoc "GoAttack/service/scan_poc"
	scanport "GoAttack/service/scan_port"
	scanweb "GoAttack/service/scan_web"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type fullScanOptions struct {
	Timeout             time.Duration
	Concurrency         int
	Ports               string
	EnableDirScan       bool
	EnableSubdomainEnum bool
	EnableUDPScan       bool   // 是否开启 UDP 端口扫描
	UDPPorts            string // UDP 扫描端口范围，默认 udptop100
	EnableWeakPassword  bool   // 是否开启弱口令探测
	BlacklistHosts      string // 黑名单资产
	BlacklistPorts      string // 黑名单端口
}

type webFingerprintRecord struct {
	URL          string
	IP           string
	Port         int
	Protocol     string
	Server       string
	Technologies []string
	Frameworks   []string
	MatchedRules []string
}

type pocCandidate struct {
	ID         int64
	Template   *mysql.PocTemplate
	Haystack   string
	HasHTTP    bool
	TemplateID string
}

// ExecuteFullScan runs a full pipeline: alive -> top1000 ports -> web fingerprint -> poc verify.
func ExecuteFullScan(ctx context.Context, taskID int, target string, options string) error {
	startTime := time.Now()
	log.Info("[FullScan] Start task #%d: %s", taskID, target)

	opts := parseFullScanOptions(options)

	// Remove old vulnerabilities for this task before running full scan.
	if err := mysql.DeleteVulnerabilitiesByTaskID(taskID); err != nil {
		log.Info("[FullScan] Warning: failed to clear vulnerabilities for task #%d: %v", taskID, err)
	}

	redisProgress := redisdb.TaskProgress{
		TaskID:         taskID,
		Status:         "running",
		Progress:       0,
		TotalTargets:   0,
		ScannedTargets: 0,
		FoundAssets:    0,
		CurrentTarget:  target,
		StartTime:      startTime,
		Message:        "Initializing full scan...",
	}
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// Stage 1: alive scan
	aliveProgress := func(current, total, found int, currentTarget, message string) {
		redisProgress.ScannedTargets = current
		redisProgress.TotalTargets = total
		redisProgress.FoundAssets = found
		redisProgress.CurrentTarget = currentTarget
		redisProgress.Progress = scaleProgress(current, total, 0, 20)
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
		return handleFullScanError(taskID, err, "alive scan failed", &redisProgress)
	}

	aliveCount := saveAliveScanResults(taskID, aliveResults)
	aliveTargets := scanhost.GetAliveTargets(aliveResults)
	redisProgress.Progress = 20
	redisProgress.Message = fmt.Sprintf("Alive scan completed: %d/%d alive", aliveCount, len(aliveResults))
	redisProgress.FoundAssets = aliveCount
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// Stage 2: port scan (top1000)
	// 存活探测没有发现任何存活主机时，直接结束扫描，跳过后续所有阶段。
	// 理由与 quick_scan 相同：对一个无响应目标继续做端口扫描只会浪费大量时间。
	if len(aliveTargets) == 0 {
		log.Info("[FullScan] Alive scan found no live hosts, skipping port scan and subsequent stages")
		redisProgress.Status = "completed"
		redisProgress.Progress = 100
		redisProgress.Message = "Full scan completed: no live hosts found"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		if err := mysql.UpdateTaskProgress(taskID, "completed", 100); err != nil {
			return fmt.Errorf("update task status failed: %v", err)
		}
		go func() {
			time.Sleep(10 * time.Second)
			redisdb.DeleteTaskProgress(taskID)
		}()
		log.Info("[FullScan] Task #%d completed (no live hosts) in %v", taskID, time.Since(startTime))
		return nil
	}

	portTargetStr := buildTargetString(aliveTargets)
	portProgress := func(current, total, found int, currentTarget, message string) {
		redisProgress.ScannedTargets = current
		redisProgress.TotalTargets = total
		redisProgress.FoundAssets = found
		redisProgress.CurrentTarget = currentTarget
		redisProgress.Progress = scaleProgress(current, total, 20, 70)
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
		return handleFullScanError(taskID, err, "port scan failed", &redisProgress)
	}

	hostsWithPorts, totalOpenPorts := savePortScanResults(taskID, portResults)
	redisProgress.Progress = 40
	redisProgress.Message = fmt.Sprintf("TCP port scan completed: %d hosts with open ports, %d open ports",
		hostsWithPorts, totalOpenPorts)
	redisProgress.FoundAssets = hostsWithPorts
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// Stage 2.5: UDP port scan (TOP100, parallel per host)
	if opts.EnableUDPScan && len(aliveTargets) > 0 {
		redisProgress.Progress = 42
		redisProgress.Message = "Running UDP port scan (TOP100)..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		targetUDPPorts := servicecommon.FilterPorts(opts.UDPPorts, opts.BlacklistPorts)
		runUDPScan(ctx, taskID, aliveTargets, targetUDPPorts)
		redisProgress.Progress = 55
		redisProgress.Message = "UDP port scan completed"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
	}

	// Stage 3: gobuster directory scan (before fingerprinting, so we can fingerprint discovered paths)
	scanTargets := extractTargetsFromPortResults(portResults)
	if len(scanTargets) == 0 {
		scanTargets = aliveTargets
	}

	if opts.EnableDirScan {
		redisProgress.Message = "Running Directory Scan plugin..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)

		// Build IP to Target mapping to preserve hostnames
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
					if strings.Contains(strings.ToLower(serviceName), "https") {
						scheme = "https"
					}
					targetUrl := fmt.Sprintf("%s://%s:%d", scheme, hostToUse, port)
					_ = plugins.RunGobuster(ctx, taskID, targetUrl, "dir")
				}
			}
		} else {
			// Fallback: Use original targets if failed to get ports from DB
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
	}

	// Stage 4: web fingerprint (covers original port targets + gobuster discovered paths)
	redisProgress.Progress = 75
	redisProgress.Message = "Web fingerprinting in progress..."
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	if err := scanweb.ScanWebFingerprintsFromPorts(ctx, taskID, scanTargets); err != nil {
		log.Info("[FullScan] Web fingerprinting warning: %v", err)
	}

	// Also fingerprint paths discovered by Gobuster dir scan
	if opts.EnableDirScan {
		if err := scanweb.ScanGobusterDiscoveredURLs(ctx, taskID); err != nil {
			log.Info("[FullScan] Gobuster path fingerprinting warning: %v", err)
		}
	}

	redisProgress.Progress = 88
	redisProgress.Message = "Web fingerprinting completed"
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	// Stage 5: POC verification based on fingerprints (now includes Gobuster-discovered paths)
	pocTargets, pocTemplateMap, err := buildPocTargetsFromFingerprints(taskID)
	if err != nil {
		log.Info("[FullScan] Failed to build POC targets: %v", err)
	} else if len(pocTargets) > 0 {
		err = runPocVerification(ctx, taskID, pocTargets, pocTemplateMap, &redisProgress)
		if err != nil {
			log.Info("[FullScan] POC verification warning: %v", err)
		}
	} else {
		redisProgress.Message = "No matched POCs from fingerprints, skip verification"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
	}

	// Stage 5.5: weak password brute force
	if opts.EnableWeakPassword {
		redisProgress.Progress = 92
		redisProgress.Message = "Running weak password brute force..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)

		scanbrute.ExecuteBruteForce(ctx, taskID)

		redisProgress.Message = "Weak password brute force completed"
		redisdb.UpdateTaskProgress(taskID, redisProgress)
	}

	// Stage 6: subdomain enumeration
	if opts.EnableSubdomainEnum {
		redisProgress.Message = "Running Subdomain Enumeration plugin..."
		redisdb.UpdateTaskProgress(taskID, redisProgress)
		for _, t := range scanTargets {
			_ = plugins.RunGobuster(ctx, taskID, t.Host, "dns")
		}
	}

	// Finalize
	redisProgress.Status = "completed"
	redisProgress.Progress = 100
	redisProgress.Message = "Full scan completed"
	redisdb.UpdateTaskProgress(taskID, redisProgress)

	if err := mysql.UpdateTaskProgress(taskID, "completed", 100); err != nil {
		return fmt.Errorf("update task status failed: %v", err)
	}

	go func() {
		time.Sleep(10 * time.Second)
		redisdb.DeleteTaskProgress(taskID)
	}()

	log.Info("[FullScan] Task #%d completed in %v", taskID, time.Since(startTime))
	return nil
}

func handleFullScanError(taskID int, err error, message string, redisProgress *redisdb.TaskProgress) error {
	status := "failed"
	if err == context.Canceled {
		status = "stopped"
	}
	redisProgress.Status = status
	redisProgress.Message = fmt.Sprintf("%s: %v", message, err)
	redisdb.UpdateTaskProgress(taskID, *redisProgress)
	_ = mysql.UpdateTaskProgress(taskID, status, redisProgress.Progress)
	return err
}

func parseFullScanOptions(options string) fullScanOptions {
	timeout := 3 * time.Second
	concurrency := 50
	ports := "top1000"
	var enableDir, enableSub bool
	enableUDP := true // 全量扫描默认开启 UDP
	udpPorts := "udptop100"
	enableWeakPassword := true // 全量扫描默认开启弱口令
	var blacklistHosts, blacklistPorts string

	if options == "" {
		return fullScanOptions{Timeout: timeout, Concurrency: concurrency, Ports: ports,
			EnableDirScan: false, EnableSubdomainEnum: false,
			EnableUDPScan: enableUDP, UDPPorts: udpPorts, EnableWeakPassword: enableWeakPassword, BlacklistHosts: blacklistHosts, BlacklistPorts: blacklistPorts}
	}

	var opts map[string]interface{}
	if err := json.Unmarshal([]byte(options), &opts); err != nil {
		return fullScanOptions{Timeout: timeout, Concurrency: concurrency, Ports: ports,
			EnableDirScan: false, EnableSubdomainEnum: false,
			EnableUDPScan: enableUDP, UDPPorts: udpPorts, EnableWeakPassword: enableWeakPassword, BlacklistHosts: blacklistHosts, BlacklistPorts: blacklistPorts}
	}

	if t, ok := opts["timeout"].(float64); ok && t > 0 {
		timeout = time.Duration(t) * time.Second
	}
	if c, ok := opts["threads"].(float64); ok && c > 0 {
		concurrency = int(c)
	}
	if p, ok := opts["ports"].(string); ok && strings.TrimSpace(p) != "" {
		ports = strings.TrimSpace(p)
	}
	if d, ok := opts["enable_dir_scan"].(bool); ok {
		enableDir = d
	}
	if s, ok := opts["enable_subdomain_enum"].(bool); ok {
		enableSub = s
	}
	if v, ok := opts["enable_udp_scan"].(bool); ok {
		enableUDP = v
	}
	if u, ok := opts["udp_ports"].(string); ok && strings.TrimSpace(u) != "" {
		udpPorts = strings.TrimSpace(u)
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

	return fullScanOptions{Timeout: timeout, Concurrency: concurrency, Ports: ports,
		EnableDirScan: enableDir, EnableSubdomainEnum: enableSub,
		EnableUDPScan: enableUDP, UDPPorts: udpPorts, EnableWeakPassword: enableWeakPassword,
		BlacklistHosts: blacklistHosts, BlacklistPorts: blacklistPorts}
}

func scaleProgress(current, total, start, end int) int {
	if total <= 0 {
		return start
	}
	if end <= start {
		return start
	}
	p := start + int(float64(end-start)*float64(current)/float64(total))
	if p > end {
		return end
	}
	if p < start {
		return start
	}
	return p
}

func buildTargetString(targets []*servicecommon.Target) string {
	if len(targets) == 0 {
		return ""
	}
	values := make([]string, 0, len(targets))
	seen := make(map[string]struct{})
	for _, t := range targets {
		value := t.Host
		if value == "" {
			value = t.IP
		}
		if value == "" {
			value = t.Original
		}
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return strings.Join(values, "\n")
}

func saveAliveScanResults(taskID int, results []scanhost.ScanResult) int {
	aliveCount := 0
	for _, result := range results {
		if result.Target == nil {
			continue
		}

		assetValue := result.Target.IP
		if assetValue == "" {
			assetValue = result.Target.Host
			if assetValue == "" {
				assetValue = result.Target.Original
			}
		}
		if assetValue == "" {
			continue
		}

		assetType := "ip"
		if result.Target.Host != "" && result.Target.IP == "" {
			assetType = "domain"
		}

		assetID, err := mysql.CreateOrUpdateAsset(assetValue, assetType, result.HostAlive)
		if err != nil {
			log.Info("[FullScan] Save asset failed (%s): %v", assetValue, err)
			continue
		}

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

		status := "failed"
		if result.HostAlive {
			status = "success"
			aliveCount++
		}

		resultJSON, _ := json.Marshal(detail)
		if err := mysql.SaveAssetScanResult(taskID, assetID, "alive", status, string(resultJSON)); err != nil {
			log.Info("[FullScan] Save alive result failed: %v", err)
		}
	}
	return aliveCount
}

func savePortScanResults(taskID int, results []scanport.PortScanServiceResult) (int, int) {
	hostsWithPorts := 0
	totalOpenPorts := 0

	for _, result := range results {
		if result.ScanResult == nil {
			continue
		}

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

		isAlive := result.ScanResult.OpenPorts > 0
		if isAlive {
			hostsWithPorts++
			totalOpenPorts += result.ScanResult.OpenPorts
		}

		assetID, err := mysql.CreateOrUpdateAsset(assetValue, assetType, isAlive)
		if err != nil {
			log.Info("[FullScan] Save asset failed (%s): %v", assetValue, err)
			continue
		}

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

		if result.ScanResult.OS.Name != "" {
			detail["os"] = map[string]interface{}{
				"name":      result.ScanResult.OS.Name,
				"accuracy":  result.ScanResult.OS.Accuracy,
				"os_family": result.ScanResult.OS.OSFamily,
				"vendor":    result.ScanResult.OS.Vendor,
			}
		}

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

			if len(port.Service.Scripts) > 0 {
				portInfo["scripts"] = port.Service.Scripts
			}

			ports = append(ports, portInfo)
		}
		detail["ports"] = ports

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

		if err := mysql.SaveAssetScanResult(taskID, assetID, "port", status, string(resultJSON)); err != nil {
			log.Info("[FullScan] Save port scan result failed: %v", err)
		}

		for _, port := range result.ScanResult.Ports {
			assetPort := &model.AssetPort{
				TaskID:   taskID,
				AssetID:  &assetID,
				IP:       result.ScanResult.IP,
				Port:     int(port.Port),
				Protocol: port.Protocol,
				State:    port.State,

				ServiceName:       port.Service.Name,
				ServiceProduct:    port.Service.Product,
				ServiceVersion:    port.Service.Version,
				ServiceExtraInfo:  port.Service.ExtraInfo,
				ServiceHostname:   port.Service.Hostname,
				ServiceOSType:     port.Service.OSType,
				ServiceDeviceType: port.Service.DeviceType,
				ServiceConfidence: port.Service.Confidence,

				CPEs:    port.Service.CPEs,
				Scripts: port.Service.Scripts,
			}

			if banner, ok := port.Service.Scripts["banner"]; ok {
				assetPort.Banner = sanitizeBanner(banner)
			}
			if method, ok := port.Service.Scripts["detection_method"]; ok {
				assetPort.FingerprintMethod = method
			}

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

			if err := mysql.SaveAssetPort(assetPort); err != nil {
				log.Info("[FullScan] Save asset port failed (%s:%d): %v", result.ScanResult.IP, port.Port, err)
			}
		}
	}

	return hostsWithPorts, totalOpenPorts
}

func extractTargetsFromPortResults(results []scanport.PortScanServiceResult) []*servicecommon.Target {
	targets := make([]*servicecommon.Target, 0, len(results))
	seen := make(map[string]struct{})
	for _, res := range results {
		if res.Target == nil {
			continue
		}
		key := res.Target.Original
		if key == "" {
			if res.Target.IP != "" {
				key = res.Target.IP
			} else {
				key = res.Target.Host
			}
		}
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, res.Target)
	}
	return targets
}

func buildPocTargetsFromFingerprints(taskID int) (map[string][]int, map[string]*mysql.PocTemplate, error) {
	fingerprints, err := loadWebFingerprints(taskID)
	if err != nil {
		return nil, nil, err
	}

	pocs, err := mysql.GetActivePocTemplates()
	if err != nil {
		return nil, nil, err
	}
	if len(pocs) == 0 || len(fingerprints) == 0 {
		return map[string][]int{}, map[string]*mysql.PocTemplate{}, nil
	}

	candidates, templateByID := buildPocCandidates(pocs)
	if len(candidates) == 0 {
		return map[string][]int{}, templateByID, nil
	}

	targetMap := make(map[string]map[int]struct{})
	for _, fp := range fingerprints {
		keywords := extractKeywords(fp)
		if len(keywords) == 0 {
			continue
		}

		matched := matchPocIDs(keywords, candidates)
		if len(matched) == 0 {
			continue
		}

		targetURL := fp.URL
		if targetURL == "" {
			targetURL = buildURL(fp.Protocol, fp.IP, fp.Port)
		}
		if targetURL == "" {
			continue
		}

		set, ok := targetMap[targetURL]
		if !ok {
			set = make(map[int]struct{})
			targetMap[targetURL] = set
		}
		for _, id := range matched {
			set[id] = struct{}{}
		}
	}

	result := make(map[string][]int)
	for targetURL, set := range targetMap {
		ids := make([]int, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		result[targetURL] = ids
	}

	return result, templateByID, nil
}

func loadWebFingerprints(taskID int) ([]webFingerprintRecord, error) {
	rows, err := mysql.GetWebFingerprintsByTaskID(taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]webFingerprintRecord, 0)
	for rows.Next() {
		var (
			id, assetID, statusCode, length, responseTime int64
			portIDArr                                     sql.NullInt64
			taskIDVal, port                               int
			urlStr, ipStr, protocol                       string
			title, server, contentType, fav               sql.NullString
			techJSON, frameworksJSON, matchedRulesJSON    sql.NullString
			headJSON                                      sql.NullString
			discoveredAt, lastChecked                     time.Time
		)

		err := rows.Scan(
			&id, &taskIDVal, &assetID, &portIDArr,
			&urlStr, &ipStr, &port, &protocol,
			&title, &statusCode, &server, &contentType, &length, &responseTime,
			&techJSON, &frameworksJSON, &matchedRulesJSON, &fav, &headJSON,
			&discoveredAt, &lastChecked,
		)
		if err != nil {
			return records, err
		}

		var techs, frameworks, matchedRules []string
		if techJSON.Valid && techJSON.String != "" {
			_ = json.Unmarshal([]byte(techJSON.String), &techs)
		}
		if frameworksJSON.Valid && frameworksJSON.String != "" {
			_ = json.Unmarshal([]byte(frameworksJSON.String), &frameworks)
		}
		if matchedRulesJSON.Valid && matchedRulesJSON.String != "" {
			_ = json.Unmarshal([]byte(matchedRulesJSON.String), &matchedRules)
		}

		record := webFingerprintRecord{
			URL:          urlStr,
			IP:           ipStr,
			Port:         port,
			Protocol:     protocol,
			Server:       server.String,
			Technologies: techs,
			Frameworks:   frameworks,
			MatchedRules: matchedRules,
		}
		records = append(records, record)
	}

	return records, nil
}

func buildPocCandidates(pocs []*mysql.PocTemplate) ([]pocCandidate, map[string]*mysql.PocTemplate) {
	candidates := make([]pocCandidate, 0)
	templateByID := make(map[string]*mysql.PocTemplate)

	for _, poc := range pocs {
		if poc == nil || !poc.IsActive {
			continue
		}
		if poc.FilePath == "" {
			continue
		}

		templateByID[poc.TemplateID] = poc

		tags := parseJSONList(poc.Tags)
		parts := []string{
			poc.TemplateID,
			poc.Name,
			poc.Description,
			poc.Category,
			poc.Protocol,
			poc.CveID,
			poc.CnvdID,
			poc.CweID,
		}
		parts = append(parts, tags...)
		haystack := strings.ToLower(strings.Join(parts, " "))

		candidates = append(candidates, pocCandidate{
			ID:         poc.ID,
			Template:   poc,
			Haystack:   haystack,
			HasHTTP:    isHTTPProtocol(poc.Protocol),
			TemplateID: poc.TemplateID,
		})
	}

	return candidates, templateByID
}

func matchPocIDs(keywords []string, candidates []pocCandidate) []int {
	matched := make([]int, 0)
	for _, c := range candidates {
		if !c.HasHTTP {
			continue
		}
		for _, kw := range keywords {
			if strings.Contains(c.Haystack, kw) {
				matched = append(matched, int(c.ID))
				break
			}
		}
	}
	return matched
}

func extractKeywords(fp webFingerprintRecord) []string {
	seed := make([]string, 0)
	seed = append(seed, fp.Technologies...)
	seed = append(seed, fp.Frameworks...)
	seed = append(seed, fp.MatchedRules...)
	if fp.Server != "" {
		seed = append(seed, fp.Server)
	}
	return normalizeKeywords(seed)
}

func normalizeKeywords(values []string) []string {
	stopWords := map[string]struct{}{
		"http":        {},
		"https":       {},
		"www":         {},
		"web":         {},
		"server":      {},
		"service":     {},
		"application": {},
	}

	seen := make(map[string]struct{})
	result := make([]string, 0)

	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}

		addKeyword(value, stopWords, seen, &result)

		// Split by non-alphanumeric characters
		builder := strings.Builder{}
		for _, r := range value {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				builder.WriteRune(r)
			} else {
				builder.WriteRune(' ')
			}
		}
		for _, part := range strings.Fields(builder.String()) {
			addKeyword(part, stopWords, seen, &result)
		}
	}

	return result
}

func addKeyword(value string, stopWords map[string]struct{}, seen map[string]struct{}, out *[]string) {
	if len(value) < 3 {
		return
	}
	if _, ok := stopWords[value]; ok {
		return
	}
	if !containsLetter(value) {
		return
	}
	if _, ok := seen[value]; ok {
		return
	}
	seen[value] = struct{}{}
	*out = append(*out, value)
}

func containsLetter(value string) bool {
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			return true
		}
	}
	return false
}

func parseJSONList(value string) []string {
	if value == "" {
		return nil
	}
	var list []string
	if err := json.Unmarshal([]byte(value), &list); err != nil {
		return nil
	}
	return list
}

func isHTTPProtocol(protocol string) bool {
	if protocol == "" {
		return true
	}
	p := strings.ToLower(protocol)
	return strings.Contains(p, "http")
}

func buildURL(protocol, ip string, port int) string {
	scheme := "http"
	if protocol != "" {
		scheme = strings.ToLower(protocol)
	}
	if ip == "" {
		return ""
	}
	if port == 0 {
		return fmt.Sprintf("%s://%s", scheme, ip)
	}
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return fmt.Sprintf("%s://%s", scheme, ip)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, ip, port)
}

func runPocVerification(ctx context.Context, taskID int, targets map[string][]int, templateByID map[string]*mysql.PocTemplate, redisProgress *redisdb.TaskProgress) error {
	if len(targets) == 0 {
		return nil
	}

	templatesDir := os.Getenv("NUCLEI_TEMPLATES_DIR")
	if templatesDir == "" {
		templatesDir = "service/lib/templates"
	}

	verifier, err := scanpoc.NewPocVerifier(templatesDir)
	if err != nil {
		return err
	}
	defer verifier.Close()

	// Build template lookup by ID for saving results
	templateByIDInt := make(map[int64]*mysql.PocTemplate)
	for _, tpl := range templateByID {
		templateByIDInt[tpl.ID] = tpl
	}
	templateByTemplateID := make(map[string]*mysql.PocTemplate)
	for _, tpl := range templateByID {
		templateByTemplateID[tpl.TemplateID] = tpl
	}

	targetList := make([]string, 0, len(targets))
	for target := range targets {
		targetList = append(targetList, target)
	}
	sort.Strings(targetList)

	total := len(targetList)
	matchedCount := 0

	for i, target := range targetList {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		redisProgress.Progress = scaleProgress(i, total, 85, 100)
		redisProgress.CurrentTarget = target
		redisProgress.Message = fmt.Sprintf("POC verification %d/%d", i+1, total)
		redisdb.UpdateTaskProgress(taskID, *redisProgress)

		pocIDs := targets[target]
		if len(pocIDs) == 0 {
			continue
		}

		resp, err := verifier.Verify(scanpoc.VerifyRequest{
			Target: target,
			PocIDs: pocIDs,
		})
		if err != nil {
			log.Info("[FullScan] POC verify failed for %s: %v", target, err)
			continue
		}

		for _, result := range resp.Results {
			template := templateByTemplateID[result.TemplateID]
			pocID := int64(0)
			if template != nil {
				pocID = template.ID
			}

			if result.TemplateName == "" && template != nil {
				result.TemplateName = template.Name
			}
			if result.Severity == "" && template != nil {
				result.Severity = template.Severity
			}
			if result.Description == "" && template != nil {
				result.Description = template.Description
			}

			dbResult := &mysql.PocVerifyResult{
				Target:        target,
				PocID:         pocID,
				TemplateID:    result.TemplateID,
				TemplateName:  result.TemplateName,
				Matched:       result.Matched,
				Severity:      result.Severity,
				Description:   result.Description,
				Request:       sanitizeStringForMySQL(result.Request),
				Response:      sanitizeStringForMySQL(result.Response),
				MatchedAt:     result.MatchedAt,
				ExtractedData: result.ExtractedData,
				Error:         result.Error,
				VerifiedBy:    "system",
				VerifiedAt:    time.Now(),
			}
			if err := mysql.SavePocVerifyResult(dbResult); err != nil {
				log.Info("[FullScan] Save POC verify result failed: %v", err)
			}

			if result.Matched {
				matchedCount++
				if template != nil {
					_ = saveVulnerabilityFromPocResult(taskID, target, result, template)
				}
			}
		}
	}

	redisProgress.Progress = 100
	redisProgress.Message = fmt.Sprintf("POC verification completed, matched %d", matchedCount)
	redisdb.UpdateTaskProgress(taskID, *redisProgress)

	return nil
}

func saveVulnerabilityFromPocResult(taskID int, target string, result scanpoc.VerifyResult, template *mysql.PocTemplate) error {
	host, port, scheme := parseTargetHostPort(target)
	ip := ""
	if host != "" && net.ParseIP(host) != nil {
		ip = host
	}

	tags := parseJSONList(template.Tags)
	tagsStr := strings.Join(tags, ",")
	references := parseJSONList(template.Reference)
	refStr := strings.Join(references, ",")

	extractedData := ""
	if len(result.ExtractedData) > 0 {
		if data, err := json.Marshal(result.ExtractedData); err == nil {
			extractedData = string(data)
		}
	}

	vuln := map[string]interface{}{
		"task_id":           taskID,
		"target":            target,
		"ip":                ip,
		"port":              port,
		"service":           scheme,
		"name":              result.TemplateName,
		"description":       result.Description,
		"severity":          result.Severity,
		"type":              "poc",
		"cve":               template.CveID,
		"cwe":               template.CweID,
		"cvss":              template.CvssScore,
		"template_id":       result.TemplateID,
		"template_path":     template.FilePath,
		"author":            template.Author,
		"tags":              tagsStr,
		"reference":         refStr,
		"evidence_request":  result.Request,
		"evidence_response": result.Response,
		"matched_at":        result.MatchedAt,
		"extracted_data":    extractedData,
		"curl_command":      "",
		"metadata":          template.Metadata,
	}

	return mysql.SaveVulnerability(vuln)
}

func parseTargetHostPort(target string) (string, int, string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, "http"
	}

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err == nil {
			host := u.Hostname()
			port := 0
			if u.Port() != "" {
				fmt.Sscanf(u.Port(), "%d", &port)
			} else if u.Scheme == "https" {
				port = 443
			} else {
				port = 80
			}
			return host, port, u.Scheme
		}
	}

	if strings.Contains(target, ":") {
		host, portStr, err := net.SplitHostPort(target)
		if err == nil {
			port := 0
			fmt.Sscanf(portStr, "%d", &port)
			return host, port, "http"
		}
	}

	return target, 0, "http"
}

// sanitizeStringForMySQL 剔除字符串中非法的 UTF-8 字节序列，避免 MySQL utf8mb4 写入失败
func sanitizeStringForMySQL(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	// 逐字节扫描，保留合法 UTF-8 rune，报错 rune 替换为问号
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// 非法字节，跳过
			i++
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// runUDPScan 对存活目标并发执行 UDP 端口扫描并保存结果到 asset_port 表
// 注意：nmap -sU 需要 root/Administrator 权限才能运行
func runUDPScan(ctx context.Context, taskID int, aliveTargets []*servicecommon.Target, udpPorts string) {
	udpPortStr := udpPorts
	if strings.ToLower(udpPorts) == "udptop100" || udpPorts == "" {
		udpPortStr = scanport.GetUDPTop100Ports()
	}

	udpScanner := scanport.NewPortScanner(5*time.Minute, 10)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // UDP 扫描较慢，限制并发

	for _, t := range aliveTargets {
		ip := t.IP
		if ip == "" {
			ip = t.Host
		}
		if ip == "" {
			continue
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result, err := udpScanner.ScanUDPPorts(ctx, targetIP, udpPortStr)
			if err != nil {
				log.Info("[UDP扫描] %s 失败: %v", targetIP, err)
				return
			}

			// 保存 UDP 开放端口到 asset_port 表
			for _, p := range result.Ports {
				assetID, err := mysql.GetOrCreateAsset(targetIP, "ip")
				if err != nil {
					log.Info("[UDP扫描] 创建资产失败 %s: %v", targetIP, err)
					continue
				}

				assetPort := &model.AssetPort{
					TaskID:            taskID,
					AssetID:           &assetID,
					IP:                targetIP,
					Port:              int(p.Port),
					Protocol:          "udp",
					State:             p.State,
					ServiceName:       p.Service.Name,
					ServiceProduct:    p.Service.Product,
					ServiceVersion:    p.Service.Version,
					ServiceExtraInfo:  p.Service.ExtraInfo,
					ServiceHostname:   p.Service.Hostname,
					ServiceConfidence: p.Service.Confidence,
				}
				if err := mysql.SaveAssetPort(assetPort); err != nil {
					log.Info("[UDP扫描] 保存端口失败 %s:%d: %v", targetIP, p.Port, err)
				}
			}
			log.Info("[UDP扫描] %s 完成，发现 %d 个 UDP 开放端口", targetIP, result.OpenPorts)
		}(ip)
	}
	wg.Wait()
}
