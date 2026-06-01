package task

import (
	"GoAttack/common/log"
	"GoAttack/common/mysql"
	"GoAttack/model"
	"GoAttack/service"
	scanport "GoAttack/service/scan_port"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/gin-gonic/gin"
)

func resolveChromeExecPath() string {
	if path := os.Getenv("CHROME_PATH"); path != "" {
		return path
	}
	if path := os.Getenv("CHROMEDP_EXEC_PATH"); path != "" {
		return path
	}

	for _, candidate := range []string{
		"chromium-browser",
		"chromium",
		"google-chrome-stable",
		"google-chrome",
	} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}

	return "chromium-browser"
}

// RegisterRoutes 注册任务管理相关的所有路由
func RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/task/create", CreateTask)                         // 创建任务
	r.GET("/task/ports/top1000", GetTopPorts)                  // 获取常见端口
	r.GET("/task/list", GetTaskList)                           // 获取任务列表
	r.GET("/task/:id", GetTaskDetail)                          // 获取任务详情
	r.POST("/task/export-pdf", ExportPDF)                      // 导出 PDF 报告
	r.PUT("/task/:id", UpdateTaskStatus)                       // 更新任务状态
	r.DELETE("/task/:id", DeleteTask)                          // 删除任务
	r.GET("/task/stats", GetTaskStats)                         // 获取任务统计
	r.POST("/task/:id/start", StartTask)                       // 启动任务
	r.POST("/task/:id/stop", StopTask)                         // 停止任务
	r.GET("/task/:id/results", GetTaskResults)                 // 获取任务扫描结果
	r.GET("/task/:id/vulnerabilities", GetTaskVulnerabilities) // 获取任务漏洞列表
	r.GET("/task/:id/progress", GetTaskRealtimeProgress)       // 获取任务实时进度
}

func GetTopPorts(c *gin.Context) {
	ports, err := scanport.GetTopPorts(1000)
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取端口列表失败: " + err.Error(),
			"data": nil,
		})
		return
	}
	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "获取端口列表成功",
		"data": gin.H{
			"ports": ports,
		},
	})
}

// CreateTask 创建新的漏洞扫描任务
func CreateTask(c *gin.Context) {
	// 从上下文获取当前用户
	username, exists := c.Get("username")
	if !exists {
		c.JSON(401, gin.H{
			"code": 40100,
			"msg":  "未认证用户",
			"data": nil,
		})
		return
	}

	// 解析请求参数
	var req model.CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 验证扫描类型
	validTypes := map[string]bool{
		"full":   true, // 全量扫描
		"quick":  true, // 快速扫描
		"custom": true, // 自定义扫描
		"alive":  true, // 存活扫描（保留兼容）
		"port":   true, // 端口扫描（保留兼容）
		"web":    true, // Web扫描（保留兼容）
		"vuln":   true, // 漏洞扫描（保留兼容）
	}
	if !validTypes[req.Type] {
		c.JSON(400, gin.H{
			"code": 40001,
			"msg":  "无效的扫描类型，支持的类型: full, quick, custom",
			"data": nil,
		})
		return
	}

	// 将扫描选项转换为JSON 字符串
	optionsJSON, err := json.Marshal(req.ScanOptions)
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40002,
			"msg":  "扫描选项格式错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	log.Info("创建任务 - 用户: %s, 目标: %s, 类型: %s, 选项: %s",
		username, req.Target, req.Type, string(optionsJSON))

	// 创建任务
	taskID, err := mysql.CreateTask(
		req.Name,
		req.Target,
		req.Type,
		username.(string),
		req.Description,
		string(optionsJSON),
	)
	if err != nil {
		log.Info("创建任务失败: %v", err)
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "创建任务失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "任务创建成功",
		"data": gin.H{
			"task_id": taskID,
		},
	})
}

// GetTaskList 获取任务列表
func GetTaskList(c *gin.Context) {
	// 从上下文获取当前用户
	username, exists := c.Get("username")
	if !exists {
		c.JSON(401, gin.H{
			"code": 40100,
			"msg":  "未认证用户",
			"data": nil,
		})
		return
	}

	// 获取分页参数
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("pageSize", "")
	if pageSizeStr == "" {
		pageSizeStr = c.DefaultQuery("page_size", "10")
	}

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	offset := (page - 1) * pageSize

	// 获取筛选参数
	name := c.Query("name")
	status := c.Query("status")
	taskType := c.Query("type")

	// 获取任务列表（带筛选）
	rows, err := mysql.GetTasksByCreatorWithFilter(username.(string), pageSize, offset, name, status, taskType)
	if err != nil {
		log.Info("获取任务列表失败: %v", err)
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取任务列表失败: " + err.Error(),
			"data": nil,
		})
		return
	}
	defer rows.Close()

	// 解析任务数据
	tasks := []model.Task{}
	for rows.Next() {
		var task model.Task
		var startedAt, completedAt sql.NullTime
		var description, options sql.NullString

		err := rows.Scan(
			&task.ID,
			&task.Name,
			&task.Target,
			&task.Type,
			&task.Status,
			&task.Progress,
			&task.Creator,
			&description,
			&options,
			&task.CreatedAt,
			&task.UpdatedAt,
			&startedAt,
			&completedAt,
		)
		if err != nil {
			log.Info("解析任务数据失败: %v", err)
			continue
		}

		// 处理可能为 NULL 的字段
		if description.Valid {
			task.Description = description.String
		}
		if options.Valid {
			task.Options = options.String
		}
		if startedAt.Valid {
			task.StartedAt = &startedAt.Time
		}
		if completedAt.Valid {
			task.CompletedAt = &completedAt.Time
		}

		tasks = append(tasks, task)
	}

	// 获取总数（应用筛选条件）
	total, err := mysql.CountTasksByCreatorWithFilter(username.(string), name, status, taskType)
	if err != nil {
		log.Info("获取任务总数失败: %v", err)
		total = 0
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "获取任务列表成功",
		"data": gin.H{
			"list":  tasks,
			"total": total,
		},
	})
}

// GetTaskDetail 获取任务详情
func GetTaskDetail(c *gin.Context) {
	// 从URL参数获取任务ID
	taskIDStr := c.Param("id")
	taskID, err := strconv.Atoi(taskIDStr)
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "无效的任务ID",
			"data": nil,
		})
		return
	}

	// 查询任务
	row, err := mysql.GetTaskByID(taskID)
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "查询任务失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	var task model.Task
	var startedAt, completedAt sql.NullTime
	var description, options sql.NullString

	err = row.Scan(
		&task.ID,
		&task.Name,
		&task.Target,
		&task.Type,
		&task.Status,
		&task.Progress,
		&task.Creator,
		&description,
		&options,
		&task.CreatedAt,
		&task.UpdatedAt,
		&startedAt,
		&completedAt,
	)
	if err == sql.ErrNoRows {
		c.JSON(404, gin.H{
			"code": 40400,
			"msg":  "任务不存在",
			"data": nil,
		})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取任务详情失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 处理可能为 NULL 的字段
	if description.Valid {
		task.Description = description.String
	}
	if options.Valid {
		task.Options = options.String
	}
	if startedAt.Valid {
		task.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		task.CompletedAt = &completedAt.Time
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "获取任务详情成功",
		"data": task,
	})
}

// UpdateTaskStatus 更新任务状态
func UpdateTaskStatus(c *gin.Context) {
	// 从URL参数获取任务ID
	taskIDStr := c.Param("id")
	taskID, err := strconv.Atoi(taskIDStr)
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "无效的任务ID",
			"data": nil,
		})
		return
	}

	// 解析更新参数
	var update model.TaskStatusUpdate
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 验证状态值
	validStatus := map[string]bool{
		"pending":   true,
		"running":   true,
		"completed": true,
		"failed":    true,
		"paused":    true,
	}
	if !validStatus[update.Status] {
		c.JSON(400, gin.H{
			"code": 40001,
			"msg":  "无效的任务状态",
			"data": nil,
		})
		return
	}

	// 更新任务
	if update.Result != "" {
		err = mysql.UpdateTaskResult(taskID, update.Status, update.Progress, update.Result)
	} else {
		err = mysql.UpdateTaskStatus(taskID, update.Status, update.Progress)
	}

	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "更新任务状态失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "任务状态更新成功",
		"data": nil,
	})
}

// DeleteTask 删除任务
func DeleteTask(c *gin.Context) {
	// 从URL参数获取任务ID
	taskIDStr := c.Param("id")
	taskID, err := strconv.Atoi(taskIDStr)
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "无效的任务ID",
			"data": nil,
		})
		return
	}

	// 删除任务
	err = mysql.DeleteTask(taskID)
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "删除任务失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "任务删除成功",
		"data": nil,
	})
}

// GetTaskStats 获取任务统计信息
func GetTaskStats(c *gin.Context) {
	// 从上下文获取当前用户
	username, exists := c.Get("username")
	if !exists {
		c.JSON(401, gin.H{
			"code": 40100,
			"msg":  "未认证用户",
			"data": nil,
		})
		return
	}

	// 获取用户的任务总数
	total, err := mysql.CountTasksByCreatorWithFilter(username.(string), "", "", "")
	if err != nil {
		log.Info("获取任务总数失败: %v", err)
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取任务统计失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "获取任务统计成功",
		"data": gin.H{
			"total":     total,
			"username":  username,
			"timestamp": time.Now(),
		},
	})
}

// StartTask 启动任务（将任务状态设置为running）
func StartTask(c *gin.Context) {
	// 从URL参数获取任务ID
	taskIDStr := c.Param("id")
	taskID, err := strconv.Atoi(taskIDStr)
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "无效的任务ID",
			"data": nil,
		})
		return
	}

	// 查询任务信息
	row, err := mysql.GetTaskByID(taskID)
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "查询任务失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	var task model.Task
	var startedAt, completedAt sql.NullTime
	var description, options sql.NullString

	err = row.Scan(
		&task.ID, &task.Name, &task.Target, &task.Type,
		&task.Status, &task.Progress, &task.Creator, &description,
		&options, &task.CreatedAt, &task.UpdatedAt,
		&startedAt, &completedAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(404, gin.H{
			"code": 40400,
			"msg":  "任务不存在",
			"data": nil,
		})
		return
	}

	if err != nil {
		log.Info("扫描任务数据失败: %v", err)
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取任务信息失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 处理可能为 NULL 的字段
	if description.Valid {
		task.Description = description.String
	}
	if options.Valid {
		task.Options = options.String
	}

	// 检查任务状态，不能启动正在运行的任务
	if task.Status == "running" {
		c.JSON(400, gin.H{
			"code": 40002,
			"msg":  "任务正在运行中，无法重新启动",
			"data": nil,
		})
		return
	}

	// 先同步更新状态，确保前端获取时状态已改变
	mysql.UpdateTaskProgress(taskID, "running", 0)

	// 异步执行扫描任务
	go func() {
		// 导入service包
		err := service.ExecuteTask(taskID, task.Target, task.Type, task.Options)
		if err != nil {
			log.Info("任务 #%d 执行失败: %v", taskID, err)
		}
	}()

	// 立即返回响应
	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "任务已启动",
		"data": gin.H{
			"task_id": taskID,
			"status":  "running",
		},
	})
}

// StopTask 停止任务
func StopTask(c *gin.Context) {
	// 从URL参数获取任务ID
	taskIDStr := c.Param("id")
	taskID, err := strconv.Atoi(taskIDStr)
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "无效的任务ID",
			"data": nil,
		})
		return
	}

	// 先查询任务当前状态
	row, err := mysql.GetTaskByID(taskID)
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "查询任务失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	var task model.Task
	var startedAt, completedAt sql.NullTime
	var description, options sql.NullString

	err = row.Scan(
		&task.ID, &task.Name, &task.Target, &task.Type,
		&task.Status, &task.Progress, &task.Creator, &description,
		&options, &task.CreatedAt, &task.UpdatedAt,
		&startedAt, &completedAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(404, gin.H{
			"code": 40400,
			"msg":  "任务不存在",
			"data": nil,
		})
		return
	}

	if err != nil {
		log.Info("扫描任务数据失败: %v", err)
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取任务信息失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 处理可能为 NULL 的字段
	if description.Valid {
		task.Description = description.String
	}
	if options.Valid {
		task.Options = options.String
	}

	// 只能停止正在运行的任务
	if task.Status != "running" {
		c.JSON(400, gin.H{
			"code": 40002,
			"msg":  fmt.Sprintf("任务当前状态为 %s，不能停止", task.Status),
			"data": nil,
		})
		return
	}

	// 尝试取消正在运行的扫描服务
	if !service.CancelTask(taskID) {
		log.Info("[API] 任务 #%d 扫描服务不在运行列表中，可能已接近完成，执行强制状态更新", taskID)
		// 即使服务不在内存中，也强制更新数据库状态为已停止
		err = mysql.UpdateTaskStatus(taskID, "stopped", task.Progress)
		if err != nil {
			c.JSON(500, gin.H{
				"code": 50000,
				"msg":  "停止任务失败: " + err.Error(),
				"data": nil,
			})
			return
		}
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "任务已停止",
		"data": gin.H{
			"task_id": taskID,
			"status":  "stopped",
		},
	})
}

// GetTaskResults 获取任务扫描结果 (资产测绘)
func GetTaskResults(c *gin.Context) {
	taskIDStr := c.Param("id")
	taskID, err := strconv.Atoi(taskIDStr)
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "无效的任务ID",
			"data": nil,
		})
		return
	}

	results := make([]map[string]interface{}, 0)

	// 1. 获取常规扫描结果 (端口/服务/存活)
	rows, err := mysql.GetAssetScanResultsByTaskID(taskID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, assetID int64
			var tID int
			var scanType, status, resultJSON string
			var scannedAt sql.NullTime
			var assetValue, assetType sql.NullString
			var isAlive sql.NullBool

			err = rows.Scan(
				&id, &tID, &assetID, &scanType, &status, &resultJSON, &scannedAt,
				&assetValue, &assetType, &isAlive,
			)
			if err != nil {
				log.Info("[API] 解析资产扫描结果失败: %v", err)
				continue
			}

			var detail map[string]interface{}
			if resultJSON != "" && resultJSON != "{}" {
				if err := json.Unmarshal([]byte(resultJSON), &detail); err != nil {
					log.Info("[API] 解析结果JSON失败: %v", err)
				}
			}

			results = append(results, map[string]interface{}{
				"id":         id,
				"task_id":    tID,
				"asset_id":   assetID,
				"scan_type":  scanType,
				"status":     status,
				"detail":     detail,
				"scanned_at": scannedAt.Time,
				"asset": map[string]interface{}{
					"value":      assetValue.String,
					"asset_type": assetType.String,
					"is_alive":   isAlive.Bool,
				},
			})
		}
	}

	// 2. 获取Web指纹扫描结果并整合进资产列表
	webRows, err := mysql.GetWebFingerprintsByTaskID(taskID)
	if err != nil {
		log.Info("[API] 获取Web指纹记录失败: %v", err)
	} else {
		defer webRows.Close()
		webCount := 0
		for webRows.Next() {
			webCount++
			var (
				id, assetID, statusCode, length, responseTime        int64
				portIDArr                                            sql.NullInt64
				taskIDVal, port                                      int
				url, ip, protocol                                    string
				title, server, contentType, fav                      sql.NullString
				techJSON, frameworksJSON, matchedRulesJSON, headJSON sql.NullString
				discoveredAt, lastChecked                            time.Time
			)

			// 注意：顺序必须与 mysql_web_fingerprint.go 中的 GetWebFingerprintsByTaskID SELECT 顺序一致
			err := webRows.Scan(
				&id, &taskIDVal, &assetID, &portIDArr,
				&url, &ip, &port, &protocol,
				&title, &statusCode, &server, &contentType, &length, &responseTime,
				&techJSON, &frameworksJSON, &matchedRulesJSON, &fav, &headJSON,
				&discoveredAt, &lastChecked,
			)
			if err != nil {
				log.Info("[API] 解析Web指纹记录失败 (ID: %d): %v", id, err)
				continue
			}

			// 转换 JSON 字段
			var techs, fws, mrs []string
			if techJSON.Valid && techJSON.String != "" {
				json.Unmarshal([]byte(techJSON.String), &techs)
			}
			if frameworksJSON.Valid && frameworksJSON.String != "" {
				json.Unmarshal([]byte(frameworksJSON.String), &fws)
			}
			if matchedRulesJSON.Valid && matchedRulesJSON.String != "" {
				json.Unmarshal([]byte(matchedRulesJSON.String), &mrs)
			}

			// 封装指纹明细
			headersMap := make(map[string]string)
			if headJSON.Valid && headJSON.String != "" {
				json.Unmarshal([]byte(headJSON.String), &headersMap)
			}

			normalizedURL := normalizeFingerprintURL(url, ip, port, protocol)
			fpDetail := map[string]interface{}{
				"url":           normalizedURL,
				"title":         title.String,
				"status_code":   statusCode,
				"server":        server.String,
				"technologies":  techs,
				"frameworks":    fws,
				"matched_rules": mrs,
				"favicon_hash":  fav.String,
				"headers":       headersMap,
				"response_time": responseTime,
			}

			// 检查是否已有该资产的任何扫描记录，如果有则合并 Web 指纹
			found := false
			for i, r := range results {
				if r["asset_id"] == assetID {
					detail, ok := r["detail"].(map[string]interface{})
					if !ok || detail == nil {
						detail = make(map[string]interface{})
					}

					// 提取或初始化 fingerprints 数组
					var fps []interface{}
					if existingFps, ok := detail["fingerprints"].([]interface{}); ok {
						fps = existingFps
					} else {
						fps = make([]interface{}, 0)
					}

					detail["fingerprints"] = append(fps, fpDetail)
					results[i]["detail"] = detail
					found = true
					break
				}
			}

			if !found {
				results = append(results, map[string]interface{}{
					"id":         id + 2000000, // 虚拟ID
					"task_id":    taskIDVal,
					"asset_id":   assetID,
					"scan_type":  "web",
					"status":     "success",
					"scanned_at": discoveredAt,
					"detail": map[string]interface{}{
						"fingerprints": []interface{}{fpDetail},
					},
					"asset": map[string]interface{}{
						"value":      ip,
						"asset_type": "ip",
						"is_alive":   true,
					},
				})
			}
		}
		log.Info("[API] 任务 %d 处理了 %d 条Web指纹记录", taskID, webCount)
	}

	for i := range results {
		detail, ok := results[i]["detail"].(map[string]interface{})
		if !ok || detail == nil {
			continue
		}

		rawFPs, ok := detail["fingerprints"].([]interface{})
		if !ok || len(rawFPs) == 0 {
			continue
		}

		seen := make(map[string]struct{}, len(rawFPs))
		filtered := make([]interface{}, 0, len(rawFPs))
		for _, item := range rawFPs {
			fp, ok := item.(map[string]interface{})
			if !ok || fp == nil {
				continue
			}

			urlVal := toString(fp["url"])
			titleVal := strings.TrimSpace(toString(fp["title"]))
			serverVal := strings.TrimSpace(toString(fp["server"]))
			statusCodeVal := toInt64(fp["status_code"])
			techs := normalizeStringSlice(fp["technologies"])
			frameworks := normalizeStringSlice(fp["frameworks"])
			matchedRules := normalizeStringSlice(fp["matched_rules"])

			if !isUsefulFingerprint(titleVal, serverVal, statusCodeVal, techs, frameworks, matchedRules) {
				continue
			}

			normalizedURL := normalizeFingerprintURL(urlVal, "", 0, "")
			if normalizedURL != "" {
				fp["url"] = normalizedURL
			}

			key := fingerprintDedupKey(
				normalizedURL,
				titleVal,
				serverVal,
				statusCodeVal,
				techs,
				frameworks,
				matchedRules,
			)
			if _, exists := seen[key]; exists {
				continue
			}

			seen[key] = struct{}{}
			filtered = append(filtered, fp)
		}

		detail["fingerprints"] = filtered
		results[i]["detail"] = detail
	}
	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "获取扫描结果成功",
		"data": results,
	})
}

// GetTaskVulnerabilities 获取任务发现的漏洞
func normalizeFingerprintURL(rawURL, ip string, port int, protocol string) string {
	url := strings.TrimSpace(rawURL)
	proto := strings.ToLower(strings.TrimSpace(protocol))
	if proto != "http" && proto != "https" {
		proto = "http"
	}

	if url == "" {
		host := strings.TrimSpace(ip)
		if host == "" {
			return ""
		}
		if port > 0 && !isDefaultWebPort(proto, port) {
			return fmt.Sprintf("%s://%s:%d", proto, host, port)
		}
		return fmt.Sprintf("%s://%s", proto, host)
	}

	lowerURL := strings.ToLower(url)
	if strings.HasPrefix(lowerURL, "http://") || strings.HasPrefix(lowerURL, "https://") {
		return url
	}

	if strings.Contains(url, "/") || strings.Contains(url, ":") {
		return fmt.Sprintf("%s://%s", proto, url)
	}

	if port > 0 && !isDefaultWebPort(proto, port) {
		return fmt.Sprintf("%s://%s:%d", proto, url, port)
	}
	return fmt.Sprintf("%s://%s", proto, url)
}

func isDefaultWebPort(protocol string, port int) bool {
	return (protocol == "http" && port == 80) || (protocol == "https" && port == 443)
}

func isUsefulFingerprint(
	title string,
	server string,
	statusCode int64,
	technologies []string,
	frameworks []string,
	matchedRules []string,
) bool {
	if len(technologies) > 0 || len(frameworks) > 0 || len(matchedRules) > 0 {
		return true
	}
	if strings.TrimSpace(title) != "" || strings.TrimSpace(server) != "" {
		return true
	}
	return statusCode > 0
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

func toInt64(v interface{}) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case json.Number:
		if num, err := t.Int64(); err == nil {
			return num
		}
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func normalizeStringSlice(v interface{}) []string {
	items := make([]string, 0)
	switch t := v.(type) {
	case []string:
		for _, s := range t {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				items = append(items, trimmed)
			}
		}
	case []interface{}:
		for _, item := range t {
			trimmed := strings.TrimSpace(toString(item))
			if trimmed != "" {
				items = append(items, trimmed)
			}
		}
	}

	if len(items) == 0 {
		return items
	}

	seen := make(map[string]struct{}, len(items))
	unique := make([]string, 0, len(items))
	for _, item := range items {
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, item)
	}
	sort.Strings(unique)
	return unique
}

func fingerprintDedupKey(
	url string,
	title string,
	server string,
	statusCode int64,
	technologies []string,
	frameworks []string,
	matchedRules []string,
) string {
	return strings.ToLower(strings.TrimSpace(url)) + "|" +
		strings.ToLower(strings.TrimSpace(title)) + "|" +
		strings.ToLower(strings.TrimSpace(server)) + "|" +
		strconv.FormatInt(statusCode, 10) + "|" +
		strings.Join(technologies, ",") + "|" +
		strings.Join(frameworks, ",") + "|" +
		strings.Join(matchedRules, ",")
}

func GetTaskVulnerabilities(c *gin.Context) {
	taskIDStr := c.Param("id")
	taskID, err := strconv.Atoi(taskIDStr)
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "无效的任务ID",
			"data": nil,
		})
		return
	}

	rows, err := mysql.GetVulnerabilitiesByTaskID(taskID)
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取漏洞列表失败: " + err.Error(),
			"data": nil,
		})
		return
	}
	defer rows.Close()

	vulns := []map[string]interface{}{}
	for rows.Next() {
		var id, tID, port int
		var target, ip, service, name, description, severity, vulnType string
		var cve, cwe string
		var cvss float64
		var templateID, templatePath, author, tags, reference string
		var evidenceReq, evidenceResp, matchedAt, extractedData, curlCommand string
		var metadata string
		var discoveredAt time.Time

		err = rows.Scan(
			&id, &tID, &target, &ip, &port, &service,
			&name, &description, &severity, &vulnType,
			&cve, &cwe, &cvss,
			&templateID, &templatePath, &author, &tags, &reference,
			&evidenceReq, &evidenceResp, &matchedAt, &extractedData, &curlCommand,
			&metadata, &discoveredAt,
		)
		if err != nil {
			log.Info("解析漏洞数据失败: %v", err)
			continue
		}

		vulns = append(vulns, map[string]interface{}{
			"id":                id,
			"task_id":           tID,
			"target":            target,
			"ip":                ip,
			"port":              port,
			"service":           service,
			"name":              name,
			"description":       description,
			"severity":          severity,
			"type":              vulnType,
			"cve":               cve,
			"cwe":               cwe,
			"cvss":              cvss,
			"template_id":       templateID,
			"template_path":     templatePath,
			"author":            author,
			"tags":              tags,
			"reference":         reference,
			"evidence_request":  evidenceReq,
			"evidence_response": evidenceResp,
			"matched_at":        matchedAt,
			"extracted_data":    extractedData,
			"curl_command":      curlCommand,
			"metadata":          metadata,
			"discovered_at":     discoveredAt,
		})
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "获取漏洞列表成功",
		"data": vulns,
	})
}

// ExportPDF 接收前端传来的 HTML，使用 Chromedp 生成高清 PDF
func ExportPDF(c *gin.Context) {
	var req struct {
		HTML string `json:"html"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "message": "参数错误"})
		return
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(resolveChromeExecPath()),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel2 := chromedp.NewContext(allocCtx)
	defer cancel2()

	ctx, cancel3 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel3()

	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		// 设定内容
		chromedp.ActionFunc(func(ctx context.Context) error {
			frameTree, err := page.GetFrameTree().Do(ctx)
			if err != nil {
				return err
			}
			return page.SetDocumentContent(frameTree.Frame.ID, req.HTML).Do(ctx)
		}),
		// 生成PDF
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			buf, _, err = page.PrintToPDF().
				WithPrintBackground(true).
				WithMarginTop(0).
				WithMarginBottom(0).
				WithMarginLeft(0).
				WithMarginRight(0).
				Do(ctx)
			return err
		}),
	)
	if err != nil {
		log.Errorf("生成 PDF 失败: %v", err)
		c.JSON(500, gin.H{"code": 500, "message": "PDF 生成失败"})
		return
	}

	c.Header("Content-Disposition", `attachment; filename="report.pdf"`)
	c.Data(200, "application/pdf", buf)
}
