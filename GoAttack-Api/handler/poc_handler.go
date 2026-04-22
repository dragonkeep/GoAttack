package handler

import (
	"GoAttack/common/log"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"GoAttack/common/mysql"
	scan_poc "GoAttack/service/scan_poc"

	"github.com/gin-gonic/gin"
)

// GetPocTemplateList 获取POC模板列表
func GetPocTemplateList(c *gin.Context) {
	// 获取分页参数
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	// 获取过滤参数
	filters := make(map[string]interface{})
	if name := c.Query("name"); name != "" {
		filters["name"] = name
	}
	if category := c.Query("category"); category != "" {
		filters["category"] = category
	}
	if severity := c.Query("severity"); severity != "" {
		// 将中文危害等级转换为英文（数据库存储的是英文）
		severityMap := map[string]string{
			"严重": "critical",
			"高危": "high",
			"中危": "medium",
			"低危": "low",
			"信息": "info",
		}
		if engSeverity, ok := severityMap[severity]; ok {
			filters["severity"] = engSeverity
		} else {
			filters["severity"] = severity // 如果是英文直接使用
		}
	}
	if cveID := c.Query("cve_id"); cveID != "" {
		filters["cve_id"] = cveID
	}
	if cnvdID := c.Query("cnvd_id"); cnvdID != "" {
		filters["cnvd_id"] = cnvdID
	}
	if protocol := c.Query("protocol"); protocol != "" {
		filters["protocol"] = protocol
	}
	if isActive := c.Query("is_active"); isActive != "" {
		filters["is_active"] = isActive == "true"
	}

	sort := c.DefaultQuery("sort", "id")
	order := c.DefaultQuery("order", "desc")

	// 查询数据
	pocs, total, err := mysql.ListPocTemplates(page, pageSize, filters, sort, order)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "获取POC列表失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 转换为响应格式（初始化为空数组，避免返回null）
	list := make([]mysql.PocTemplateListResponse, 0)
	for _, poc := range pocs {
		list = append(list, poc.ConvertToListResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "获取成功",
		"data": gin.H{
			"list":      list,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// GetPocTemplateDetail 获取POC模板详情
func GetPocTemplateDetail(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "无效的POC ID: " + err.Error(),
			"data": nil,
		})
		return
	}

	poc, err := mysql.GetPocTemplateByID(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "获取POC详情失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	if poc == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"code": 40400,
			"msg":  "POC不存在",
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "获取成功",
		"data": poc,
	})
}

// SearchPocTemplates 搜索POC模板
func SearchPocTemplates(c *gin.Context) {
	keyword := c.Query("keyword")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	pocs, total, err := mysql.SearchPocTemplates(keyword, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "搜索失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 转换为响应格式
	list := make([]mysql.PocTemplateListResponse, 0)
	for _, poc := range pocs {
		list = append(list, poc.ConvertToListResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "搜索成功",
		"data": gin.H{
			"list":      list,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// GetPocTemplateStats 获取POC统计信息
func GetPocTemplateStats(c *gin.Context) {
	stats, err := mysql.GetPocTemplateStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "获取统计信息失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "获取成功",
		"data": stats,
	})
}

// UpdatePocTemplate 更新POC模板
func UpdatePocTemplate(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "无效的POC ID: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 获取现有的 POC 模板
	poc, err := mysql.GetPocTemplateByID(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "获取POC失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	if poc == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"code": 40400,
			"msg":  "POC不存在",
			"data": nil,
		})
		return
	}

	// 接收更新数据
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 更新字段
	if val, ok := updates["is_active"].(bool); ok {
		poc.IsActive = val
	}
	if val, ok := updates["verified"].(bool); ok {
		poc.Verified = val
	}
	if val, ok := updates["template_content"].(string); ok {
		poc.TemplateContent = val
	}

	// 保存更新
	err = mysql.UpdatePocTemplate(poc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "更新失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "更新成功",
		"data": nil,
	})
}

// DeletePocTemplate 删除POC模板
func DeletePocTemplate(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "无效的POC ID: " + err.Error(),
			"data": nil,
		})
		return
	}

	err = mysql.DeletePocTemplate(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "删除失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "删除成功",
		"data": nil,
	})
}

// BatchDeletePocs 批量删除POC
func BatchDeletePocs(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	if err := mysql.BatchDeletePocTemplates(req.IDs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "批量删除失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "批量删除成功",
		"data": nil,
	})
}

// ScanAndImportPocs 扫描并导入POC模板
func ScanAndImportPocs(c *gin.Context) {
	var req struct {
		Path string `json:"path" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	scanner := scan_poc.NewPocScanner(req.Path)
	totalFiles, validFiles, err := scanner.ScanAndImport()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "导入失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "导入成功",
		"data": gin.H{
			"total_files": totalFiles,
			"valid_files": validFiles,
		},
	})
}

// UploadDirectoryPocs 接收前端上传的目录/多个文件并扫描导入
func UploadDirectoryPocs(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "获取上传文件失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	files := form.File["files"]
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "未选择文件夹或文件夹为空",
			"data": nil,
		})
		return
	}

	// 创建临时目录存放上传的POC
	tempDir, err := os.MkdirTemp("", "poc_upload_*")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 50000, "msg": "创建临时目录失败"})
		return
	}
	defer os.RemoveAll(tempDir)

	// 将所有文件保存到临时目录
	for _, file := range files {
		// 忽略非 yaml/yml 文件
		if !strings.HasSuffix(file.Filename, ".yaml") && !strings.HasSuffix(file.Filename, ".yml") {
			continue
		}
		baseName := filepath.Base(file.Filename)
		err := c.SaveUploadedFile(file, filepath.Join(tempDir, baseName))
		if err != nil {
			log.Error("保存文件失败: %v", err)
			continue
		}
	}

	// 调用扫描器扫描临时目录
	scanner := scan_poc.NewPocScanner(tempDir)
	totalFiles, validFiles, err := scanner.ScanAndImport()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "导入失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "导入成功",
		"data": gin.H{
			"total_files": totalFiles,
			"valid_files": validFiles,
		},
	})
}

// SaveManualPoc 保存手动输入的POC
func SaveManualPoc(c *gin.Context) {
	var req struct {
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 1. 解析模板内容
	scanner := scan_poc.NewPocScanner("")
	poc, err := scanner.ParseContent([]byte(req.Content), "manual")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 40000,
			"msg":  "POC模板解析失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 2. 创建手动导入文件夹（如果不存在）
	manualDir := "service/lib/templates/manual"
	if err := os.MkdirAll(manualDir, 0755); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 50000,
			"msg":  "创建目录失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 3. 保存到文件系统
	fileName := poc.TemplateID + ".yaml"
	filePath := manualDir + "/" + fileName
	if err := os.WriteFile(filePath, []byte(req.Content), 0644); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 50000,
			"msg":  "保存文件失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 4. 更新数据库信息
	poc.Category = "manual"
	poc.FilePath = "manual/" + fileName // 标记为手动导入类别

	if err := mysql.SavePocTemplate(poc); err != nil {
		// 区分重复导入错误和服务器错误
		if errors.Is(err, mysql.ErrDuplicatePoc) {
			c.JSON(http.StatusOK, gin.H{
				"code": 40000,
				"msg":  err.Error(),
				"data": nil,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"code": 50000,
			"msg":  "保存到数据库失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "手动导入并保存成功",
		"data": gin.H{
			"id":       poc.ID,
			"name":     poc.Name,
			"location": filePath,
		},
	})
}

// VerifyPoc 执行 POC 验证
func VerifyPoc(c *gin.Context) {
	var req scan_poc.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	targets := normalizeTargets(req.Targets, req.Target)
	if len(targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "目标地址不能为空",
			"data": nil,
		})
		return
	}

	// 验证 POC ID 列表
	if len(req.PocIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "POC ID 列表不能为空",
			"data": nil,
		})
		return
	}

	if req.ResultID > 0 && len(targets) > 1 {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "result_id 仅支持单目标验证",
			"data": nil,
		})
		return
	}

	// 创建 POC 验证器
	templatesDir := os.Getenv("NUCLEI_TEMPLATES_DIR")
	if templatesDir == "" {
		templatesDir = "service/lib/templates"
	}

	log.Info("[VerifyPoc] Creating verifier with templates dir: %s", templatesDir)

	verifier, err := scan_poc.NewPocVerifier(templatesDir)
	if err != nil {
		log.Error("[VerifyPoc] Error creating verifier: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "创建验证器失败: " + err.Error(),
			"data": nil,
		})
		return
	}
	defer verifier.Close()

	// 获取当前用户名
	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	if usernameStr == "" {
		usernameStr = "unknown"
	}

	allResults := make([]scan_poc.VerifyResult, 0)
	total := 0
	message := ""

	for _, target := range targets {
		subReq := req
		subReq.Target = target
		subReq.Targets = nil

		log.Info("[VerifyPoc] Starting verification for target: %s with %d POCs", target, len(req.PocIDs))

		// 执行验证
		resp, err := verifier.Verify(subReq)
		if err != nil {
			log.Error("[VerifyPoc] Verification error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"code": 50000,
				"msg":  "验证失败: " + err.Error(),
				"data": nil,
			})
			return
		}

		if message == "" {
			message = resp.Message
		}

		// 保存验证结果到数据库
		for i, result := range resp.Results {
			// 查找对应的 POC ID
			var pocID int64
			for _, id := range req.PocIDs {
				poc, err := mysql.GetPocTemplateByID(int64(id))
				if err == nil && poc != nil && poc.TemplateID == result.TemplateID {
					pocID = poc.ID
					break
				}
			}

			dbResult := &mysql.PocVerifyResult{
				Target:        target,
				PocID:         pocID,
				TemplateID:    result.TemplateID,
				TemplateName:  result.TemplateName,
				Matched:       result.Matched,
				Severity:      result.Severity,
				Description:   result.Description,
				Request:       result.Request,
				Response:      result.Response,
				MatchedAt:     result.MatchedAt,
				ExtractedData: result.ExtractedData,
				Error:         result.Error,
				VerifiedBy:    usernameStr,
				VerifiedAt:    time.Now(),
			}

			// 检查是否需要更新现有结果（重新验证）
			if req.ResultID > 0 {
				// 确保更新正确的记录
				// 在重新验证场景下，通常只验证单个POC
				dbResult.ID = req.ResultID
				if err := mysql.UpdatePocVerifyResult(dbResult); err != nil {
					log.Error("[VerifyPoc] 更新验证结果失败: %v", err)
				}
			} else {
				if err := mysql.SavePocVerifyResult(dbResult); err != nil {
					log.Error("[VerifyPoc] 保存验证结果失败: %v", err)
				}
			}

			// 将数据库ID赋值给返回结果，以便前端更新ID
			resp.Results[i].ID = dbResult.ID
		}

		allResults = append(allResults, resp.Results...)
		total += resp.Total
	}

	if message == "" {
		message = "Verification completed successfully"
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  message,
		"data": gin.H{
			"results": allResults,
			"total":   total,
		},
	})
}

func normalizeTargets(targets []string, target string) []string {
	if len(targets) == 0 && target != "" {
		targets = splitTargets(target)
	}
	if len(targets) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(targets))
	for _, value := range targets {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func splitTargets(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case '\n', '\r', ',', '，', ';', '；':
			return true
		default:
			return false
		}
	})
}

// GetPocVerifyResultList 获取POC验证结果列表
func GetPocVerifyResultList(c *gin.Context) {
	// 获取分页参数
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	// 获取过滤参数
	filters := make(map[string]interface{})
	if target := c.Query("target"); target != "" {
		filters["target"] = target
	}
	if pocID := c.Query("poc_id"); pocID != "" {
		if id, err := strconv.ParseInt(pocID, 10, 64); err == nil {
			filters["poc_id"] = id
		}
	}
	if templateID := c.Query("template_id"); templateID != "" {
		filters["template_id"] = templateID
	}
	if matched := c.Query("matched"); matched != "" {
		filters["matched"] = matched == "true"
	}
	if severity := c.Query("severity"); severity != "" {
		filters["severity"] = severity
	}

	// 查询数据
	results, total, err := mysql.ListPocVerifyResults(page, pageSize, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "获取验证结果列表失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 初始化为空数组避免返回null
	if results == nil {
		results = make([]*mysql.PocVerifyResult, 0)
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "获取成功",
		"data": gin.H{
			"list":      results,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// GetPocVerifyResultDetail 获取POC验证结果详情
func GetPocVerifyResultDetail(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "无效的结果ID: " + err.Error(),
			"data": nil,
		})
		return
	}

	result, err := mysql.GetPocVerifyResultByID(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "获取验证结果详情失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	if result == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"code": 40400,
			"msg":  "验证结果不存在",
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "获取成功",
		"data": result,
	})
}

// DeletePocVerifyResult 删除验证结果
func DeletePocVerifyResult(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "无效的结果ID: " + err.Error(),
			"data": nil,
		})
		return
	}

	err = mysql.DeletePocVerifyResult(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "删除失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "删除成功",
		"data": nil,
	})
}

// BatchDeletePocVerifyResults 批量删除验证结果
func BatchDeletePocVerifyResults(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	if err := mysql.BatchDeletePocVerifyResults(req.IDs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "批量删除失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "批量删除成功",
		"data": nil,
	})
}

// ClearPocVerifyResults 清空所有验证结果
func ClearPocVerifyResults(c *gin.Context) {
	if err := mysql.ClearPocVerifyResults(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "清空失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "清空成功",
		"data": nil,
	})
}
