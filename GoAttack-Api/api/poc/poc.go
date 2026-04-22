package poc

import (
	"GoAttack/handler"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes 注册POC管理相关路由
func RegisterRoutes(r *gin.RouterGroup) {
	poc := r.Group("/poc")
	{
		// POC模板管理（注意：具体路径要放在参数路径之前）
		poc.GET("/templates/search", handler.SearchPocTemplates) // 搜索POC模板
		poc.GET("/templates/stats", handler.GetPocTemplateStats) // 获取POC统计信息
		poc.GET("/templates", handler.GetPocTemplateList)        // 获取POC模板列表
		poc.GET("/templates/:id", handler.GetPocTemplateDetail)  // 获取POC模板详情
		poc.PUT("/templates/:id", handler.UpdatePocTemplate)     // 更新POC模板
		poc.DELETE("/templates/:id", handler.DeletePocTemplate)  // 删除POC模板
		poc.DELETE("/batch-delete", handler.BatchDeletePocs)     // 批量删除POC

		// POC扫描和导入
		poc.POST("/scan-import", handler.ScanAndImportPocs)        // 扫描并导入POC模板
		poc.POST("/upload-directory", handler.UploadDirectoryPocs) // 前端上传目录导入

		// 手动导入
		poc.POST("/manual-import/save", handler.SaveManualPoc) // 保存手动导入的POC

		// HTTP请求包转YAML模板
		poc.POST("/convert-http", handler.ConvertHTTPToYaml) // HTTP请求包转Nuclei YAML

		// POC 验证
		poc.POST("/verify", handler.VerifyPoc) // 执行 POC 验证

		// POC 验证结果管理
		poc.GET("/verify-results", handler.GetPocVerifyResultList)               // 获取验证结果列表
		poc.GET("/verify-results/:id", handler.GetPocVerifyResultDetail)         // 获取验证结果详情
		poc.DELETE("/verify-results/clear", handler.ClearPocVerifyResults)       // 清空所有验证结果
		poc.DELETE("/verify-results/:id", handler.DeletePocVerifyResult)         // 删除验证结果
		poc.DELETE("/verify-results/batch", handler.BatchDeletePocVerifyResults) // 批量删除验证结果
	}
}
