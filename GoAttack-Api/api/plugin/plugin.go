package plugin

import (
	"GoAttack/common/mysql"
	"GoAttack/service"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes 注册插件相关路由
func RegisterRoutes(r *gin.RouterGroup) {
	r.GET("/plugin/list", GetPlugins)
	r.POST("/plugin/status", UpdatePluginStatus)
	r.POST("/plugin/config", UpdatePluginConfig)
	r.POST("/plugin/sync", SyncPlugins)
}

// SyncPlugins 同步本地插件到数据库
func SyncPlugins(c *gin.Context) {
	err := syncLocalPlugins()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "同步插件失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "success",
	})
}

func syncLocalPlugins() error {
	return service.SyncBuiltinPlugins()
}

// GetPlugins 获取插件列表
func GetPlugins(c *gin.Context) {
	// 每次查询前建议同步一下（或者也可以手动触发这个逻辑）
	syncLocalPlugins()

	name := c.Query("name")
	pluginType := c.Query("type")
	// 这里可以加上分页，目前直接查所有

	plugins, err := mysql.GetAllPlugins()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "获取失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 过滤
	var filtered []mysql.Plugin
	for _, p := range plugins {
		if name != "" && !strings.Contains(strings.ToLower(p.Name), strings.ToLower(name)) {
			continue
		}
		if pluginType != "" && p.Type != pluginType {
			continue
		}
		filtered = append(filtered, p)
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "success",
		"data": filtered,
	})
}

// UpdatePluginStatusRequest 更新状态请求
type UpdatePluginStatusRequest struct {
	ID      int  `json:"id" binding:"required"`
	Enabled bool `json:"enabled"`
}

// UpdatePluginStatus 启用/禁用插件
func UpdatePluginStatus(c *gin.Context) {
	var req UpdatePluginStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 40000, "msg": "参数错误 (" + err.Error() + ")"})
		return
	}

	err := mysql.UpdatePluginStatus(req.ID, req.Enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "更新状态失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "更新成功",
	})
}

// UpdatePluginConfigRequest 更新配置请求
type UpdatePluginConfigRequest struct {
	ID     int    `json:"id" binding:"required"`
	Config string `json:"config"`
}

// UpdatePluginConfig 更新插件配置
func UpdatePluginConfig(c *gin.Context) {
	var req UpdatePluginConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 40000, "msg": "参数错误 (" + err.Error() + ")"})
		return
	}

	err := mysql.UpdatePluginConfig(req.ID, req.Config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "更新配置失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "更新成功",
	})
}
