package api

import (
	"GoAttack/api/admin"
	"GoAttack/api/dashboard"
	"GoAttack/api/dict"
	"GoAttack/api/notification"
	"GoAttack/api/plugin"
	"GoAttack/api/poc"
	"GoAttack/api/setting"
	"GoAttack/api/task"
	"GoAttack/api/tools"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()

	// 设置上传文件时的最大内存限制，默认是32MB，对于巨量的POC文件批量导入可能不够，扩大到 1GB
	r.MaxMultipartMemory = 1024 << 20
	// CORS 设置
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// 静态文件服务（用于访问上传的头像等文件）
	r.Static("/api/uploads", "./uploads")

	// 登录接口（公开，不需要认证）
	r.POST("/api/user/login", admin.Login)

	// 所有 /api/* 路径都需要认证
	api := r.Group("/api")
	api.Use(admin.AuthMiddleware())
	{
		// 用户管理
		admin.RegisterRoutes(api)

		// 任务管理
		task.RegisterRoutes(api)

		// 系统设置
		setting.RegisterRoutes(api)

		// POC 管理
		poc.RegisterRoutes(api)
		tools.RegisterRoutes(api)

		// 仪表盘
		dashboard.RegisterRoutes(api)

		// 插件管理
		plugin.RegisterRoutes(api)

		// 字典管理
		dict.RegisterRoutes(api)

		// 通知功能
		notification.RegisterRoutes(api)
	}

	return r
}
