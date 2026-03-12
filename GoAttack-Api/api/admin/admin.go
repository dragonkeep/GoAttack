package admin

import (
	"GoAttack/common/mysql"
	"GoAttack/common/redis"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// RegisterRoutes 注册用户管理相关的所有路由
func RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/user/register", Register)       // 用户注册
	r.POST("/user/logout", Logout)           // 用户登出
	r.POST("/user/info", GetUserInfo)        // 获取用户信息
	r.POST("/user/password", ChangePassword) // 修改密码
	r.POST("/user/upload", UploadAvatar)     // 上传头像
}

func GenerateJWTSecretBytes(bits int) ([]byte, error) {
	key := make([]byte, bits/8)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// JWT密钥
var jwtSecret, _ = GenerateJWTSecretBytes(256)

// LoginRequest 登录请求结构体
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RegisterRequest 注册请求结构体
type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse 登录响应结构体
type LoginResponse struct {
	Token string `json:"token"`
}

// Claims JWT声明结构体
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Register 处理用户注册请求
func Register(c *gin.Context) {
	// 权限检查：只有管理员可以注册新用户
	role, exists := c.Get("role")
	if !exists || role != "admin" {
		c.JSON(403, gin.H{
			"code": 40300,
			"msg":  "只有管理员可以注册新用户",
			"data": nil,
		})
		return
	}

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 验证用户名长度
	if len(req.Username) < 3 || len(req.Username) > 20 {
		c.JSON(400, gin.H{
			"code": 40001,
			"msg":  "用户名长度必须在3-20个字符之间",
			"data": nil,
		})
		return
	}

	// 验证密码长度
	if len(req.Password) < 6 {
		c.JSON(400, gin.H{
			"code": 40002,
			"msg":  "密码长度至少为6位",
			"data": nil,
		})
		return
	}

	// 创建用户
	err := mysql.CreateUser(req.Username, req.Password)
	if err != nil {
		// 检查是否是用户已存在的错误
		if strings.Contains(err.Error(), "Duplicate") || strings.Contains(err.Error(), "已存在") {
			c.JSON(400, gin.H{
				"code": 40003,
				"msg":  "用户名已存在",
				"data": nil,
			})
			return
		}
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "注册失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 注册成功后自动登录，生成token
	token, err := generateToken(req.Username)
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50001,
			"msg":  "注册成功但生成token失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 将token存储到Redis
	if err := redis.SaveToken(req.Username, token, 24*time.Hour); err != nil {
		fmt.Printf("Warning: Failed to save token to redis: %v\n", err)
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "注册成功",
		"data": LoginResponse{Token: token},
	})
}

// Login 处理用户登录请求
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request body", "msg": err.Error()})
		return
	}

	// 验证用户名和密码
	valid := validateCredentials(req.Username, req.Password)
	if !valid {
		c.JSON(401, gin.H{"error": "Invalid credentials", "msg": "用户名或密码错误"})
		return
	}

	// 生成JWT令牌
	token, err := generateToken(req.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token", "msg": err.Error()})
		return
	}

	// 将token存储到Redis（24小时过期）
	if err := redis.SaveToken(req.Username, token, 24*time.Hour); err != nil {
		// 如果Redis存储失败，记录错误但不影响登录
		fmt.Printf("Warning: Failed to save token to redis: %v\n", err)
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "Login successful",
		"data": LoginResponse{Token: token},
	})
}

// Logout 处理用户登出请求
func Logout(c *gin.Context) {
	// 从上下文中获取用户名（如果使用了认证中间件）
	username, exists := c.Get("username")
	if exists {
		// 从 Redis 中删除 token
		if err := redis.DeleteToken(username.(string)); err != nil {
			fmt.Printf("Warning: Failed to delete token from redis: %v\n", err)
		}
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "Logout successful",
		"data": nil,
	})
}

// GetUserInfo 获取当前用户信息
func GetUserInfo(c *gin.Context) {
	// 从上下文中获取用户名（由认证中间件设置）
	username, exists := c.Get("username")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	// 从数据库获取用户头像
	avatar, err := mysql.GetUserAvatar(username.(string))
	if err != nil || avatar == "" {
		// 如果没有头像或获取失败，使用默认本地头像
		avatar = "/api/uploads/avatars/admin.jpg"
	}

	// 获取角色和ID
	role, _ := c.Get("role")
	if role == nil {
		role = "user"
	}
	uid, _ := mysql.GetUserID(username.(string))

	// 返回用户信息
	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "Success",
		"data": gin.H{
			"name":         username,
			"avatar":       avatar,
			"email":        fmt.Sprintf("%v@goattack.com", username),
			"job":          "Security Engineer",
			"jobName":      "安全工程师",
			"organization": "GoAttack Team",
			"location":     "China",
			"role":         role,
			"accountId":    uid,
		},
	})
}

// ChangePasswordRequest 修改密码请求结构体
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ChangePassword 处理修改密码请求
func ChangePassword(c *gin.Context) {
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
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 验证新密码长度
	if len(req.NewPassword) < 6 {
		c.JSON(400, gin.H{
			"code": 40001,
			"msg":  "密码长度至少为6位",
			"data": nil,
		})
		return
	}

	// 调用数据库更新密码
	err := mysql.UpdatePassword(username.(string), req.OldPassword, req.NewPassword)
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40002,
			"msg":  err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "密码修改成功",
		"data": nil,
	})
}

// AuthMiddleware JWT认证中间件
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取Authorization头部
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(401, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// 移除"Bearer "前缀
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		} else {
			c.JSON(401, gin.H{"error": "Authorization header format must be Bearer {token}"})
			c.Abort()
			return
		}

		// 解析JWT令牌
		claims, err := parseToken(tokenString)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token", "msg": err.Error()})
			c.Abort()
			return
		}

		// 验证token是否在Redis中存在（检查用户是否已登录）
		valid, err := redis.ValidateToken(claims.Username, tokenString)
		if err != nil || !valid {
			c.JSON(401, gin.H{"error": "Token not found or expired", "msg": "用户未登录或token已过期"})
			c.Abort()
			return
		}

		// 将用户信息存储到上下文中，供后续处理函数使用
		c.Set("username", claims.Username)

		// 获取并设置角色
		role, err := mysql.GetUserRole(claims.Username)
		if err == nil {
			c.Set("role", role)
		}

		c.Next()
	}
}

// validateCredentials 验证用户名和密码
func validateCredentials(username, password string) bool {
	// 从 MySQL 数据库验证用户
	valid, role, err := mysql.ValidateUser(username, password)
	if err != nil {
		fmt.Printf("Database error during validation: %v\n", err)
		return false
	}

	// 这里可以根据需要处理 role，或者直接返回验证结果
	_ = role
	return valid
}

// generateToken 生成JWT令牌
func generateToken(username string) (string, error) {
	// 设置令牌的声明
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // 24小时后过期
			Issuer:    "GoAttack-API",                                     // 发行人
		},
	}

	// 创建一个新的令牌对象
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 使用密钥签名并获得完整的编码令牌
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// parseToken 解析JWT令牌
func parseToken(tokenString string) (*Claims, error) {
	// 解析令牌
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	// 验证令牌并提取声明
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// UploadAvatar 处理头像上传
func UploadAvatar(c *gin.Context) {
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

	// 获取上传的文件
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "文件上传失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 验证文件类型
	ext := filepath.Ext(file.Filename)
	validExts := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
	}
	if !validExts[strings.ToLower(ext)] {
		c.JSON(400, gin.H{
			"code": 40001,
			"msg":  "只支持 JPG、JPEG、PNG、GIF 格式的图片",
			"data": nil,
		})
		return
	}

	// 限制文件大小（2MB）
	if file.Size > 2*1024*1024 {
		c.JSON(400, gin.H{
			"code": 40002,
			"msg":  "文件大小不能超过 2MB",
			"data": nil,
		})
		return
	}

	// 创建上传目录
	uploadDir := "uploads/avatars"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		fmt.Printf("创建上传目录失败: %v\n", err)
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "创建上传目录失败",
			"data": nil,
		})
		return
	}

	// 生成唯一文件名
	filename := fmt.Sprintf("%s_%d%s", username, time.Now().Unix(), ext)
	filePath := filepath.Join(uploadDir, filename)

	// 保存文件
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		fmt.Printf("保存文件失败: %v\n", err)
		c.JSON(500, gin.H{
			"code": 50001,
			"msg":  "保存文件失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 生成访问URL（相对路径，为了兼容 Docker 部署和域名部署）
	avatarURL := fmt.Sprintf("/api/uploads/avatars/%s", filename)

	// 更新数据库
	if err := mysql.UpdateUserAvatar(username.(string), avatarURL); err != nil {
		fmt.Printf("更新数据库失败: %v\n", err)
	}

	fmt.Printf("用户 %s 上传头像成功: %s (大小: %d)\n", username, filename, file.Size)

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "头像上传成功",
		"data": gin.H{
			"url": avatarURL,
		},
	})
}
