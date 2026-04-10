package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MySQL 配置
var MySQLUser = getEnv("MYSQL_USER", "root")
var MySQLPassword = getEnv("MYSQL_PASSWORD", "goattack") // 请修改为你的密码
var MySQLHost = getEnv("MYSQL_HOST", "127.0.0.1")
var MySQLPort = getEnvInt("MYSQL_PORT", 3306)
var MySQLDBName = getEnv("MYSQL_DB", "goattack")

// Redis 配置
var RedisPassword = getEnv("REDIS_PASSWORD", "")
var RedisHost = getEnv("REDIS_HOST", "127.0.0.1")
var RedisPort = getEnvInt("REDIS_PORT", 6379)

// Redis Addr in format host:port for easier docker environment mapping
var RedisAddr = getEnv("REDIS_ADDR", "")

// JWT 配置
// 优先使用 JWT_SECRET 环境变量；未设置时读取/生成随机密钥并持久化到本地文件。
var JWTSecret = mustLoadJWTSecret()

func mustLoadJWTSecret() string {
	if secret := strings.TrimSpace(getEnv("JWT_SECRET", "")); secret != "" {
		return secret
	}

	secretFile := getEnv("JWT_SECRET_FILE", ".jwt_secret")
	if data, err := os.ReadFile(secretFile); err == nil {
		if secret := strings.TrimSpace(string(data)); secret != "" {
			return secret
		}
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("failed to generate JWT secret: %v", err))
	}
	secret := hex.EncodeToString(buf)

	if err := os.WriteFile(secretFile, []byte(secret), 0600); err != nil {
		panic(fmt.Sprintf("failed to persist JWT secret to %s: %v", secretFile, err))
	}

	return secret
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return fallback
}
