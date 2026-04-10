package mysql

import (
	"GoAttack/common/config"
	"database/sql"
	"fmt"
	"log"

	"os"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

// InitDB 初始化数据库连接
func InitDB() error {
	// 1. 先不指定数据库连接，用于创建数据库
	dsnWithoutDB := fmt.Sprintf("%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=Asia%%2FShanghai",
		config.MySQLUser,
		config.MySQLPassword,
		config.MySQLHost,
		config.MySQLPort,
	)

	tempDB, err := sql.Open("mysql", dsnWithoutDB)
	if err != nil {
		return fmt.Errorf("open mysql (without db) failed: %v", err)
	}

	if err = tempDB.Ping(); err != nil {
		tempDB.Close()
		return fmt.Errorf("ping mysql (without db) failed: %v", err)
	}

	// 2. 创建数据库（如果不存在）
	createDBQuery := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", config.MySQLDBName)
	if _, err := tempDB.Exec(createDBQuery); err != nil {
		tempDB.Close()
		return fmt.Errorf("create database failed: %v", err)
	}
	tempDB.Close()

	// 3. 连接到指定的数据库，并开启多语句支持以执行 init.sql
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Asia%%2FShanghai&multiStatements=true",
		config.MySQLUser,
		config.MySQLPassword,
		config.MySQLHost,
		config.MySQLPort,
		config.MySQLDBName,
	)

	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("open mysql failed: %v", err)
	}

	if err = DB.Ping(); err != nil {
		return fmt.Errorf("ping mysql failed: %v", err)
	}

	// 统一当前会话时区，确保 NOW()/TIMESTAMP 与中国时区一致。
	if _, err = DB.Exec("SET time_zone = '+08:00'"); err != nil {
		return fmt.Errorf("set mysql session time_zone failed: %v", err)
	}

	// 4. 检查是否需要初始化表结构
	if err := checkAndInitTables(); err != nil {
		return fmt.Errorf("init tables failed: %v", err)
	}

	// 自动创建新增的表（幂等，不影响已有数据）
	autoMigrate()

	log.Println("MySQL connected successfully")
	return nil
}

// checkAndInitTables 检查表是否存在，不存在则执行 init.sql
func checkAndInitTables() error {
	var tableName string
	// 检查 user 表是否存在
	err := DB.QueryRow("SELECT table_name FROM information_schema.tables WHERE table_schema = ? AND table_name = 'user' LIMIT 1", config.MySQLDBName).Scan(&tableName)
	if err == sql.ErrNoRows {
		// user 表不存在，需要执行 init.sql
		log.Println("Database tables not found, initializing from common/sql/init.sql...")
		sqlBytes, err := os.ReadFile("common/sql/init.sql")
		if err != nil {
			return fmt.Errorf("read init.sql failed: %v", err)
		}

		// 执行整个 sql 脚本
		if _, err := DB.Exec(string(sqlBytes)); err != nil {
			return fmt.Errorf("execute init.sql failed: %v", err)
		}
		log.Println("Database tables initialized successfully.")
		return nil
	} else if err != nil {
		return fmt.Errorf("check table existence failed: %v", err)
	}

	return nil
}

// autoMigrate 自动创建新增表（使用 CREATE TABLE IF NOT EXISTS，不影响已有数据）
func autoMigrate() {
	sqls := []string{
		`CREATE TABLE IF NOT EXISTS notification_read_time (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL UNIQUE COMMENT '用户名',
			last_read_at TIMESTAMP DEFAULT '2000-01-01 00:00:00' COMMENT '上次已读时间',
			last_cleared_at TIMESTAMP DEFAULT '2000-01-01 00:00:00' COMMENT '上次清空时间',
			INDEX idx_username (username)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='通知已读时间追踪表'`,
		`ALTER TABLE poc_template MODIFY COLUMN category VARCHAR(625) COMMENT '分类：cves/vulnerabilities/exposures/misconfiguration等'`,
	}
	for _, s := range sqls {
		if _, err := DB.Exec(s); err != nil {
			log.Printf("[AutoMigrate] 执行失败: %v", err)
		}
	}
}

// Close 关闭数据库连接
func Close() {
	if DB != nil {
		DB.Close()
	}
}
