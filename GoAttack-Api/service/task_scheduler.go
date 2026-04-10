package service

import (
	"GoAttack/common/log"
	"GoAttack/common/mysql"
	"GoAttack/model"
	"database/sql"
	"encoding/json"
	"time"
)

var chinaLocation = time.FixedZone("CST", 8*3600)

// StartTaskScheduler 启动定时任务调度器
func StartTaskScheduler() {
	go func() {
		for {
			time.Sleep(10 * time.Second)
			checkAndRunScheduledTasks()
		}
	}()
}

func checkAndRunScheduledTasks() {
	rows, err := mysql.GetPendingScheduledTasks()
	if err != nil {
		if err != sql.ErrNoRows {
			log.Warn("获取定时任务失败: %v", err)
		}
		return
	}
	defer rows.Close()

	now := time.Now().In(chinaLocation)
	for rows.Next() {
		var task model.Task
		var description, options sql.NullString
		var startedAt, completedAt sql.NullTime

		err := rows.Scan(
			&task.ID, &task.Name, &task.Target, &task.Type,
			&task.Status, &task.Progress, &task.Creator, &description,
			&options, &task.CreatedAt, &task.UpdatedAt,
			&startedAt, &completedAt,
		)
		if err != nil {
			log.Warn("解析定时任务数据失败: %v", err)
			continue
		}

		if options.Valid && options.String != "" {
			var opts model.ScanOptions
			err := json.Unmarshal([]byte(options.String), &opts)
			if err != nil {
				log.Warn("解析定时任务扫描选项失败 task_id=%d: %v", task.ID, err)
				continue
			}

			// 如果设置了调度时间
			if opts.ScheduledTime != "" {
				// 尝试解析，例如: "2026-03-01 12:00:00" 或者 "2026-03-01T12:00:00Z"
				scheduledTime, err := time.ParseInLocation("2006-01-02 15:04:05", opts.ScheduledTime, chinaLocation)
				if err != nil {
					// 尝试 ISO 格式
					scheduledTime, err = time.Parse(time.RFC3339, opts.ScheduledTime)
					if err != nil {
						log.Warn("定时任务时间格式错误 task_id=%d, scheduled_time=%s: %v", task.ID, opts.ScheduledTime, err)
						continue
					}
					scheduledTime = scheduledTime.In(chinaLocation)
				}

				if now.After(scheduledTime) || now.Equal(scheduledTime) {
					log.Info("定时任务到达执行时间, 开始启动任务: #%d %s", task.ID, task.Name)

					// 更新状态为 running
					mysql.UpdateTaskProgress(task.ID, "running", 0)

					// 开启 goroutine 异步执行
					go func(taskID int, target string, taskType string, options string) {
						err := ExecuteTask(taskID, target, taskType, options)
						if err != nil {
							log.Info("任务 #%d 执行失败: %v", taskID, err)
						}
					}(task.ID, task.Target, task.Type, options.String)
				}
			}
		}
	}
}
