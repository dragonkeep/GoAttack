package plugincore

import (
	"GoAttack/common/log"
	"GoAttack/common/mysql"
	"context"
	"strings"
)

func RunStage(ctx context.Context, execCtx *ExecContext) error {
	if execCtx == nil {
		return nil
	}
	if len(execCtx.Targets) == 0 && strings.TrimSpace(execCtx.TaskTarget) == "" {
		return nil
	}

	for _, plugin := range ListByStage(execCtx.Stage) {
		meta := plugin.Metadata()
		if !mysql.IsPluginEnabled(meta.Name) {
			log.Info("[PluginRuntime] plugin %s disabled, skip stage %s", meta.Name, execCtx.Stage)
			continue
		}
		if err := plugin.Run(ctx, execCtx); err != nil {
			log.Warn("[PluginRuntime] plugin %s failed at stage %s: %v", meta.Name, execCtx.Stage, err)
		}
	}

	return nil
}
