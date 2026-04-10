package service

import (
	"GoAttack/common/log"
	"GoAttack/common/mysql"
	"GoAttack/service/plugincore"
)

func SyncBuiltinPlugins() error {
	for _, plugin := range plugincore.List() {
		meta := plugin.Metadata()
		if err := mysql.UpsertPlugin(mysql.Plugin{
			Name:        meta.Name,
			Version:     meta.Version,
			Type:        meta.Type,
			Enabled:     meta.DefaultEnabled,
			Description: meta.Description,
			Path:        meta.Path,
		}); err != nil {
			return err
		}
		log.Info("[PluginSync] Synced plugin: %s", meta.Name)
	}
	return nil
}
