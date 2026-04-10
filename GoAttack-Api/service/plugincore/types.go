package plugincore

import "context"

type Stage string

const (
	StageDirScan       Stage = "dir_scan"
	StageSubdomainEnum Stage = "subdomain_enum"
)

type Metadata struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Type           string `json:"type"`
	Description    string `json:"description"`
	Path           string `json:"path"`
	DefaultEnabled bool   `json:"default_enabled"`
	Order          int    `json:"order"`
}

type ExecContext struct {
	TaskID     int
	TaskType   string
	TaskTarget string
	Stage      Stage
	Targets    []string
}

type Plugin interface {
	Metadata() Metadata
	Stages() []Stage
	Run(ctx context.Context, execCtx *ExecContext) error
}
