package plugincore

import (
	"fmt"
	"sort"
	"sync"
)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Plugin)
)

func Register(p Plugin) error {
	if p == nil {
		return fmt.Errorf("plugin is nil")
	}

	meta := p.Metadata()
	if meta.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[meta.Name]; exists {
		return fmt.Errorf("plugin already registered: %s", meta.Name)
	}

	registry[meta.Name] = p
	return nil
}

func MustRegister(p Plugin) {
	if err := Register(p); err != nil {
		panic(err)
	}
}

func List() []Plugin {
	registryMu.RLock()
	defer registryMu.RUnlock()

	plugins := make([]Plugin, 0, len(registry))
	for _, p := range registry {
		plugins = append(plugins, p)
	}
	return sortPlugins(plugins)
}

func ListByStage(stage Stage) []Plugin {
	registryMu.RLock()
	defer registryMu.RUnlock()

	plugins := make([]Plugin, 0)
	for _, p := range registry {
		for _, supportedStage := range p.Stages() {
			if supportedStage == stage {
				plugins = append(plugins, p)
				break
			}
		}
	}
	return sortPlugins(plugins)
}

func sortPlugins(plugins []Plugin) []Plugin {
	sorted := append([]Plugin(nil), plugins...)
	sort.Slice(sorted, func(i, j int) bool {
		left := sorted[i].Metadata()
		right := sorted[j].Metadata()
		if left.Order == right.Order {
			return left.Name < right.Name
		}
		return left.Order < right.Order
	})
	return sorted
}
