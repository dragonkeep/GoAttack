package native

import (
	"GoAttack/common/log"
	"GoAttack/service/plugincore"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type gobusterConfig struct {
	DirDict     string `json:"dir_dict"`
	DNSDict     string `json:"dns_dict"`
	Threads     string `json:"threads"`
	Timeout     string `json:"timeout"`
	StatusCodes string `json:"status_codes"`
}

type gobusterPlugin struct{}

func init() {
	plugincore.MustRegister(&gobusterPlugin{})
}

func (p *gobusterPlugin) Metadata() plugincore.Metadata {
	return plugincore.Metadata{
		Name:           "gobuster",
		Version:        "1.0.0",
		Type:           "scanner",
		Description:    "目录扫描和子域名爆破工具",
		Path:           "builtin:gobuster",
		DefaultEnabled: true,
		Order:          100,
	}
}

func (p *gobusterPlugin) Stages() []plugincore.Stage {
	return []plugincore.Stage{plugincore.StageDirScan, plugincore.StageSubdomainEnum}
}

func (p *gobusterPlugin) Run(ctx context.Context, execCtx *plugincore.ExecContext) error {
	if execCtx == nil || len(execCtx.Targets) == 0 {
		return nil
	}

	config := gobusterConfig{
		DirDict:     "fuzz_web.txt",
		DNSDict:     "subdomains_top1000.txt",
		Threads:     "10",
		Timeout:     "5s",
		StatusCodes: "200,204,301,302,307,401,403",
	}
	if err := plugincore.LoadConfig("gobuster", &config); err != nil {
		return err
	}

	execPath, err := resolveExecutablePath()
	if err != nil {
		log.Warn("[Gobuster Plugin] %v", err)
		return nil
	}

	scanType := ""
	dictName := ""
	sourceLabel := "GobusterPlugin"
	switch execCtx.Stage {
	case plugincore.StageDirScan:
		scanType = "dir"
		dictName = config.DirDict
	case plugincore.StageSubdomainEnum:
		scanType = "dns"
		dictName = config.DNSDict
	default:
		return nil
	}

	wordlist, err := plugincore.GetDictPath(dictName)
	if err != nil {
		log.Warn("[Gobuster Plugin] %v", err)
		return err
	}

	for _, target := range execCtx.Targets {
		cmdArgs, err := buildArgs(scanType, target, wordlist, config)
		if err != nil {
			log.Warn("[Gobuster Plugin] build args failed for %s: %v", target, err)
			continue
		}

		cmd := exec.CommandContext(ctx, execPath, cmdArgs...)
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		log.Info("[Gobuster Plugin] Running: %s %v", execPath, cmdArgs)
		err = cmd.Run()
		if err != nil && ctx.Err() == context.DeadlineExceeded {
			log.Warn("[Gobuster Plugin] Timeout for target %s", target)
			continue
		}

		parseAndPersist(execCtx.TaskID, target, scanType, sourceLabel, cmdArgs, out.String())
	}

	return nil
}

func resolveExecutablePath() (string, error) {
	pluginDir := "./service/plugins/gobuster"
	extension := ""
	if runtime.GOOS == "windows" {
		extension = ".exe"
	}
	execPath := filepath.Join(pluginDir, "gobuster"+extension)
	if _, err := os.Stat(execPath); err != nil {
		return "", fmt.Errorf("executable not found: %s", execPath)
	}
	return execPath, nil
}

func buildArgs(scanType string, target string, wordlist string, config gobusterConfig) ([]string, error) {
	switch scanType {
	case "dir":
		targetURL := target
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + targetURL
		}
		return []string{"dir", "-u", targetURL, "-w", wordlist, "-t", config.Threads, "-s", config.StatusCodes, "--status-codes-blacklist=", "-q", "--no-color", "--timeout", config.Timeout}, nil
	case "dns":
		domain := strings.TrimPrefix(target, "http://")
		domain = strings.TrimPrefix(domain, "https://")
		domain = strings.Split(domain, ":")[0]
		domain = strings.Split(domain, "/")[0]
		return []string{"dns", "-d", domain, "-w", wordlist, "-t", config.Threads, "-q", "--no-color", "--timeout", config.Timeout}, nil
	default:
		return nil, fmt.Errorf("unknown gobuster scan type: %s", scanType)
	}
}

func parseAndPersist(taskID int, target string, scanType string, sourceLabel string, cmdArgs []string, output string) {
	lines := strings.Split(output, "\n")
	foundItems := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		statusCode := 200
		if strings.Contains(line, "(Status:") {
			parts := strings.Split(line, "(Status:")
			if len(parts) > 1 {
				numParts := strings.Split(strings.TrimSpace(parts[1]), ")")
				if len(numParts) > 0 {
					fmt.Sscanf(numParts[0], "%d", &statusCode)
				}
			}
		}

		if scanType == "dir" && strings.Contains(line, "(Status:") {
			foundItems++
			pathPart := strings.TrimSpace(strings.Split(line, "(Status:")[0])
			if !strings.HasPrefix(pathPart, "/") {
				pathPart = "/" + pathPart
			}
			_ = plugincore.SaveDiscoveryResult(taskID, sourceLabel, targetURLFromArgs(cmdArgs), pathPart, plugincore.DiscoveryKindDirectory, statusCode)
		} else if scanType == "dns" && strings.HasPrefix(line, "Found:") {
			foundItems++
			_ = plugincore.SaveDiscoveryResult(taskID, sourceLabel, target, strings.TrimSpace(strings.TrimPrefix(line, "Found:")), plugincore.DiscoveryKindSubdomain, statusCode)
		}
	}
	log.Info("[Gobuster Plugin] Finished %s scan for %s. Found %d items.", scanType, target, foundItems)
}

func targetURLFromArgs(args []string) string {
	for i, arg := range args {
		if arg == "-u" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
