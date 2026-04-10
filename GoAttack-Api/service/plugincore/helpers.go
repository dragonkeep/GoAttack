package plugincore

import (
	"GoAttack/common/log"
	"GoAttack/common/mysql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func LoadConfig(name string, out any) error {
	if out == nil {
		return fmt.Errorf("config target cannot be nil")
	}

	config := strings.TrimSpace(mysql.GetPluginConfig(name))
	if config == "" {
		return nil
	}

	if err := json.Unmarshal([]byte(config), out); err != nil {
		return fmt.Errorf("parse plugin config %s failed: %w", name, err)
	}
	return nil
}

func GetDictPath(name string) (string, error) {
	dict, err := mysql.GetDictByName(name)
	if err != nil || dict.Path == "" {
		return "", fmt.Errorf("dictionary not found in DB: %s", name)
	}
	return dict.Path, nil
}

type DiscoveryKind string

const (
	DiscoveryKindDirectory DiscoveryKind = "Directory"
	DiscoveryKindSubdomain DiscoveryKind = "Subdomain"
)

func SaveDiscoveryResult(taskID int, sourceLabel string, target string, finding string, kind DiscoveryKind, statusCode int) error {
	url := finding
	if kind == DiscoveryKindDirectory {
		if strings.HasSuffix(target, "/") {
			target = strings.TrimSuffix(target, "/")
		}
		if !strings.HasPrefix(finding, "/") {
			finding = "/" + finding
		}
		url = target + finding
	} else if kind == DiscoveryKindSubdomain {
		url = "http://" + finding
	}

	serverType := fmt.Sprintf("目录扫描/%s", sourceLabel)
	if kind == DiscoveryKindSubdomain {
		serverType = fmt.Sprintf("子域名爆破/%s", sourceLabel)
	}

	assetValue := target
	if after := strings.TrimPrefix(assetValue, "http://"); after != assetValue {
		assetValue = strings.Split(after, "/")[0]
	} else if after := strings.TrimPrefix(assetValue, "https://"); after != assetValue {
		assetValue = strings.Split(after, "/")[0]
	}
	assetID, err := mysql.GetOrCreateAsset(assetValue, "ip")
	if err != nil {
		return fmt.Errorf("get/create asset failed for %s: %w", assetValue, err)
	}

	err = mysql.SaveWebFingerprint(
		taskID,
		assetID,
		nil,
		url,
		"",
		0,
		"",
		"",
		statusCode,
		serverType,
		"",
		0,
		0,
		[]string{sourceLabel},
		[]string{},
		[]string{},
		"",
		map[string]string{},
	)
	if err != nil {
		return err
	}

	if kind == DiscoveryKindDirectory && statusCode >= 300 && statusCode < 400 {
		go followRedirectAndSave(taskID, assetID, url, sourceLabel)
	}

	return nil
}

func followRedirectAndSave(taskID int, assetID int64, originalURL string, sourceLabel string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(originalURL)
	if err != nil {
		log.Warn("[PluginRuntime] follow redirect failed for %s: %v", originalURL, err)
		return
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	if finalURL == originalURL {
		return
	}

	buf := make([]byte, 65536)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	title := extractTitle(body)
	contentType := resp.Header.Get("Content-Type")

	headers := map[string]string{}
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}

	_ = mysql.SaveWebFingerprint(
		taskID,
		assetID,
		nil,
		finalURL,
		"",
		0,
		"",
		title,
		resp.StatusCode,
		resp.Header.Get("Server"),
		contentType,
		0,
		0,
		[]string{sourceLabel},
		[]string{},
		[]string{},
		"",
		headers,
	)
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}
