package native

import (
	"GoAttack/common/log"
	"GoAttack/common/mysql"
	"GoAttack/service/plugincore"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ossScannerConfig struct {
	MaxTargets        int    `json:"max_targets"`
	MaxBucketPerPage  int    `json:"max_bucket_per_page"`
	RequestTimeoutSec int    `json:"request_timeout_sec"`
	EnableUploadProbe bool   `json:"enable_upload_probe"`
	EnableOverwriteProbe bool `json:"enable_overwrite_probe"`
	TestPathPrefix    string `json:"test_path_prefix"`
	UserAgent         string `json:"user_agent"`
}

type ossScannerPlugin struct{}

const (
	ossScannerName   = "oss_scaner"
	ossScannerSource = "OSSScannerPlugin"
	maxEvidenceResponseChars = 12000
)

var urlPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

func init() {
	plugincore.MustRegister(&ossScannerPlugin{})
}

func (p *ossScannerPlugin) Metadata() plugincore.Metadata {
	return plugincore.Metadata{
		Name:           ossScannerName,
		Version:        "1.0.0",
		Type:           "scanner",
		Description:    "扫描页面中的对象存储链接并探测匿名访问风险",
		Path:           "builtin:oss_scaner",
		DefaultEnabled: true,
		Order:          120,
	}
}

func (p *ossScannerPlugin) Stages() []plugincore.Stage {
	return []plugincore.Stage{plugincore.StageDirScan}
}

func (p *ossScannerPlugin) Run(ctx context.Context, execCtx *plugincore.ExecContext) error {
	if execCtx == nil {
		return nil
	}

	config := ossScannerConfig{
		MaxTargets:        100,
		MaxBucketPerPage:  20,
		RequestTimeoutSec: 8,
		EnableUploadProbe: true,
		EnableOverwriteProbe: false,
		TestPathPrefix:    "goattack-oss-probe",
		UserAgent:         "GoAttack-OSSScanner/1.0",
	}
	if err := plugincore.LoadConfig(ossScannerName, &config); err != nil {
		return err
	}

	if config.MaxTargets <= 0 {
		config.MaxTargets = 100
	}
	if config.MaxBucketPerPage <= 0 {
		config.MaxBucketPerPage = 20
	}
	if config.RequestTimeoutSec <= 0 {
		config.RequestTimeoutSec = 8
	}
	if strings.TrimSpace(config.TestPathPrefix) == "" {
		config.TestPathPrefix = "goattack-oss-probe"
	}
	if strings.TrimSpace(config.UserAgent) == "" {
		config.UserAgent = "GoAttack-OSSScanner/1.0"
	}

	client := &http.Client{Timeout: time.Duration(config.RequestTimeoutSec) * time.Second}
	processedTargets := 0

	targetCandidates := make([]string, 0, len(execCtx.Targets)+1)
	targetCandidates = append(targetCandidates, execCtx.Targets...)
	if strings.TrimSpace(execCtx.TaskTarget) != "" {
		targetCandidates = append(targetCandidates, execCtx.TaskTarget)
	}

	uniqueTargets := make([]string, 0, len(targetCandidates))
	seenTargets := make(map[string]struct{})
	for _, raw := range targetCandidates {
		normalized := normalizeTargetURL(raw)
		if normalized == "" {
			continue
		}
		if _, ok := seenTargets[normalized]; ok {
			continue
		}
		seenTargets[normalized] = struct{}{}
		uniqueTargets = append(uniqueTargets, normalized)
	}

	for _, targetURL := range uniqueTargets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if processedTargets >= config.MaxTargets {
			break
		}

		pageBody, err := fetchPageBody(ctx, client, targetURL, config.UserAgent)
		if err != nil {
			continue
		}

		buckets := extractBucketURLs(pageBody)
		if len(buckets) == 0 {
			processedTargets++
			continue
		}

		if len(buckets) > config.MaxBucketPerPage {
			buckets = buckets[:config.MaxBucketPerPage]
		}

		for _, bucketURL := range buckets {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			p.probeBucket(ctx, client, execCtx.TaskID, targetURL, bucketURL, &config)
		}

		processedTargets++
	}

	return nil
}

func normalizeTargetURL(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "http://" + target
}

func fetchPageBody(ctx context.Context, client *http.Client, targetURL string, userAgent string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func extractBucketURLs(pageBody string) []string {
	all := urlPattern.FindAllString(pageBody, -1)
	if len(all) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	results := make([]string, 0)
	for _, raw := range all {
		raw = strings.TrimSpace(strings.TrimRight(raw, ").,;"))
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		if !isLikelyBucketHost(strings.ToLower(u.Host)) {
			continue
		}
		u.RawQuery = ""
		u.Fragment = ""
		clean := u.String()
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		results = append(results, clean)
	}

	sort.Strings(results)
	return results
}

func isLikelyBucketHost(host string) bool {
	switch {
	case strings.Contains(host, ".amazonaws.com"):
		return true
	case strings.Contains(host, ".aliyuncs.com"):
		return true
	case strings.Contains(host, ".myqcloud.com"):
		return true
	case strings.Contains(host, ".myhuaweicloud.com"):
		return true
	case strings.Contains(host, ".blob.core.windows.net"):
		return true
	case strings.Contains(host, "storage.googleapis.com"):
		return true
	default:
		return false
	}
}

func (p *ossScannerPlugin) probeBucket(ctx context.Context, client *http.Client, taskID int, sourceURL string, bucketURL string, config *ossScannerConfig) {
	statusCode, headers, body, err := doGet(ctx, client, bucketURL, config.UserAgent)
	if err != nil {
		return
	}

	isPublicRead := statusCode == http.StatusOK && seemsBucketListing(body)
	if isPublicRead {
		responsePacket := buildHTTPResponsePacket(statusCode, headers, body)
		p.saveFinding(taskID, sourceURL, bucketURL, statusCode, "public-read", nil)
		p.saveFindingAsVulnerability(taskID, sourceURL, bucketURL, statusCode, "public-read", nil, responsePacket)
	}

	if !config.EnableUploadProbe {
		return
	}

	uploadURL, marker := buildUploadProbeURL(bucketURL, config.TestPathPrefix)
	writeStatus, uploaded, verifyStatus := tryUploadProbe(ctx, client, uploadURL, marker, config.UserAgent)
	if uploaded {
		headers := map[string]string{
			"upload_status": fmt.Sprintf("%d", writeStatus),
			"verify_status": fmt.Sprintf("%d", verifyStatus),
		}
		responsePacket := fmt.Sprintf("HTTP/1.1 %d %s\nUpload probe verify status: %d", writeStatus, http.StatusText(writeStatus), verifyStatus)
		p.saveFinding(taskID, sourceURL, uploadURL, writeStatus, "public-write", headers)
		p.saveFindingAsVulnerability(taskID, sourceURL, uploadURL, writeStatus, "public-write", headers, responsePacket)

		if config.EnableOverwriteProbe {
			overwriteStatus, overwritten, overwriteVerifyStatus := tryOverwriteProbe(ctx, client, uploadURL, config.UserAgent)
			if overwritten {
				overwriteHeaders := map[string]string{
					"overwrite_status":        fmt.Sprintf("%d", overwriteStatus),
					"overwrite_verify_status": fmt.Sprintf("%d", overwriteVerifyStatus),
				}
				overwritePacket := fmt.Sprintf("HTTP/1.1 %d %s\nOverwrite probe verify status: %d", overwriteStatus, http.StatusText(overwriteStatus), overwriteVerifyStatus)
				p.saveFinding(taskID, sourceURL, uploadURL, overwriteStatus, "object-overwrite", overwriteHeaders)
				p.saveFindingAsVulnerability(taskID, sourceURL, uploadURL, overwriteStatus, "object-overwrite", overwriteHeaders, overwritePacket)
			}
		}

		_ = tryDeleteProbe(ctx, client, uploadURL, config.UserAgent)
	}
}

func doGet(ctx context.Context, client *http.Client, targetURL string, userAgent string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.StatusCode, resp.Header.Clone(), body, nil
}

func seemsBucketListing(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "listbucketresult") || strings.Contains(lower, "<contents>") || strings.Contains(lower, "<commonprefixes>")
}

func buildUploadProbeURL(bucketURL string, prefix string) (string, string) {
	u, err := url.Parse(bucketURL)
	if err != nil {
		return bucketURL, ""
	}

	basePath := strings.TrimSuffix(u.Path, "/")
	if basePath == "" {
		basePath = "/"
	}

	key := fmt.Sprintf("%s-%d.txt", prefix, time.Now().UnixNano())
	if basePath == "/" {
		u.Path = "/" + key
	} else {
		u.Path = basePath + "/" + key
	}
	u.RawQuery = ""
	u.Fragment = ""

	marker := fmt.Sprintf("goattack-oss-upload-probe-%d", time.Now().UnixNano())
	return u.String(), marker
}

func tryUploadProbe(ctx context.Context, client *http.Client, uploadURL string, marker string, userAgent string) (int, bool, int) {
	body := []byte(marker)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(body))
	if err != nil {
		return 0, false, 0
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return 0, false, 0
	}
	defer resp.Body.Close()

	writeStatus := resp.StatusCode
	if writeStatus != http.StatusOK && writeStatus != http.StatusCreated && writeStatus != http.StatusNoContent {
		return writeStatus, false, 0
	}

	verifyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, uploadURL, nil)
	if err != nil {
		return writeStatus, true, 0
	}
	verifyReq.Header.Set("User-Agent", userAgent)

	verifyResp, err := client.Do(verifyReq)
	if err != nil {
		return writeStatus, true, 0
	}
	defer verifyResp.Body.Close()

	verifyBody, _ := io.ReadAll(io.LimitReader(verifyResp.Body, 4096))
	if verifyResp.StatusCode == http.StatusOK && bytes.Contains(verifyBody, []byte(marker)) {
		return writeStatus, true, verifyResp.StatusCode
	}

	return writeStatus, false, verifyResp.StatusCode
}

func tryOverwriteProbe(ctx context.Context, client *http.Client, uploadURL string, userAgent string) (int, bool, int) {
	overwriteMarker := fmt.Sprintf("goattack-oss-overwrite-probe-%d", time.Now().UnixNano())
	body := []byte(overwriteMarker)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(body))
	if err != nil {
		return 0, false, 0
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return 0, false, 0
	}
	defer resp.Body.Close()

	overwriteStatus := resp.StatusCode
	if overwriteStatus != http.StatusOK && overwriteStatus != http.StatusCreated && overwriteStatus != http.StatusNoContent {
		return overwriteStatus, false, 0
	}

	verifyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, uploadURL, nil)
	if err != nil {
		return overwriteStatus, false, 0
	}
	verifyReq.Header.Set("User-Agent", userAgent)

	verifyResp, err := client.Do(verifyReq)
	if err != nil {
		return overwriteStatus, false, 0
	}
	defer verifyResp.Body.Close()

	verifyBody, _ := io.ReadAll(io.LimitReader(verifyResp.Body, 4096))
	if verifyResp.StatusCode == http.StatusOK && bytes.Contains(verifyBody, []byte(overwriteMarker)) {
		return overwriteStatus, true, verifyResp.StatusCode
	}

	return overwriteStatus, false, verifyResp.StatusCode
}

func tryDeleteProbe(ctx context.Context, client *http.Client, uploadURL string, userAgent string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uploadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("delete probe file failed: status=%d", resp.StatusCode)
}

func (p *ossScannerPlugin) saveFinding(taskID int, sourceURL string, findingURL string, statusCode int, riskTag string, extraHeaders map[string]string) {
	parsedSource, err := url.Parse(sourceURL)
	if err != nil {
		return
	}

	assetValue := parsedSource.Hostname()
	if assetValue == "" {
		return
	}

	assetID, err := mysql.GetOrCreateAsset(assetValue, "ip")
	if err != nil {
		log.Warn("[OSSScanner Plugin] get/create asset failed for %s: %v", assetValue, err)
		return
	}

	headers := map[string]string{
		"source_url": sourceURL,
		"risk_tag":   riskTag,
	}
	for k, v := range extraHeaders {
		headers[k] = v
	}

	if err = mysql.SaveWebFingerprint(
		taskID,
		assetID,
		nil,
		findingURL,
		"",
		0,
		"",
		"OSS bucket exposure",
		statusCode,
		"对象存储暴露/"+ossScannerSource,
		"text/plain",
		0,
		0,
		[]string{ossScannerSource, riskTag},
		[]string{},
		[]string{},
		"",
		headers,
	); err != nil {
		log.Warn("[OSSScanner Plugin] save finding failed: %v", err)
	}
}

func (p *ossScannerPlugin) saveFindingAsVulnerability(taskID int, sourceURL string, findingURL string, statusCode int, riskTag string, extraHeaders map[string]string, responsePacket string) {
	severity, cvss := severityForRiskTag(riskTag)
	vulnName := vulnNameForRiskTag(riskTag)

	meta := map[string]interface{}{
		"source":      ossScannerSource,
		"source_url":  sourceURL,
		"finding_url": findingURL,
		"risk_tag":    riskTag,
		"status_code": statusCode,
	}
	for k, v := range extraHeaders {
		meta[k] = v
	}
	metaJSON, _ := json.Marshal(meta)

	referencesJSON, _ := json.Marshal([]string{findingURL})
	tagsJSON, _ := json.Marshal([]string{"oss", riskTag})

	parsed, _ := url.Parse(findingURL)
	service := "http"
	if parsed != nil && parsed.Scheme != "" {
		service = parsed.Scheme
	}

	vuln := map[string]interface{}{
		"task_id":           taskID,
		"target":            findingURL,
		"ip":                "",
		"port":              0,
		"service":           service,
		"name":              vulnName,
		"description":       fmt.Sprintf("在页面 %s 中提取到对象存储地址 %s，并检测到 %s 风险。", sourceURL, findingURL, riskTag),
		"severity":          severity,
		"type":              "oss-exposure",
		"cve":               "",
		"cwe":               "",
		"cvss":              cvss,
		"template_id":       "oss-scaner/" + riskTag,
		"template_path":     "builtin:oss_scaner",
		"author":            "GoAttack",
		"tags":              string(tagsJSON),
		"reference":         string(referencesJSON),
		"evidence_request":  "",
		"evidence_response": truncateResponse(responsePacket),
		"matched_at":        sourceURL,
		"extracted_data":    string(metaJSON),
		"curl_command":      fmt.Sprintf("curl -i \"%s\"", findingURL),
		"metadata":          string(metaJSON),
	}

	if err := mysql.SaveVulnerability(vuln); err != nil {
		log.Warn("[OSSScanner Plugin] save vulnerability failed: %v", err)
	}
}

func buildHTTPResponsePacket(statusCode int, headers http.Header, body []byte) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", statusCode, http.StatusText(statusCode)))

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vals := headers.Values(k)
		for _, v := range vals {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}

	sb.WriteString("\n")
	sb.Write(body)
	return sb.String()
}

func truncateResponse(s string) string {
	if len(s) <= maxEvidenceResponseChars {
		return s
	}
	truncated := s[:maxEvidenceResponseChars]
	return truncated + "\n\n...[truncated]"
}

func severityForRiskTag(riskTag string) (string, float64) {
	switch riskTag {
	case "object-overwrite":
		return "critical", 9.1
	case "public-write":
		return "high", 8.2
	case "public-read":
		return "medium", 6.5
	default:
		return "info", 0
	}
}

func vulnNameForRiskTag(riskTag string) string {
	switch riskTag {
	case "object-overwrite":
		return "OSS对象可覆盖风险"
	case "public-write":
		return "OSS匿名写入风险"
	case "public-read":
		return "OSS匿名列目录/读取风险"
	default:
		return "OSS暴露风险"
	}
}