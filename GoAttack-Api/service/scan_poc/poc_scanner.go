package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"GoAttack/common/mysql"

	"gopkg.in/yaml.v3"
)

// NucleiTemplate Nuclei模板YAML结构
type NucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string                 `yaml:"name"`
		Author         interface{}            `yaml:"author"` // 可能是字符串或数组
		Severity       string                 `yaml:"severity"`
		Description    string                 `yaml:"description"`
		Tags           interface{}            `yaml:"tags"` // 可能是字符串或数组
		Classification map[string]interface{} `yaml:"classification"`
		Metadata       map[string]interface{} `yaml:"metadata"`
		Reference      interface{}            `yaml:"reference"` // 可能是字符串或数组
	} `yaml:"info"`
	HTTP    interface{} `yaml:"http"`
	Network interface{} `yaml:"network"`
	DNS     interface{} `yaml:"dns"`
	SSL     interface{} `yaml:"ssl"`
	File    interface{} `yaml:"file"`
}

// PocScanner POC扫描器
type PocScanner struct {
	templatesDir string
}

// NewPocScanner 创建POC扫描器
func NewPocScanner(templatesDir string) *PocScanner {
	if templatesDir == "" {
		templatesDir = "service/lib/templates"
	}
	return &PocScanner{
		templatesDir: templatesDir,
	}
}

// ScanAndImport 扫描并导入POC模板
func (s *PocScanner) ScanAndImport() (int, int, error) {
	log.Println("开始扫描 nuclei-templates 目录:", s.templatesDir)

	var allPocs []*mysql.PocTemplate
	totalFiles := 0
	validFiles := 0
	savedCount := 0 // 实际保存的POC数量

	// 遍历所有目录
	err := filepath.Walk(s.templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		ext := filepath.Ext(path)
		if info.IsDir() || (ext != ".yaml" && ext != ".yml") {
			return nil
		}

		totalFiles++

		// 解析模板文件
		poc, err := s.parseTemplate(path)
		if err != nil {
			// 跳过解析失败的文件
			log.Printf("跳过文件 %s: %v", path, err)
			return nil
		}

		if poc != nil {
			allPocs = append(allPocs, poc)
			validFiles++

			// 每1000个批量保存一次
			if len(allPocs) >= 1000 {
				saved, err := mysql.BatchSavePocTemplates(allPocs)
				if err != nil {
					log.Printf("批量保存POC失败: %v", err)
				} else {
					savedCount += saved
					skipped := len(allPocs) - saved
					log.Printf("已保存 %d 个新POC模板，跳过 %d 个重复模板", saved, skipped)
				}
				allPocs = []*mysql.PocTemplate{}
			}
		}

		return nil
	})

	if err != nil {
		return 0, 0, err
	}

	// 保存剩余的POC
	if len(allPocs) > 0 {
		saved, err := mysql.BatchSavePocTemplates(allPocs)
		if err != nil {
			return 0, 0, err
		}
		savedCount += saved
		skipped := len(allPocs) - saved
		log.Printf("已保存最后 %d 个新POC模板，跳过 %d 个重复模板", saved, skipped)
	}

	log.Printf("扫描完成: 总文件数=%d, 有效POC=%d, 新增POC=%d, 跳过重复=%d",
		totalFiles, validFiles, savedCount, validFiles-savedCount)
	return totalFiles, validFiles, nil
}

// ParseContent 解析原始内容并返回PocTemplate
func (s *PocScanner) ParseContent(content []byte, filename string) (*mysql.PocTemplate, error) {
	// 计算内容哈希
	hash := sha256.Sum256(content)
	fileHash := hex.EncodeToString(hash[:])

	// 解析 YAML
	var tmpl NucleiTemplate
	err := yaml.Unmarshal(content, &tmpl)
	if err != nil {
		return nil, err
	}

	// 验证必要字段
	if tmpl.ID == "" || tmpl.Info.Name == "" || tmpl.Info.Severity == "" {
		return nil, fmt.Errorf("缺少必要字段: id=%s, name=%s, severity=%s", tmpl.ID, tmpl.Info.Name, tmpl.Info.Severity)
	}

	// 确定协议类型
	protocol := "http"
	if tmpl.Network != nil {
		protocol = "network"
	} else if tmpl.DNS != nil {
		protocol = "dns"
	} else if tmpl.SSL != nil {
		protocol = "ssl"
	} else if tmpl.File != nil {
		protocol = "file"
	}

	// 分类
	category := "manual"

	// 处理 author（可能是字符串或数组）
	author := extractStringOrArray(tmpl.Info.Author)

	// 处理 tags
	tagsJSON := extractArrayJSON(tmpl.Info.Tags)

	// 处理 reference
	referenceJSON := extractArrayJSON(tmpl.Info.Reference)

	// 处理 classification
	classificationJSON := "{}"
	if len(tmpl.Info.Classification) > 0 {
		if data, err := json.Marshal(tmpl.Info.Classification); err == nil {
			classificationJSON = string(data)
		}
	}

	// 处理 metadata
	metadataJSON := "{}"
	if len(tmpl.Info.Metadata) > 0 {
		if data, err := json.Marshal(tmpl.Info.Metadata); err == nil {
			metadataJSON = string(data)
		}
	}

	// 提取 CVE/CWE/CVSS/CNVD
	cveID := ""
	cnvdID := ""
	cweID := ""
	cvssScore := float32(0.0)
	cvssMetrics := ""

	// 1. 优先尝试从模板 ID 中通过正则解析
	cveReg := regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
	cnvdReg := regexp.MustCompile(`(?i)CNVD-\d{4}-\d{5}`)

	if cveID == "" {
		cveID = cveReg.FindString(tmpl.ID)
	}
	if cnvdID == "" {
		cnvdID = cnvdReg.FindString(tmpl.ID)
	}

	// 2. 尝试从 Classification 中获取
	if tmpl.Info.Classification != nil {
		if val, ok := tmpl.Info.Classification["cve-id"].(string); ok && cveID == "" {
			cveID = val
		}
		if val, ok := tmpl.Info.Classification["cnvd-id"].(string); ok && cnvdID == "" {
			cnvdID = val
		}
		if val, ok := tmpl.Info.Classification["cwe-id"].([]interface{}); ok && len(val) > 0 {
			if cwe, ok := val[0].(string); ok {
				cweID = cwe
			}
		} else if val, ok := tmpl.Info.Classification["cwe-id"].(string); ok {
			cweID = val
		}
		if val, ok := tmpl.Info.Classification["cvss-score"].(float64); ok {
			cvssScore = float32(val)
		}
		if val, ok := tmpl.Info.Classification["cvss-metrics"].(string); ok {
			cvssMetrics = val
		}
	}

	// 3. 补充查询
	hasCveTag := false
	hasCnvdTag := false
	var tagList []string
	switch v := tmpl.Info.Tags.(type) {
	case string:
		tagList = strings.Split(v, ",")
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				tagList = append(tagList, s)
			}
		}
	}
	for _, tag := range tagList {
		t := strings.ToLower(strings.TrimSpace(tag))
		if t == "cve" || strings.HasPrefix(t, "cve-") {
			hasCveTag = true
		}
		if t == "cnvd" || strings.HasPrefix(t, "cnvd-") {
			hasCnvdTag = true
		}
	}

	contentStr := string(content)
	if (hasCveTag || cveID == "") && cveID == "" {
		cveID = cveReg.FindString(contentStr)
	}
	if (hasCnvdTag || cnvdID == "") && cnvdID == "" {
		cnvdID = cnvdReg.FindString(contentStr)
	}

	cveID = strings.ToUpper(cveID)
	cnvdID = strings.ToUpper(cnvdID)

	maxRequest := 1
	if val, ok := tmpl.Info.Metadata["max-request"].(int); ok {
		maxRequest = val
	}

	// 构造 PocTemplate
	poc := &mysql.PocTemplate{
		TemplateID:      tmpl.ID,
		Name:            tmpl.Info.Name,
		Description:     tmpl.Info.Description,
		Author:          author,
		Category:        category,
		Severity:        strings.ToLower(tmpl.Info.Severity),
		Tags:            tagsJSON,
		CveID:           cveID,
		CnvdID:          cnvdID,
		CweID:           cweID,
		CvssScore:       cvssScore,
		CvssMetrics:     cvssMetrics,
		Protocol:        protocol,
		MaxRequest:      maxRequest,
		Reference:       referenceJSON,
		Classification:  classificationJSON,
		Metadata:        metadataJSON,
		FilePath:        filename,
		FileHash:        fileHash,
		TemplateContent: contentStr,
		IsActive:        true,
		Verified:        false,
	}

	return poc, nil
}

// parseTemplate 解析单个模板文件
func (s *PocScanner) parseTemplate(filePath string) (*mysql.PocTemplate, error) {
	// 读取文件内容
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// 计算文件哈希
	hash := sha256.Sum256(content)
	fileHash := hex.EncodeToString(hash[:])

	// 解析 YAML
	var tmpl NucleiTemplate
	err = yaml.Unmarshal(content, &tmpl)
	if err != nil {
		return nil, err
	}

	// 验证必要字段
	if tmpl.ID == "" || tmpl.Info.Name == "" || tmpl.Info.Severity == "" {
		return nil, fmt.Errorf("缺少必要字段: id=%s, name=%s, severity=%s", tmpl.ID, tmpl.Info.Name, tmpl.Info.Severity)
	}

	// 确定协议类型
	protocol := "http"
	if tmpl.Network != nil {
		protocol = "network"
	} else if tmpl.DNS != nil {
		protocol = "dns"
	} else if tmpl.SSL != nil {
		protocol = "ssl"
	} else if tmpl.File != nil {
		protocol = "file"
	}

	// 确定分类（从文件路径推断）
	relPath, _ := filepath.Rel(s.templatesDir, filePath)
	category := deriveCategory(relPath)

	// 处理 author（可能是字符串或数组）
	author := extractStringOrArray(tmpl.Info.Author)

	// 处理 tags
	tagsJSON := extractArrayJSON(tmpl.Info.Tags)

	// 处理 reference
	referenceJSON := extractArrayJSON(tmpl.Info.Reference)

	// 处理 classification
	classificationJSON := "{}"
	if len(tmpl.Info.Classification) > 0 {
		if data, err := json.Marshal(tmpl.Info.Classification); err == nil {
			classificationJSON = string(data)
		}
	}

	// 处理 metadata
	metadataJSON := "{}"
	if len(tmpl.Info.Metadata) > 0 {
		if data, err := json.Marshal(tmpl.Info.Metadata); err == nil {
			metadataJSON = string(data)
		}
	}

	// 提取 CVE/CWE/CVSS/CNVD
	cveID := ""
	cnvdID := ""
	cweID := ""
	cvssScore := float32(0.0)
	cvssMetrics := ""

	// 1. 优先尝试从模板 ID 中通过正则解析 (例如 id: CNVD-2017-03561)
	cveReg := regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
	cnvdReg := regexp.MustCompile(`(?i)CNVD-\d{4}-\d{5}`)

	if cveID == "" {
		cveID = cveReg.FindString(tmpl.ID)
	}
	if cnvdID == "" {
		cnvdID = cnvdReg.FindString(tmpl.ID)
	}

	// 2. 尝试从 Classification 中获取
	if tmpl.Info.Classification != nil {
		if val, ok := tmpl.Info.Classification["cve-id"].(string); ok && cveID == "" {
			cveID = val
		}
		if val, ok := tmpl.Info.Classification["cnvd-id"].(string); ok && cnvdID == "" {
			cnvdID = val
		}
		if val, ok := tmpl.Info.Classification["cwe-id"].([]interface{}); ok && len(val) > 0 {
			if cwe, ok := val[0].(string); ok {
				cweID = cwe
			}
		} else if val, ok := tmpl.Info.Classification["cwe-id"].(string); ok {
			cweID = val
		}
		if val, ok := tmpl.Info.Classification["cvss-score"].(float64); ok {
			cvssScore = float32(val)
		}
		if val, ok := tmpl.Info.Classification["cvss-metrics"].(string); ok {
			cvssMetrics = val
		}
	}

	// 3. 补充方案：如果依然没有，或者 Tags 中包含关键标记，则全文匹配
	hasCveTag := false
	hasCnvdTag := false
	var tagList []string
	switch v := tmpl.Info.Tags.(type) {
	case string:
		tagList = strings.Split(v, ",")
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				tagList = append(tagList, s)
			}
		}
	}

	for _, tag := range tagList {
		t := strings.ToLower(strings.TrimSpace(tag))
		if t == "cve" || strings.HasPrefix(t, "cve-") {
			hasCveTag = true
		}
		if t == "cnvd" || strings.HasPrefix(t, "cnvd-") {
			hasCnvdTag = true
		}
	}

	// 如果有标记或者 ID 仍为空，尝试正则全文匹配
	contentStr := string(content)
	if (hasCveTag || cveID == "") && cveID == "" {
		cveID = cveReg.FindString(contentStr)
	}
	if (hasCnvdTag || cnvdID == "") && cnvdID == "" {
		cnvdID = cnvdReg.FindString(contentStr)
	}

	// 统一转大写
	cveID = strings.ToUpper(cveID)
	cnvdID = strings.ToUpper(cnvdID)

	// 提取 max-request
	maxRequest := 1
	if val, ok := tmpl.Info.Metadata["max-request"].(int); ok {
		maxRequest = val
	}

	// 构造 PocTemplate
	poc := &mysql.PocTemplate{
		TemplateID:      tmpl.ID,
		Name:            tmpl.Info.Name,
		Description:     tmpl.Info.Description,
		Author:          author,
		Category:        category,
		Severity:        strings.ToLower(tmpl.Info.Severity),
		Tags:            tagsJSON,
		CveID:           cveID,
		CnvdID:          cnvdID,
		CweID:           cweID,
		CvssScore:       cvssScore,
		CvssMetrics:     cvssMetrics,
		Protocol:        protocol,
		MaxRequest:      maxRequest,
		Reference:       referenceJSON,
		Classification:  classificationJSON,
		Metadata:        metadataJSON,
		FilePath:        relPath,
		FileHash:        fileHash,
		TemplateContent: string(content),
		IsActive:        true,
		Verified:        false,
	}

	return poc, nil
}

// extractStringOrArray 提取字符串或数组的第一个元素
func extractStringOrArray(val interface{}) string {
	if val == nil {
		return ""
	}

	switch v := val.(type) {
	case string:
		return v
	case []interface{}:
		if len(v) > 0 {
			if str, ok := v[0].(string); ok {
				return str
			}
		}
	case []string:
		if len(v) > 0 {
			return v[0]
		}
	}

	return ""
}

// extractArrayJSON 提取数组并转换为JSON字符串
func extractArrayJSON(val interface{}) string {
	if val == nil {
		return "[]"
	}

	var arr []string

	switch v := val.(type) {
	case string:
		// 如果是字符串，按逗号分割
		arr = strings.Split(v, ",")
		for i := range arr {
			arr[i] = strings.TrimSpace(arr[i])
		}
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok {
				arr = append(arr, str)
			}
		}
	case []string:
		arr = v
	}

	if len(arr) == 0 {
		return "[]"
	}

	data, _ := json.Marshal(arr)
	return string(data)
}

// deriveCategory 从相对路径推断分类。
// 当上传目录被浏览器扁平化后，relPath 可能只是文件名，这时回退到 custom，避免把超长文件名写入 category。
func deriveCategory(relPath string) string {
	cleanPath := strings.TrimSpace(filepath.ToSlash(relPath))
	if cleanPath == "" {
		return "custom"
	}

	parts := strings.Split(cleanPath, "/")
	if len(parts) <= 1 {
		return "custom"
	}

	cat := strings.TrimSpace(parts[0])
	if cat == "" {
		return "custom"
	}

	// 与数据库 VARCHAR(625) 对齐，防止异常路径导致长度超限。
	if len(cat) > 625 {
		cat = cat[:625]
	}
	return cat
}
