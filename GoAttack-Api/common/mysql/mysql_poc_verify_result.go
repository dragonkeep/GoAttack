package mysql

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// PocVerifyResult POC验证结果
type PocVerifyResult struct {
	ID            int64                  `json:"id"`
	Target        string                 `json:"target"`
	PocID         int64                  `json:"poc_id"`
	TemplateID    string                 `json:"template_id"`
	TemplateName  string                 `json:"template_name"`
	Matched       bool                   `json:"matched"`
	Severity      string                 `json:"severity"`
	Description   string                 `json:"description"`
	Request       string                 `json:"request"`
	Response      string                 `json:"response"`
	MatchedAt     string                 `json:"matched_at"`
	ExtractedData map[string]interface{} `json:"extracted_data,omitempty"`
	Error         string                 `json:"error,omitempty"`
	VerifiedBy    string                 `json:"verified_by"`
	VerifiedAt    time.Time              `json:"verified_at"`
}

// SavePocVerifyResult 保存POC验证结果
func SavePocVerifyResult(result *PocVerifyResult) error {
	// 序列化 ExtractedData
	var extractedDataJSON []byte
	var err error
	if result.ExtractedData != nil {
		extractedDataJSON, err = json.Marshal(result.ExtractedData)
		if err != nil {
			return fmt.Errorf("序列化extracted_data失败: %v", err)
		}
	}

	query := `
		INSERT INTO poc_verify_result (
			target, poc_id, template_id, template_name, matched, severity, description,
			request, response, matched_at, extracted_data, error, verified_by, verified_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	res, err := DB.Exec(query,
		result.Target, result.PocID, result.TemplateID, result.TemplateName,
		result.Matched, result.Severity, result.Description,
		result.Request, result.Response, result.MatchedAt,
		extractedDataJSON, result.Error, result.VerifiedBy, result.VerifiedAt,
	)

	if err != nil {
		return fmt.Errorf("保存验证结果失败: %v", err)
	}

	id, err := res.LastInsertId()
	if err == nil {
		result.ID = id
	}

	return nil
}

// GetPocVerifyResultByID 根据ID获取验证结果
func GetPocVerifyResultByID(id int64) (*PocVerifyResult, error) {
	query := `
		SELECT 
			id, target, poc_id, template_id, template_name, matched, severity, description,
			request, response, matched_at, extracted_data, error, verified_by, verified_at
		FROM poc_verify_result
		WHERE id = ?
	`

	result := &PocVerifyResult{}
	var extractedDataJSON []byte

	err := DB.QueryRow(query, id).Scan(
		&result.ID, &result.Target, &result.PocID, &result.TemplateID, &result.TemplateName,
		&result.Matched, &result.Severity, &result.Description,
		&result.Request, &result.Response, &result.MatchedAt,
		&extractedDataJSON, &result.Error, &result.VerifiedBy, &result.VerifiedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询验证结果失败: %v", err)
	}

	// 解析 ExtractedData
	if len(extractedDataJSON) > 0 {
		if err := json.Unmarshal(extractedDataJSON, &result.ExtractedData); err != nil {
			return nil, fmt.Errorf("解析extracted_data失败: %v", err)
		}
	}

	return result, nil
}

// ListPocVerifyResults 获取验证结果列表（分页）
func ListPocVerifyResults(page, pageSize int, filters map[string]interface{}) ([]*PocVerifyResult, int, error) {
	// 构建查询条件
	where := "WHERE 1=1"
	args := make([]interface{}, 0)

	if target, ok := filters["target"].(string); ok && target != "" {
		where += " AND target LIKE ?"
		args = append(args, "%"+target+"%")
	}

	if pocID, ok := filters["poc_id"].(int64); ok && pocID > 0 {
		where += " AND poc_id = ?"
		args = append(args, pocID)
	}

	if templateID, ok := filters["template_id"].(string); ok && templateID != "" {
		where += " AND template_id = ?"
		args = append(args, templateID)
	}

	if matched, ok := filters["matched"].(bool); ok {
		where += " AND matched = ?"
		args = append(args, matched)
	}

	if severity, ok := filters["severity"].(string); ok && severity != "" {
		where += " AND severity = ?"
		args = append(args, severity)
	}

	// 查询总数
	var total int
	countQuery := "SELECT COUNT(*) FROM poc_verify_result " + where
	err := DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("查询总数失败: %v", err)
	}

	// 查询列表
	offset := (page - 1) * pageSize
	query := `
		SELECT 
			id, target, poc_id, template_id, template_name, matched, severity, description,
			request, response, matched_at, extracted_data, error, verified_by, verified_at
		FROM poc_verify_result
	` + where + `
		ORDER BY verified_at DESC
		LIMIT ? OFFSET ?
	`

	args = append(args, pageSize, offset)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询验证结果列表失败: %v", err)
	}
	defer rows.Close()

	results := make([]*PocVerifyResult, 0)
	for rows.Next() {
		result := &PocVerifyResult{}
		var extractedDataJSON []byte

		err := rows.Scan(
			&result.ID, &result.Target, &result.PocID, &result.TemplateID, &result.TemplateName,
			&result.Matched, &result.Severity, &result.Description,
			&result.Request, &result.Response, &result.MatchedAt,
			&extractedDataJSON, &result.Error, &result.VerifiedBy, &result.VerifiedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("扫描结果失败: %v", err)
		}

		// 解析 ExtractedData
		if len(extractedDataJSON) > 0 {
			if err := json.Unmarshal(extractedDataJSON, &result.ExtractedData); err != nil {
				return nil, 0, fmt.Errorf("解析extracted_data失败: %v", err)
			}
		}

		results = append(results, result)
	}

	return results, total, nil
}

// DeletePocVerifyResult 删除验证结果
func DeletePocVerifyResult(id int64) error {
	query := "DELETE FROM poc_verify_result WHERE id = ?"
	_, err := DB.Exec(query, id)
	if err != nil {
		return fmt.Errorf("删除验证结果失败: %v", err)
	}
	return nil
}

// BatchDeletePocVerifyResults 批量删除验证结果
func BatchDeletePocVerifyResults(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	query := "DELETE FROM poc_verify_result WHERE id IN ("
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		if i > 0 {
			query += ","
		}
		query += "?"
		args[i] = id
	}
	query += ")"

	_, err := DB.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("批量删除验证结果失败: %v", err)
	}
	return nil
}

// ClearPocVerifyResults 清空所有验证结果
func ClearPocVerifyResults() error {
	query := "DELETE FROM poc_verify_result"
	_, err := DB.Exec(query)
	if err != nil {
		return fmt.Errorf("清空验证结果失败: %v", err)
	}
	return nil
}

// UpdatePocVerifyResult 更新POC验证结果
func UpdatePocVerifyResult(result *PocVerifyResult) error {
	// 序列化 ExtractedData
	var extractedDataJSON []byte
	var err error
	if result.ExtractedData != nil {
		extractedDataJSON, err = json.Marshal(result.ExtractedData)
		if err != nil {
			return fmt.Errorf("序列化extracted_data失败: %v", err)
		}
	}

	query := `
		UPDATE poc_verify_result SET
			target = ?, poc_id = ?, template_id = ?, template_name = ?, matched = ?, severity = ?, description = ?,
			request = ?, response = ?, matched_at = ?, extracted_data = ?, error = ?, verified_by = ?, verified_at = ?
		WHERE id = ?
	`

	_, err = DB.Exec(query,
		result.Target, result.PocID, result.TemplateID, result.TemplateName,
		result.Matched, result.Severity, result.Description,
		result.Request, result.Response, result.MatchedAt,
		extractedDataJSON, result.Error, result.VerifiedBy, result.VerifiedAt,
		result.ID,
	)

	if err != nil {
		return fmt.Errorf("更新验证结果失败: %v", err)
	}

	return nil
}
