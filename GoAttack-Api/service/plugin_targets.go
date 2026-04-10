package service

import (
	"GoAttack/common/mysql"
	servicecommon "GoAttack/service/common"
	"fmt"
	"strings"
)

func buildDirScanTargets(taskID int, scanTargets []*servicecommon.Target) []string {
	ipToTargets := make(map[string][]*servicecommon.Target)
	for _, t := range scanTargets {
		if t != nil && t.IP != "" {
			ipToTargets[t.IP] = append(ipToTargets[t.IP], t)
		}
	}

	targets := make([]string, 0)
	seen := make(map[string]struct{})

	rows, err := mysql.GetHTTPPortsByTaskID(taskID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var ip string
			var port int
			var protocol string
			var serviceName string
			if err := rows.Scan(&id, &ip, &port, &protocol, &serviceName); err != nil {
				continue
			}

			hostToUse := ip
			if tList, ok := ipToTargets[ip]; ok && len(tList) > 0 {
				for _, t := range tList {
					if t.Host != "" && t.Host != t.IP {
						hostToUse = t.Host
						break
					}
				}
				if hostToUse == ip && tList[0].Host != "" {
					hostToUse = tList[0].Host
				}
			}

			scheme := "http"
			if protocol == "https" || port == 443 || port == 8443 || strings.Contains(strings.ToLower(serviceName), "https") {
				scheme = "https"
			}
			targetURL := fmt.Sprintf("%s://%s:%d", scheme, hostToUse, port)
			appendUniqueTarget(&targets, seen, targetURL)
		}
	}

	if len(targets) > 0 {
		return targets
	}

	for _, t := range scanTargets {
		if t == nil {
			continue
		}
		targetURL := t.Original
		if t.Port > 0 {
			targetURL = fmt.Sprintf("%s:%d", t.Host, t.Port)
		} else if targetURL == "" {
			targetURL = t.Host
		}
		appendUniqueTarget(&targets, seen, targetURL)
	}

	return targets
}

func buildSubdomainTargets(scanTargets []*servicecommon.Target) []string {
	targets := make([]string, 0, len(scanTargets))
	seen := make(map[string]struct{})
	for _, t := range scanTargets {
		if t == nil {
			continue
		}
		candidate := strings.TrimSpace(t.Host)
		if candidate == "" {
			candidate = strings.TrimSpace(t.Original)
		}
		appendUniqueTarget(&targets, seen, candidate)
	}
	return targets
}

func appendUniqueTarget(targets *[]string, seen map[string]struct{}, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if _, exists := seen[value]; exists {
		return
	}
	seen[value] = struct{}{}
	*targets = append(*targets, value)
}
