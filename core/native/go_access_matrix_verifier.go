// SPECTRE v10.0 Native Go Cross-Role Access Matrix Verifier (BOLA / BFLA / Auth Bypass, ABI=1000)
// Evaluates Admin, UserA, UserB, and Anonymous capability matrices with Dual-Baseline Jitter (Law 2)
// and Stub/Redirect/Decoy isolation (Law 5) for zero-false-positive authorization verification.
package main

import (
	"encoding/json"
	"os"
	"strings"
)

type AccessMatrixProbe struct {
	Endpoint      string `json:"endpoint"`
	Method        string `json:"method"`
	AdminStatus   int    `json:"admin_status"`
	AdminLen      int    `json:"admin_len"`
	AdminHash     uint64 `json:"admin_hash"`
	UserAStatus   int    `json:"user_a_status"`
	UserALen      int    `json:"user_a_len"`
	UserAHash     uint64 `json:"user_a_hash"`
	UserBStatus   int    `json:"user_b_status"`
	UserBLen      int    `json:"user_b_len"`
	UserBHash     uint64 `json:"user_b_hash"`
	AnonStatus    int    `json:"anon_status"`
	AnonLen       int    `json:"anon_len"`
	AnonHash      uint64 `json:"anon_hash"`
	BaseJitter    int    `json:"base_jitter"`
	BodySnippet   string `json:"body_snippet"`
	HasOwnerMatch bool   `json:"has_owner_match"`
}

type AccessMatrixFinding struct {
	Endpoint      string `json:"endpoint"`
	Method        string `json:"method"`
	Class         string `json:"class"`
	CWE           string `json:"cwe"`
	Severity      string `json:"severity"`
	ConfidenceQoD int    `json:"confidence_qod"`
	Evidence      string `json:"evidence"`
}

func dualBaselineToleranceGo(baseLen int, jitter int) int {
	thr := 500
	if j4 := jitter * 4; j4 > thr {
		thr = j4
	}
	if p12 := int(float64(baseLen) * 0.12); p12 > thr {
		thr = p12
	}
	return thr
}

func isDecoyOrStubSnippetGo(snippet string, bodyLen int) bool {
	if bodyLen < 64 {
		return true
	}
	low := strings.ToLower(snippet)
	for _, dec := range []string{
		"welcome to nginx!",
		"apache2 ubuntu default page",
		"telegram web",
		"attention required!",
		"<meta http-equiv=\"refresh\"",
	} {
		if strings.Contains(low, dec) {
			return true
		}
	}
	return false
}

func isPrivilegedAdminRouteGo(endpoint string, method string) bool {
	low := strings.ToLower(endpoint)
	for _, p := range []string{"/admin", "/internal", "/manage", "/console", "/actuator", "/_cluster", "/api/v1/users"} {
		if strings.Contains(low, p) {
			return true
		}
	}
	m := strings.ToUpper(strings.TrimSpace(method))
	return (m == "DELETE" || m == "PUT") && strings.Contains(low, "/api/")
}

func routeHasObjectIdentifierGo(endpoint string) bool {
	pathPart := strings.SplitN(endpoint, "?", 2)[0]
	for _, seg := range strings.Split(pathPart, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if (seg[0] == 'v' || seg[0] == 'V') && len(seg) >= 2 && seg[1] >= '0' && seg[1] <= '9' {
			continue
		}
		allDigits := len(seg) <= 20
		hasDigit := false
		allHexUuid := len(seg) >= 8
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			isDig := c >= '0' && c <= '9'
			isHex := isDig || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-'
			if isDig {
				hasDigit = true
			} else {
				allDigits = false
			}
			if !isHex {
				allHexUuid = false
			}
		}
		if allDigits || (allHexUuid && hasDigit) {
			return true
		}
	}
	return false
}

func absIntGo(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func EvaluateAccessMatrixGo(probes []AccessMatrixProbe) []AccessMatrixFinding {
	var findings []AccessMatrixFinding
	for _, p := range probes {
		method := strings.ToUpper(strings.TrimSpace(p.Method))
		if method == "" {
			method = "GET"
		}
		if p.AdminStatus == 200 && p.AnonStatus == 200 && isPrivilegedAdminRouteGo(p.Endpoint, method) {
			if !isDecoyOrStubSnippetGo(p.BodySnippet, p.AnonLen) {
				tol := dualBaselineToleranceGo(p.AdminLen, p.BaseJitter)
				if absIntGo(p.AdminLen-p.AnonLen) <= tol && p.AdminHash != 0 && p.AdminHash == p.AnonHash {
					findings = append(findings, AccessMatrixFinding{
						Endpoint:      p.Endpoint,
						Method:        method,
						Class:         "UNAUTHENTICATED_PRIVILEGED_BYPASS",
						CWE:           "CWE-306",
						Severity:      "Critical",
						ConfidenceQoD: 95,
						Evidence:      "Anon=200 matches Admin=200 structural skeleton within Dual-Baseline jitter",
					})
					continue
				}
			}
		}
		if p.AnonStatus != 401 && p.AnonStatus != 403 {
			continue
		}
		if p.AdminStatus == 200 && p.UserAStatus == 200 && isPrivilegedAdminRouteGo(p.Endpoint, method) {
			if !isDecoyOrStubSnippetGo(p.BodySnippet, p.UserALen) {
				tol := dualBaselineToleranceGo(p.AdminLen, p.BaseJitter)
				if absIntGo(p.AdminLen-p.UserALen) <= tol && p.AdminHash != 0 && p.AdminHash == p.UserAHash {
					findings = append(findings, AccessMatrixFinding{
						Endpoint:      p.Endpoint,
						Method:        method,
						Class:         "VERTICAL_BFLA",
						CWE:           "CWE-285",
						Severity:      "High",
						ConfidenceQoD: 93,
						Evidence:      "Anon=401/403, Low-Priv UserA=200 matches Admin=200 privileged response",
					})
					continue
				}
			}
		}
		if p.UserAStatus == 200 && p.UserBStatus == 200 && routeHasObjectIdentifierGo(p.Endpoint) && p.HasOwnerMatch {
			if !isDecoyOrStubSnippetGo(p.BodySnippet, p.UserBLen) {
				tol := dualBaselineToleranceGo(p.UserALen, p.BaseJitter)
				if absIntGo(p.UserALen-p.UserBLen) <= tol && p.UserAHash != 0 && p.UserAHash == p.UserBHash {
					findings = append(findings, AccessMatrixFinding{
						Endpoint:      p.Endpoint,
						Method:        method,
						Class:         "HORIZONTAL_BOLA",
						CWE:           "CWE-639",
						Severity:      "High",
						ConfidenceQoD: 95,
						Evidence:      "Anon=401/403, UserB=200 accessed UserA object record with matching owner identifier",
					})
				}
			}
		}
	}
	return findings
}

func RunAccessMatrixFromFileGo(jsonPath string) ([]AccessMatrixFinding, error) {
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}
	var probes []AccessMatrixProbe
	if err := json.Unmarshal(raw, &probes); err != nil {
		return nil, err
	}
	return EvaluateAccessMatrixGo(probes), nil
}

