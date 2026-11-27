// SPECTRE v10.0 Native Go RFC 9112 HTTP/1.1 Framing & Reverse-Proxy Desync Auditor (ABI=1000)
// Strictly non-destructive RFC 9112 Section 6 framing hygiene verifier auditing HTTP response
// wire headers and proxy configs (nginx/haproxy/envoy) for CL+TE ambiguity & h2c tunneling.
package main

import (
	"encoding/json"
	"os"
	"strings"
)

type HttpFramingInput struct {
	Asset          string              `json:"asset"`
	RawHeaders     map[string][]string `json:"raw_headers"`
	StatusCode     int                 `json:"status_code"`
	ProxyConfigTxt string              `json:"proxy_config_txt"`
}

type HttpFramingFinding struct {
	Asset         string `json:"asset"`
	RuleID        string `json:"rule_id"`
	CWE           string `json:"cwe"`
	Severity      string `json:"severity"`
	ConfidenceQoD int    `json:"confidence_qod"`
	Detail        string `json:"detail"`
}

func AuditHttpRfc9112FramingGo(inputs []HttpFramingInput) []HttpFramingFinding {
	var out []HttpFramingFinding
	for _, in := range inputs {
		var clVals []string
		var teVals []string
		var upgVals []string
		for k, vals := range in.RawHeaders {
			kl := strings.ToLower(strings.TrimSpace(k))
			switch kl {
			case "content-length":
				clVals = append(clVals, vals...)
			case "transfer-encoding":
				teVals = append(teVals, vals...)
			case "upgrade":
				upgVals = append(upgVals, vals...)
			}
		}

		// RFC 9112 Section 6.3: Sender MUST NOT send Content-Length with Transfer-Encoding
		if len(clVals) > 0 && len(teVals) > 0 {
			out = append(out, HttpFramingFinding{
				Asset:         in.Asset,
				RuleID:        "RFC9112_CL_TE_CONFLICT",
				CWE:           "CWE-444",
				Severity:      "High",
				ConfidenceQoD: 92,
				Detail:        "Response emits both Content-Length and Transfer-Encoding headers (RFC 9112 §6.3 violation)",
			})
		}

		// RFC 9112 Section 6.3: Conflicting duplicate Content-Length values
		if len(clVals) >= 2 {
			first := strings.TrimSpace(clVals[0])
			conflict := false
			for _, v := range clVals[1:] {
				if strings.TrimSpace(v) != first {
					conflict = true
					break
				}
			}
			if conflict {
				out = append(out, HttpFramingFinding{
					Asset:         in.Asset,
					RuleID:        "RFC9112_DUPLICATE_CL_MISMATCH",
					CWE:           "CWE-444",
					Severity:      "High",
					ConfidenceQoD: 94,
					Detail:        "Response contains multiple differing Content-Length header values",
				})
			}
		}

		// Cleartext HTTP/2 h2c Upgrade exposure on public listener
		for _, uv := range upgVals {
			if strings.EqualFold(strings.TrimSpace(uv), "h2c") && (in.StatusCode == 101 || in.StatusCode == 200) {
				out = append(out, HttpFramingFinding{
					Asset:         in.Asset,
					RuleID:        "HTTP_H2C_CLEARTEXT_UPGRADE",
					CWE:           "CWE-444",
					Severity:      "Medium",
					ConfidenceQoD: 86,
					Detail:        "Endpoint advertises/accepts cleartext h2c Upgrade header across reverse proxy boundary",
				})
				break
			}
		}

		// Reverse-proxy static configuration framing posture
		cfgLow := strings.ToLower(in.ProxyConfigTxt)
		if cfgLow != "" {
			if strings.Contains(cfgLow, "ignore_invalid_headers off") || strings.Contains(cfgLow, "underscores_in_headers on") && strings.Contains(cfgLow, "proxy_http_version 1.0") {
				out = append(out, HttpFramingFinding{
					Asset:         in.Asset,
					RuleID:        "PROXY_PERMISSIVE_HEADER_FRAMING",
					CWE:           "CWE-444",
					Severity:      "Medium",
					ConfidenceQoD: 85,
					Detail:        "Reverse proxy disables strict header validation (ignore_invalid_headers off / HTTP/1.0 backend)",
				})
			}
		}
	}
	return out
}

func RunHttpFramingAuditFromFileGo(jsonPath string) ([]HttpFramingFinding, error) {
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}
	var items []HttpFramingInput
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	return AuditHttpRfc9112FramingGo(items), nil
}
