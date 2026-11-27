// SPECTRE v10.0 Native Go Cloud IAM, Storage Bucket & Metadata Posture Auditor (ABI=1000)
// Read-only defensive auditor for AWS/GCP/Azure IAM policy JSON, Terraform (.tf),
// S3/GCS/MinIO XML ACLs (suppressing <Code>AccessDenied</Code>), and IMDSv1 hop-limit posture.
package main

import (
	"encoding/json"
	"os"
	"strings"
)

type CloudPostureInput struct {
	Asset   string `json:"asset"`
	Kind    string `json:"kind"` // "iam_json", "terraform", "bucket_xml"
	Content string `json:"content"`
}

type CloudPostureFinding struct {
	Asset         string `json:"asset"`
	RuleID        string `json:"rule_id"`
	CWE           string `json:"cwe"`
	Severity      string `json:"severity"`
	ConfidenceQoD int    `json:"confidence_qod"`
	Detail        string `json:"detail"`
}

func stringOrSliceHasStarGo(val any) bool {
	switch v := val.(type) {
	case string:
		t := strings.TrimSpace(v)
		return t == "*" || strings.HasSuffix(t, ":*")
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				t := strings.TrimSpace(s)
				if t == "*" || strings.HasSuffix(t, ":*") {
					return true
				}
			}
		}
	}
	return false
}

func stringOrSliceContainsGo(val any, needle string) bool {
	nl := strings.ToLower(needle)
	switch v := val.(type) {
	case string:
		return strings.Contains(strings.ToLower(v), nl)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.Contains(strings.ToLower(s), nl) {
				return true
			}
		}
	}
	return false
}

func auditIamJsonGo(asset string, content string) []CloudPostureFinding {
	var res []CloudPostureFinding
	var doc map[string]any
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}
	stmts, ok := doc["Statement"].([]any)
	if !ok {
		return nil
	}
	for _, rawSt := range stmts {
		st, ok := rawSt.(map[string]any)
		if !ok {
			continue
		}
		eff, _ := st["Effect"].(string)
		if !strings.EqualFold(strings.TrimSpace(eff), "Allow") {
			continue
		}
		act := st["Action"]
		rsc := st["Resource"]
		if stringOrSliceHasStarGo(act) && stringOrSliceHasStarGo(rsc) {
			res = append(res, CloudPostureFinding{
				Asset:         asset,
				RuleID:        "CLOUD_IAM_WILDCARD_ADMIN",
				CWE:           "CWE-269",
				Severity:      "Critical",
				ConfidenceQoD: 95,
				Detail:        "IAM Policy grants Effect=Allow with Action=* and Resource=*",
			})
		}
		if stringOrSliceContainsGo(act, "sts:AssumeRole") {
			cond, hasCond := st["Condition"].(map[string]any)
			condTxt := ""
			if hasCond {
				cb, _ := json.Marshal(cond)
				condTxt = strings.ToLower(string(cb))
			}
			if pr, hasPr := st["Principal"].(map[string]any); hasPr {
				pb, _ := json.Marshal(pr)
				pLow := strings.ToLower(string(pb))
				if strings.Contains(pLow, "arn:aws:iam::") && !strings.Contains(condTxt, "sts:externalid") {
					res = append(res, CloudPostureFinding{
						Asset:         asset,
						RuleID:        "CLOUD_IAM_ASSUMEROLE_CONFUSED_DEPUTY",
						CWE:           "CWE-863",
						Severity:      "High",
						ConfidenceQoD: 88,
						Detail:        "Cross-account sts:AssumeRole trust policy lacks sts:ExternalId condition",
					})
				}
			}
		}
	}
	return res
}

func AuditCloudPostureGo(items []CloudPostureInput) []CloudPostureFinding {
	var out []CloudPostureFinding
	for _, it := range items {
		low := strings.ToLower(it.Content)
		switch strings.ToLower(strings.TrimSpace(it.Kind)) {
		case "iam_json":
			out = append(out, auditIamJsonGo(it.Asset, it.Content)...)
		case "bucket_xml":
			if strings.Contains(low, "<code") && strings.Contains(low, "accessdenied") {
				continue
			}
			if strings.Contains(low, "<listbucketresult") && strings.Contains(low, "<contents>") {
				out = append(out, CloudPostureFinding{
					Asset:         it.Asset,
					RuleID:        "CLOUD_BUCKET_PUBLIC_LISTING",
					CWE:           "CWE-284",
					Severity:      "High",
					ConfidenceQoD: 96,
					Detail:        "Unauthenticated S3/GCS/MinIO ListBucketResult exposes bucket objects",
				})
			}
		default:
			if strings.Contains(low, `acl = "public-read`) || strings.Contains(low, "allusers") || strings.Contains(low, "allauthenticatedusers") {
				out = append(out, CloudPostureFinding{
					Asset:         it.Asset,
					RuleID:        "CLOUD_STORAGE_PUBLIC_ACL_IAC",
					CWE:           "CWE-284",
					Severity:      "High",
					ConfidenceQoD: 92,
					Detail:        "Cloud storage IaC grants public-read / allUsers access",
				})
			}
			if strings.Contains(low, `http_tokens = "optional"`) || strings.Contains(low, `http_tokens="optional"`) {
				out = append(out, CloudPostureFinding{
					Asset:         it.Asset,
					RuleID:        "CLOUD_IMDSV1_TOKEN_OPTIONAL",
					CWE:           "CWE-918",
					Severity:      "Medium",
					ConfidenceQoD: 90,
					Detail:        "Compute instance metadata allows unauthenticated IMDSv1 (http_tokens = optional)",
				})
			}
		}
	}
	return out
}

func RunCloudPostureFromFileGo(jsonPath string) ([]CloudPostureFinding, error) {
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}
	var items []CloudPostureInput
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	return AuditCloudPostureGo(items), nil
}

