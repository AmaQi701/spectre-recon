// SPECTRE v10.0 Native Go Passive OSINT Pivot Graph & Origin Unmasking Engine (ABI=1000)
// Correlates passive EASM signals (TLS Cert Serial, SANs, Favicon MMH3, ETag, Title Hash)
// while strictly isolating CDN/WAF edge IPs (Law 11) to uncover true direct-origin hosts.
package main

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
)

type OsintAssetNode struct {
	Domain      string   `json:"domain"`
	IP          string   `json:"ip"`
	CdnWaf      string   `json:"cdn_waf"`
	CertSerial  string   `json:"cert_serial"`
	CertSANs    []string `json:"cert_sans"`
	FaviconMMH3 int64    `json:"favicon_mmh3"`
	ETag        string   `json:"etag"`
	TitleHash   uint64   `json:"title_hash"`
}

type OriginUnmaskCandidate struct {
	ProtectedDomain   string   `json:"protected_domain"`
	CdnProvider       string   `json:"cdn_provider"`
	CandidateOriginIP string   `json:"candidate_origin_ip"`
	PivotDomain       string   `json:"pivot_domain"`
	MatchedSignals    []string `json:"matched_signals"`
	ConfidenceQoD     int      `json:"confidence_qod"`
}

type OsintPivotReport struct {
	ABI              int                     `json:"abi"`
	TotalNodes       int                     `json:"total_nodes"`
	CdnProtected     int                     `json:"cdn_protected"`
	DirectOriginPool int                     `json:"direct_origin_pool"`
	UnmaskCandidates []OriginUnmaskCandidate `json:"unmask_candidates"`
}

var knownCdnVendorsGo = []string{
	"cloudflare", "cloudfront", "akamai", "fastly", "imperva",
	"incapsula", "qrator", "ddos-guard", "sucuri", "azure front door",
}

func isCdnProtectedNodeGo(n OsintAssetNode) bool {
	w := strings.ToLower(strings.TrimSpace(n.CdnWaf))
	if w == "" {
		return false
	}
	for _, kw := range knownCdnVendorsGo {
		if strings.Contains(w, kw) {
			return true
		}
	}
	return true
}

func normalizeEtagSignalGo(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "W/")
	s = strings.Trim(s, "\"'")
	if len(s) < 8 {
		return ""
	}
	return strings.ToLower(s)
}

func sanSetIntersectsGo(a, b []string, domA, domB string) bool {
	setA := make(map[string]struct{}, len(a)+1)
	for _, s := range a {
		cl := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "*.")
		if cl != "" {
			setA[cl] = struct{}{}
		}
	}
	if domB != "" {
		if _, ok := setA[strings.ToLower(domB)]; ok {
			return true
		}
	}
	for _, s := range b {
		cl := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "*.")
		if cl != "" {
			if _, ok := setA[cl]; ok {
				return true
			}
			if domA != "" && cl == strings.ToLower(domA) {
				return true
			}
		}
	}
	return false
}

func BuildOsintPivotGraphGo(nodes []OsintAssetNode) OsintPivotReport {
	var cdnNodes []OsintAssetNode
	var directNodes []OsintAssetNode
	for _, n := range nodes {
		n.Domain = strings.ToLower(strings.TrimSpace(n.Domain))
		n.IP = strings.TrimSpace(n.IP)
		if n.Domain == "" {
			continue
		}
		if isCdnProtectedNodeGo(n) {
			cdnNodes = append(cdnNodes, n)
		} else if n.IP != "" && !strings.HasPrefix(n.IP, "127.") && n.IP != "0.0.0.0" {
			directNodes = append(directNodes, n)
		}
	}

	var candidates []OriginUnmaskCandidate
	seenPairs := make(map[string]struct{})

	for _, cNode := range cdnNodes {
		cSerial := strings.ToLower(strings.TrimSpace(cNode.CertSerial))
		cEtag := normalizeEtagSignalGo(cNode.ETag)
		for _, dNode := range directNodes {
			if cNode.Domain == dNode.Domain {
				continue
			}
			var signals []string
			qod := 0
			dSerial := strings.ToLower(strings.TrimSpace(dNode.CertSerial))
			if cSerial != "" && len(cSerial) >= 8 && cSerial == dSerial {
				signals = append(signals, "tls_cert_serial")
				qod += 55
			}
			if sanSetIntersectsGo(cNode.CertSANs, dNode.CertSANs, cNode.Domain, dNode.Domain) {
				signals = append(signals, "tls_san_overlap")
				qod += 30
			}
			if cNode.FaviconMMH3 != 0 && cNode.FaviconMMH3 == dNode.FaviconMMH3 {
				signals = append(signals, "favicon_mmh3")
				qod += 35
			}
			dEtag := normalizeEtagSignalGo(dNode.ETag)
			if cEtag != "" && cEtag == dEtag {
				signals = append(signals, "http_etag")
				qod += 25
			}
			if cNode.TitleHash != 0 && cNode.TitleHash == dNode.TitleHash && len(signals) > 0 {
				signals = append(signals, "dom_title_hash")
				qod += 15
			}
			if len(signals) == 0 || qod < 55 {
				continue
			}
			if qod > 96 {
				qod = 96
			}
			pairKey := cNode.Domain + "|" + dNode.IP
			if _, exists := seenPairs[pairKey]; exists {
				continue
			}
			seenPairs[pairKey] = struct{}{}
			candidates = append(candidates, OriginUnmaskCandidate{
				ProtectedDomain:   cNode.Domain,
				CdnProvider:       cNode.CdnWaf,
				CandidateOriginIP: dNode.IP,
				PivotDomain:       dNode.Domain,
				MatchedSignals:    signals,
				ConfidenceQoD:     qod,
			})
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].ConfidenceQoD != candidates[j].ConfidenceQoD {
			return candidates[i].ConfidenceQoD > candidates[j].ConfidenceQoD
		}
		return candidates[i].ProtectedDomain < candidates[j].ProtectedDomain
	})

	return OsintPivotReport{
		ABI:              1000,
		TotalNodes:       len(nodes),
		CdnProtected:     len(cdnNodes),
		DirectOriginPool: len(directNodes),
		UnmaskCandidates: candidates,
	}
}

func RunOsintPivotFromFileGo(jsonPath string) (*OsintPivotReport, error) {
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}
	var nodes []OsintAssetNode
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return nil, err
	}
	rep := BuildOsintPivotGraphGo(nodes)
	return &rep, nil
}
