// SPECTRE Native Go Clean-Room Vulnerability Stream Indexer (`--sync-feeds`)
// Streams 100% legal OpenSSF/Google OSV (CC-BY-4.0) + CISA KEV (17 U.S.C. 105 Public Domain)
// advisories on disk with O(1) per-entry memory (< 50 MB RSS) into TSV for SQLite B-Tree load.
package main

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvAffected struct {
	Package          osvPackage     `json:"package"`
	Ranges           []osvRange     `json:"ranges"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type osvEntry struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Affected         []osvAffected  `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type SyncFeedsReport struct {
	ABI         int            `json:"abi"`
	TotalSynced int            `json:"total_synced"`
	Ecosystems  map[string]int `json:"ecosystems"`
	OutputPath  string         `json:"output_path"`
}

func cleanTsvFieldGo(s string, maxLen int) string {
	r := strings.NewReplacer("\t", " ", "\r", " ", "\n", " ")
	out := strings.TrimSpace(r.Replace(s))
	if len(out) > maxLen {
		return out[:maxLen]
	}
	return out
}

func slugCpeTokenGo(s string) string {
	var b strings.Builder
	prevU := false
	low := strings.ToLower(strings.TrimSpace(s))
	for i := 0; i < len(low); i++ {
		c := low[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'
		if ok {
			b.WriteByte(c)
			prevU = false
		} else if !prevU {
			b.WriteByte('_')
			prevU = true
		}
	}
	res := strings.Trim(b.String(), "_")
	if res == "" {
		return "pkg"
	}
	if len(res) > 48 {
		return res[:48]
	}
	return res
}

func mapOsvSeverityGo(dbSpec map[string]any) (string, float64, string) {
	sev := "High"
	cvss := 7.5
	cwe := "CWE-1104"
	if dbSpec != nil {
		if sv, ok := dbSpec["severity"].(string); ok {
			switch strings.ToUpper(strings.TrimSpace(sv)) {
			case "CRITICAL":
				sev, cvss = "Critical", 9.4
			case "HIGH":
				sev, cvss = "High", 8.1
			case "MODERATE", "MEDIUM":
				sev, cvss = "Medium", 5.9
			case "LOW":
				sev, cvss = "Low", 3.7
			}
		}
		if arr, ok := dbSpec["cwe_ids"].([]any); ok && len(arr) > 0 {
			if cs, ok2 := arr[0].(string); ok2 && strings.HasPrefix(strings.ToUpper(cs), "CWE-") {
				cwe = strings.ToUpper(cs)
			}
		}
	}
	return sev, cvss, cwe
}

func downloadTempZipGo(urlStr string, dstPath string) error {
	cli := &http.Client{Timeout: 45 * time.Second}
	resp, err := cli.Get(urlStr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	outF, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	_, cerr := io.Copy(outF, resp.Body)
	_ = outF.Close()
	return cerr
}

func resolvePrimaryAdvIDGo(ent *osvEntry) string {
	idUp := strings.ToUpper(strings.TrimSpace(ent.ID))
	if strings.HasPrefix(idUp, "CVE-") {
		return idUp
	}
	for _, al := range ent.Aliases {
		au := strings.ToUpper(strings.TrimSpace(al))
		if strings.HasPrefix(au, "CVE-") {
			return au
		}
	}
	return idUp
}

func extractOsvRowGo(ent *osvEntry) (string, bool) {
	advID := resolvePrimaryAdvIDGo(ent)
	if advID == "" || len(ent.Affected) == 0 {
		return "", false
	}
	aff := ent.Affected[0]
	eco := strings.TrimSpace(aff.Package.Ecosystem)
	pkg := strings.TrimSpace(aff.Package.Name)
	if eco == "" || pkg == "" {
		return "", false
	}
	minV, maxV := "*", "*"
	for _, rng := range aff.Ranges {
		for _, ev := range rng.Events {
			if ev.Introduced != "" && ev.Introduced != "0" && minV == "*" {
				minV = ev.Introduced
			}
			if ev.Fixed != "" && maxV == "*" {
				maxV = ev.Fixed
			}
		}
	}
	sev, cvss, cwe := mapOsvSeverityGo(ent.DatabaseSpecific)
	if aff.DatabaseSpecific != nil && sev == "High" && cvss == 7.5 {
		s2, c2, w2 := mapOsvSeverityGo(aff.DatabaseSpecific)
		sev, cvss = s2, c2
		if cwe == "CWE-1104" && w2 != "CWE-1104" {
			cwe = w2
		}
	}
	vSlug := slugCpeTokenGo(eco)
	pSlug := slugCpeTokenGo(pkg)
	cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", vSlug, pSlug)
	summ := ent.Summary
	if summ == "" {
		summ = ent.Details
	}
	if summ == "" {
		summ = fmt.Sprintf("%s %s security advisory (%s)", eco, pkg, advID)
	}
	rem := fmt.Sprintf("Upgrade %s (%s) to patched version >= %s", pkg, eco, maxV)
	if maxV == "*" {
		rem = fmt.Sprintf("Apply official %s security update for %s (%s)", eco, pkg, advID)
	}
	line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%.1f\t%s\t%s\t0\tUnknown\t0.15\t%s\t%s\tCC-BY-4.0",
		cleanTsvFieldGo(advID, 40),
		cleanTsvFieldGo(eco, 40),
		cleanTsvFieldGo(pkg, 80),
		cleanTsvFieldGo(cpe, 140),
		cleanTsvFieldGo(minV, 40),
		cleanTsvFieldGo(maxV, 40),
		cvss,
		sev,
		cleanTsvFieldGo(cwe, 20),
		cleanTsvFieldGo(summ, 240),
		cleanTsvFieldGo(rem, 200),
	)
	return line, true
}

func StreamSyncCleanroomFeedsGo(outTsvPath string, ecosystems []string) (*SyncFeedsReport, error) {
	if err := os.MkdirAll(filepath.Dir(outTsvPath), 0o755); err != nil {
		return nil, err
	}
	outF, err := os.Create(outTsvPath)
	if err != nil {
		return nil, err
	}
	defer outF.Close()
	bw := bufio.NewWriterSize(outF, 262144)
	seen := make(map[string]struct{}, 90000)
	ecoCounts := make(map[string]int)
	total := 0

	for _, r := range CompiledCleanroomAdvisories {
		if _, dup := seen[r.ID]; dup {
			continue
		}
		seen[r.ID] = struct{}{}
		_, _ = fmt.Fprintf(bw, "%s\t%s\t%s\t%s\t%s\t%s\t%.1f\t%s\t%s\t%d\tUnknown\t0.65\t%s\t%s\t%s\n",
			r.ID, r.Vendor, r.Product, r.CPE23, r.MinVer, r.MaxVer, r.CVSS, r.Severity, r.CWE, r.IsKEV,
			cleanTsvFieldGo(r.Summary, 240), cleanTsvFieldGo(r.Remediation, 200), r.SPDX)
		ecoCounts["SPECTRE-Cleanroom-Seed"]++
		total++
	}

	for _, eco := range ecosystems {
		tmpZip := filepath.Join(os.TempDir(), fmt.Sprintf("spectre_osv_%s.zip", slugCpeTokenGo(eco)))
		urlStr := fmt.Sprintf("https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip", eco)
		if err := downloadTempZipGo(urlStr, tmpZip); err != nil {
			_ = os.Remove(tmpZip)
			continue
		}
		zr, zerr := zip.OpenReader(tmpZip)
		if zerr == nil {
			for _, zf := range zr.File {
				if !strings.HasSuffix(zf.Name, ".json") || zf.UncompressedSize64 > 2*1024*1024 {
					continue
				}
				rc, oerr := zf.Open()
				if oerr != nil {
					continue
				}
				var ent osvEntry
				if json.NewDecoder(rc).Decode(&ent) == nil {
					advID := resolvePrimaryAdvIDGo(&ent)
					if _, dup := seen[advID]; !dup {
						if row, ok := extractOsvRowGo(&ent); ok {
							seen[advID] = struct{}{}
							_, _ = bw.WriteString(row)
							_ = bw.WriteByte('\n')
							ecoCounts[eco]++
							total++
						}
					}
				}
				_ = rc.Close()
			}
			_ = zr.Close()
		}
		_ = os.Remove(tmpZip)
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	return &SyncFeedsReport{ABI: 950, TotalSynced: total, Ecosystems: ecoCounts, OutputPath: outTsvPath}, nil
}
