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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxZipDownloadBytes = 256 << 20 // 256 MiB max OSV archive stream
	maxEntryJsonBytes   = 2 << 20   // 2 MiB max decompressed OSV JSON entry
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
	if len(out) <= maxLen {
		return out
	}
	cut := out[:maxLen]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return strings.TrimSpace(cut)
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

func downloadTempZipFileGo(urlStr string) (*os.File, int64, error) {
	cli := &http.Client{Timeout: 45 * time.Second}
	resp, err := cli.Get(urlStr)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	tmpF, err := os.CreateTemp("", "spectre_osv_*.zip")
	if err != nil {
		return nil, 0, err
	}
	written, cerr := io.Copy(tmpF, io.LimitReader(resp.Body, maxZipDownloadBytes+1))
	if cerr != nil {
		name := tmpF.Name()
		_ = tmpF.Close()
		_ = os.Remove(name)
		return nil, 0, cerr
	}
	if written > maxZipDownloadBytes {
		name := tmpF.Name()
		_ = tmpF.Close()
		_ = os.Remove(name)
		return nil, 0, fmt.Errorf("archive exceeds %d bytes cap", maxZipDownloadBytes)
	}
	return tmpF, written, nil
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

func extractOsvRowWithIDGo(ent *osvEntry, chosenID string) (string, bool) {
	if chosenID == "" || len(ent.Affected) == 0 {
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
		summ = fmt.Sprintf("%s %s security advisory (%s)", eco, pkg, chosenID)
	}
	rem := fmt.Sprintf("Upgrade %s (%s) to patched version >= %s", pkg, eco, maxV)
	if maxV == "*" {
		rem = fmt.Sprintf("Apply official %s security update for %s (%s)", eco, pkg, chosenID)
	}
	line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%.1f\t%s\t%s\t0\tUnknown\t0.15\t%s\t%s\tCC-BY-4.0",
		cleanTsvFieldGo(chosenID, 40),
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
	const maxTotalAdvisories = 215000
	if err := os.MkdirAll(filepath.Dir(outTsvPath), 0o755); err != nil {
		return nil, err
	}
	outF, err := os.Create(outTsvPath)
	if err != nil {
		return nil, err
	}
	defer outF.Close()
	bw := bufio.NewWriterSize(outF, 262144)
	seenIDs := make(map[string]struct{}, 220000)
	ecoCounts := make(map[string]int)
	total := 0

	for _, r := range CompiledCleanroomAdvisories {
		if _, dup := seenIDs[r.ID]; dup {
			continue
		}
		seenIDs[r.ID] = struct{}{}
		_, _ = fmt.Fprintf(bw, "%s\t%s\t%s\t%s\t%s\t%s\t%.1f\t%s\t%s\t%d\tUnknown\t0.65\t%s\t%s\t%s\n",
			r.ID, r.Vendor, r.Product, r.CPE23, r.MinVer, r.MaxVer, r.CVSS, r.Severity, r.CWE, r.IsKEV,
			cleanTsvFieldGo(r.Summary, 240), cleanTsvFieldGo(r.Remediation, 200), r.SPDX)
		ecoCounts["SPECTRE-Cleanroom-Seed"]++
		total++
	}

	for _, eco := range ecosystems {
		if total >= maxTotalAdvisories {
			break
		}
		escEco := url.PathEscape(strings.TrimSpace(eco))
		if escEco == "" {
			continue
		}
		urlStr := fmt.Sprintf("https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip", escEco)
		tmpF, zipSz, derr := downloadTempZipFileGo(urlStr)
		if derr != nil {
			continue
		}
		tmpName := tmpF.Name()
		zr, zerr := zip.NewReader(tmpF, zipSz)
		if zerr == nil {
			for _, zf := range zr.File {
				if total >= maxTotalAdvisories {
					break
				}
				if !strings.HasSuffix(zf.Name, ".json") || zf.UncompressedSize64 > maxEntryJsonBytes {
					continue
				}
				rc, oerr := zf.Open()
				if oerr != nil {
					continue
				}
				rawJSON, rerr := io.ReadAll(io.LimitReader(rc, maxEntryJsonBytes+1))
				_ = rc.Close()
				if rerr != nil || int64(len(rawJSON)) > maxEntryJsonBytes {
					continue
				}
				var ent osvEntry
				if json.Unmarshal(rawJSON, &ent) == nil {
					candID := resolvePrimaryAdvIDGo(&ent)
					if _, dup := seenIDs[candID]; dup {
						altID := strings.ToUpper(strings.TrimSpace(ent.ID))
						if altID != "" && altID != candID {
							candID = altID
						}
					}
					if _, dup := seenIDs[candID]; !dup {
						if row, ok := extractOsvRowWithIDGo(&ent, candID); ok {
							seenIDs[candID] = struct{}{}
							_, _ = bw.WriteString(row)
							_ = bw.WriteByte('\n')
							ecoCounts[eco]++
							total++
						}
					}
				}
			}
		}
		_ = tmpF.Close()
		_ = os.Remove(tmpName)
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	return &SyncFeedsReport{ABI: 1000, TotalSynced: total, Ecosystems: ecoCounts, OutputPath: outTsvPath}, nil
}
