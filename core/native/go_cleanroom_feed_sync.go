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
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxZipDownloadBytes = 512 << 20 // 512 MiB max OSV archive stream on disk
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

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvAffected struct {
	Package          osvPackage     `json:"package"`
	Ranges           []osvRange     `json:"ranges"`
	Severity         []osvSeverity  `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type osvEntry struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases"`
	Upstream         []string       `json:"upstream"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Severity         []osvSeverity  `json:"severity"`
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
	cli := &http.Client{Timeout: 120 * time.Second}
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

func extractCanonicalCveTokenGo(raw string) string {
	up := strings.ToUpper(strings.TrimSpace(raw))
	idx := strings.Index(up, "CVE-")
	if idx < 0 || idx+13 > len(up) {
		return ""
	}
	sub := up[idx:]
	for i := 4; i < 8; i++ {
		if sub[i] < '0' || sub[i] > '9' {
			return ""
		}
	}
	if sub[8] != '-' {
		return ""
	}
	end := 9
	for end < len(sub) && sub[end] >= '0' && sub[end] <= '9' {
		end++
	}
	if end-9 < 4 {
		return ""
	}
	return sub[:end]
}

func scoreCvss31VectorGo(vec string) (float64, string, bool) {
	v := strings.ToUpper(strings.TrimSpace(vec))
	if !strings.HasPrefix(v, "CVSS:3.") {
		return 0, "", false
	}
	av, ac, pr, ui, sc := 0.85, 0.77, 0.85, 0.85, "U"
	cImp, iImp, aImp := 0.0, 0.0, 0.0
	prRaw := "N"
	for _, part := range strings.Split(v, "/")[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "AV":
			switch kv[1] {
			case "N":
				av = 0.85
			case "A":
				av = 0.62
			case "L":
				av = 0.55
			case "P":
				av = 0.20
			}
		case "AC":
			if kv[1] == "H" {
				ac = 0.44
			}
		case "PR":
			prRaw = kv[1]
		case "UI":
			if kv[1] == "R" {
				ui = 0.62
			}
		case "S":
			if kv[1] == "C" {
				sc = "C"
			}
		case "C":
			if kv[1] == "H" {
				cImp = 0.56
			} else if kv[1] == "L" {
				cImp = 0.22
			}
		case "I":
			if kv[1] == "H" {
				iImp = 0.56
			} else if kv[1] == "L" {
				iImp = 0.22
			}
		case "A":
			if kv[1] == "H" {
				aImp = 0.56
			} else if kv[1] == "L" {
				aImp = 0.22
			}
		}
	}
	switch prRaw {
	case "L":
		if sc == "C" {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if sc == "C" {
			pr = 0.50
		} else {
			pr = 0.27
		}
	}
	iss := 1.0 - (1.0-cImp)*(1.0-iImp)*(1.0-aImp)
	if iss <= 0.0 {
		return 0.0, "Low", true
	}
	var impact float64
	if sc == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15.0)
	} else {
		impact = 6.42 * iss
	}
	expl := 8.22 * av * ac * pr * ui
	raw := impact + expl
	if sc == "C" {
		raw = 1.08 * raw
	}
	if raw > 10.0 {
		raw = 10.0
	}
	score := math.Ceil(math.Round(raw*100000.0)/10000.0) / 10.0
	sev := "Low"
	if score >= 9.0 {
		sev = "Critical"
	} else if score >= 7.0 {
		sev = "High"
	} else if score >= 4.0 {
		sev = "Medium"
	}
	return score, sev, true
}

func resolvePrimaryAdvIDGo(ent *osvEntry) string {
	if c := extractCanonicalCveTokenGo(ent.ID); c != "" {
		return c
	}
	for _, al := range ent.Aliases {
		if c := extractCanonicalCveTokenGo(al); c != "" {
			return c
		}
	}
	for _, up := range ent.Upstream {
		if c := extractCanonicalCveTokenGo(up); c != "" {
			return c
		}
	}
	return strings.ToUpper(strings.TrimSpace(ent.ID))
}

func isGitCommitShaVerGo(v string) bool {
	if len(v) < 20 || strings.Contains(v, ".") {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func extractOsvRowsWithIDGo(ent *osvEntry, chosenID string) []string {
	if chosenID == "" || strings.HasPrefix(chosenID, "MAL-") || len(ent.Affected) == 0 {
		return nil
	}
	sev, cvss, cwe := mapOsvSeverityGo(ent.DatabaseSpecific)
	for _, sv := range ent.Severity {
		if sc, sl, ok := scoreCvss31VectorGo(sv.Score); ok && sc > 0 {
			cvss, sev = sc, sl
			break
		}
	}
	var outRows []string
	maxPkg := len(ent.Affected)
	if maxPkg > 3 {
		maxPkg = 3
	}
	for aIdx := 0; aIdx < maxPkg; aIdx++ {
		aff := ent.Affected[aIdx]
		eco := strings.TrimSpace(aff.Package.Ecosystem)
		pkg := strings.TrimSpace(aff.Package.Name)
		if eco == "" || pkg == "" || strings.EqualFold(eco, "OSS-Fuzz") {
			continue
		}
		if strings.HasPrefix(eco, "Packagist:") {
			eco = "Packagist"
		}
		if strings.HasPrefix(eco, "Debian:") && eco != "Debian:11" && eco != "Debian:12" && eco != "Debian:13" {
			continue
		}
		if strings.HasPrefix(eco, "Ubuntu:") && !strings.Contains(eco, "20.04") && !strings.Contains(eco, "22.04") && !strings.Contains(eco, "24.04") {
			continue
		}
		aSev, aCvss, aCwe := sev, cvss, cwe
		for _, sv := range aff.Severity {
			if sc, sl, ok := scoreCvss31VectorGo(sv.Score); ok && sc > 0 {
				aCvss, aSev = sc, sl
				break
			}
		}
		if aff.DatabaseSpecific != nil {
			s2, c2, w2 := mapOsvSeverityGo(aff.DatabaseSpecific)
			if aCvss == 7.5 && c2 != 7.5 {
				aSev, aCvss = s2, c2
			}
			if aCwe == "CWE-1104" && w2 != "CWE-1104" {
				aCwe = w2
			}
		}
		type verPair struct{ minV, maxV string }
		var pairs []verPair
		for _, rng := range aff.Ranges {
			if strings.EqualFold(rng.Type, "GIT") {
				continue
			}
			curIntro := "*"
			for _, ev := range rng.Events {
				if ev.Introduced != "" {
					if ev.Introduced == "0" || isGitCommitShaVerGo(ev.Introduced) {
						curIntro = "*"
					} else {
						curIntro = ev.Introduced
					}
				}
				if ev.Fixed != "" && !isGitCommitShaVerGo(ev.Fixed) {
					pairs = append(pairs, verPair{minV: curIntro, maxV: ev.Fixed})
					curIntro = "*"
					if len(pairs) >= 4 {
						break
					}
				}
			}
			if len(pairs) >= 4 {
				break
			}
		}
		if len(pairs) == 0 {
			if strings.HasPrefix(chosenID, "CVE-") {
				pairs = append(pairs, verPair{minV: "*", maxV: "*"})
			} else {
				continue
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
		for _, vp := range pairs {
			rem := fmt.Sprintf("Upgrade %s (%s) to patched version >= %s", pkg, eco, vp.maxV)
			if vp.maxV == "*" {
				rem = fmt.Sprintf("Apply official %s security update for %s (%s)", eco, pkg, chosenID)
			}
			line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%.1f\t%s\t%s\t0\tUnknown\t0.15\t%s\t%s\tCC-BY-4.0",
				cleanTsvFieldGo(chosenID, 40),
				cleanTsvFieldGo(eco, 40),
				cleanTsvFieldGo(pkg, 80),
				cleanTsvFieldGo(cpe, 140),
				cleanTsvFieldGo(vp.minV, 40),
				cleanTsvFieldGo(vp.maxV, 40),
				aCvss,
				aSev,
				cleanTsvFieldGo(aCwe, 20),
				cleanTsvFieldGo(summ, 240),
				cleanTsvFieldGo(rem, 200),
			)
			outRows = append(outRows, line)
		}
	}
	return outRows
}

func StreamSyncCleanroomFeedsGo(outTsvPath string, ecosystems []string) (*SyncFeedsReport, error) {
	const maxTotalAdvisories = 260000
	const maxPerEco = 38000
	if err := os.MkdirAll(filepath.Dir(outTsvPath), 0o755); err != nil {
		return nil, err
	}
	outF, err := os.Create(outTsvPath)
	if err != nil {
		return nil, err
	}
	defer outF.Close()
	bw := bufio.NewWriterSize(outF, 262144)
	seenKeys := make(map[string]struct{}, 250000)
	ecoCounts := make(map[string]int)
	total := 0

	for _, r := range CompiledCleanroomAdvisories {
		compK := strings.ToLower(fmt.Sprintf("%s|%s|%s|%s|%s", r.ID, r.Vendor, r.Product, r.MinVer, r.MaxVer))
		if _, dup := seenKeys[compK]; dup {
			continue
		}
		seenKeys[compK] = struct{}{}
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
				if total >= maxTotalAdvisories || ecoCounts[eco] >= maxPerEco {
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
					rows := extractOsvRowsWithIDGo(&ent, candID)
					for _, row := range rows {
						if total >= maxTotalAdvisories {
							break
						}
						cols := strings.SplitN(row, "\t", 7)
						if len(cols) < 6 {
							continue
						}
						compK := strings.ToLower(cols[0] + "|" + cols[1] + "|" + cols[2] + "|" + cols[4] + "|" + cols[5])
						if _, dup := seenKeys[compK]; !dup {
							seenKeys[compK] = struct{}{}
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
