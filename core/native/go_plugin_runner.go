// SPECTRE Native Go Request-Clustered Declarative YAML Plugin Runner (plugins/*.yaml)
// Features: Lexical indentation/quote/block-scalar YAML parser, KB Pre-Flight Gating,
// Structural-Hash Dual-Baseline Calibration, Regex/Header Matchers, and HTTP Clustering.
package main

import (
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type YamlPluginRule struct {
	ID             string            `json:"id"`
	Title          string            `json:"title"`
	Category       string            `json:"category"`
	Severity       string            `json:"severity"`
	CVSS           float64           `json:"cvss"`
	CWE            string            `json:"cwe"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Status         int               `json:"status"`
	MinBytes       int               `json:"min_bytes"`
	Headers        map[string]string `json:"headers,omitempty"`
	MandatoryKeys  []string          `json:"mandatory_keys"`
	ContentTypeAny []string          `json:"content_type_any"`
	HeaderMatchAny []string          `json:"header_match_any,omitempty"`
	MatchAll       []string          `json:"match_all"`
	MatchAny       []string          `json:"match_any"`
	MatchRegex     []string          `json:"match_regex,omitempty"`
	ExcludeAny     []string          `json:"exclude_any"`
	Remediation    string            `json:"remediation"`
	compiledRegex  []*regexp.Regexp
}

type YamlPluginFinding struct {
	PluginID    string  `json:"plugin_id"`
	Title       string  `json:"title"`
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	CWE         string  `json:"cwe"`
	Asset       string  `json:"asset"`
	Evidence    string  `json:"evidence"`
	Remediation string  `json:"remediation"`
	Confidence  int     `json:"confidence"`
}

type YamlPluginRunReport struct {
	ABI              int                 `json:"abi"`
	LoadedRules      int                 `json:"loaded_rules"`
	EligibleRules    int                 `json:"eligible_rules"`
	ClusteredFetches int                 `json:"clustered_fetches"`
	Findings         []YamlPluginFinding `json:"findings"`
}

func stripInlineYamlComment(s string) string {
	inSQ := false
	inDQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inDQ && c == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if !inDQ && c == '\'' {
			if inSQ && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			inSQ = !inSQ
			continue
		}
		if !inSQ && c == '"' {
			inDQ = !inDQ
			continue
		}
		if !inSQ && !inDQ && c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimRight(s[:i], " \t")
		}
	}
	return strings.TrimRight(s, " \t")
}

func splitYamlKeyValue(line string) (string, string, bool) {
	inSQ := false
	inDQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inDQ && c == '\\' && i+1 < len(line) {
			i++
			continue
		}
		if !inDQ && c == '\'' {
			inSQ = !inSQ
			continue
		}
		if !inSQ && c == '"' {
			inDQ = !inDQ
			continue
		}
		if !inSQ && !inDQ && c == ':' && (i+1 == len(line) || line[i+1] == ' ' || line[i+1] == '\t') {
			return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
		}
	}
	return "", "", false
}

func decodeYamlScalar(raw string) string {
	s := strings.TrimSpace(stripInlineYamlComment(raw))
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		inner := s[1 : len(s)-1]
		var b strings.Builder
		for i := 0; i < len(inner); i++ {
			if inner[i] == '\\' && i+1 < len(inner) {
				i++
				switch inner[i] {
				case 'n':
					b.WriteByte('\n')
				case 'r':
					b.WriteByte('\r')
				case 't':
					b.WriteByte('\t')
				case '"', '\\', '/':
					b.WriteByte(inner[i])
				default:
					b.WriteByte('\\')
					b.WriteByte(inner[i])
				}
				continue
			}
			b.WriteByte(inner[i])
		}
		return b.String()
	}
	return s
}

func parseFlowSequence(raw string) ([]string, bool) {
	s := strings.TrimSpace(stripInlineYamlComment(raw))
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return nil, false
	}
	inner := s[1 : len(s)-1]
	var items []string
	var cur strings.Builder
	inSQ, inDQ := false, false
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if inDQ && c == '\\' && i+1 < len(inner) {
			cur.WriteByte(c)
			cur.WriteByte(inner[i+1])
			i++
			continue
		}
		if !inDQ && c == '\'' {
			inSQ = !inSQ
		} else if !inSQ && c == '"' {
			inDQ = !inDQ
		} else if !inSQ && !inDQ && c == ',' {
			if v := decodeYamlScalar(cur.String()); v != "" {
				items = append(items, v)
			}
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if v := decodeYamlScalar(cur.String()); v != "" {
		items = append(items, v)
	}
	return items, true
}

func countLeadingSpaces(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			n++
		} else if s[i] == '\t' {
			n += 2
		} else {
			break
		}
	}
	return n
}

func assignYamlListItem(r *YamlPluginRule, listKey string, item string) {
	if item == "" {
		return
	}
	switch listKey {
	case "mandatory_keys":
		r.MandatoryKeys = append(r.MandatoryKeys, item)
	case "content_type_any":
		r.ContentTypeAny = append(r.ContentTypeAny, item)
	case "header_match_any":
		r.HeaderMatchAny = append(r.HeaderMatchAny, item)
	case "match_all":
		r.MatchAll = append(r.MatchAll, item)
	case "match_any":
		r.MatchAny = append(r.MatchAny, item)
	case "match_regex":
		r.MatchRegex = append(r.MatchRegex, item)
	case "exclude_any":
		r.ExcludeAny = append(r.ExcludeAny, item)
	}
}

func assignYamlScalarField(r *YamlPluginRule, key string, val string) {
	switch key {
	case "id":
		r.ID = val
	case "title":
		r.Title = val
	case "category":
		r.Category = val
	case "severity":
		r.Severity = val
	case "cvss":
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			r.CVSS = f
		}
	case "cwe":
		r.CWE = val
	case "method":
		r.Method = strings.ToUpper(val)
	case "path":
		r.Path = val
	case "status":
		if v, err := strconv.Atoi(val); err == nil {
			r.Status = v
		}
	case "min_bytes":
		if v, err := strconv.Atoi(val); err == nil {
			r.MinBytes = v
		}
	case "remediation":
		r.Remediation = val
	}
}

func ParseYamlPluginFileGo(path string) (*YamlPluginRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := &YamlPluginRule{
		Method: "GET", Status: 200, MinBytes: 16,
		Severity: "Medium", CVSS: 5.3, CWE: "CWE-200",
		Headers: make(map[string]string),
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	activeSection := ""
	sectionIndent := 0

	for i := 0; i < len(lines); i++ {
		rawLn := lines[i]
		trimmed := strings.TrimSpace(rawLn)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" {
			continue
		}
		indent := countLeadingSpaces(rawLn)
		if indent <= sectionIndent && !strings.HasPrefix(trimmed, "- ") {
			activeSection = ""
		}
		if strings.HasPrefix(trimmed, "- ") && activeSection != "" {
			assignYamlListItem(r, activeSection, decodeYamlScalar(trimmed[2:]))
			continue
		}
		if activeSection == "headers" && indent > sectionIndent {
			if hk, hv, ok := splitYamlKeyValue(trimmed); ok && hk != "" {
				r.Headers[hk] = decodeYamlScalar(hv)
			}
			continue
		}
		kRaw, vRaw, ok := splitYamlKeyValue(trimmed)
		if !ok {
			continue
		}
		key := strings.ToLower(kRaw)
		vClean := strings.TrimSpace(stripInlineYamlComment(vRaw))
		if vClean == "" {
			activeSection = key
			sectionIndent = indent
			continue
		}
		if vClean == "|" || vClean == "|-" || vClean == ">" || vClean == ">-" {
			folded := strings.HasPrefix(vClean, ">")
			var blk []string
			baseInd := -1
			for i+1 < len(lines) {
				nxt := lines[i+1]
				nt := strings.TrimSpace(nxt)
				if nt == "" {
					blk = append(blk, "")
					i++
					continue
				}
				ni := countLeadingSpaces(nxt)
				if ni <= indent {
					break
				}
				if baseInd < 0 {
					baseInd = ni
				}
				cut := baseInd
				if cut > len(nxt) {
					cut = len(nxt)
				}
				blk = append(blk, nxt[cut:])
				i++
			}
			sep := "\n"
			if folded {
				sep = " "
			}
			assignYamlScalarField(r, key, strings.TrimSpace(strings.Join(blk, sep)))
			continue
		}
		if seq, isSeq := parseFlowSequence(vRaw); isSeq {
			for _, it := range seq {
				assignYamlListItem(r, key, it)
			}
			continue
		}
		assignYamlScalarField(r, key, decodeYamlScalar(vRaw))
	}

	if r.ID == "" || r.Path == "" {
		return nil, fmt.Errorf("missing id or path")
	}
	for _, pat := range r.MatchRegex {
		re, cerr := regexp.Compile(pat)
		if cerr != nil {
			return nil, cerr
		}
		r.compiledRegex = append(r.compiledRegex, re)
	}
	return r, nil
}

var reTitleGo = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var reHtmlTagGo = regexp.MustCompile(`(?i)<(/?[a-z][a-z0-9]{0,20})`)
var reJsonKeyGo = regexp.MustCompile(`"([A-Za-z0-9_\-]{1,40})"\s*:`)

func extractHtmlTitleGo(body string) string {
	win := body
	if len(win) > 16384 {
		win = win[:16384]
	}
	if m := reTitleGo.FindStringSubmatch(win); len(m) > 1 {
		return strings.ToLower(strings.TrimSpace(m[1]))
	}
	return ""
}

func structuralHashGo(body string) uint64 {
	s := strings.TrimSpace(body)
	if s == "" {
		return 0
	}
	if len(s) > 32768 {
		s = s[:32768]
	}
	h := fnv.New64a()
	if s[0] == '{' || s[0] == '[' {
		_, _ = h.Write([]byte("json:"))
		for _, m := range reJsonKeyGo.FindAllStringSubmatch(s, 64) {
			_, _ = h.Write([]byte(strings.ToLower(m[1]) + ","))
		}
		return h.Sum64()
	}
	if strings.Contains(s, "<") {
		_, _ = h.Write([]byte("html:"))
		for _, m := range reHtmlTagGo.FindAllStringSubmatch(s, 96) {
			_, _ = h.Write([]byte(strings.ToLower(m[1]) + ","))
		}
		return h.Sum64()
	}
	return 0
}

func kbRuleMatchesGo(rule *YamlPluginRule, kb map[string]string) bool {
	for _, expr := range rule.MandatoryKeys {
		eq := strings.IndexByte(expr, '=')
		if eq <= 0 {
			if _, ok := kb[expr]; !ok {
				return false
			}
			continue
		}
		k := strings.TrimSpace(expr[:eq])
		pat := strings.TrimSpace(expr[eq+1:])
		val, ok := kb[k]
		if !ok {
			return false
		}
		re, err := regexp.Compile("(?i)" + pat)
		if err != nil || !re.MatchString(val) {
			return false
		}
	}
	return true
}

type baselineProfileGo struct {
	code   int
	length int
	thr    int
	title  string
	skel   uint64
}

func evalRuleOnClusteredRespGo(
	r *YamlPluginRule,
	code int,
	hdrs http.Header,
	body string,
	bp baselineProfileGo,
) bool {
	if code != r.Status || len(body) < r.MinBytes {
		return false
	}
	if bp.code == code && code == 200 {
		diff := len(body) - bp.length
		if diff < 0 {
			diff = -diff
		}
		if diff < bp.thr {
			t := extractHtmlTitleGo(body)
			if bp.title != "" && t == bp.title {
				return false
			}
			sk := structuralHashGo(body)
			if bp.skel != 0 && sk == bp.skel {
				return false
			}
		}
	}
	if len(r.ContentTypeAny) > 0 {
		ctLow := strings.ToLower(hdrs.Get("Content-Type"))
		okCt := false
		for _, want := range r.ContentTypeAny {
			if strings.Contains(ctLow, strings.ToLower(want)) {
				okCt = true
				break
			}
		}
		if !okCt {
			return false
		}
	}
	if len(r.HeaderMatchAny) > 0 {
		var flat strings.Builder
		for hk, hv := range hdrs {
			flat.WriteString(strings.ToLower(hk))
			flat.WriteString(": ")
			flat.WriteString(strings.ToLower(strings.Join(hv, ", ")))
			flat.WriteByte('\n')
		}
		hBlob := flat.String()
		okHdr := false
		for _, want := range r.HeaderMatchAny {
			if want != "" && strings.Contains(hBlob, strings.ToLower(want)) {
				okHdr = true
				break
			}
		}
		if !okHdr {
			return false
		}
	}
	for _, ex := range r.ExcludeAny {
		if ex != "" && strings.Contains(body, ex) {
			return false
		}
	}
	for _, ma := range r.MatchAll {
		if ma != "" && !strings.Contains(body, ma) {
			return false
		}
	}
	if len(r.MatchAny) > 0 {
		anyHit := false
		for _, mn := range r.MatchAny {
			if mn != "" && strings.Contains(body, mn) {
				anyHit = true
				break
			}
		}
		if !anyHit {
			return false
		}
	}
	for _, rx := range r.compiledRegex {
		if !rx.MatchString(body) {
			return false
		}
	}
	return true
}

func RunClusteredYamlPluginsGo(
	baseURL string,
	pluginsDir string,
	kbHints string,
	timeoutMs int,
) (*YamlPluginRunReport, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if timeoutMs <= 0 {
		timeoutMs = 3500
	}
	kb := make(map[string]string)
	for _, part := range strings.Split(kbHints, ";") {
		if eq := strings.IndexByte(part, '='); eq > 0 {
			kb[strings.TrimSpace(part[:eq])] = strings.TrimSpace(part[eq+1:])
		}
	}
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return &YamlPluginRunReport{ABI: 950}, nil
	}
	var allRules []*YamlPluginRule
	for _, ent := range entries {
		name := ent.Name()
		if !ent.IsDir() && (strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) {
			if r, perr := ParseYamlPluginFileGo(filepath.Join(pluginsDir, name)); perr == nil {
				allRules = append(allRules, r)
			}
		}
	}
	clusters := make(map[string][]*YamlPluginRule)
	eligible := 0
	for _, r := range allRules {
		if len(kb) > 0 && !kbRuleMatchesGo(r, kb) {
			continue
		}
		eligible++
		ck := r.Method + " " + r.Path
		clusters[ck] = append(clusters[ck], r)
	}
	cli := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   time.Duration(timeoutMs) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	fetchOnce := func(m string, p string, extraHdrs map[string]string) (int, http.Header, string) {
		req, rerr := http.NewRequest(m, base+p, nil)
		if rerr != nil {
			return 0, nil, ""
		}
		req.Header.Set("User-Agent", "SPECTRE-Audit/9.5")
		for hk, hv := range extraHdrs {
			req.Header.Set(hk, hv)
		}
		resp, derr := cli.Do(req)
		if derr != nil {
			return 0, nil, ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 131072))
		return resp.StatusCode, resp.Header, string(b)
	}
	bCode1, _, bBody1 := fetchOnce("GET", "/.spectre-baseline-a91f82", nil)
	_, _, bBody2 := fetchOnce("GET", "/.spectre-baseline-b73c41", nil)
	bJitter := len(bBody1) - len(bBody2)
	if bJitter < 0 {
		bJitter = -bJitter
	}
	bThr := 500
	if bJitter*4 > bThr {
		bThr = bJitter * 4
	}
	if pct := int(float64(len(bBody1)) * 0.12); pct > bThr {
		bThr = pct
	}
	bp := baselineProfileGo{
		code:   bCode1,
		length: len(bBody1),
		thr:    bThr,
		title:  extractHtmlTitleGo(bBody1),
		skel:   structuralHashGo(bBody1),
	}

	var findings []YamlPluginFinding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for ck, grp := range clusters {
		wg.Add(1)
		go func(key string, rules []*YamlPluginRule) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			sp := strings.SplitN(key, " ", 2)
			mergedHdrs := make(map[string]string)
			for _, rl := range rules {
				for hk, hv := range rl.Headers {
					mergedHdrs[hk] = hv
				}
			}
			code, hdrs, body := fetchOnce(sp[0], sp[1], mergedHdrs)
			if code == 0 {
				return
			}
			for _, rl := range rules {
				if evalRuleOnClusteredRespGo(rl, code, hdrs, body, bp) {
					mu.Lock()
					findings = append(findings, YamlPluginFinding{
						PluginID:    rl.ID,
						Title:       rl.Title,
						Category:    rl.Category,
						Severity:    rl.Severity,
						CVSS:        rl.CVSS,
						CWE:         rl.CWE,
						Asset:       base + rl.Path,
						Evidence:    fmt.Sprintf("HTTP %d (%dB) clustered match", code, len(body)),
						Remediation: rl.Remediation,
						Confidence:  95,
					})
					mu.Unlock()
				}
			}
		}(ck, grp)
	}
	wg.Wait()
	return &YamlPluginRunReport{
		ABI:              950,
		LoadedRules:      len(allRules),
		EligibleRules:    eligible,
		ClusteredFetches: len(clusters),
		Findings:         findings,
	}, nil
}
