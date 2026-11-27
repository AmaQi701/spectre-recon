// SPECTRE Polyglot Go Threat-Intel & SecLists Concurrent Stream Indexer (v8.5.0, ABI=850)
// Build: go build -ldflags="-s -w" -o core/native/spectre-intel-indexer core/native/spectre_intel_indexer.go
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type WordlistResult struct {
	DatasetID string `json:"dataset_id"`
	Count     int    `json:"count"`
	SHA256    string `json:"sha256"`
	Origin    string `json:"origin"`
}

type IndexerReport struct {
	ABI       int                       `json:"abi"`
	Engine    string                    `json:"engine"`
	Wordlists map[string]WordlistResult `json:"wordlists"`
}

func isValidDNSLabel(s string) bool {
	n := len(s)
	if n < 1 || n > 63 || s[0] == '-' || s[n-1] == '-' {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func isValidParamName(s string) bool {
	n := len(s)
	if n < 1 || n > 49 {
		return false
	}
	c0 := s[0]
	if !((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || c0 == '_') {
		return false
	}
	for i := 1; i < n; i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '[' || c == ']' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

func writeAndHashLines(outPath string, lines []string) (string, error) {
	f, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	mw := io.MultiWriter(f, h)
	bw := bufio.NewWriterSize(mw, 262144)
	for _, ln := range lines {
		_, _ = bw.WriteString(ln)
		_ = bw.WriteByte('\n')
	}
	if err := bw.Flush(); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func streamFileLines(path string, fn func(string)) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 131072)
	sc.Buffer(buf, 1048576)
	for sc.Scan() {
		fn(sc.Text())
	}
	return true
}

func parseSocketSpecsFlagGo(specStr string, singlePort int) []SocketProbeSpec {
	var specs []SocketProbeSpec
	if specStr != "" {
		for _, tok := range strings.Split(specStr, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if strings.Contains(tok, ":") {
				parts := strings.SplitN(tok, ":", 2)
				lp, e1 := strconv.Atoi(parts[0])
				cp, e2 := strconv.Atoi(parts[1])
				if e1 == nil && e2 == nil && lp > 0 && cp > 0 {
					specs = append(specs, SocketProbeSpec{LogicalPort: lp, ConnectPort: cp})
				}
			} else if lp, err := strconv.Atoi(tok); err == nil && lp > 0 {
				specs = append(specs, SocketProbeSpec{LogicalPort: lp, ConnectPort: lp})
			}
		}
	} else if singlePort > 0 {
		specs = append(specs, SocketProbeSpec{LogicalPort: singlePort, ConnectPort: singlePort})
	}
	return specs
}

func main() {
	showVer := flag.Bool("version", false, "Print Go engine ABI version and .rodata stats")
	outDir := flag.String("out-dir", "", "Output directory for deduplicated wordlists")
	secRoot := flag.String("seclists", "/usr/share/seclists/Discovery", "SecLists Discovery root")
	lookupOui := flag.String("lookup-oui", "", "Lookup MAC OUI vendor via Go binary search")
	lookupPsl := flag.String("lookup-psl", "", "Check Mozilla Public Suffix via Go binary search")
	probeHost := flag.String("probe-host", "", "Optional target host/IP for Go concurrent socket verifier")
	dispHost := flag.String("disp-host", "", "Optional display hostname for socket findings")
	probePort := flag.Int("probe-port", 0, "Optional single port for Go socket verifier")
	probePorts := flag.String("probe-ports", "", "Comma-separated port or logical:connect specs")
	timeoutMs := flag.Int("timeout-ms", 2400, "Socket/HTTP timeout in milliseconds")
	syncFeeds := flag.String("sync-feeds", "", "Stream OSV + Clean-Room advisories into TSV path")
	syncEcos := flag.String("ecosystems", "PyPI,Go,Maven,NuGet,crates.io,Packagist,RubyGems,Alpine,Debian,Ubuntu,Rocky Linux,AlmaLinux,Bitnami,Wolfi,OSS-Fuzz,Linux,Hex,Pub,GitHub Actions", "OSV ecosystems to sync")
	runPlugins := flag.String("run-plugins", "", "Target base URL to execute YAML plugins against")
	pluginsDir := flag.String("plugins-dir", "", "Directory containing declarative *.yaml plugins")
	kbHints := flag.String("kb-hints", "", "Semicolon-separated key=val KB facts for YAML plugin gating")
	mcpServer := flag.Bool("mcp-server", false, "Start local read-only JSON-RPC 2.0 MCP server on stdio")
	mcpTsvPath := flag.String("intel-tsv", "", "Optional clean-room TSV advisory file for local MCP queries")
	mcpDbPath := flag.String("intel-db", "", "Legacy alias for -intel-tsv advisory path")
	selfTestSockets := flag.Bool("selftest-sockets", false, "Run ephemeral loopback binary socket & MCP JSON-RPC self-tests")
	osintPivot := flag.String("osint-pivot", "", "JSON input path for Passive OSINT Pivot Graph unmasking")
	accessMatrix := flag.String("verify-access-matrix", "", "JSON input path for Cross-Role Access Matrix verifier")
	cloudPosture := flag.String("audit-cloud-posture", "", "JSON input path for Cloud IAM/Storage/IMDS posture auditor")
	httpFraming := flag.String("audit-http-framing", "", "JSON input path for RFC 9112 HTTP/1.1 framing auditor")
	flag.Parse()

	if *selfTestSockets {
		rep := RunAllGoProtocolSelfTests()
		b, _ := json.Marshal(rep)
		fmt.Println(string(b))
		if !rep.AllPassed {
			os.Exit(1)
		}
		return
	}

	if *showVer {
		fmt.Printf("SPECTRE-Go-Security-Engine v10.0.0 ABI=1000 PSL=%d OUI=%d SCA=%d CleanAdv=%d SocketPorts=%d\n",
			len(CompiledPslTable), len(CompiledOuiTable), len(CompiledScaTable),
			len(CompiledCleanroomAdvisories), len(SupportedSocketPorts))
		return
	}
	if *osintPivot != "" {
		rep, err := RunOsintPivotFromFileGo(*osintPivot)
		if err != nil {
			os.Exit(1)
		}
		b, _ := json.Marshal(rep)
		fmt.Println(string(b))
		return
	}
	if *accessMatrix != "" {
		res, err := RunAccessMatrixFromFileGo(*accessMatrix)
		if err != nil {
			os.Exit(1)
		}
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
		return
	}
	if *cloudPosture != "" {
		res, err := RunCloudPostureFromFileGo(*cloudPosture)
		if err != nil {
			os.Exit(1)
		}
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
		return
	}
	if *httpFraming != "" {
		res, err := RunHttpFramingAuditFromFileGo(*httpFraming)
		if err != nil {
			os.Exit(1)
		}
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
		return
	}
	if *mcpServer {
		hint := *mcpTsvPath
		if hint == "" {
			hint = *mcpDbPath
		}
		if err := RunLocalMcpStdioServerGo(hint); err != nil {
			os.Exit(1)
		}
		return
	}
	if *runPlugins != "" {
		res, err := RunClusteredYamlPluginsGo(*runPlugins, *pluginsDir, *kbHints, *timeoutMs)
		if err != nil {
			os.Exit(1)
		}
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
		return
	}
	if *syncFeeds != "" {
		var ecos []string
		for _, e := range strings.Split(*syncEcos, ",") {
			if t := strings.TrimSpace(e); t != "" {
				ecos = append(ecos, t)
			}
		}
		rep, err := StreamSyncCleanroomFeedsGo(*syncFeeds, ecos)
		if err != nil {
			os.Exit(1)
		}
		b, _ := json.Marshal(rep)
		fmt.Println(string(b))
		return
	}
	if *lookupOui != "" {
		if r := LookupOuiBinaryGo(*lookupOui); r != nil {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		}
		return
	}
	if *lookupPsl != "" {
		fmt.Println(LookupPslBinaryGo(*lookupPsl))
		return
	}
	if *probeHost != "" && (*probePort > 0 || *probePorts != "") {
		specs := parseSocketSpecsFlagGo(*probePorts, *probePort)
		res := ProbePortsConcurrentGo(*probeHost, *dispHost, specs, *timeoutMs)
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
		return
	}
	if *outDir == "" {
		os.Exit(2)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		os.Exit(1)
	}

	results := make(map[string]WordlistResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		seeds := []string{
			"www", "api", "dev", "staging", "stage", "test", "admin", "portal",
			"mail", "webmail", "vpn", "auth", "sso", "id", "cdn", "static",
			"media", "storage", "s3", "minio", "docs", "app", "cabinet", "dashboard",
			"git", "gitlab", "jenkins", "grafana", "kibana", "prometheus", "zabbix",
			"status", "backend", "cms", "crm", "erp", "billing", "db",
		}
		seen := make(map[string]struct{}, 160000)
		list := make([]string, 0, 160000)
		for _, s := range seeds {
			seen[s] = struct{}{}
			list = append(list, s)
		}
		used := false
		dnsFiles := []string{
			"DNS/services-names.txt",
			"DNS/subdomains-top1million-110000.txt",
			"DNS/bitquark-subdomains-top100000.txt",
		}
		for _, rel := range dnsFiles {
			if streamFileLines(filepath.Join(*secRoot, rel), func(raw string) {
				tok := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "*.")
				if _, ok := seen[tok]; !ok && isValidDNSLabel(tok) {
					seen[tok] = struct{}{}
					list = append(list, tok)
				}
			}) {
				used = true
			}
		}
		sha, err := writeAndHashLines(filepath.Join(*outDir, "subdomains_seclists.txt"), list)
		if err == nil {
			orig := "SPECTRE-Builtin-Seed (MIT)"
			if used {
				orig = "SecLists/Discovery/DNS (MIT, Go-Indexed)"
			}
			mu.Lock()
			results["wordlist_subdomains"] = WordlistResult{"wordlist_subdomains", len(list), sha, orig}
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		seeds := []string{
			"/robots.txt", "/sitemap.xml", "/swagger.json", "/openapi.json",
			"/v1/api-docs", "/graphql", "/.well-known/security.txt",
			"/.well-known/openid-configuration", "/actuator/health",
			"/wp-json/wp/v2/users", "/server-status", "/nginx_status",
		}
		seen := make(map[string]struct{}, 240000)
		list := make([]string, 0, 240000)
		for _, s := range seeds {
			seen[s] = struct{}{}
			list = append(list, s)
		}
		used := false
		webFiles := []string{
			"Web-Content/Common-DB-Backups.txt",
			"Web-Content/SAP-NetWeaver.txt",
			"Web-Content/Roundcube-123.txt",
			"Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
		}
		for _, rel := range webFiles {
			if streamFileLines(filepath.Join(*secRoot, rel), func(raw string) {
				ln := strings.TrimSpace(raw)
				if ln == "" || strings.HasPrefix(ln, "#") || strings.ContainsRune(ln, ' ') {
					return
				}
				norm := "/" + strings.TrimLeft(ln, "/")
				if len(norm) <= 140 {
					if _, ok := seen[norm]; !ok {
						seen[norm] = struct{}{}
						list = append(list, norm)
					}
				}
			}) {
				used = true
			}
		}
		sha, err := writeAndHashLines(filepath.Join(*outDir, "web_paths_seclists.txt"), list)
		if err == nil {
			orig := "SPECTRE-Builtin-Seed (MIT)"
			if used {
				orig = "SecLists/Discovery/Web-Content (MIT, Go-Indexed)"
			}
			mu.Lock()
			results["wordlist_web_paths"] = WordlistResult{"wordlist_web_paths", len(list), sha, orig}
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		seeds := []string{
			"id", "user_id", "account_id", "org_id", "role", "admin", "debug",
			"redirect", "redirect_uri", "next", "url", "callback", "token",
			"api_key", "file", "path", "template", "page", "limit", "offset",
			"sort", "filter", "q", "search",
		}
		seen := make(map[string]struct{}, 12000)
		list := make([]string, 0, 12000)
		for _, s := range seeds {
			seen[s] = struct{}{}
			list = append(list, s)
		}
		used := false
		for _, subDir := range []string{"Web-Content/BurpSuite-ParamMiner", "Variables"} {
			entries, err := os.ReadDir(filepath.Join(*secRoot, subDir))
			if err == nil {
				for _, ent := range entries {
					if !ent.IsDir() {
						if streamFileLines(filepath.Join(*secRoot, subDir, ent.Name()), func(raw string) {
							tok := strings.TrimSpace(raw)
							if _, ok := seen[tok]; !ok && isValidParamName(tok) {
								seen[tok] = struct{}{}
								list = append(list, tok)
							}
						}) {
							used = true
						}
					}
				}
			}
		}
		sha, err := writeAndHashLines(filepath.Join(*outDir, "api_params_seclists.txt"), list)
		if err == nil {
			orig := "SPECTRE-Builtin-Seed (MIT)"
			if used {
				orig = "SecLists/ParamMiner+Variables (MIT, Go-Indexed)"
			}
			mu.Lock()
			results["wordlist_api_params"] = WordlistResult{"wordlist_api_params", len(list), sha, orig}
			mu.Unlock()
		}
	}()

	wg.Wait()
	rep := IndexerReport{ABI: 1000, Engine: "go-goroutine-indexer", Wordlists: results}
	enc, _ := json.Marshal(rep)
	fmt.Println(string(enc))
}
