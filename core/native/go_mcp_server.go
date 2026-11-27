// SPECTRE Native Go Read-Only Local JSON-RPC 2.0 MCP Server (`--mcp-server`)
// 100% Local stdio transport, zero external API keys, zero network egress.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *mcpError `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func searchCleanroomAdvisoryGo(query string, tsvHintPath string) []map[string]any {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	var out []map[string]any
	for _, r := range CompiledCleanroomAdvisories {
		if strings.Contains(strings.ToLower(r.ID), q) || strings.Contains(strings.ToLower(r.Product), q) || strings.Contains(strings.ToLower(r.Vendor), q) {
			out = append(out, map[string]any{
				"id": r.ID, "vendor": r.Vendor, "product": r.Product, "cpe23": r.CPE23,
				"min_ver": r.MinVer, "max_ver": r.MaxVer, "cvss": r.CVSS,
				"severity": r.Severity, "cwe": r.CWE, "is_kev": r.IsKEV == 1,
				"summary": r.Summary, "remediation": r.Remediation, "spdx": r.SPDX,
			})
			if len(out) >= 10 {
				return out
			}
		}
	}
	for _, s := range CompiledScaTable {
		if strings.Contains(strings.ToLower(s.CVE), q) || strings.Contains(strings.ToLower(s.Pkg), q) {
			out = append(out, map[string]any{
				"id": s.CVE, "ecosystem": s.Eco, "package": s.Pkg,
				"min_ver": s.MinV, "max_ver": s.MaxV, "cvss": s.CVSS, "severity": s.Sev,
			})
			if len(out) >= 10 {
				return out
			}
		}
	}
	if tsvHintPath != "" {
		if f, err := os.Open(tsvHintPath); err == nil {
			defer f.Close()
			hdr := make([]byte, 16)
			nHdr, _ := f.Read(hdr)
			if nHdr >= 15 && strings.HasPrefix(string(hdr[:nHdr]), "SQLite format 3") {
				return out
			}
			_, _ = f.Seek(0, 0)
			sc := bufio.NewScanner(f)
			for sc.Scan() && len(out) < 10 {
				ln := sc.Text()
				if strings.Contains(strings.ToLower(ln), q) {
					cols := strings.Split(ln, "\t")
					if len(cols) >= 14 {
						out = append(out, map[string]any{
							"id": cols[0], "vendor": cols[1], "product": cols[2],
							"cpe23": cols[3], "min_ver": cols[4], "max_ver": cols[5],
							"severity": cols[7], "cwe": cols[8], "summary": cols[12],
						})
					}
				}
			}
		}
	}
	return out
}


func handleMcpToolCallGo(params mcpCallParams, intelHint string) (any, *mcpError) {
	switch params.Name {
	case "spectre_engine_posture":
		info := map[string]any{
			"engine":          "SPECTRE Polyglot Native Security Engine",
			"version":         "9.5.0",
			"abi":             950,
			"socket_ports":    len(SupportedSocketPorts),
			"oui_vendors":     len(CompiledOuiTable),
			"psl_suffixes":    len(CompiledPslTable),
			"clean_seed_cves": len(CompiledCleanroomAdvisories),
			"cloud_ai_keys":   0,
		}
		b, _ := json.Marshal(info)
		return map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}}, nil
	case "spectre_lookup_oui":
		mac, _ := params.Arguments["mac"].(string)
		hit := LookupOuiBinaryGo(mac)
		b, _ := json.Marshal(hit)
		return map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}}, nil
	case "spectre_check_public_suffix":
		dom, _ := params.Arguments["suffix"].(string)
		ok := LookupPslBinaryGo(dom)
		return map[string]any{"content": []map[string]any{{"type": "text", "text": fmt.Sprintf(`{"suffix":%q,"is_public_suffix":%v}`, dom, ok)}}}, nil
	case "spectre_query_advisory":
		q, _ := params.Arguments["query"].(string)
		hits := searchCleanroomAdvisoryGo(q, intelHint)
		b, _ := json.Marshal(hits)
		return map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}}, nil
	default:
		return nil, &mcpError{Code: -32601, Message: "Unknown SPECTRE MCP tool: " + params.Name}
	}
}

func RunLocalMcpStdioServerGo(intelHintPath string) error {
	sc := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 0, 65536)
	sc.Buffer(buf, 1048576)
	bw := bufio.NewWriter(os.Stdout)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var req mcpRequest
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			errResp := mcpResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &mcpError{Code: -32700, Message: "Parse error"},
			}
			encE, _ := json.Marshal(errResp)
			_, _ = bw.Write(encE)
			_ = bw.WriteByte('\n')
			_ = bw.Flush()
			continue
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			errResp := mcpResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &mcpError{Code: -32600, Message: "Invalid Request"},
			}
			encE, _ := json.Marshal(errResp)
			_, _ = bw.Write(encE)
			_ = bw.WriteByte('\n')
			_ = bw.Flush()
			continue
		}
		if req.ID == nil {
			continue
		}
		var resp mcpResponse
		resp.JSONRPC = "2.0"
		resp.ID = req.ID
		switch req.Method {
		case "initialize":
			resp.Result = map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "spectre-local-mcp", "version": "9.5.0"},
			}
		case "ping":
			resp.Result = map[string]any{}
		case "tools/list":
			strProp := func(k string) map[string]any {
				return map[string]any{
					"type":       "object",
					"properties": map[string]any{k: map[string]any{"type": "string"}},
					"required":   []string{k},
				}
			}
			resp.Result = map[string]any{
				"tools": []map[string]any{
					{
						"name":        "spectre_engine_posture",
						"description": "Read-only SPECTRE v9.5.0 native engine status",
						"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
					},
					{
						"name":        "spectre_lookup_oui",
						"description": "Lookup IEEE MAC OUI hardware vendor offline",
						"inputSchema": strProp("mac"),
					},
					{
						"name":        "spectre_check_public_suffix",
						"description": "Check Mozilla Public Suffix List boundary offline",
						"inputSchema": strProp("suffix"),
					},
					{
						"name":        "spectre_query_advisory",
						"description": "Query Clean-Room CVE/OSV/KEV advisories offline",
						"inputSchema": strProp("query"),
					},
				},
			}
		case "tools/call":
			var cp mcpCallParams
			if err := json.Unmarshal(req.Params, &cp); err != nil {
				resp.Error = &mcpError{Code: -32602, Message: "Invalid tool call params"}
			} else {
				res, merr := handleMcpToolCallGo(cp, intelHintPath)
				resp.Result = res
				resp.Error = merr
			}
		default:
			resp.Error = &mcpError{Code: -32601, Message: "Method not found: " + req.Method}
		}
		enc, _ := json.Marshal(resp)
		_, _ = bw.Write(enc)
		_ = bw.WriteByte('\n')
		_ = bw.Flush()
	}
	return nil
}
