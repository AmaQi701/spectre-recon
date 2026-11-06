import collections
import threading
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory

from agents.recon_agent import ReconSuperAgent
from agents.triage_chain_agent import TriageAndChainSuperAgent
from agents.vuln_agent import VulnAssessmentSuperAgent
from core.database import DatabaseManager

BASE_DIR = Path("/home/amaqi/projects/apex-pentest-gui")
app = Flask(__name__, static_folder=str(BASE_DIR / "ui"), static_url_path="/ui")

db = DatabaseManager(str(BASE_DIR / "workspaces" / "apex_state.db"))
recon_agent = ReconSuperAgent(db, str(BASE_DIR / "config" / "tools_registry.yaml"))
vuln_agent = VulnAssessmentSuperAgent(db)
triage_agent = TriageAndChainSuperAgent(db, str(BASE_DIR / "reports"))

LIVE_LOGS: dict[int, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=400))


def append_log(project_id: int, msg: str):
    LIVE_LOGS[project_id].append(msg)


@app.route("/")
def index():
    return send_from_directory(str(BASE_DIR / "ui"), "index.html")


@app.route("/api/projects", methods=["GET", "POST"])
def handle_projects():
    if request.method == "GET":
        return jsonify({"projects": db.get_projects()})
    data = request.json or {}
    name = data.get("name", "Audit Project").strip()
    target = data.get("primary_target", "").strip()
    in_scope = data.get("in_scope", target).strip()
    out_scope = data.get("out_of_scope", "").strip()
    code_path = data.get("source_code_path", "").strip()
    notes = data.get("notes", "").strip()
    if not target:
        return jsonify({"error": "Asosiy nishon (Primary Target) kiritilishi shart"}), 400
    pid = db.create_project(name, target, in_scope, out_scope, code_path, notes)
    append_log(pid, f"[INIT] Loyiha yaratildi: {name} | Target: {target} | In-Scope: {in_scope}")
    return jsonify({"project_id": pid, "status": "created"})


@app.route("/api/projects/<int:project_id>/bundle", methods=["GET"])
def project_bundle(project_id: int):
    bundle = db.get_project_bundle(project_id)
    bundle["live_logs"] = list(LIVE_LOGS[project_id])
    return jsonify(bundle)


@app.route("/api/tools", methods=["GET", "POST"])
def handle_tools():
    if request.method == "GET":
        return jsonify({"tools": recon_agent.get_tools_status()})
    data = request.json or {}
    if data.get("action") == "toggle":
        recon_agent.toggle_tool(data.get("id", ""), bool(data.get("enabled", True)))
        return jsonify({"status": "updated"})
    if data.get("action") == "add":
        tool_obj = {
            "id": data.get("id", "").strip(),
            "name": data.get("name", "").strip(),
            "stage": data.get("stage", "1_passive_dns"),
            "binary": data.get("binary", "").strip(),
            "enabled": True,
            "description": data.get("description", ""),
            "command_template": data.get("command_template", ""),
        }
        recon_agent.save_custom_tool(tool_obj)
        return jsonify({"status": "added"})
    return jsonify({"error": "Unknown action"}), 400


@app.route("/api/projects/<int:project_id>/run_agent", methods=["POST"])
def run_agent_endpoint(project_id: int):
    data = request.json or {}
    agent_type = data.get("agent", "all")
    auth_header = data.get("auth_header", "").strip()
    if auth_header:
        if ":" in auth_header:
            k, v = auth_header.split(":", 1)
            recon_agent.session.headers[k.strip()] = v.strip()
        else:
            recon_agent.session.headers["Cookie"] = auth_header

    def worker():
        log_fn = lambda m: append_log(project_id, m)
        if agent_type in ("recon", "all"):
            recon_agent.run_full_recon(project_id, data.get("selected_tools"), log_fn)
        if agent_type in ("vuln", "all"):
            vuln_agent.run_assessment(project_id, log_fn)
        if agent_type in ("triage", "all"):
            triage_agent.run_triage_and_chaining(project_id, log_fn)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return jsonify({"status": "started", "agent": agent_type})


@app.route("/api/projects/<int:project_id>/report", methods=["POST"])
def build_report(project_id: int):
    res = triage_agent.generate_reports(project_id)
    append_log(project_id, f"[REPORT] Hisobot tayyorlandi: {res['markdown_path']} va {res['html_path']}")
    return jsonify(res)


@app.route("/api/projects/<int:project_id>/abort", methods=["POST"])
def abort_project_run(project_id: int):
    recon_agent.abort_project(project_id, lambda m: append_log(project_id, m))
    db.update_project_status(project_id, "ABORTED")
    return jsonify({"status": "aborted"})



@app.route("/api/jwt/audit", methods=["POST"])
def jwt_audit():
    token = (request.json or {}).get("token", "")
    return jsonify(vuln_agent.audit_jwt_token(token))


@app.route("/api/findings/<int:finding_id>/triage", methods=["POST"])
def update_triage(finding_id: int):
    status = (request.json or {}).get("triage_status", "Verified")
    db.update_finding_triage(finding_id, status)
    return jsonify({"status": "updated", "finding_id": finding_id, "triage_status": status})


@app.route("/api/projects/<int:project_id>/manual_finding", methods=["POST"])
def add_manual_finding(project_id: int):
    d = request.json or {}
    db.upsert_finding(
        project_id=project_id,
        agent="Agent-5 (Manual Pentester PoC)",
        title=d.get("title", "Manual Finding"),
        category=d.get("category", "Business Logic / Manual PoC"),
        severity=d.get("severity", "High"),
        cvss_score=float(d.get("cvss_score", 7.5)),
        cvss_vector=d.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
        cwe=d.get("cwe", "CWE-284"),
        owasp=d.get("owasp", "A01:2021 - Broken Access Control"),
        asset=d.get("asset", ""),
        evidence=d.get("evidence", ""),
        root_cause=d.get("root_cause", ""),
        remediation=d.get("remediation", ""),
        confidence="Confirmed-PoC",
        triage_status="Verified",
    )
    append_log(project_id, f"[MANUAL PoC] Pentester tomonidan yangi zaiflik qo'shildi: {d.get('title')}")
    return jsonify({"status": "added"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8765, debug=False, threaded=True)

