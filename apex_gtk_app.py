#!/usr/bin/env python3
import json
import os
import sys
import threading
from pathlib import Path

# Snap (VS Code) muhitidan chaqirilganda GTK3 schema to'qnashuvini oldini olish
if any("snap" in os.environ.get(k, "") for k in ("GSETTINGS_SCHEMA_DIR", "XDG_DATA_DIRS", "GTK_PATH", "GIO_MODULE_DIR")):
    for k in ("GSETTINGS_SCHEMA_DIR", "GTK_PATH", "GIO_MODULE_DIR", "LD_LIBRARY_PATH", "GTK_EXE_PREFIX", "GTK_DATA_PREFIX"):
        os.environ.pop(k, None)
    os.environ["XDG_DATA_DIRS"] = "/usr/local/share:/usr/share:/var/lib/snapd/desktop"
    os.execv(sys.executable, [sys.executable] + sys.argv)

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, GLib, Gtk, Pango

BASE_DIR = Path("/home/amaqi/projects/apex-pentest-gui")
sys.path.insert(0, str(BASE_DIR))

from agents.recon_agent import ReconSuperAgent
from agents.triage_chain_agent import TriageAndChainSuperAgent
from agents.vuln_agent import VulnAssessmentSuperAgent
from agents import spectre_deep_modules
from core.database import DatabaseManager

DARK_CSS = b"""
window, .background { background-color: #090d16; color: #e5e7eb; }
headerbar { background: #111827; color: #38bdf8; border-bottom: 1px solid #1f2937; }
notebook, stack { background-color: #0b1120; }
notebook header { background-color: #111827; border-bottom: 1px solid #1f2937; }
notebook tab { padding: 8px 14px; color: #9ca3af; font-weight: bold; }
notebook tab:checked { background-color: #1e293b; color: #38bdf8; border-bottom: 2px solid #0ea5e9; }
treeview { background-color: #0f172a; color: #e2e8f0; font-size: 12px; }
treeview:selected { background-color: #0284c7; color: #ffffff; }
entry, textview, textview text { background-color: #05080f; color: #34d399; border: 1px solid #374151; border-radius: 4px; padding: 4px; }
button { background-image: none; background-color: #0284c7; color: #ffffff; font-weight: bold; border-radius: 5px; padding: 5px 10px; border: none; }
button:hover { background-color: #0369a1; }
.btn-green { background-color: #059669; }
.btn-amber { background-color: #d97706; }
.btn-red { background-color: #dc2626; }
.btn-purple { background-color: #4f46e5; }
.stat-card { background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 10px; }
.stat-val { font-size: 18px; font-weight: bold; color: #38bdf8; }
"""


class ApexNativeWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="SPECTRE Recon & Attack Surface Studio v3.0 (Native Ubuntu Desktop)")
        self.set_default_size(1460, 900)
        self.set_wmclass("spectre-recon", "SPECTRE Recon Studio")
        icon_path = BASE_DIR / "ui" / "apex-icon.svg"
        if icon_path.exists():
            try:
                self.set_icon_from_file(str(icon_path))
            except Exception:
                pass

        settings = Gtk.Settings.get_default()
        if settings:
            settings.set_property("gtk-application-prefer-dark-theme", True)

        provider = Gtk.CssProvider()
        provider.load_from_data(DARK_CSS)
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        self.db = DatabaseManager(str(BASE_DIR / "workspaces" / "apex_state.db"))
        self.recon_agent = ReconSuperAgent(self.db, str(BASE_DIR / "config" / "tools_registry.yaml"))
        self.vuln_agent = VulnAssessmentSuperAgent(self.db)
        self.triage_agent = TriageAndChainSuperAgent(self.db, str(BASE_DIR / "reports"))
        self.current_project_id = None

        self._build_ui()
        self.refresh_projects()
        self.refresh_tools()
        GLib.timeout_add(3000, self._periodic_refresh)

    def _make_btn(self, label: str, css_cls: str = "", callback=None) -> Gtk.Button:
        btn = Gtk.Button(label=label)
        if css_cls:
            btn.get_style_context().add_class(css_cls)
        if callback:
            btn.connect("clicked", callback)
        return btn

    def _make_tree(self, columns: list[tuple[str, type]]) -> tuple[Gtk.ScrolledWindow, Gtk.ListStore, Gtk.TreeView]:
        store = Gtk.ListStore(*[c[1] for c in columns])
        tree = Gtk.TreeView(model=store)
        tree.set_grid_lines(Gtk.TreeViewGridLines.BOTH)
        for idx, (col_title, _) in enumerate(columns):
            renderer = Gtk.CellRendererText()
            renderer.set_property("ellipsize", Pango.EllipsizeMode.END)
            col = Gtk.TreeViewColumn(col_title, renderer, text=idx)
            col.set_resizable(True)
            col.set_min_width(90)
            col.set_expand(True)
            tree.append_column(col)
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_hexpand(True)
        scroll.add(tree)
        return scroll, store, tree

    def _build_ui(self):
        # HeaderBar
        hb = Gtk.HeaderBar()
        hb.set_show_close_button(True)
        hb.props.title = "👻 SPECTRE Recon & Attack Surface Studio v3.0"
        hb.props.subtitle = "Autonomous OSINT Mesh • Shodan CVE • Deep JS/SourceMap • Bug Chaining"
        self.set_titlebar(hb)

        self.proj_combo = Gtk.ComboBoxText()
        self.proj_combo.connect("changed", self.on_project_changed)
        hb.pack_start(self.proj_combo)

        self.auth_entry = Gtk.Entry()
        self.auth_entry.set_placeholder_text("Grey-box Auth (Cookie: ... / Authorization: Bearer ...)")
        self.auth_entry.set_width_chars(26)
        hb.pack_start(self.auth_entry)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("🔎 Filter (subdomen, port, api, cve...)")
        self.search_entry.set_width_chars(22)
        self.search_entry.connect("search-changed", lambda _: self.load_bundle())
        hb.pack_start(self.search_entry)

        hb.pack_end(self._make_btn("🛑 STOP", "btn-red", lambda _: self.on_abort()))
        hb.pack_end(self._make_btn("🚀 FULL AUTO", "btn-purple", lambda _: self.on_run_agent("all")))
        hb.pack_end(self._make_btn("🔗 3-Agent", "btn-green", lambda _: self.on_run_agent("triage")))
        hb.pack_end(self._make_btn("🔍 2-Agent", "btn-amber", lambda _: self.on_run_agent("vuln")))
        hb.pack_end(self._make_btn("🛰️ 1-Agent", "", lambda _: self.on_run_agent("recon")))

        root_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        root_vbox.set_margin_top(8)
        root_vbox.set_margin_bottom(8)
        root_vbox.set_margin_start(10)
        root_vbox.set_margin_end(10)
        self.add(root_vbox)

        # Stats Row
        stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.lbl_stat_dom = Gtk.Label(label="Subdomenlar: 0")
        self.lbl_stat_http = Gtk.Label(label="Portlar / Web: 0 / 0")
        self.lbl_stat_ep = Gtk.Label(label="API & Endpointlar: 0")
        self.lbl_stat_find = Gtk.Label(label="Zaifliklar / Zanjirlar: 0 / 0")
        for lbl in (self.lbl_stat_dom, self.lbl_stat_http, self.lbl_stat_ep, self.lbl_stat_find):
            lbl.get_style_context().add_class("stat-val")
            frame = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            frame.get_style_context().add_class("stat-card")
            frame.set_hexpand(True)
            frame.pack_start(lbl, True, True, 4)
            stats_box.pack_start(frame, True, True, 0)
        root_vbox.pack_start(stats_box, False, False, 0)

        vpaned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        vpaned.set_position(560)
        root_vbox.pack_start(vpaned, True, True, 0)

        notebook = Gtk.Notebook()
        vpaned.pack1(notebook, True, False)

        # TAB 0: Target & Scope
        tab0 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        tab0.set_margin_top(12); tab0.set_margin_start(12); tab0.set_margin_end(12)
        grid0 = Gtk.Grid(column_spacing=12, row_spacing=10)
        self.ent_pname = Gtk.Entry(); self.ent_pname.set_placeholder_text("Masalan: Enterprise Security Audit Q4")
        self.ent_ptarget = Gtk.Entry(); self.ent_ptarget.set_placeholder_text("example.com")
        self.ent_pinscope = Gtk.Entry(); self.ent_pinscope.set_placeholder_text("example.com, *.example.com")
        self.ent_poutscope = Gtk.Entry(); self.ent_poutscope.set_placeholder_text("out-of-scope.example.com")
        self.ent_pcode = Gtk.Entry(); self.ent_pcode.set_placeholder_text("/home/amaqi/projects/source-code (SAST uchun)")
        for r_idx, (title_txt, widget) in enumerate([
            ("Loyiha Nomi:", self.ent_pname),
            ("Asosiy Nishon (Primary Target):", self.ent_ptarget),
            ("In-Scope (Ruxsat berilgan domen/IP):", self.ent_pinscope),
            ("Out-of-Scope (Taqiqlangan manzillar):", self.ent_poutscope),
            ("White-box Kod Papkasi (SAST):", self.ent_pcode),
        ]):
            lbl = Gtk.Label(label=title_txt, xalign=0)
            widget.set_hexpand(True)
            grid0.attach(lbl, 0, r_idx, 1, 1)
            grid0.attach(widget, 1, r_idx, 1, 1)
        tab0.pack_start(grid0, False, False, 0)
        tab0.pack_start(self._make_btn("➕ Yangi Audit Loyihasini Yaratish va Faollashtirish", "btn-green", self.on_create_project), False, False, 6)
        notebook.append_page(tab0, Gtk.Label(label="🎯 0. Target & Scope"))

        # TAB 1: Recon & Attack Surface + Target Dossier Inspector
        tab1 = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        tab1.set_position(900)
        tab1_left = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        tab1_left.set_position(240)
        sc_http, self.store_http, _ = self._make_tree([("URL", str), ("Status", str), ("Title", str), ("Server / Tech", str), ("WAF", str), ("Missing Headers", str)])
        sc_dom, self.store_dom, self.tree_dom = self._make_tree([("Subdomen / Host", str), ("IP Manzil", str), ("CNAME", str), ("Manba", str), ("Ochiq Portlar va Servislar", str)])
        self.tree_dom.connect("cursor-changed", self.on_domain_selected)
        tab1_left.pack1(sc_http, True, False)
        tab1_left.pack2(sc_dom, True, False)

        dossier_scroll = Gtk.ScrolledWindow()
        self.dossier_view = Gtk.TextView()
        self.dossier_view.set_editable(False)
        self.dossier_view.set_monospace(True)
        self.dossier_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.dossier_view.get_buffer().set_text("Subdomen ustiga bosing — uning To'liq Texnik Pasporti (Target Dossier & PTT) shu yerda ochiladi...")
        dossier_scroll.add(self.dossier_view)

        tab1.pack1(tab1_left, True, False)
        tab1.pack2(dossier_scroll, True, False)
        notebook.append_page(tab1, Gtk.Label(label="🛰️ 1. Recon & Target Dossier"))

        # TAB 2: Endpoints, API & JS Bundles
        tab2_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        ep_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        ep_bar.pack_start(Gtk.Label(label="Ro'yxatdan endpointni tanlab, Burp Suite / Terminal uchun cURL nusxalashingiz mumkin:", xalign=0), True, True, 6)
        ep_bar.pack_end(self._make_btn("📋 Copy Selected Endpoint as cURL", "btn-amber", self.on_copy_curl), False, False, 6)
        tab2_box.pack_start(ep_bar, False, False, 4)
        tab2_paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        tab2_paned.set_position(260)
        sc_ep, self.store_ep, self.tree_ep = self._make_tree([("Method", str), ("Endpoint URL", str), ("Parametrlar", str), ("Kategoriya", str), ("Xavf Teglari (Manual Guide)", str)])
        sc_js, self.store_js, _ = self._make_tree([("JS Bundle Fayl", str), ("Ajratilgan API Route / URL'lar", str), ("Parametrlar", str), ("DOM Sinks & Config/Keys", str)])
        tab2_paned.pack1(sc_ep, True, False)
        tab2_paned.pack2(sc_js, True, False)
        tab2_box.pack_start(tab2_paned, True, True, 0)
        notebook.append_page(tab2_box, Gtk.Label(label="🗂️ 2. Endpoints, API & JS"))

        # TAB 3: Vuln Audit & SAST
        tab3_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        triage_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        triage_bar.pack_start(Gtk.Label(label="Tanlangan topilma (Finding) statusini o'zgartirish:", xalign=0), True, True, 6)
        triage_bar.pack_end(self._make_btn("❌ False-Positive", "btn-red", lambda _: self.on_set_triage("False-Positive")), False, False, 4)
        triage_bar.pack_end(self._make_btn("🕵️ Manual-Review", "btn-amber", lambda _: self.on_set_triage("Manual-Review")), False, False, 4)
        triage_bar.pack_end(self._make_btn("✅ Verified", "btn-green", lambda _: self.on_set_triage("Verified")), False, False, 4)
        tab3_box.pack_start(triage_bar, False, False, 4)
        sc_find, self.store_find, self.tree_find = self._make_tree([
            ("ID", int), ("Severity", str), ("CVSS", str), ("Zaiflik Nomi", str),
            ("CWE / OWASP", str), ("Nishon (Asset)", str), ("Dalil (Evidence)", str),
            ("Remediation (Yechim)", str), ("Triage Holati", str)
        ])
        tab3_box.pack_start(sc_find, True, True, 0)
        notebook.append_page(tab3_box, Gtk.Label(label="🔍 3. Vuln Audit & SAST"))

        # TAB 4: Bug Chains
        sc_chain, self.store_chain, _ = self._make_tree([
            ("Severity", str), ("CVSS", str), ("Zanjir Nomi (Attack Chain)", str),
            ("Bosqichlar (Nodes)", str), ("Hujum Ssenariysi va Impact", str), ("Remediation", str)
        ])
        notebook.append_page(sc_chain, Gtk.Label(label="🔗 4. Triage & Bug Chains"))

        # TAB 5: Manual PoC & Report Studio
        tab5 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        tab5.set_margin_top(10); tab5.set_margin_start(10); tab5.set_margin_end(10)
        pgrid = Gtk.Grid(column_spacing=8, row_spacing=6)
        self.ent_mtitle = Gtk.Entry(); self.ent_mtitle.set_placeholder_text("Zaiflik nomi (masalan: IDOR in /api/v1/orders)")
        self.ent_msev = Gtk.Entry(); self.ent_msev.set_text("High")
        self.ent_mcvss = Gtk.Entry(); self.ent_mcvss.set_text("8.2")
        self.ent_masset = Gtk.Entry(); self.ent_masset.set_placeholder_text("URL yoki Fayl:Qator")
        self.ent_mevid = Gtk.Entry(); self.ent_mevid.set_placeholder_text("PoC HTTP Request/Response dalili")
        self.ent_mrem = Gtk.Entry(); self.ent_mrem.set_placeholder_text("Remediation / Patch")
        for idx, w in enumerate([self.ent_mtitle, self.ent_msev, self.ent_mcvss, self.ent_masset, self.ent_mevid, self.ent_mrem]):
            w.set_hexpand(True)
            pgrid.attach(w, idx % 3, idx // 3, 1, 1)
        tab5.pack_start(pgrid, False, False, 0)
        btn_row5 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_row5.pack_start(self._make_btn("➕ Manual PoC Zaiflik Qo'shish", "btn-amber", self.on_add_manual), False, False, 0)
        btn_row5.pack_start(self._make_btn("📥 Markdown va HTML Hisobot Generatsiya Qilish", "btn-green", self.on_generate_report), False, False, 0)
        tab5.pack_start(btn_row5, False, False, 0)
        self.rep_view = Gtk.TextView(); self.rep_view.set_editable(False); self.rep_view.set_monospace(True)
        sc_rep = Gtk.ScrolledWindow(); sc_rep.set_vexpand(True); sc_rep.add(self.rep_view)
        tab5.pack_start(sc_rep, True, True, 0)
        notebook.append_page(tab5, Gtk.Label(label="📄 5. Manual PoC & Report"))

        # TAB 6: Tool Registry & JWT Auditor
        tab6 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        jwt_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.ent_jwt = Gtk.Entry(); self.ent_jwt.set_placeholder_text("JWT Token kiriting (eyJhbGciOi...)")
        self.ent_jwt.set_hexpand(True)
        jwt_row.pack_start(self.ent_jwt, True, True, 6)
        jwt_row.pack_start(self._make_btn("🔐 JWT Tekshirish", "", self.on_audit_jwt), False, False, 6)
        jwt_row.pack_start(self._make_btn("🔄 Tanlangan Toolni Yoqish/O'chirish", "btn-amber", self.on_toggle_tool), False, False, 6)
        tab6.pack_start(jwt_row, False, False, 4)
        sc_tools, self.store_tools, self.tree_tools = self._make_tree([
            ("ID", str), ("Faol (Enabled)", str), ("Tool Nomi", str), ("Bosqich", str),
            ("O'rnatilganligi", str), ("Binary Yo'li", str), ("Command Shabloni", str)
        ])
        tab6.pack_start(sc_tools, True, True, 0)
        notebook.append_page(tab6, Gtk.Label(label="⚙️ 6. Tool Registry & JWT"))

        # Bottom Live Terminal
        term_scroll = Gtk.ScrolledWindow()
        self.term_view = Gtk.TextView()
        self.term_view.set_editable(False)
        self.term_view.set_monospace(True)
        self.term_buf = self.term_view.get_buffer()
        self.term_buf.set_text("[SPECTRE v3.0 NATIVE GTK3 STUDIO] Mahalliy Ubuntu kiber-razvedka platformasi ishga tushdi.\n")
        term_scroll.add(self.term_view)
        vpaned.pack2(term_scroll, False, False)

    def log_msg(self, msg: str):
        def _append():
            end_iter = self.term_buf.get_end_iter()
            self.term_buf.insert(end_iter, msg + "\n")
            mark = self.term_buf.create_mark(None, self.term_buf.get_end_iter(), False)
            self.term_view.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)
            return False
        GLib.idle_add(_append)

    def refresh_projects(self):
        projs = self.db.get_projects()
        self.proj_combo.remove_all()
        for p in projs:
            self.proj_combo.append(str(p["id"]), f"#{p['id']} {p['name']} ({p['primary_target']}) [{p['status']}]")
        if projs:
            target_id = str(self.current_project_id or projs[0]["id"])
            self.proj_combo.set_active_id(target_id)
            if not self.proj_combo.get_active_id():
                self.proj_combo.set_active(0)

    def on_project_changed(self, combo):
        aid = combo.get_active_id()
        if aid:
            self.current_project_id = int(aid)
            self.load_bundle()

    def on_domain_selected(self, tree):
        if not self.current_project_id:
            return
        sel = tree.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            dom_name = model[treeiter][0]
            dossier_txt = spectre_deep_modules.build_target_dossier(self.db, self.current_project_id, dom_name)
            self.dossier_view.get_buffer().set_text(dossier_txt)


    def _periodic_refresh(self):
        if self.current_project_id:
            self.load_bundle()
        return True

    def load_bundle(self):
        if not self.current_project_id:
            return
        b = self.db.get_project_bundle(self.current_project_id)
        doms = b.get("domains", [])
        ports = b.get("ports", [])
        https = b.get("http_services", [])
        eps = b.get("endpoints", [])
        js_list = b.get("js_assets", [])
        finds = b.get("findings", [])
        chains = b.get("bug_chains", [])

        self.lbl_stat_dom.set_text(f"Subdomenlar: {len(doms)}")
        self.lbl_stat_http.set_text(f"Portlar: {len(ports)} | Web: {len(https)}")
        self.lbl_stat_ep.set_text(f"Endpointlar: {len(eps)} | JS: {len(js_list)}")
        self.lbl_stat_find.set_text(f"Topilmalar: {len(finds)} | Zanjirlar: {len(chains)}")

        q = (self.search_entry.get_text() or "").strip().lower() if hasattr(self, "search_entry") else ""

        self.store_http.clear()
        for s in https:
            tech = ", ".join(json.loads(s.get("tech_stack") or "[]"))
            sec = json.loads(s.get("security_headers_json") or "{}")
            miss = ", ".join([k for k, v in sec.items() if not v])
            row_h = [s["url"], str(s["status_code"]), s["title"], f"{s['server']} ({tech})", s["waf"] or "-", miss or "OK"]
            if not q or any(q in str(x).lower() for x in row_h):
                self.store_http.append(row_h)

        ports_map = {}
        for pt in ports:
            ports_map.setdefault(pt["host"], []).append(f"{pt['port']}/{pt['protocol']} ({pt['service']} {pt['version']})")
        self.store_dom.clear()
        for d in doms:
            p_str = ", ".join(ports_map.get(d["domain"], []))
            row_d = [d["domain"], d["ip"] or "-", d["cname"] or "-", d["source"], p_str or "-"]
            if not q or any(q in str(x).lower() for x in row_d):
                self.store_dom.append(row_d)

        self.store_ep.clear()
        for e in eps:
            prm = ", ".join(json.loads(e.get("params_json") or "[]"))
            rsk = ", ".join(json.loads(e.get("risk_tags_json") or "[]"))
            row_e = [e["method"], e["url"], prm or "-", f"{e['category']} ({e['source']})", rsk or "-"]
            if not q or any(q in str(x).lower() for x in row_e):
                self.store_ep.append(row_e)

        self.store_js.clear()
        for j in js_list:
            jeps = ", ".join(json.loads(j.get("endpoints_json") or "[]")[:10])
            jprm = ", ".join(json.loads(j.get("params_json") or "[]")[:12])
            jsnk = ", ".join(json.loads(j.get("sinks_json") or "[]") + json.loads(j.get("secrets_hints_json") or "[]"))
            row_j = [j["js_url"].split("/")[-1], jeps or "-", jprm or "-", jsnk or "-"]
            if not q or any(q in str(x).lower() for x in row_j):
                self.store_js.append(row_j)

        self.store_find.clear()
        for f in finds:
            row_f = [f["id"], f["severity"], str(f["cvss_score"]), f["title"], f"{f['cwe']} | {f['owasp']}", f["asset"], f["evidence"], f["remediation"], f["triage_status"]]
            if not q or any(q in str(x).lower() for x in row_f):
                self.store_find.append(row_f)


        self.store_chain.clear()
        for c in chains:
            nodes = " ➔ ".join(json.loads(c.get("nodes_json") or "[]"))
            self.store_chain.append([c["severity"], str(c["cvss_score"]), c["chain_title"], nodes, f"{c['attack_scenario']} | Impact: {c['impact']}", c["remediation"]])

    def on_create_project(self, _btn):
        name = self.ent_pname.get_text().strip() or "Audit Project"
        target = self.ent_ptarget.get_text().strip()
        in_sc = self.ent_pinscope.get_text().strip() or target
        out_sc = self.ent_poutscope.get_text().strip()
        code_p = self.ent_pcode.get_text().strip()
        if not target:
            self.log_msg("[ERR] Asosiy nishon (Primary Target) kiritilishi shart!")
            return
        pid = self.db.create_project(name, target, in_sc, out_sc, code_p)
        self.current_project_id = pid
        self.refresh_projects()
        self.load_bundle()
        self.log_msg(f"[INIT] Yangi loyiha #{pid} yaratildi: {name} ({target})")

    def on_run_agent(self, agent_type: str):
        if not self.current_project_id:
            self.log_msg("[ERR] Avval loyiha yarating yoki tanlang!")
            return
        pid = self.current_project_id
        auth = self.auth_entry.get_text().strip()
        if auth:
            if ":" in auth:
                k, v = auth.split(":", 1)
                self.recon_agent.session.headers[k.strip()] = v.strip()
            else:
                self.recon_agent.session.headers["Cookie"] = auth

        def worker():
            if agent_type in ("recon", "all"):
                self.recon_agent.run_full_recon(pid, None, self.log_msg)
            if agent_type in ("vuln", "all"):
                self.vuln_agent.run_assessment(pid, self.log_msg)
            if agent_type in ("triage", "all"):
                self.triage_agent.run_triage_and_chaining(pid, self.log_msg)
            GLib.idle_add(self.refresh_projects)
            GLib.idle_add(self.load_bundle)

        threading.Thread(target=worker, daemon=True).start()

    def on_abort(self):
        if self.current_project_id:
            self.recon_agent.abort_project(self.current_project_id, self.log_msg)
            self.db.update_project_status(self.current_project_id, "ABORTED")
            self.refresh_projects()

    def on_copy_curl(self, _btn):
        sel = self.tree_ep.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            method, url = model[treeiter][0], model[treeiter][1]
            auth = self.auth_entry.get_text().strip()
            h_flag = f' -H "{auth if ":" in auth else "Cookie: " + auth}"' if auth else ""
            cmd = f'curl -i -s -k -X {method}{h_flag} "{url}"'
            clip = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            clip.set_text(cmd, -1)
            self.log_msg(f"[CLIPBOARD] cURL nusxalandi: {cmd}")

    def on_set_triage(self, status: str):
        sel = self.tree_find.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            fid = model[treeiter][0]
            self.db.update_finding_triage(int(fid), status)
            self.load_bundle()
            self.log_msg(f"[TRIAGE] Topilma #{fid} statusi '{status}' ga o'zgartirildi.")

    def on_add_manual(self, _btn):
        if not self.current_project_id:
            return
        title = self.ent_mtitle.get_text().strip() or "Manual PoC Finding"
        sev = self.ent_msev.get_text().strip() or "High"
        try:
            cvss = float(self.ent_mcvss.get_text().strip() or 7.5)
        except ValueError:
            cvss = 7.5
        asset = self.ent_masset.get_text().strip()
        evid = self.ent_mevid.get_text().strip()
        rem = self.ent_mrem.get_text().strip()
        self.db.upsert_finding(
            self.current_project_id, "Agent-5 (Manual PoC)", title, "Manual Pentester PoC",
            sev, cvss, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "CWE-284", "A01:2021 - Broken Access Control",
            asset, evid, "Manual verification by pentester", rem, confidence="Confirmed-PoC", triage_status="Verified"
        )
        self.load_bundle()
        self.log_msg(f"[MANUAL PoC] Qo'shildi: {title} ({sev})")

    def on_generate_report(self, _btn):
        if not self.current_project_id:
            return
        res = self.triage_agent.generate_reports(self.current_project_id)
        buf = self.rep_view.get_buffer()
        buf.set_text(f"Hisobot fayllari saqlandi:\n- {res['markdown_path']}\n- {res['html_path']}\n\n{res['markdown_preview']}")
        self.log_msg(f"[REPORT] Hisobot tayyor: {res['markdown_path']}")

    def refresh_tools(self):
        self.store_tools.clear()
        for t in self.recon_agent.get_tools_status():
            self.store_tools.append([
                t["id"], "YES" if t.get("enabled") else "NO", t["name"],
                t["stage"], "READY" if t["installed"] else "MISSING",
                t["resolved_path"], t["command_template"]
            ])

    def on_toggle_tool(self, _btn):
        sel = self.tree_tools.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            tid = model[treeiter][0]
            cur_en = model[treeiter][1] == "YES"
            self.recon_agent.toggle_tool(tid, not cur_en)
            self.refresh_tools()

    def on_audit_jwt(self, _btn):
        tok = self.ent_jwt.get_text().strip()
        res = self.vuln_agent.audit_jwt_token(tok)
        self.log_msg(f"[JWT AUDIT] {json.dumps(res, ensure_ascii=False)}")


if __name__ == "__main__":
    win = ApexNativeWindow()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()




