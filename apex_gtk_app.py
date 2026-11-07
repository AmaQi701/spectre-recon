#!/usr/bin/env python3
import json
import os
import sys
import threading
from pathlib import Path

# Snap (VS Code) muhitidan chaqirilganda GTK3 schema to'qnashuvini oldini olish
if any("/snap/" in os.environ.get(k, "") for k in ("GSETTINGS_SCHEMA_DIR", "XDG_DATA_DIRS", "GTK_PATH", "GIO_MODULE_DIR")):
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
window, .background { background-color: #090d16; color: #e2e8f0; font-family: "Inter", "Ubuntu", system-ui, sans-serif; }
headerbar { background-image: none; background-color: #0b1120; color: #f8fafc; border-bottom: 1px solid #1e293b; padding: 4px 10px; }
headerbar button.titlebutton { background-image: none; background-color: transparent; color: #94a3b8; border: none; box-shadow: none; }
headerbar button.titlebutton:hover { background-color: #1e293b; color: #ffffff; }

.sidebar { background-color: #0b1120; border-right: 1px solid #1e293b; padding: 10px; }
.nav-btn { background-image: none; background-color: transparent; color: #94a3b8; border: 1px solid transparent; border-radius: 7px; padding: 9px 12px; font-weight: 600; font-size: 13px; box-shadow: none; }
.nav-btn:hover { background-color: #111827; color: #e2e8f0; }
.nav-btn-active { background-image: none; background-color: #1e293b; color: #38bdf8; border: 1px solid #0284c7; border-radius: 7px; padding: 9px 12px; font-weight: 700; font-size: 13px; }

.toolbar-bar { background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 8px 12px; }
.stat-card { background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 12px 16px; }
.stat-title { font-size: 11px; color: #64748b; font-weight: 700; }
.stat-val { font-size: 20px; font-weight: 800; color: #38bdf8; }

treeview { background-color: #0b1120; color: #e2e8f0; font-size: 12.5px; border: none; }
treeview:selected { background-color: #1e3a8a; color: #ffffff; }
treeview header button { background-image: none; background-color: #111827; color: #94a3b8; font-weight: 700; font-size: 11.5px; border: none; border-bottom: 1px solid #1e293b; border-right: 1px solid #1e293b; padding: 8px 10px; box-shadow: none; }
treeview header button:hover { background-color: #1e293b; color: #38bdf8; }

entry, combobox button { background-image: none; background-color: #090d16; color: #e2e8f0; border: 1px solid #334155; border-radius: 6px; padding: 6px 10px; box-shadow: none; }
entry:focus { border-color: #0ea5e9; }
textview, textview text { background-color: #070a12; color: #cbd5e1; font-family: "JetBrains Mono", "Ubuntu Mono", monospace; font-size: 12px; }
.panel-box { background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 10px; }

.act-btn { background-image: none; background-color: #0284c7; color: #ffffff; font-weight: 700; font-size: 12px; border-radius: 6px; padding: 6px 13px; border: none; box-shadow: none; }
.act-btn:hover { background-color: #0369a1; }
.btn-green { background-image: none; background-color: #059669; color: #ffffff; font-weight: 700; font-size: 12px; border-radius: 6px; padding: 6px 13px; border: none; box-shadow: none; }
.btn-green:hover { background-color: #047857; }
.btn-amber { background-image: none; background-color: #d97706; color: #ffffff; font-weight: 700; font-size: 12px; border-radius: 6px; padding: 6px 13px; border: none; box-shadow: none; }
.btn-amber:hover { background-color: #b45309; }
.btn-red { background-image: none; background-color: #dc2626; color: #ffffff; font-weight: 700; font-size: 12px; border-radius: 6px; padding: 6px 13px; border: none; box-shadow: none; }
.btn-red:hover { background-color: #b91c1c; }
.btn-purple { background-image: none; background-color: #4f46e5; color: #ffffff; font-weight: 700; font-size: 12px; border-radius: 6px; padding: 6px 13px; border: none; box-shadow: none; }
.btn-purple:hover { background-color: #4338ca; }
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
        self.db.reset_stale_running_projects()
        self.recon_agent = ReconSuperAgent(self.db, str(BASE_DIR / "config" / "tools_registry.yaml"))
        self.vuln_agent = VulnAssessmentSuperAgent(self.db)
        self.triage_agent = TriageAndChainSuperAgent(self.db, str(BASE_DIR / "reports"))
        self.current_project_id = None

        self.is_running_job = False
        self._last_data_sig = None
        self._build_ui()
        self.refresh_projects()
        self.refresh_tools()
        GLib.timeout_add(2500, self._periodic_refresh)

    def _make_btn(self, label: str, css_cls: str = "act-btn", callback=None) -> Gtk.Button:
        btn = Gtk.Button(label=label)
        btn.get_style_context().add_class(css_cls or "act-btn")
        if callback:
            btn.connect("clicked", callback)
        return btn

    def _make_tree(self, columns: list[tuple[str, type]], use_markup: bool = True) -> tuple[Gtk.ScrolledWindow, Gtk.ListStore, Gtk.TreeView]:
        store = Gtk.ListStore(*[c[1] for c in columns])
        tree = Gtk.TreeView(model=store)
        tree.set_grid_lines(Gtk.TreeViewGridLines.HORIZONTAL)
        tree.set_headers_visible(True)
        for idx, (col_title, col_type) in enumerate(columns):
            renderer = Gtk.CellRendererText()
            renderer.set_padding(10, 7)
            renderer.set_property("ellipsize", Pango.EllipsizeMode.END)
            if use_markup and col_type == str:
                col = Gtk.TreeViewColumn(col_title, renderer, markup=idx)
            else:
                col = Gtk.TreeViewColumn(col_title, renderer, text=idx)
            col.set_resizable(True)
            col.set_min_width(80 if col_type == int else 110)
            col.set_expand(col_type == str)
            tree.append_column(col)
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_hexpand(True)
        scroll.get_style_context().add_class("panel-box")
        scroll.add(tree)
        return scroll, store, tree

    def _switch_page(self, page_name: str, clicked_btn: Gtk.Button):
        self.stack.set_visible_child_name(page_name)
        for b in self.nav_buttons:
            ctx = b.get_style_context()
            ctx.remove_class("nav-btn-active")
            ctx.add_class("nav-btn")
        clicked_btn.get_style_context().remove_class("nav-btn")
        clicked_btn.get_style_context().add_class("nav-btn-active")


    def _build_ui(self):
        # Clean Minimal HeaderBar (window controls stay sleek & native)
        hb = Gtk.HeaderBar()
        hb.set_show_close_button(True)
        hb.props.title = "👻 SPECTRE Recon & Attack Surface Studio v4.1"
        hb.props.subtitle = "Autonomous OSINT Mesh • Shodan CVE • Deep JS/SourceMap • Pentest Task Tree"
        self.set_titlebar(hb)

        outer_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.add(outer_hbox)

        # Left Modern Sidebar (Obsidian / Caido style)
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        sidebar.get_style_context().add_class("sidebar")
        sidebar.set_size_request(235, -1)
        brand_lbl = Gtk.Label(xalign=0)
        brand_lbl.set_markup("<span foreground='#38bdf8' weight='bold' size='large'>👻 SPECTRE v4.1</span>\n<span foreground='#64748b' size='small'>Cyber-Recon &amp; ASM Studio</span>")
        brand_lbl.set_margin_bottom(10)
        sidebar.pack_start(brand_lbl, False, False, 4)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(120)
        self.nav_buttons = []

        nav_items = [
            ("p_scope", "➕  1. Yangi Target & Scope"),
            ("p_recon", "🛰️  2. Recon & Target Dossier"),
            ("p_endpoints", "🗂️  3. Endpoints, API & JS"),
            ("p_vulns", "🔍  4. Vuln Audit & SAST"),
            ("p_chains", "🔗  5. Triage & Bug Chains"),
            ("p_report", "📄  6. Manual PoC & Report"),
            ("p_tools", "⚙️  7. Tool Registry & JWT"),
        ]
        for idx, (pname, plabel) in enumerate(nav_items):
            b = Gtk.Button(label=plabel)
            b.get_style_context().add_class("nav-btn-active" if idx == 1 else "nav-btn")
            b.connect("clicked", lambda btn, n=pname: self._switch_page(n, btn))
            self.nav_buttons.append(b)
            sidebar.pack_start(b, False, False, 0)

        outer_hbox.pack_start(sidebar, False, False, 0)

        # Right Main Workspace
        root_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        root_vbox.set_margin_top(10); root_vbox.set_margin_bottom(10)
        root_vbox.set_margin_start(12); root_vbox.set_margin_end(12)
        outer_hbox.pack_start(root_vbox, True, True, 0)

        # Top Command & Filter Toolbar
        cmd_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        cmd_bar.get_style_context().add_class("toolbar-bar")
        cmd_bar.pack_start(self._make_btn("➕ Yangi Target", "btn-green", lambda _: self._switch_page("p_scope", self.nav_buttons[0])), False, False, 0)
        self.proj_combo = Gtk.ComboBoxText()
        self.proj_combo.connect("changed", self.on_project_changed)
        cmd_bar.pack_start(self.proj_combo, False, False, 0)
        cmd_bar.pack_start(self._make_btn("🗑️", "btn-red", self.on_delete_project), False, False, 0)


        self.auth_entry = Gtk.Entry()
        self.auth_entry.set_placeholder_text("🔑 Grey-box Auth (Cookie: ... / Authorization: Bearer ...)")
        self.auth_entry.set_hexpand(True)
        cmd_bar.pack_start(self.auth_entry, True, True, 0)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("🔎 Filter (subdomen, port, api, cve...)")
        self.search_entry.set_width_chars(26)
        self.search_entry.connect("search-changed", lambda _: self.load_bundle())
        cmd_bar.pack_start(self.search_entry, False, False, 0)

        cmd_bar.pack_end(self._make_btn("🛑 STOP", "btn-red", lambda _: self.on_abort()), False, False, 0)
        cmd_bar.pack_end(self._make_btn("🚀 FULL AUTO", "btn-purple", lambda _: self.on_run_agent("all")), False, False, 0)
        cmd_bar.pack_end(self._make_btn("🔗 3-Agent", "btn-green", lambda _: self.on_run_agent("triage")), False, False, 0)
        cmd_bar.pack_end(self._make_btn("🔍 2-Agent", "btn-amber", lambda _: self.on_run_agent("vuln")), False, False, 0)
        cmd_bar.pack_end(self._make_btn("🛰️ 1-Agent", "act-btn", lambda _: self.on_run_agent("recon")), False, False, 0)
        root_vbox.pack_start(cmd_bar, False, False, 0)

        # Stats Row
        stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.lbl_stat_dom = Gtk.Label(label="0", xalign=0)
        self.lbl_stat_http = Gtk.Label(label="0 / 0", xalign=0)
        self.lbl_stat_ep = Gtk.Label(label="0 / 0", xalign=0)
        self.lbl_stat_find = Gtk.Label(label="0 / 0", xalign=0)
        for title_cap, lbl in [
            ("🌐 SUBDOMENLAR & DNS", self.lbl_stat_dom),
            ("🔌 OCHIQ PORTLAR & WEB", self.lbl_stat_http),
            ("🗂️ ENDPOINTLAR & JS BUNDLES", self.lbl_stat_ep),
            ("🚨 TOPILMALAR & ZANJIRLAR", self.lbl_stat_find),
        ]:
            t_lbl = Gtk.Label(label=title_cap, xalign=0)
            t_lbl.get_style_context().add_class("stat-title")
            lbl.get_style_context().add_class("stat-val")
            frame = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            frame.get_style_context().add_class("stat-card")
            frame.set_hexpand(True)
            frame.pack_start(t_lbl, False, False, 0)
            frame.pack_start(lbl, False, False, 0)
            stats_box.pack_start(frame, True, True, 0)
        root_vbox.pack_start(stats_box, False, False, 0)

        vpaned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        vpaned.set_position(560)
        root_vbox.pack_start(vpaned, True, True, 0)
        vpaned.pack1(self.stack, True, False)


        # TAB 0: Target & Scope (Quick + Full Creation Card)
        tab0 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        tab0.get_style_context().add_class("panel-box")
        tab0.set_margin_top(8); tab0.set_margin_start(8); tab0.set_margin_end(8)
        hdr0 = Gtk.Label(xalign=0)
        hdr0.set_markup("<span foreground='#38bdf8' weight='bold' size='large'>🎯 Yangi Nishon (Target) va Audit Loyihasi Qo'shish</span>\n<span foreground='#94a3b8'>Domen yoki IP manzilni kiriting (masalan: target.uz). In-Scope bo'sh qolsa avtomatik ravishda target.uz va *.target.uz olinadi.</span>")
        tab0.pack_start(hdr0, False, False, 4)
        grid0 = Gtk.Grid(column_spacing=14, row_spacing=12)
        self.ent_pname = Gtk.Entry(); self.ent_pname.set_placeholder_text("Masalan: MyTarget Audit")
        self.ent_ptarget = Gtk.Entry(); self.ent_ptarget.set_placeholder_text("Masalan: target.uz yoki https://www.target.uz")
        self.ent_pinscope = Gtk.Entry(); self.ent_pinscope.set_placeholder_text("Bo'sh qoldirsangiz avtomatik target.uz, *.target.uz olinadi")
        self.ent_poutscope = Gtk.Entry(); self.ent_poutscope.set_placeholder_text("Taqiqlangan subdomenlar (ixtiyoriy)")
        self.ent_pcode = Gtk.Entry(); self.ent_pcode.set_placeholder_text("/home/amaqi/projects/source-code (White-box SAST uchun ixtiyoriy)")
        for r_idx, (title_txt, widget) in enumerate([
            ("1. Loyiha Nomi:", self.ent_pname),
            ("2. Asosiy Nishon (Domain / URL / IP):", self.ent_ptarget),
            ("3. In-Scope (Ruxsat berilgan doira):", self.ent_pinscope),
            ("4. Out-of-Scope (Taqiqlangan manzillar):", self.ent_poutscope),
            ("5. White-box Kod Papkasi (SAST):", self.ent_pcode),
        ]):
            lbl = Gtk.Label(label=title_txt, xalign=0)
            widget.set_hexpand(True)
            grid0.attach(lbl, 0, r_idx, 1, 1)
            grid0.attach(widget, 1, r_idx, 1, 1)
        tab0.pack_start(grid0, False, False, 4)
        btn_row0 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_row0.pack_start(self._make_btn("➕ Loyihani Yaratish", "btn-green", self.on_create_project), False, False, 0)
        btn_row0.pack_start(self._make_btn("🚀 Loyihani Yaratish va Darhol 1-Agent (Recon) ni Boshlash!", "btn-purple", lambda b: self.on_create_project(b, auto_start=True)), False, False, 0)
        tab0.pack_start(btn_row0, False, False, 6)


        # TAB 1: Recon & Attack Surface + Target Dossier Inspector
        tab1 = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        tab1.set_position(740)
        tab1_left = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        tab1_left.set_position(250)
        sc_http, self.store_http, _ = self._make_tree([("URL", str), ("Status", str), ("Title", str), ("Server / Tech", str), ("WAF", str), ("Missing Headers", str)])
        sc_dom, self.store_dom, self.tree_dom = self._make_tree([("Subdomen / Host", str), ("IP Manzil", str), ("CNAME", str), ("Manba", str), ("Ochiq Portlar va Servislar", str)])
        self.tree_dom.connect("cursor-changed", self.on_domain_selected)
        tab1_left.pack1(sc_http, True, False)
        tab1_left.pack2(sc_dom, True, False)

        dossier_scroll = Gtk.ScrolledWindow()
        dossier_scroll.get_style_context().add_class("panel-box")
        self.dossier_view = Gtk.TextView()
        self.dossier_view.set_editable(False)
        self.dossier_view.set_monospace(True)
        self.dossier_view.set_left_margin(10); self.dossier_view.set_top_margin(8)
        self.dossier_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.dossier_view.get_buffer().set_text("Subdomen ustiga bosing — uning To'liq Texnik Pasporti (Target Dossier & PTT) shu yerda ochiladi...")
        dossier_scroll.add(self.dossier_view)

        tab1.pack1(tab1_left, True, False)
        tab1.pack2(dossier_scroll, True, False)
        self.stack.add_named(tab1, "p_recon")
        self.stack.add_named(tab0, "p_scope")


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
        self.stack.add_named(tab2_box, "p_endpoints")

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
        self.stack.add_named(tab3_box, "p_vulns")

        # TAB 4: Bug Chains
        sc_chain, self.store_chain, _ = self._make_tree([
            ("Severity", str), ("CVSS", str), ("Zanjir Nomi (Attack Chain)", str),
            ("Bosqichlar (Nodes)", str), ("Hujum Ssenariysi va Impact", str), ("Remediation", str)
        ])
        self.stack.add_named(sc_chain, "p_chains")

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
        self.stack.add_named(tab5, "p_report")

        # TAB 6: Tool Registry & JWT Auditor
        tab6 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        jwt_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.ent_jwt = Gtk.Entry(); self.ent_jwt.set_placeholder_text("JWT Token kiriting (eyJhbGciOi...)")
        self.ent_jwt.set_hexpand(True)
        jwt_row.pack_start(self.ent_jwt, True, True, 6)
        jwt_row.pack_start(self._make_btn("🔐 JWT Tekshirish", "act-btn", self.on_audit_jwt), False, False, 6)
        jwt_row.pack_start(self._make_btn("🔄 Tanlangan Toolni Yoqish/O'chirish", "btn-amber", self.on_toggle_tool), False, False, 6)
        tab6.pack_start(jwt_row, False, False, 4)
        sc_tools, self.store_tools, self.tree_tools = self._make_tree([
            ("ID", str), ("Faol (Enabled)", str), ("Tool Nomi", str), ("Bosqich", str),
            ("O'rnatilganligi", str), ("Binary Yo'li", str), ("Command Shabloni", str)
        ])
        tab6.pack_start(sc_tools, True, True, 0)
        self.stack.add_named(tab6, "p_tools")


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
            self._last_data_sig = None
            self.load_bundle()

    def on_delete_project(self, _btn):
        if not self.current_project_id:
            return
        old_id = self.current_project_id
        self.db.delete_project(old_id)
        self.current_project_id = None
        self._last_data_sig = None
        self.refresh_projects()
        self.load_bundle()
        self.log_msg(f"[DELETE] 🗑️ Loyiha #{old_id} bazadan o'chirildi.")


    @staticmethod
    def _esc(val: str) -> str:
        return GLib.markup_escape_text(str(val or ""))

    @classmethod
    def _color_sev(cls, sev: str) -> str:
        s = str(sev or "")
        if s in ("Critical", "High"):
            return f"<span foreground='#f87171' weight='bold'>● {cls._esc(s)}</span>"
        if s == "Medium":
            return f"<span foreground='#fbbf24' weight='bold'>● {cls._esc(s)}</span>"
        return f"<span foreground='#34d399' weight='bold'>● {cls._esc(s)}</span>"

    def on_domain_selected(self, tree):
        if not self.current_project_id:
            return
        sel = tree.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            import re as _re
            dom_name = _re.sub(r"<[^>]+>", "", model[treeiter][0])
            dossier_txt = spectre_deep_modules.build_target_dossier(self.db, self.current_project_id, dom_name)
            self.dossier_view.get_buffer().set_text(dossier_txt)

    def _periodic_refresh(self):
        # Faqat orqa fonda skaner ishlayotganda va ma'lumot o'zgargandagina yangilaymiz (tanlangan qator o'chib ketmasligi uchun!)
        if self.current_project_id and self.is_running_job:
            self.load_bundle(preserve_if_unchanged=True)
        return True

    def load_bundle(self, preserve_if_unchanged: bool = False):
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

        q = (self.search_entry.get_text() or "").strip().lower() if hasattr(self, "search_entry") else ""
        sig = (self.current_project_id, len(doms), len(ports), len(https), len(eps), len(js_list), len(finds), len(chains), q)
        if preserve_if_unchanged and sig == self._last_data_sig:
            return
        self._last_data_sig = sig


        self.lbl_stat_dom.set_text(f"{len(doms)} ta subdomen")
        self.lbl_stat_http.set_text(f"{len(ports)} port  •  {len(https)} web")
        self.lbl_stat_ep.set_text(f"{len(eps)} route  •  {len(js_list)} JS")
        self.lbl_stat_find.set_text(f"{len(finds)} topilma  •  {len(chains)} zanjir")

        q = (self.search_entry.get_text() or "").strip().lower() if hasattr(self, "search_entry") else ""

        self.store_http.clear()
        for s in https:
            tech = ", ".join(json.loads(s.get("tech_stack") or "[]"))
            sec = json.loads(s.get("security_headers_json") or "{}")
            miss = ", ".join([k for k, v in sec.items() if not v])
            code = int(s.get("status_code") or 0)
            c_col = "#34d399" if code == 200 else ("#fbbf24" if code in (301, 302, 401, 403) else "#f87171")
            raw_str = f"{s['url']} {code} {s['title']} {s['server']} {tech} {miss}".lower()
            if not q or q in raw_str:
                self.store_http.append([
                    f"<span foreground='#38bdf8' weight='bold'>{self._esc(s['url'])}</span>",
                    f"<span foreground='{c_col}' weight='bold'>{code}</span>",
                    self._esc(s["title"] or "-"),
                    self._esc(f"{s['server']} ({tech})"),
                    self._esc(s["waf"] or "-"),
                    self._esc(miss or "OK"),
                ])

        ports_by_host = {}
        ports_by_ip = {}
        for pt in ports:
            p_tag = f"{pt['port']}/{pt['protocol']}"
            if pt.get("host"):
                ports_by_host.setdefault(pt["host"], set()).add(p_tag)
            if pt.get("ip"):
                ports_by_ip.setdefault(pt["ip"], set()).add(p_tag)
        self.store_dom.clear()
        for d in doms:
            combined_ports = sorted(ports_by_host.get(d["domain"], set()) | ports_by_ip.get(d.get("ip", ""), set()), key=lambda x: int(x.split("/")[0]))
            p_str = ", ".join(combined_ports)
            raw_str = f"{d['domain']} {d['ip']} {d['cname']} {d['source']} {p_str}".lower()
            if not q or q in raw_str:
                self.store_dom.append([
                    f"<span foreground='#38bdf8' weight='bold'>{self._esc(d['domain'])}</span>",
                    f"<span foreground='#a78bfa'>{self._esc(d['ip'] or '-')}</span>",
                    self._esc(d["cname"] or "-"),
                    f"<span foreground='#34d399'>{self._esc(d['source'])}</span>",
                    self._esc(p_str or "-"),
                ])



        self.store_ep.clear()
        for e in eps:
            prm = ", ".join(json.loads(e.get("params_json") or "[]"))
            rsk = ", ".join(json.loads(e.get("risk_tags_json") or "[]"))
            raw_str = f"{e['method']} {e['url']} {prm} {e['category']} {rsk}".lower()
            if not q or q in raw_str:
                m_col = "#34d399" if e["method"] == "GET" else "#fbbf24"
                rsk_markup = f"<span foreground='#f87171' weight='bold'>{self._esc(rsk)}</span>" if rsk else "-"
                self.store_ep.append([
                    f"<span foreground='{m_col}' weight='bold'>{self._esc(e['method'])}</span>",
                    f"<span foreground='#38bdf8'>{self._esc(e['url'])}</span>",
                    self._esc(prm or "-"),
                    self._esc(f"{e['category']} ({e['source']})"),
                    rsk_markup,
                ])

        self.store_js.clear()
        for j in js_list:
            jeps = ", ".join(json.loads(j.get("endpoints_json") or "[]")[:10])
            jprm = ", ".join(json.loads(j.get("params_json") or "[]")[:12])
            jsnk = ", ".join(json.loads(j.get("sinks_json") or "[]") + json.loads(j.get("secrets_hints_json") or "[]"))
            raw_str = f"{j['js_url']} {jeps} {jprm} {jsnk}".lower()
            if not q or q in raw_str:
                self.store_js.append([
                    f"<span foreground='#38bdf8' weight='bold'>{self._esc(j['js_url'].split('/')[-1])}</span>",
                    self._esc(jeps or "-"),
                    self._esc(jprm or "-"),
                    f"<span foreground='#f87171'>{self._esc(jsnk)}</span>" if jsnk else "-",
                ])

        self.store_find.clear()
        for f in finds:
            raw_str = f"{f['severity']} {f['title']} {f['cwe']} {f['asset']} {f['evidence']}".lower()
            if not q or q in raw_str:
                t_col = "#34d399" if f["triage_status"] == "Verified" else ("#fbbf24" if f["triage_status"] == "Manual-Review" else "#64748b")
                self.store_find.append([
                    f["id"],
                    self._color_sev(f["severity"]),
                    f"<b>{f['cvss_score']}</b>",
                    f"<b>{self._esc(f['title'])}</b>",
                    self._esc(f"{f['cwe']} | {f['owasp']}"),
                    f"<span foreground='#38bdf8'>{self._esc(f['asset'])}</span>",
                    self._esc(f["evidence"]),
                    self._esc(f["remediation"]),
                    f"<span foreground='{t_col}' weight='bold'>{self._esc(f['triage_status'])}</span>",
                ])

        self.store_chain.clear()
        for c in chains:
            nodes = " ➔ ".join(json.loads(c.get("nodes_json") or "[]"))
            self.store_chain.append([
                self._color_sev(c["severity"]),
                f"<b>{c['cvss_score']}</b>",
                f"<b>{self._esc(c['chain_title'])}</b>",
                f"<span foreground='#38bdf8'>{self._esc(nodes)}</span>",
                self._esc(f"{c['attack_scenario']} | Impact: {c['impact']}"),
                self._esc(c["remediation"]),
            ])


    def on_create_project(self, _btn, auto_start: bool = False):
        target = self.ent_ptarget.get_text().strip()
        if not target:
            self.log_msg("[ERR] ⚠️ Asosiy nishon (Domain / IP) kiritilishi shart!")
            return
        name = self.ent_pname.get_text().strip() or target
        in_sc = self.ent_pinscope.get_text().strip() or f"{target}\n*.{target.lstrip('www.')}"
        out_sc = self.ent_poutscope.get_text().strip()
        code_p = self.ent_pcode.get_text().strip()
        pid = self.db.create_project(name, target, in_sc, out_sc, code_p)
        self.current_project_id = pid
        self._last_data_sig = None
        self.refresh_projects()
        self.load_bundle()
        self._switch_page("p_recon", self.nav_buttons[1])
        self.log_msg(f"[INIT] ✅ Yangi loyiha #{pid} yaratildi va faollashtirildi: {name} ({target})")
        if auto_start:
            self.on_run_agent("recon")

    def on_run_agent(self, agent_type: str):
        if not self.current_project_id:
            self.log_msg("[ERR] Avval loyiha yarating yoki tanlang!")
            return
        pid = self.current_project_id
        self.is_running_job = True
        self._switch_page("p_recon", self.nav_buttons[1])
        auth = self.auth_entry.get_text().strip()
        if auth:
            if ":" in auth:
                k, v = auth.split(":", 1)
                self.recon_agent.session.headers[k.strip()] = v.strip()
            else:
                self.recon_agent.session.headers["Cookie"] = auth

        def worker():
            try:
                if agent_type in ("recon", "all"):
                    self.recon_agent.run_full_recon(pid, None, self.log_msg)
                if agent_type in ("vuln", "all"):
                    self.vuln_agent.run_assessment(pid, self.log_msg)
                if agent_type in ("triage", "all"):
                    self.triage_agent.run_triage_and_chaining(pid, self.log_msg)
            finally:
                self.is_running_job = False
                self._last_data_sig = None
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
        if treeiter is None and len(model) > 0:
            treeiter = model.get_iter_first()
        if treeiter is not None:
            import re as _re
            method = _re.sub(r"<[^>]+>", "", model[treeiter][0])
            url = _re.sub(r"<[^>]+>", "", model[treeiter][1])
            auth = self.auth_entry.get_text().strip()
            h_flag = f' -H "{auth if ":" in auth else "Cookie: " + auth}"' if auth else ""
            cmd = f'curl -i -s -k -X {method}{h_flag} "{url}"'
            clip = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            clip.set_text(cmd, -1)
            self.log_msg(f"[CLIPBOARD] ✅ cURL nusxalandi: {cmd}")
        else:
            self.log_msg("[!] Endpointlar jadvali bo'sh yoki qator tanlanmagan.")

    def on_set_triage(self, status: str):
        sel = self.tree_find.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is None and len(model) > 0:
            treeiter = model.get_iter_first()
        if treeiter is not None:
            fid = model[treeiter][0]
            self.db.update_finding_triage(int(fid), status)
            self._last_data_sig = None
            self.load_bundle()
            self.log_msg(f"[TRIAGE] ✅ Topilma #{fid} statusi '{status}' ga o'zgartirildi.")
        else:
            self.log_msg("[!] Avval Topilmalar jadvalidan qatorni tanlang.")


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
            en_markup = "<span foreground='#34d399' weight='bold'>● YES</span>" if t.get("enabled") else "<span foreground='#64748b'>○ NO</span>"
            inst_markup = "<span foreground='#34d399' weight='bold'>READY</span>" if t["installed"] else "<span foreground='#f87171' weight='bold'>MISSING</span>"
            self.store_tools.append([
                self._esc(t["id"]),
                en_markup,
                f"<b>{self._esc(t['name'])}</b>",
                f"<span foreground='#38bdf8'>{self._esc(t['stage'])}</span>",
                inst_markup,
                self._esc(t["resolved_path"]),
                self._esc(t["command_template"]),
            ])

    def on_toggle_tool(self, _btn):
        sel = self.tree_tools.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            import re as _re
            tid = _re.sub(r"<[^>]+>", "", model[treeiter][0])
            cur_en = "YES" in model[treeiter][1]
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
    win.present()
    Gtk.main()





