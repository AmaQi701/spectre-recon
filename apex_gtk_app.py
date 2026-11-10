#!/usr/bin/env python3
import json
import os
import re
import subprocess
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
from agents import spectre_deep_modules, spectre_v5_modules
from core.database import DatabaseManager
from core.scope_guard import ScopeGuard

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
textview, textview text { background-color: #070a12; color: #34d399; font-family: "JetBrains Mono", "Ubuntu Mono", monospace; font-size: 12.5px; }
.panel-box { background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 8px; }
progressbar text { color: #ffffff; font-weight: 700; font-size: 12px; }
progressbar trough { min-height: 22px; background-color: #090d16; border: 1px solid #1e293b; border-radius: 6px; }
progressbar progress { min-height: 22px; background-image: none; background-color: #0284c7; border-radius: 6px; }


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
        super().__init__(title="SPECTRE Recon & Attack Surface Studio v6.0 (Native Ubuntu Desktop)")
        self.set_default_size(1280, 760)
        self.maximize()
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
        narrow_cols = {"ID", "Status", "CVSS", "WAF", "Method", "Manba", "CNAME", "Faol (Enabled)", "O'rnatilganligi"}
        wide_cols = {"URL", "Endpoint URL", "Subdomen / Host", "Zaiflik Nomi", "Nishon (Asset)", "Ajratilgan API Route / URL'lar"}
        for idx, (col_title, col_type) in enumerate(columns):
            renderer = Gtk.CellRendererText()
            renderer.set_padding(8, 6)
            renderer.set_property("ellipsize", Pango.EllipsizeMode.END)
            if use_markup and col_type == str:
                col = Gtk.TreeViewColumn(col_title, renderer, markup=idx)
            else:
                col = Gtk.TreeViewColumn(col_title, renderer, text=idx)
            col.set_resizable(True)
            col.set_sort_column_id(idx)
            col.set_clickable(True)
            if col_title in narrow_cols or col_type == int:
                col.set_min_width(55)
                col.set_expand(False)
            elif col_title in wide_cols:
                col.set_min_width(170)
                col.set_expand(True)
            else:
                col.set_min_width(90)
                col.set_expand(True)
            tree.append_column(col)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        scroll.set_hexpand(True)
        scroll.get_style_context().add_class("panel-box")
        scroll.add(tree)
        return scroll, store, tree

    def _attach_context_menu(self, tree: Gtk.TreeView, target_col: int):
        def _on_btn_press(tv, event):
            if event.button != 3:
                return False
            path_info = tv.get_path_at_pos(int(event.x), int(event.y))
            if not path_info:
                return False
            path, col, _, _ = path_info
            tv.grab_focus()
            tv.set_cursor(path, col, 0)
            model = tv.get_model()
            raw_val = re.sub(r"<[^>]+>", "", str(model[path][target_col] or "")).strip()
            if not raw_val:
                return False
            full_url = raw_val if raw_val.startswith("http") else f"https://{raw_val.lstrip('/')}"
            host_only = re.sub(r"^https?://", "", full_url).split("/")[0].split(":")[0]

            menu = Gtk.Menu()
            it_open = Gtk.MenuItem(label=f"🌐 Brauzerda Ochish ({raw_val[:38]})")
            it_open.connect("activate", lambda _: subprocess.Popen(["xdg-open", full_url]))
            menu.append(it_open)

            it_rep = Gtk.MenuItem(label="⚡ HTTP Repeater'ga Yuborish")
            def _send_rep(_):
                self.rep_url_entry.set_text(full_url)
                self._switch_page("p_endpoints", self.nav_buttons[2])
                self.log_msg(f"[REPEATER] ⚡ URL Repeater'ga yuklandi: {full_url}")
            it_rep.connect("activate", _send_rep)
            menu.append(it_rep)

            it_deep = Gtk.MenuItem(label=f"🎯 Shu Hostni Chuqur Skanerlash ({host_only})")
            def _deep_host(_):
                self._selected_domain = host_only
                self.on_deep_scan_selected_subdomain(None, explicit_host=host_only)
            it_deep.connect("activate", _deep_host)
            menu.append(it_deep)

            it_copy = Gtk.MenuItem(label="📋 Manzilni Nusxalash (Copy)")
            it_copy.connect("activate", lambda _: Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(raw_val, -1))
            menu.append(it_copy)

            menu.show_all()
            menu.popup_at_pointer(event)
            return True

        tree.connect("button-press-event", _on_btn_press)


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
        hb.props.title = "👻 SPECTRE Recon & Attack Surface Studio v8.0"
        hb.props.subtitle = "Adaptive Brain • Safe Auto-Validator • True SNI Unmasker • Visual Topology Graph"
        self.set_titlebar(hb)

        outer_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.add(outer_hbox)

        # Left Modern Sidebar (compact 205px width so it always fits 1920x1080)
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        sidebar.get_style_context().add_class("sidebar")
        sidebar.set_size_request(205, -1)
        brand_lbl = Gtk.Label(xalign=0)
        brand_lbl.set_markup("<span foreground='#38bdf8' weight='bold' size='large'>👻 SPECTRE v8.0</span>\n<span foreground='#64748b' size='small'>Adaptive Cyber-Recon Studio</span>")
        brand_lbl.set_margin_bottom(8)
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
            ("p_graph", "🕸️  6. Attack Surface Graph"),
            ("p_report", "📄  7. Manual PoC & Report"),
            ("p_tools", "⚙️  8. Tool Registry & JWT"),
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

        # Top Command & Filter Toolbar (Row 1: Project, Filter, Mode & Agent Buttons)
        cmd_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        cmd_bar.get_style_context().add_class("toolbar-bar")
        cmd_bar.pack_start(self._make_btn("➕ Yangi Target", "btn-green", lambda _: self._switch_page("p_scope", self.nav_buttons[0])), False, False, 0)
        self.proj_combo = Gtk.ComboBoxText()
        self.proj_combo.connect("changed", self.on_project_changed)
        cmd_bar.pack_start(self.proj_combo, False, False, 0)
        cmd_bar.pack_start(self._make_btn("🗑️", "btn-red", self.on_delete_project), False, False, 0)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("🔎 Filter (subdomen, port, api, cve...)")
        self.search_entry.set_hexpand(True)
        self.search_entry.connect("search-changed", lambda _: self.load_bundle())
        cmd_bar.pack_start(self.search_entry, True, True, 0)

        self.mode_combo = Gtk.ComboBoxText()
        self.mode_combo.append("full", "🛰️ Full Recon")
        self.mode_combo.append("subdomains", "🌐 Subdomains")
        self.mode_combo.append("ports", "🔌 Ports/Shodan")
        self.mode_combo.append("web_js", "📦 Web/API/JS")
        self.mode_combo.set_active_id("full")
        cmd_bar.pack_start(self.mode_combo, False, False, 0)

        cmd_bar.pack_end(self._make_btn("🛑 STOP", "btn-red", lambda _: self.on_abort()), False, False, 0)
        cmd_bar.pack_end(self._make_btn("🚀 FULL AUTO", "btn-purple", lambda _: self.on_run_agent("all")), False, False, 0)
        cmd_bar.pack_end(self._make_btn("🔗 3-Agent", "btn-green", lambda _: self.on_run_agent("triage")), False, False, 0)
        cmd_bar.pack_end(self._make_btn("🔍 2-Agent", "btn-amber", lambda _: self.on_run_agent("vuln")), False, False, 0)
        cmd_bar.pack_end(self._make_btn("🛰️ 1-Agent", "act-btn", lambda _: self.on_run_agent("recon")), False, False, 0)
        root_vbox.pack_start(cmd_bar, False, False, 0)

        # Row 2: Auth, Proxy & Live Stage Progress Bar
        sub_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.auth_entry = Gtk.Entry()
        self.auth_entry.set_placeholder_text("🔑 Grey-box Auth (Cookie: ... / Authorization: Bearer ...)")
        self.auth_entry.set_width_chars(28)
        sub_bar.pack_start(self.auth_entry, False, False, 0)

        self.proxy_entry = Gtk.Entry()
        self.proxy_entry.set_placeholder_text("🌐 Proxy (http://127.0.0.1:8080)")
        self.proxy_entry.set_width_chars(22)
        sub_bar.pack_start(self.proxy_entry, False, False, 0)

        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        self.progress_bar.set_text("SPECTRE v6.0 Ready — Nishonni tanlang yoki skanerni boshlang")
        self.progress_bar.set_fraction(0.0)
        self.progress_bar.set_hexpand(True)
        self.progress_bar.set_valign(Gtk.Align.CENTER)
        sub_bar.pack_start(self.progress_bar, True, True, 0)
        root_vbox.pack_start(sub_bar, False, False, 0)



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
        vpaned.set_position(430)
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
        sc_http, self.store_http, self.tree_http = self._make_tree([("URL", str), ("Status", str), ("Title", str), ("Server / Tech", str), ("WAF", str), ("Missing Headers", str)])
        sc_dom, self.store_dom, self.tree_dom = self._make_tree([("Subdomen / Host", str), ("IP Manzil", str), ("CNAME", str), ("Manba", str), ("Ochiq Portlar va Servislar", str)])
        self.tree_dom.connect("cursor-changed", self.on_domain_selected)
        self._attach_context_menu(self.tree_http, 0)
        self._attach_context_menu(self.tree_dom, 0)
        tab1_left.pack1(sc_http, True, False)
        tab1_left.pack2(sc_dom, True, False)

        dossier_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        dos_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        dos_bar.pack_start(Gtk.Label(label="🎯 Target Dossier & Pentesting Task Tree (PTT):", xalign=0), True, True, 6)
        dos_bar.pack_end(self._make_btn("🧠 AI Tactical Analysis", "btn-purple", self.on_ai_dossier_analysis), False, False, 4)
        dos_bar.pack_end(self._make_btn("🎯 Chuqur Skan (Tanlangan Host)", "btn-green", self.on_deep_scan_selected_subdomain), False, False, 4)
        dossier_box.pack_start(dos_bar, False, False, 2)

        dossier_scroll = Gtk.ScrolledWindow()
        dossier_scroll.get_style_context().add_class("panel-box")
        self.dossier_view = Gtk.TextView()
        self.dossier_view.set_editable(False)
        self.dossier_view.set_monospace(True)
        self.dossier_view.set_left_margin(10); self.dossier_view.set_top_margin(8)
        self.dossier_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.dossier_view.get_buffer().set_text("Subdomen ustiga bosing — uning To'liq Texnik Pasporti (Target Dossier & PTT) shu yerda ochiladi...")
        dossier_scroll.add(self.dossier_view)
        dossier_box.pack_start(dossier_scroll, True, True, 0)

        tab1.pack1(tab1_left, True, False)
        tab1.pack2(dossier_box, True, False)
        self.stack.add_named(tab1, "p_recon")
        self.stack.add_named(tab0, "p_scope")


        # TAB 2: Endpoints, API & JS Bundles + Full Interactive HTTP Repeater
        tab2_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        ep_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.rep_method_combo = Gtk.ComboBoxText()
        for m_name in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
            self.rep_method_combo.append(m_name, m_name)
        self.rep_method_combo.set_active_id("GET")
        ep_bar.pack_start(self.rep_method_combo, False, False, 0)

        self.rep_url_entry = Gtk.Entry()
        self.rep_url_entry.set_placeholder_text("URL (jadvaldan tanlang yoki qo'lda o'zgartiring, masalan: https://target.uz/api/v1/item/1)")
        self.rep_url_entry.set_hexpand(True)
        ep_bar.pack_start(self.rep_url_entry, True, True, 0)

        self.rep_body_entry = Gtk.Entry()
        self.rep_body_entry.set_placeholder_text('Request Body (JSON/Form, masalan: {"id":1,"role":"admin"})')
        self.rep_body_entry.set_width_chars(28)
        ep_bar.pack_start(self.rep_body_entry, False, False, 0)

        ep_bar.pack_end(self._make_btn("📋 Copy cURL", "btn-amber", self.on_copy_curl), False, False, 2)
        ep_bar.pack_end(self._make_btn("⚡ Send Request", "btn-purple", self.on_send_repeater), False, False, 2)
        tab2_box.pack_start(ep_bar, False, False, 4)

        tab2_hpaned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        tab2_hpaned.set_position(740)
        tab2_paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        tab2_paned.set_position(250)
        sc_ep, self.store_ep, self.tree_ep = self._make_tree([("Method", str), ("Endpoint URL", str), ("Parametrlar", str), ("Kategoriya", str), ("Xavf Teglari (Manual Guide)", str)])
        self.tree_ep.connect("cursor-changed", self.on_endpoint_selected)
        self._attach_context_menu(self.tree_ep, 1)
        sc_js, self.store_js, self.tree_js = self._make_tree([("JS Bundle Fayl", str), ("Ajratilgan API Route / URL'lar", str), ("Parametrlar", str), ("DOM Sinks & Config/Keys", str)])
        tab2_paned.pack1(sc_ep, True, False)
        tab2_paned.pack2(sc_js, True, False)


        rep_insp_scroll = Gtk.ScrolledWindow()
        rep_insp_scroll.get_style_context().add_class("panel-box")
        self.repeater_view = Gtk.TextView()
        self.repeater_view.set_editable(False)
        self.repeater_view.set_monospace(True)
        self.repeater_view.set_left_margin(10); self.repeater_view.set_top_margin(8)
        self.repeater_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.repeater_view.get_buffer().set_text("Endpointni tanlab '⚡ Send Request (In-App Inspector)' tugmasini bosing — HTTP Status, Response Headers va Body shu yerda ko'rinadi...")
        rep_insp_scroll.add(self.repeater_view)

        tab2_hpaned.pack1(tab2_paned, True, False)
        tab2_hpaned.pack2(rep_insp_scroll, True, False)
        tab2_box.pack_start(tab2_hpaned, True, True, 0)
        self.stack.add_named(tab2_box, "p_endpoints")


        # TAB 3: Vuln Audit & SAST (with Smart Noise Filter)
        tab3_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        triage_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.finding_filter_combo = Gtk.ComboBoxText()
        self.finding_filter_combo.append("no_noise", "⚠️ Muhim Topilmalar (Medium+ / Shovqinsiz)")
        self.finding_filter_combo.append("crit_high", "🚨 Faqat Critical & High")
        self.finding_filter_combo.append("confirmed", "✅ Faqat Tasdiqlangan ([CONFIRMED] / Verified)")
        self.finding_filter_combo.append("all", "🔥 Barcha Topilmalar (Low/Info bilan)")
        self.finding_filter_combo.set_active_id("all")
        self.finding_filter_combo.connect("changed", lambda _: self.load_bundle())
        triage_bar.pack_start(self.finding_filter_combo, False, False, 4)
        triage_bar.pack_start(Gtk.Label(label="Tanlangan topilma statusi:", xalign=0), True, True, 6)
        triage_bar.pack_end(self._make_btn("❌ False-Positive", "btn-red", lambda _: self.on_set_triage("False-Positive")), False, False, 4)
        triage_bar.pack_end(self._make_btn("🕵️ Manual-Review", "btn-amber", lambda _: self.on_set_triage("Manual-Review")), False, False, 4)
        triage_bar.pack_end(self._make_btn("✅ Verified", "btn-green", lambda _: self.on_set_triage("Verified")), False, False, 4)
        tab3_box.pack_start(triage_bar, False, False, 4)
        sc_find, self.store_find, self.tree_find = self._make_tree([
            ("ID", int), ("Severity", str), ("CVSS", str), ("Zaiflik Nomi", str),
            ("CWE / OWASP", str), ("Nishon (Asset)", str), ("Dalil (Evidence)", str),
            ("Remediation (Yechim)", str), ("Triage Holati", str)
        ])
        self._attach_context_menu(self.tree_find, 5)
        tab3_box.pack_start(sc_find, True, True, 0)
        self.stack.add_named(tab3_box, "p_vulns")

        # TAB 4: Bug Chains
        sc_chain, self.store_chain, _ = self._make_tree([
            ("Severity", str), ("CVSS", str), ("Zanjir Nomi (Attack Chain)", str),
            ("Bosqichlar (Nodes)", str), ("Hujum Ssenariysi va Impact", str), ("Remediation", str)
        ])
        self.stack.add_named(sc_chain, "p_chains")

        # TAB 5 (NEW): Cairo 2D Visual Attack Surface Topology Graph
        graph_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.graph_area = Gtk.DrawingArea()
        self.graph_area.set_vexpand(True)
        self.graph_area.set_hexpand(True)
        self.graph_area.connect("draw", self._draw_attack_graph)
        graph_box.pack_start(self.graph_area, True, True, 0)
        self.stack.add_named(graph_box, "p_graph")

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
        btn_row5.pack_start(self._make_btn("📤 Export All (Burp Scope JSON / Nuclei URLs / CSV)", "btn-purple", self.on_export_artifacts), False, False, 0)
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


        # Bottom Live Terminal (Guaranteed 185px minimum height so it is always clearly visible)
        term_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        term_box.get_style_context().add_class("panel-box")
        term_hdr = Gtk.Label(xalign=0)
        term_hdr.set_markup("<span foreground='#38bdf8' weight='bold' size='small'>🖥️ LIVE RECON &amp; AGENT TERMINAL STREAM</span>")
        term_box.pack_start(term_hdr, False, False, 0)
        term_scroll = Gtk.ScrolledWindow()
        term_scroll.set_size_request(-1, 175)
        self.term_view = Gtk.TextView()
        self.term_view.set_editable(False)
        self.term_view.set_monospace(True)
        self.term_view.set_left_margin(8); self.term_view.set_top_margin(6)
        self.term_buf = self.term_view.get_buffer()
        self.term_buf.set_text("[SPECTRE v12.0 TITAN GTK3 STUDIO] 49/49 Recon Tools • Predator v9 + Phantom v10 + Apex v11 + Titan v12 (Headless V8 / IPv6 / WASM / UDP) tayyor.\n")
        term_scroll.add(self.term_view)
        term_box.pack_start(term_scroll, True, True, 0)
        vpaned.pack2(term_box, False, False)


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
            self._selected_domain = dom_name
            dossier_txt = spectre_deep_modules.build_target_dossier(self.db, self.current_project_id, dom_name)
            self.dossier_view.get_buffer().set_text(dossier_txt)

    def on_ai_dossier_analysis(self, _btn):
        if not self.current_project_id:
            return
        pid = self.current_project_id
        dom_name = getattr(self, "_selected_domain", "")
        self.dossier_view.get_buffer().set_text(f"⏳ '{dom_name or 'Primary Target'}' bo'yicha AI va taktik tahlil tayyorlanmoqda...")

        def _ai_worker():
            ai_txt = spectre_v5_modules.generate_ai_tactical_analysis(self.db, pid, dom_name)
            dossier_txt = spectre_deep_modules.build_target_dossier(self.db, pid, dom_name)
            full_txt = ai_txt + "\n\n" + dossier_txt
            GLib.idle_add(lambda: self.dossier_view.get_buffer().set_text(full_txt) or False)
            self.log_msg(f"[AI ANALYST] 🧠 '{dom_name or 'Primary Target'}' bo'yicha taktik tahlil tayyorlandi.")

        threading.Thread(target=_ai_worker, daemon=True).start()


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
        f_mode = self.finding_filter_combo.get_active_id() if hasattr(self, "finding_filter_combo") else "all"
        ip_cnt = sum(1 for d in doms if d.get("ip"))
        fp_cnt = sum(1 for f in finds if f.get("triage_status") == "False-Positive")
        sig = (self.current_project_id, len(doms), ip_cnt, len(ports), len(https), len(eps), len(js_list), len(finds), fp_cnt, len(chains), q, f_mode)
        if preserve_if_unchanged and sig == self._last_data_sig:
            return
        self._last_data_sig = sig

        self.lbl_stat_dom.set_text(f"{len(doms)} ta subdomen ({ip_cnt} IP)")
        self.lbl_stat_http.set_text(f"{len(ports)} port  •  {len(https)} web")
        self.lbl_stat_ep.set_text(f"{len(eps)} route  •  {len(js_list)} JS")
        self.lbl_stat_find.set_text(f"{len(finds)} topilma  •  {len(chains)} zanjir")

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
        f_mode = self.finding_filter_combo.get_active_id() if hasattr(self, "finding_filter_combo") else "all"
        sorted_finds = sorted(finds, key=lambda x: float(x.get("cvss_score") or 0.0), reverse=True)
        for f in sorted_finds:
            sev = str(f.get("severity") or "")
            title_str = str(f.get("title") or "")
            conf_str = str(f.get("confidence") or "")
            triage_str = str(f.get("triage_status") or "")
            if f_mode == "crit_high" and sev not in ("Critical", "High"):
                continue
            if f_mode == "no_noise" and sev in ("Low", "Info"):
                continue
            if f_mode == "confirmed" and not ("[CONFIRMED]" in title_str or "Confirmed" in conf_str or triage_str == "Verified"):
                continue
            raw_str = f"{sev} {title_str} {f['cwe']} {f['asset']} {f['evidence']}".lower()
            if not q or q in raw_str:
                t_col = "#34d399" if triage_str == "Verified" else ("#fbbf24" if triage_str == "Manual-Review" else "#64748b")
                self.store_find.append([
                    f["id"],
                    self._color_sev(sev),
                    f"<b>{f['cvss_score']}</b>",
                    f"<b>{self._esc(title_str)}</b>",
                    self._esc(f"{f['cwe']} | {f['owasp']}"),
                    f"<span foreground='#38bdf8'>{self._esc(f['asset'])}</span>",
                    self._esc(f["evidence"]),
                    self._esc(f["remediation"]),
                    f"<span foreground='{t_col}' weight='bold'>{self._esc(triage_str)}</span>",
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

        if hasattr(self, "graph_area"):
            self.graph_area.queue_draw()


    def _draw_attack_graph(self, area, cr):
        import math
        alloc = area.get_allocation()
        w, h = alloc.width, alloc.height
        cr.set_source_rgb(0.04, 0.06, 0.11)
        cr.rectangle(0, 0, w, h)
        cr.fill()

        if not self.current_project_id:
            return False
        b = self.db.get_project_bundle(self.current_project_id)
        proj = b.get("project") or {}
        target = proj.get("primary_target", "Target")
        doms = b.get("domains", [])
        ports = b.get("ports", [])
        finds = b.get("findings", [])

        cx, cy = w / 2.0, h / 2.0
        # Legend header
        cr.set_source_rgb(0.22, 0.74, 0.97)
        cr.select_font_face("Monospace", 0, 1)
        cr.set_font_size(13)
        cr.move_to(18, 26)
        cr.show_text(f"🕸️ SPECTRE ATTACK SURFACE TOPOLOGY GRAPH — {target} ({len(doms)} Hosts | {len(ports)} Open Ports | {len(finds)} Findings)")

        by_ip = {}
        for d in doms[:36]:
            ip = d.get("ip") or "Unresolved"
            by_ip.setdefault(ip, []).append(d["domain"])

        ips = list(by_ip.keys())[:12]
        r_inner = min(w, h) * 0.23
        r_outer = min(w, h) * 0.41

        crit_hosts = {f.get("asset", "") for f in finds if f.get("severity") in ("Critical", "High")}

        for idx, ip in enumerate(ips):
            ang = (2 * math.pi * idx) / max(1, len(ips))
            ix = cx + r_inner * math.cos(ang)
            iy = cy + r_inner * math.sin(ang)

            # Edge Center -> IP
            cr.set_source_rgba(0.22, 0.74, 0.97, 0.35)
            cr.set_line_width(1.6)
            cr.move_to(cx, cy)
            cr.line_to(ix, iy)
            cr.stroke()

            hosts = by_ip[ip][:5]
            for h_idx, h_name in enumerate(hosts):
                spread = 0.38
                sub_ang = ang + ((h_idx - (len(hosts) - 1) / 2.0) * (spread / max(1, len(hosts))))
                ox = cx + r_outer * math.cos(sub_ang)
                oy = cy + r_outer * math.sin(sub_ang)

                is_vuln = any(h_name in ch for ch in crit_hosts)
                cr.set_source_rgba(0.97, 0.44, 0.44, 0.55) if is_vuln else cr.set_source_rgba(0.20, 0.83, 0.60, 0.35)
                cr.set_line_width(1.2)
                cr.move_to(ix, iy)
                cr.line_to(ox, oy)
                cr.stroke()

                # Outer Host Node
                cr.arc(ox, oy, 7 if is_vuln else 5, 0, 2 * math.pi)
                if is_vuln:
                    cr.set_source_rgb(0.97, 0.44, 0.44)
                else:
                    cr.set_source_rgb(0.20, 0.83, 0.60)
                cr.fill()

                cr.set_source_rgb(0.88, 0.91, 0.94)
                cr.set_font_size(10)
                cr.move_to(ox + 9, oy + 4)
                cr.show_text(h_name[:26])

            # IP Node
            cr.arc(ix, iy, 11, 0, 2 * math.pi)
            cr.set_source_rgb(0.65, 0.54, 0.98)
            cr.fill()
            cr.set_source_rgb(0.95, 0.96, 0.98)
            cr.set_font_size(10.5)
            cr.move_to(ix - 28, iy - 14)
            cr.show_text(ip)

        # Center Apex Node
        cr.arc(cx, cy, 22, 0, 2 * math.pi)
        cr.set_source_rgb(0.22, 0.74, 0.97)
        cr.fill()
        cr.set_source_rgb(0.04, 0.06, 0.11)
        cr.set_font_size(11)
        cr.move_to(cx - min(60, len(target) * 3.2), cy + 4)
        cr.show_text(target[:22])
        return False


    def on_create_project(self, _btn, auto_start: bool = False):
        raw_target = self.ent_ptarget.get_text().strip()
        if not raw_target:
            self.log_msg("[ERR] ⚠️ Asosiy nishon (Domain / IP) kiritilishi shart!")
            return
        target = ScopeGuard.extract_host(raw_target)
        apex_dom = ScopeGuard.extract_apex_domain(target)
        name = self.ent_pname.get_text().strip() or target
        in_sc = self.ent_pinscope.get_text().strip() or f"{target}\n{apex_dom}\n*.{apex_dom}"
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
        # Avvalgi loyihadan qolgan custom Header/Cookie va Proxy sozlamalarini tozalash (Zero Cross-Project State Leak)
        self.recon_agent.session.headers.clear()
        self.recon_agent.session.headers.update({"User-Agent": "SPECTRE-ASM-Security-Audit/8.5"})
        self.recon_agent.session.proxies.clear()

        auth = self.auth_entry.get_text().strip()
        if auth:
            if ":" in auth:
                k, v = auth.split(":", 1)
                self.recon_agent.session.headers[k.strip()] = v.strip()
            else:
                self.recon_agent.session.headers["Cookie"] = auth

        proxy_val = self.proxy_entry.get_text().strip() if hasattr(self, "proxy_entry") else ""
        if proxy_val:
            self.recon_agent.session.proxies.update({"http": proxy_val, "https": proxy_val})
            self.log_msg(f"[PROXY] 🌐 Outbound Proxy ulandi: {proxy_val}")


        rec_mode = self.mode_combo.get_active_id() if hasattr(self, "mode_combo") else "full"

        def update_prog(frac: float, text: str):
            def _u():
                self.progress_bar.set_fraction(max(0.0, min(1.0, frac)))
                self.progress_bar.set_text(f"[{int(frac*100)}%] {text}")
                return False
            GLib.idle_add(_u)

        def worker():
            try:
                if agent_type in ("recon", "all"):
                    self.recon_agent.run_full_recon(pid, None, self.log_msg, recon_mode=rec_mode or "full", progress_fn=update_prog)
                if agent_type in ("vuln", "all"):
                    update_prog(0.92, "2-SuperAgent: Vulnerability & SAST Audit...")
                    self.vuln_agent.run_assessment(pid, self.log_msg)
                if agent_type in ("triage", "all"):
                    update_prog(0.96, "3-SuperAgent: Triage & Dynamic Bug Chaining...")
                    self.triage_agent.run_triage_and_chaining(pid, self.log_msg)
                update_prog(1.0, "✅ Barcha tanlangan jarayonlar yakunlandi!")
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

    def on_endpoint_selected(self, tree):
        sel = tree.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            import re as _re
            method = _re.sub(r"<[^>]+>", "", model[treeiter][0]).strip()
            url = _re.sub(r"<[^>]+>", "", model[treeiter][1]).strip()
            self.rep_method_combo.set_active_id(method if method in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD") else "GET")
            self.rep_url_entry.set_text(url)

    def on_send_repeater(self, _btn):
        method = self.rep_method_combo.get_active_id() or "GET"
        url = self.rep_url_entry.get_text().strip()
        if not url:
            self.on_endpoint_selected(self.tree_ep)
            url = self.rep_url_entry.get_text().strip()
        if not url:
            self.log_msg("[!] Avval Endpointlar jadvalidan qatorni tanlang yoki URL kiriting.")
            return
        req_body = self.rep_body_entry.get_text().strip()
        auth = self.auth_entry.get_text().strip()
        proxy_val = self.proxy_entry.get_text().strip() if hasattr(self, "proxy_entry") else ""
        self.repeater_view.get_buffer().set_text(f"⏳ So'rov yuborilmoqda: {method} {url} ...")

        def _req_worker():
            out = spectre_v5_modules.send_repeater_request(method, url, auth, proxy_val, req_body=req_body)
            GLib.idle_add(lambda: self.repeater_view.get_buffer().set_text(out) or False)

        threading.Thread(target=_req_worker, daemon=True).start()


    def on_export_artifacts(self, _btn):
        if not self.current_project_id:
            return
        res = spectre_v5_modules.export_project_artifacts(self.db, self.current_project_id)
        msg = (
            "╔══ 📤 SPECTRE MULTI-FORMAT ARTIFACTS EXPORTED ══╗\n"
            f"• Burp Suite Scope JSON: {res['burp_scope_json']}\n"
            f"• Live URLs (Nuclei/HTTPX): {res['live_urls_txt']}\n"
            f"• Subdomains List: {res['subdomains_txt']}\n"
            f"• Findings CSV: {res['findings_csv']}\n"
            f"• Full Database JSON: {res['full_json']}\n"
        )
        self.rep_view.get_buffer().set_text(msg)
        self.log_msg(f"[EXPORT] ✅ Burp Scope, Nuclei URLs, CSV va JSON saqlandi: {res['burp_scope_json']}")


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

    def on_deep_scan_selected_subdomain(self, _btn, explicit_host: str = ""):
        if not self.current_project_id:
            self.log_msg("[!] Avval loyiha tanlang!")
            return
        host = (explicit_host or "").strip()
        if not host:
            sel = self.tree_dom.get_selection()
            model, treeiter = sel.get_selected()
            if treeiter is None and len(model) > 0:
                treeiter = model.get_iter_first()
            if treeiter is None:
                self.log_msg("[!] Subdomenlar jadvalidan biror qatorni tanlang.")
                return
            host = re.sub(r"<[^>]+>", "", model[treeiter][0]).strip()
        pid = self.current_project_id
        self.is_running_job = True

        def update_prog(frac: float, text: str):
            def _u():
                self.progress_bar.set_fraction(max(0.0, min(1.0, frac)))
                self.progress_bar.set_text(f"[{int(frac*100)}%] {text}")
                return False
            GLib.idle_add(_u)

        def _worker():
            try:
                self.recon_agent.run_single_subdomain_deep_recon(pid, host, self.log_msg, progress_fn=update_prog)
            finally:
                self.is_running_job = False
                self._last_data_sig = None
                GLib.idle_add(self.refresh_projects)
                GLib.idle_add(self.load_bundle)

        threading.Thread(target=_worker, daemon=True).start()



if __name__ == "__main__":
    win = ApexNativeWindow()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    win.present()
    Gtk.main()





