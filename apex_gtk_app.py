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

GLib.set_prgname("spectre-recon")
GLib.set_application_name("SPECTRE Recon Studio")
Gdk.set_program_class("spectre-recon")

BASE_DIR = Path("/home/amaqi/projects/apex-pentest-gui")
sys.path.insert(0, str(BASE_DIR))

from agents.recon_agent import ReconSuperAgent
from agents.triage_chain_agent import TriageAndChainSuperAgent
from agents.vuln_agent import VulnAssessmentSuperAgent
from agents import spectre_deep_modules, spectre_v5_modules
from core.database import DatabaseManager
from core.scope_guard import ScopeGuard

DARK_CSS = b"""
window, .background { background-color: #090c0a; color: #e2e8f0; font-family: "Inter", "Ubuntu", system-ui, sans-serif; }
headerbar { background-image: none; background-color: #0d120f; color: #f8fafc; border-bottom: 1px solid #1a2820; padding: 4px 12px; }
headerbar .title { font-weight: 800; font-size: 13.5px; color: #f8fafc; }
headerbar .subtitle { font-size: 11px; color: #4ade80; }
headerbar button.titlebutton { background-image: none; background-color: transparent; color: #94a3b8; border: none; box-shadow: none; }
headerbar button.titlebutton:hover { background-color: #16241b; color: #ffffff; }

.sidebar { background-color: #0c100e; border-right: 1px solid #1a2820; padding: 14px 11px; }
.nav-btn { background-image: none; background-color: transparent; color: #9ca3af; border: 1px solid transparent; border-radius: 8px; padding: 9px 12px; font-weight: 600; font-size: 12.5px; box-shadow: none; }
.nav-btn:hover { background-color: #121b16; color: #f1f5f9; }
.nav-btn-active { background-image: none; background-color: #11261a; color: #4ade80; border: 1px solid #1f4d33; border-radius: 8px; padding: 9px 12px; font-weight: 700; font-size: 12.5px; }

.toolbar-bar { background-color: #0f1512; border: 1px solid #1b2a21; border-radius: 10px; padding: 7px 12px; }
.stat-card { background-color: #0f1512; border: 1px solid #1b2a21; border-radius: 10px; padding: 9px 15px; }
.stat-title { font-size: 10px; color: #6ee7b7; font-weight: 700; letter-spacing: 0.6px; }
.stat-val { font-size: 15px; font-weight: 800; color: #f8fafc; }

treeview { background-color: #0b0f0d; color: #e2e8f0; font-size: 12.5px; border: none; }
treeview:selected { background-color: #143321; color: #4ade80; }
treeview header button { background-image: none; background-color: #101613; color: #94a3b8; font-weight: 700; font-size: 10.5px; border: none; border-bottom: 1px solid #1b2a21; padding: 8px 10px; box-shadow: none; }
treeview header button:hover { background-color: #15221a; color: #4ade80; }

entry, combobox button { background-image: none; background-color: #090c0a; color: #f1f5f9; border: 1px solid #223328; border-radius: 8px; padding: 6px 10px; font-size: 12px; box-shadow: none; }
entry:focus { border-color: #22c55e; }
textview, textview text { background-color: #080b09; color: #d8e2dc; font-family: "JetBrains Mono", "Ubuntu Mono", monospace; font-size: 12px; }
.panel-box { background-color: #0f1512; border: 1px solid #1b2a21; border-radius: 10px; padding: 6px; }
.section-hdr { font-size: 11.5px; font-weight: 700; color: #4ade80; }
progressbar text { color: #86efac; font-weight: 600; font-size: 11.5px; }
progressbar trough { min-height: 22px; background-color: #0c1911; border: 1px solid #1b3b28; border-radius: 8px; }
progressbar progress { min-height: 22px; background-image: none; background-color: #16a34a; border-radius: 7px; }

.act-btn { background-image: none; background-color: #121915; color: #e2e8f0; font-weight: 600; font-size: 12px; border-radius: 8px; padding: 6px 13px; border: 1px solid #24362b; box-shadow: none; }
.act-btn:hover { background-color: #18251e; border-color: #22c55e; color: #4ade80; }
.btn-green { background-image: none; background-color: #11281c; color: #4ade80; font-weight: 700; font-size: 12px; border-radius: 8px; padding: 6px 13px; border: 1px solid #22c55e; box-shadow: none; }
.btn-green:hover { background-color: #173826; }
.btn-amber { background-image: none; background-color: #231d12; color: #fbbf24; font-weight: 600; font-size: 12px; border-radius: 8px; padding: 6px 13px; border: 1px solid #92400e; box-shadow: none; }
.btn-amber:hover { background-color: #302717; }
.btn-red { background-image: none; background-color: #241417; color: #f87171; font-weight: 600; font-size: 12px; border-radius: 8px; padding: 6px 13px; border: 1px solid #991b1b; box-shadow: none; }
.btn-red:hover { background-color: #331b1f; border-color: #ef4444; }
.btn-purple { background-image: none; background-color: #22c55e; color: #052e16; font-weight: 800; font-size: 12px; border-radius: 8px; padding: 6px 15px; border: 1px solid #4ade80; box-shadow: none; }
.btn-purple:hover { background-color: #4ade80; color: #022c22; }
"""



class ApexNativeWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="SPECTRE Recon & Attack Surface Studio v14.0 NASL-Titan")
        self.set_default_size(1280, 760)
        self.maximize()
        self.set_wmclass("spectre-recon", "spectre-recon")
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

    def _make_btn(self, label: str, css_cls: str = "act-btn", callback=None, icon_name: str | None = None) -> Gtk.Button:
        btn = Gtk.Button()
        if icon_name:
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            img = Gtk.Image.new_from_icon_name(icon_name, Gtk.IconSize.MENU)
            lbl = Gtk.Label(label=label)
            box.pack_start(img, False, False, 0)
            box.pack_start(lbl, False, False, 0)
            box.set_halign(Gtk.Align.CENTER)
            btn.add(box)
        else:
            btn.set_label(label)
        btn.get_style_context().add_class(css_cls or "act-btn")
        if callback:
            btn.connect("clicked", callback)
        return btn

    @staticmethod
    def _set_styled_text(textview: Gtk.TextView, content: str):
        buf = textview.get_buffer()
        buf.set_text("")
        tbl = buf.get_tag_table()
        for tname, props in [
            ("hdr", {"foreground": "#4ade80", "weight": Pango.Weight.BOLD}),
            ("div", {"foreground": "#1e3a29"}),
            ("crit", {"foreground": "#f87171", "weight": Pango.Weight.BOLD}),
            ("muted", {"foreground": "#94a3b8"}),
        ]:
            if not tbl.lookup(tname):
                buf.create_tag(tname, **props)
        for line in (content or "").splitlines(True):
            end_it = buf.get_end_iter()
            s_strip = line.strip()
            if s_strip.startswith(("◈", "FINDING #", "[TECHNICAL", "[ROOT CAUSE", "[REMEDIATION")):
                buf.insert_with_tags_by_name(end_it, line, "hdr")
            elif s_strip.startswith(("─", "═")):
                buf.insert_with_tags_by_name(end_it, line, "div")
            elif any(k in s_strip for k in ("[CRITICAL", "[HIGH")):
                buf.insert_with_tags_by_name(end_it, line, "crit")
            else:
                buf.insert(end_it, line)

    def _make_tree(self, columns: list[tuple[str, type]], use_markup: bool = True) -> tuple[Gtk.ScrolledWindow, Gtk.ListStore, Gtk.TreeView]:
        store = Gtk.ListStore(*[c[1] for c in columns])
        tree = Gtk.TreeView(model=store)
        tree.set_grid_lines(Gtk.TreeViewGridLines.NONE)
        tree.set_headers_visible(True)
        narrow_cols = {"ID", "Status", "STATUS", "CVSS", "WAF", "Method", "METHOD", "Manba", "SOURCE", "CNAME", "ENABLED", "INSTALLED"}
        wide_cols = {"URL", "Endpoint URL", "ENDPOINT URL", "Subdomen / Host", "HOST / SUBDOMAIN", "Zaiflik Nomi", "FINDING TITLE", "Nishon (Asset)", "TARGET ASSET", "EXTRACTED API ROUTES"}
        for idx, (col_title, col_type) in enumerate(columns):
            renderer = Gtk.CellRendererText()
            renderer.set_padding(10, 8)
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
            it_open = Gtk.MenuItem(label=f"Open in Browser ({raw_val[:38]})")
            it_open.connect("activate", lambda _: subprocess.Popen(["xdg-open", full_url]))
            menu.append(it_open)

            it_rep = Gtk.MenuItem(label="Send to HTTP Repeater")
            def _send_rep(_):
                self.rep_url_entry.set_text(full_url)
                self._switch_page("p_endpoints", self.nav_buttons[2])
                self.log_msg(f"[REPEATER] Loaded target URL: {full_url}")
            it_rep.connect("activate", _send_rep)
            menu.append(it_rep)

            it_deep = Gtk.MenuItem(label=f"Deep Scan Host ({host_only})")
            def _deep_host(_):
                self._selected_domain = host_only
                self.on_deep_scan_selected_subdomain(None, explicit_host=host_only)
            it_deep.connect("activate", _deep_host)
            menu.append(it_deep)

            it_copy = Gtk.MenuItem(label="Copy Target Value")
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
        hb = Gtk.HeaderBar()
        hb.set_show_close_button(True)
        hb.props.title = "SPECTRE  —  Kiber-Razvedka va Hujum Yuzasi Platformasi"
        hb.props.subtitle = "●  v13.1 Obsidian Emerald  •  Multi-Role BOLA Matrix, Asset-Bound Graph Chaining & Recon"
        self.set_titlebar(hb)

        outer_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.add(outer_hbox)

        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        sidebar.get_style_context().add_class("sidebar")
        sidebar.set_size_request(218, -1)

        brand_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        brand_row.set_margin_bottom(12)
        brand_row.set_margin_start(4)
        icon_svg = BASE_DIR / "ui" / "apex-icon.svg"
        if icon_svg.exists():
            try:
                from gi.repository import GdkPixbuf
                pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(icon_svg), 30, 30, True)
                brand_row.pack_start(Gtk.Image.new_from_pixbuf(pb), False, False, 0)
            except Exception:
                pass
        brand_lbl = Gtk.Label(xalign=0)
        brand_lbl.set_markup("<span foreground='#f8fafc' weight='bold' size='11500'>SPECTRE</span>\n<span foreground='#4ade80' size='8500'>Kiber-Audit Studiyasi</span>")
        brand_row.pack_start(brand_lbl, False, False, 0)
        sidebar.pack_start(brand_row, False, False, 2)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(110)
        self.nav_buttons = []
        self.nav_label_widgets = []
        self.nav_base_labels = [
            ("p_scope", "Yangi Nishon", "list-add-symbolic"),
            ("p_recon", "Hujum Yuzasi", "network-workgroup-symbolic"),
            ("p_endpoints", "Endpoint va JS", "folder-remote-symbolic"),
            ("p_vulns", "Zaifliklar Auditi", "security-high-symbolic"),
            ("p_chains", "Hujum Zanjirlari", "emblem-shared-symbolic"),
            ("p_graph", "Topologiya Xaritasi", "view-grid-symbolic"),
            ("p_report", "Hisobot va Eksport", "document-properties-symbolic"),
            ("p_tools", "Arsenallar (49)", "preferences-system-symbolic"),
        ]
        for idx, (pname, plabel, picon) in enumerate(self.nav_base_labels):
            b = Gtk.Button()
            row_b = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            row_b.pack_start(Gtk.Image.new_from_icon_name(picon, Gtk.IconSize.MENU), False, False, 0)
            lw = Gtk.Label(label=plabel, xalign=0)
            lw.set_hexpand(True)
            row_b.pack_start(lw, True, True, 0)
            b.add(row_b)
            b.get_style_context().add_class("nav-btn-active" if idx == 1 else "nav-btn")
            b.connect("clicked", lambda btn, n=pname: self._switch_page(n, btn))
            self.nav_buttons.append(b)
            self.nav_label_widgets.append(lw)
            sidebar.pack_start(b, False, False, 0)

        outer_hbox.pack_start(sidebar, False, False, 0)

        # Right Main Workspace
        root_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        root_vbox.set_margin_top(8); root_vbox.set_margin_bottom(8)
        root_vbox.set_margin_start(10); root_vbox.set_margin_end(10)
        outer_hbox.pack_start(root_vbox, True, True, 0)

        # Top Command & Filter Toolbar
        cmd_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        cmd_bar.get_style_context().add_class("toolbar-bar")
        cmd_bar.pack_start(self._make_btn("Yangi Nishon", "act-btn", lambda _: self._switch_page("p_scope", self.nav_buttons[0]), "list-add-symbolic"), False, False, 0)
        self.proj_combo = Gtk.ComboBoxText()
        self.proj_combo.connect("changed", self.on_project_changed)
        cmd_bar.pack_start(self.proj_combo, False, False, 0)
        cmd_bar.pack_start(self._make_btn("O‘chirish", "btn-red", self.on_delete_project, "user-trash-symbolic"), False, False, 0)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Qidiruv (subdomen, port, API route, CVE...)")
        self.search_entry.set_hexpand(True)
        self.search_entry.connect("search-changed", lambda _: self.load_bundle())
        cmd_bar.pack_start(self.search_entry, True, True, 0)

        self.mode_combo = Gtk.ComboBoxText()
        self.mode_combo.append("full", "Rejim: To‘liq Razvedka")
        self.mode_combo.append("subdomains", "Rejim: Subdomenlar")
        self.mode_combo.append("ports", "Rejim: Port va Shodan")
        self.mode_combo.append("web_js", "Rejim: Veb / API / JS")
        self.mode_combo.set_active_id("full")
        cmd_bar.pack_start(self.mode_combo, False, False, 0)

        cmd_bar.pack_end(self._make_btn("To‘xtatish", "btn-red", lambda _: self.on_abort(), "process-stop-symbolic"), False, False, 0)
        cmd_bar.pack_end(self._make_btn("To‘liq Skaner", "btn-purple", lambda _: self.on_run_agent("all"), "media-playback-start-symbolic"), False, False, 0)
        cmd_bar.pack_end(self._make_btn("3-Zanjir", "act-btn", lambda _: self.on_run_agent("triage")), False, False, 0)
        cmd_bar.pack_end(self._make_btn("2-Zaiflik", "act-btn", lambda _: self.on_run_agent("vuln")), False, False, 0)
        cmd_bar.pack_end(self._make_btn("1-Razvedka", "act-btn", lambda _: self.on_run_agent("recon")), False, False, 0)
        root_vbox.pack_start(cmd_bar, False, False, 0)

        # Row 2: Multi-Role Auth (Role-A & Role-B), Proxy & Emerald Status Banner
        sub_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.auth_entry = Gtk.Entry()
        self.auth_entry.set_placeholder_text("Role-A Auth (Cookie: ... / Bearer ...)")
        self.auth_entry.set_width_chars(22)
        sub_bar.pack_start(self.auth_entry, False, False, 0)

        self.auth_b_entry = Gtk.Entry()
        self.auth_b_entry.set_placeholder_text("Role-B Auth (BOLA/IDOR uchun 2-akkaunt)")
        self.auth_b_entry.set_width_chars(22)
        sub_bar.pack_start(self.auth_b_entry, False, False, 0)

        self.proxy_entry = Gtk.Entry()
        self.proxy_entry.set_placeholder_text("Proksi (http://127.0.0.1:8080)")
        self.proxy_entry.set_width_chars(19)
        sub_bar.pack_start(self.proxy_entry, False, False, 0)

        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        self.progress_bar.set_text("●  Platforma jangovar holatda — Nishonni tanlang yoki skanerni boshlang")
        self.progress_bar.set_fraction(0.0)
        self.progress_bar.set_hexpand(True)
        self.progress_bar.set_valign(Gtk.Align.CENTER)
        sub_bar.pack_start(self.progress_bar, True, True, 0)
        root_vbox.pack_start(sub_bar, False, False, 0)



        # Compact Telemetry Strip
        stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=9)
        self.lbl_stat_dom = Gtk.Label(label="0", xalign=0)
        self.lbl_stat_http = Gtk.Label(label="0 / 0", xalign=0)
        self.lbl_stat_ep = Gtk.Label(label="0 / 0", xalign=0)
        self.lbl_stat_find = Gtk.Label(label="0 / 0", xalign=0)
        for title_cap, lbl in [
            ("SUBDOMENLAR VA DNS", self.lbl_stat_dom),
            ("TARMOQ PORTLARI VA VEB", self.lbl_stat_http),
            ("ENDPOINTLAR VA JS FAYLLAR", self.lbl_stat_ep),
            ("XAVFSIZLIK TOPILMALARI", self.lbl_stat_find),
        ]:
            t_lbl = Gtk.Label(label=title_cap, xalign=0)
            t_lbl.get_style_context().add_class("stat-title")
            lbl.get_style_context().add_class("stat-val")
            frame = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            frame.get_style_context().add_class("stat-card")
            frame.set_hexpand(True)
            frame.pack_start(t_lbl, False, False, 0)
            frame.pack_start(lbl, False, False, 0)
            stats_box.pack_start(frame, True, True, 0)
        root_vbox.pack_start(stats_box, False, False, 0)

        vpaned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        vpaned.set_position(495)
        root_vbox.pack_start(vpaned, True, True, 0)
        vpaned.pack1(self.stack, True, False)


        # TAB 0: Target & Scope (Enterprise Project Configuration)
        tab0 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        tab0.get_style_context().add_class("panel-box")
        tab0.set_margin_top(8); tab0.set_margin_start(8); tab0.set_margin_end(8)
        hdr0 = Gtk.Label(xalign=0)
        hdr0.set_markup("<span foreground='#f8fafc' weight='bold' size='large'>Yangi Nishon va Audit Doirasi (Scope)</span>\n<span foreground='#94a3b8'>Asosiy domen, URL yoki IP kiriting. In-Scope bo‘sh qoldirilsa, target.tld va *.target.tld avtomatik olinadi.</span>")
        tab0.pack_start(hdr0, False, False, 4)
        grid0 = Gtk.Grid(column_spacing=14, row_spacing=12)
        self.ent_pname = Gtk.Entry(); self.ent_pname.set_placeholder_text("Loyiha nomi (masalan: Corp-Audit-2026)")
        self.ent_ptarget = Gtk.Entry(); self.ent_ptarget.set_placeholder_text("Asosiy nishon (masalan: example.uz yoki https://app.example.uz)")
        self.ent_pinscope = Gtk.Entry(); self.ent_pinscope.set_placeholder_text("Ixtiyoriy scope (bo‘sh qolsa avtomatik target.tld va *.target.tld olinadi)")
        self.ent_poutscope = Gtk.Entry(); self.ent_poutscope.set_placeholder_text("Taqiqlangan xost yoki yo‘llar (ixtiyoriy)")
        self.ent_pcode = Gtk.Entry(); self.ent_pcode.set_placeholder_text("/path/to/source-code (ixtiyoriy White-Box SAST papkasi)")
        for r_idx, (title_txt, widget) in enumerate([
            ("01. Loyiha Nomi:", self.ent_pname),
            ("02. Asosiy Nishon (Domain / URL / IP):", self.ent_ptarget),
            ("03. Ruxsat Etilgan Scope (In-Scope):", self.ent_pinscope),
            ("04. Taqiqlangan Manzillar (Out-of-Scope):", self.ent_poutscope),
            ("05. Manba Kodi Papkasi (White-Box SAST):", self.ent_pcode),
        ]):
            lbl = Gtk.Label(label=title_txt, xalign=0)
            widget.set_hexpand(True)
            grid0.attach(lbl, 0, r_idx, 1, 1)
            grid0.attach(widget, 1, r_idx, 1, 1)
        tab0.pack_start(grid0, False, False, 4)
        btn_row0 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_row0.pack_start(self._make_btn("Loyihani Yaratish", "act-btn", self.on_create_project), False, False, 0)
        btn_row0.pack_start(self._make_btn("Yaratish + 1-Razvedka", "btn-green", lambda b: self.on_create_project(b, auto_mode="recon")), False, False, 0)
        btn_row0.pack_start(self._make_btn("Yaratish va To‘liq Skaner (1 -> 2 -> 3)", "btn-purple", lambda b: self.on_create_project(b, auto_mode="all"), "media-playback-start-symbolic"), False, False, 0)
        tab0.pack_start(btn_row0, False, False, 6)


        # TAB 1: Recon & Attack Surface + Target Dossier Inspector
        tab1 = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        tab1.set_position(760)
        tab1_left = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        tab1_left.set_position(250)
        sc_http, self.store_http, self.tree_http = self._make_tree([("URL", str), ("STATUS", str), ("TITLE", str), ("SERVER / STACK", str), ("WAF", str), ("MISSING HEADERS", str)])
        sc_dom, self.store_dom, self.tree_dom = self._make_tree([("HOST / SUBDOMAIN", str), ("IP ADDRESS", str), ("CNAME", str), ("SOURCE", str), ("OPEN PORTS", str)])
        self.tree_dom.connect("cursor-changed", self.on_domain_selected)
        self._attach_context_menu(self.tree_http, 0)
        self._attach_context_menu(self.tree_dom, 0)
        tab1_left.pack1(sc_http, True, False)
        tab1_left.pack2(sc_dom, True, False)

        dossier_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        dos_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        dos_lbl = Gtk.Label(label="TARGET DOSSIER & PENTESTING TASK TREE", xalign=0)
        dos_lbl.get_style_context().add_class("section-hdr")
        dos_bar.pack_start(dos_lbl, True, True, 4)
        dos_bar.pack_end(self._make_btn("AI Tactical Brief", "btn-purple", self.on_ai_dossier_analysis), False, False, 2)
        dos_bar.pack_end(self._make_btn("Deep Scan Host", "btn-green", self.on_deep_scan_selected_subdomain), False, False, 2)
        dossier_box.pack_start(dos_bar, False, False, 2)

        dossier_scroll = Gtk.ScrolledWindow()
        dossier_scroll.get_style_context().add_class("panel-box")
        self.dossier_view = Gtk.TextView()
        self.dossier_view.set_editable(False)
        self.dossier_view.set_monospace(True)
        self.dossier_view.set_left_margin(10); self.dossier_view.set_top_margin(8)
        self.dossier_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.dossier_view.get_buffer().set_text("Select any host row on the left to inspect its infrastructure passport and Pentesting Task Tree...")
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

        ep_bar.pack_end(self._make_btn("Copy cURL", "act-btn", self.on_copy_curl), False, False, 2)
        ep_bar.pack_end(self._make_btn("Send Request", "btn-purple", self.on_send_repeater), False, False, 2)
        tab2_box.pack_start(ep_bar, False, False, 4)

        tab2_hpaned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        tab2_hpaned.set_position(760)
        tab2_paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        tab2_paned.set_position(250)
        sc_ep, self.store_ep, self.tree_ep = self._make_tree([("METHOD", str), ("ENDPOINT URL", str), ("PARAMETERS", str), ("CATEGORY", str), ("RISK TAGS", str)])
        self.tree_ep.connect("cursor-changed", self.on_endpoint_selected)
        self._attach_context_menu(self.tree_ep, 1)
        sc_js, self.store_js, self.tree_js = self._make_tree([("JS BUNDLE", str), ("EXTRACTED API ROUTES", str), ("PARAMETERS", str), ("DOM SINKS & SECRETS", str)])
        tab2_paned.pack1(sc_ep, True, False)
        tab2_paned.pack2(sc_js, True, False)


        rep_insp_scroll = Gtk.ScrolledWindow()
        rep_insp_scroll.get_style_context().add_class("panel-box")
        self.repeater_view = Gtk.TextView()
        self.repeater_view.set_editable(False)
        self.repeater_view.set_monospace(True)
        self.repeater_view.set_left_margin(10); self.repeater_view.set_top_margin(8)
        self.repeater_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.repeater_view.get_buffer().set_text("Select an endpoint row and click 'Send Request' to inspect raw HTTP status, response headers, and payload...")
        rep_insp_scroll.add(self.repeater_view)

        tab2_hpaned.pack1(tab2_paned, True, False)
        tab2_hpaned.pack2(rep_insp_scroll, True, False)
        tab2_box.pack_start(tab2_hpaned, True, True, 0)
        self.stack.add_named(tab2_box, "p_endpoints")


        # TAB 3: Vuln Audit & SAST + Interactive Finding Inspector
        tab3_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        triage_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.finding_filter_combo = Gtk.ComboBoxText()
        self.finding_filter_combo.append("qod_80", "Filter: QoD >= 80% (High-Precision Only)")
        self.finding_filter_combo.append("no_noise", "Filter: Medium & Above (No Info/Low)")
        self.finding_filter_combo.append("crit_high", "Filter: Critical & High Only")
        self.finding_filter_combo.append("confirmed", "Filter: Verified / Confirmed Only")
        self.finding_filter_combo.append("all", "Filter: All Findings (Including Info/Low)")
        self.finding_filter_combo.set_active_id("all")
        self.finding_filter_combo.connect("changed", lambda _: self.load_bundle())
        triage_bar.pack_start(self.finding_filter_combo, False, False, 4)
        lbl_tr = Gtk.Label(label="Set Triage Disposition:", xalign=1.0)
        lbl_tr.get_style_context().add_class("section-hdr")
        triage_bar.pack_start(lbl_tr, True, True, 6)
        triage_bar.pack_end(self._make_btn("Mark False-Positive", "btn-red", lambda _: self.on_set_triage("False-Positive")), False, False, 2)
        triage_bar.pack_end(self._make_btn("Needs Review", "btn-amber", lambda _: self.on_set_triage("Manual-Review")), False, False, 2)
        triage_bar.pack_end(self._make_btn("Mark Verified", "btn-green", lambda _: self.on_set_triage("Verified")), False, False, 2)
        tab3_box.pack_start(triage_bar, False, False, 2)

        vuln_vpaned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        vuln_vpaned.set_position(275)
        sc_find, self.store_find, self.tree_find = self._make_tree([
            ("ID", int), ("SEVERITY", str), ("CVSS", str), ("FINDING TITLE", str),
            ("CWE / OWASP", str), ("TARGET ASSET", str), ("EVIDENCE", str),
            ("REMEDIATION", str), ("STATUS", str)
        ])
        self.tree_find.connect("cursor-changed", self.on_finding_selected)
        self._attach_context_menu(self.tree_find, 5)
        vuln_vpaned.pack1(sc_find, True, False)

        find_insp_scroll = Gtk.ScrolledWindow()
        find_insp_scroll.get_style_context().add_class("panel-box")
        self.finding_detail_view = Gtk.TextView()
        self.finding_detail_view.set_editable(False)
        self.finding_detail_view.set_monospace(True)
        self.finding_detail_view.set_left_margin(10); self.finding_detail_view.set_top_margin(8)
        self.finding_detail_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.finding_detail_view.get_buffer().set_text("Select any finding row above to inspect full Evidence, Root Cause Analysis, CVSS 3.1 Vector, and Remediation guidance...")
        find_insp_scroll.add(self.finding_detail_view)
        vuln_vpaned.pack2(find_insp_scroll, False, False)

        tab3_box.pack_start(vuln_vpaned, True, True, 0)
        self.stack.add_named(tab3_box, "p_vulns")

        # TAB 4: Bug Chains
        sc_chain, self.store_chain, _ = self._make_tree([
            ("SEVERITY", str), ("CVSS", str), ("ATTACK CHAIN", str),
            ("CHAIN NODES", str), ("EXPLOIT SCENARIO & IMPACT", str), ("REMEDIATION", str)
        ])
        self.stack.add_named(sc_chain, "p_chains")

        # TAB 5: Cairo 2D Visual Attack Surface Topology Graph
        graph_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.graph_area = Gtk.DrawingArea()
        self.graph_area.set_vexpand(True)
        self.graph_area.set_hexpand(True)
        self.graph_area.connect("draw", self._draw_attack_graph)
        graph_box.pack_start(self.graph_area, True, True, 0)
        self.stack.add_named(graph_box, "p_graph")

        # TAB 6: Manual PoC & Report Studio
        tab5 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        tab5.set_margin_top(10); tab5.set_margin_start(10); tab5.set_margin_end(10)
        pgrid = Gtk.Grid(column_spacing=8, row_spacing=6)
        self.ent_mtitle = Gtk.Entry(); self.ent_mtitle.set_placeholder_text("Finding title (e.g., IDOR in /api/v1/orders)")
        self.ent_msev = Gtk.Entry(); self.ent_msev.set_text("High")
        self.ent_mcvss = Gtk.Entry(); self.ent_mcvss.set_text("8.2")
        self.ent_masset = Gtk.Entry(); self.ent_masset.set_placeholder_text("Target URL or file:line")
        self.ent_mevid = Gtk.Entry(); self.ent_mevid.set_placeholder_text("PoC HTTP request/response evidence")
        self.ent_mrem = Gtk.Entry(); self.ent_mrem.set_placeholder_text("Remediation guidance")
        for idx, w in enumerate([self.ent_mtitle, self.ent_msev, self.ent_mcvss, self.ent_masset, self.ent_mevid, self.ent_mrem]):
            w.set_hexpand(True)
            pgrid.attach(w, idx % 3, idx // 3, 1, 1)
        tab5.pack_start(pgrid, False, False, 0)
        btn_row5 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_row5.pack_start(self._make_btn("+ Add Manual PoC", "act-btn", self.on_add_manual), False, False, 0)
        btn_row5.pack_start(self._make_btn("Generate Executive HTML & Markdown Report", "btn-green", self.on_generate_report), False, False, 0)
        btn_row5.pack_start(self._make_btn("Export Artifacts (Burp JSON / Nuclei / CSV)", "btn-purple", self.on_export_artifacts), False, False, 0)
        tab5.pack_start(btn_row5, False, False, 0)
        self.rep_view = Gtk.TextView(); self.rep_view.set_editable(False); self.rep_view.set_monospace(True)
        sc_rep = Gtk.ScrolledWindow(); sc_rep.set_vexpand(True); sc_rep.add(self.rep_view)
        tab5.pack_start(sc_rep, True, True, 0)
        self.stack.add_named(tab5, "p_report")

        # TAB 7: Tool Registry & JWT Auditor
        tab6 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        jwt_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.ent_jwt = Gtk.Entry(); self.ent_jwt.set_placeholder_text("Paste JWT token for cryptographic & claim audit (eyJhbGciOi...)")
        self.ent_jwt.set_hexpand(True)
        jwt_row.pack_start(self.ent_jwt, True, True, 6)
        jwt_row.pack_start(self._make_btn("Audit JWT", "act-btn", self.on_audit_jwt), False, False, 4)
        jwt_row.pack_start(self._make_btn("Toggle Selected Tool", "btn-amber", self.on_toggle_tool), False, False, 4)
        tab6.pack_start(jwt_row, False, False, 4)
        sc_tools, self.store_tools, self.tree_tools = self._make_tree([
            ("ID", str), ("ENABLED", str), ("TOOL NAME", str), ("STAGE", str),
            ("INSTALLED", str), ("BINARY PATH", str), ("COMMAND TEMPLATE", str)
        ])
        tab6.pack_start(sc_tools, True, True, 0)
        self.stack.add_named(tab6, "p_tools")


        # Bottom Live Telemetry Console
        term_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        term_box.get_style_context().add_class("panel-box")
        term_hdr = Gtk.Label(xalign=0)
        term_hdr.set_markup("<span foreground='#8b949e' weight='bold' size='small'>TELEMETRY &amp; EXECUTION CONSOLE</span>")
        term_box.pack_start(term_hdr, False, False, 0)
        term_scroll = Gtk.ScrolledWindow()
        term_scroll.set_size_request(-1, 145)
        self.term_view = Gtk.TextView()
        self.term_view.set_editable(False)
        self.term_view.set_monospace(True)
        self.term_view.set_left_margin(8); self.term_view.set_top_margin(6)
        self.term_buf = self.term_view.get_buffer()
        self.term_buf.set_text("[SPECTRE v12.11 Enterprise ASM Workstation] 49/49 CLI & Deep Intelligence Engines initialized.\n")
        term_scroll.add(self.term_view)
        term_box.pack_start(term_scroll, True, True, 0)
        vpaned.pack2(term_box, False, False)


    def log_msg(self, msg: str):
        import time as _time
        clean_m = re.sub(r"[🚀🛰️🎯🧠🚨🗂️🔌🔍🔎👻🔥⚡🛡️📂✅❌🗑️📋🌐🕵️]", "", str(msg or "")).replace("  ", " ").strip()
        ts_prefix = "" if clean_m.startswith("[") and ":" in clean_m[:10] else f"[{_time.strftime('%H:%M:%S')}] "
        line_out = f"{ts_prefix}{clean_m}"
        def _append():
            end_iter = self.term_buf.get_end_iter()
            self.term_buf.insert(end_iter, line_out + "\n")
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
            self._set_styled_text(self.dossier_view, dossier_txt)

    def on_finding_selected(self, tree):
        if not self.current_project_id:
            return
        sel = tree.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            fid = int(model[treeiter][0])
            finds = self.db.get_project_bundle(self.current_project_id).get("findings", [])
            f_obj = next((f for f in finds if int(f.get("id", 0)) == fid), None)
            if f_obj:
                detail_lines = [
                    f"FINDING #{fid}  |  {f_obj.get('severity', '').upper()} (CVSS {f_obj.get('cvss_score', '')})  |  STATUS: {f_obj.get('triage_status', '')}",
                    "─" * 88,
                    f"Title       : {f_obj.get('title', '')}",
                    f"Category    : {f_obj.get('category', '')}   |   Agent: {f_obj.get('agent', '')}",
                    f"Confidence  : {f_obj.get('confidence', '')}",
                    f"Taxonomy    : {f_obj.get('cwe', '')}   |   {f_obj.get('owasp', '')}",
                    f"CVSS Vector : {f_obj.get('cvss_vector', '')}",
                    f"Target Asset: {f_obj.get('asset', '')}",
                    "",
                    "[TECHNICAL EVIDENCE / POC]",
                    str(f_obj.get("evidence", "") or "-"),
                    "",
                    "[ROOT CAUSE ANALYSIS]",
                    str(f_obj.get("root_cause", "") or "-"),
                    "",
                    "[REMEDIATION GUIDANCE]",
                    str(f_obj.get("remediation", "") or "-"),
                ]
                self._set_styled_text(self.finding_detail_view, "\n".join(detail_lines))

    def on_ai_dossier_analysis(self, _btn):
        if not self.current_project_id:
            return
        pid = self.current_project_id
        dom_name = getattr(self, "_selected_domain", "")
        self.dossier_view.get_buffer().set_text(f"Generating tactical architecture analysis for '{dom_name or 'Primary Target'}'...")

        def _ai_worker():
            ai_txt = spectre_v5_modules.generate_ai_tactical_analysis(self.db, pid, dom_name)
            dossier_txt = spectre_deep_modules.build_target_dossier(self.db, pid, dom_name)
            full_txt = ai_txt + "\n\n" + dossier_txt
            GLib.idle_add(lambda: self.dossier_view.get_buffer().set_text(full_txt) or False)
            self.log_msg(f"[AI ANALYST] Tactical analysis generated for '{dom_name or 'Primary Target'}'.")

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
        ip_cnt = len({d["ip"] for d in doms if d.get("ip")})
        fp_cnt = sum(1 for f in finds if f.get("triage_status") == "False-Positive")
        sig = (self.current_project_id, len(doms), ip_cnt, len(ports), len(https), len(eps), len(js_list), len(finds), fp_cnt, len(chains), q, f_mode)
        if preserve_if_unchanged and sig == self._last_data_sig:
            return
        self._last_data_sig = sig

        self.lbl_stat_dom.set_text(f"{len(doms)} subdomen  •  {ip_cnt} noyob IP")
        self.lbl_stat_http.set_text(f"{len(ports)} port  •  {len(https)} veb-servis")
        self.lbl_stat_ep.set_text(f"{len(eps)} route  •  {len(js_list)} JS paket")
        self.lbl_stat_find.set_text(f"{len(finds)} topilma  •  {len(chains)} zanjir")

        if hasattr(self, "nav_label_widgets") and len(self.nav_label_widgets) >= 8:
            badge_counts = {
                1: len(doms),
                2: len(eps),
                3: len(finds),
                4: len(chains),
            }
            for idx_b, entry_b in enumerate(self.nav_base_labels):
                base_lbl = entry_b[1]
                if idx_b in badge_counts:
                    self.nav_label_widgets[idx_b].set_text(f"{base_lbl}  ({badge_counts[idx_b]})")

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
        sorted_doms = sorted(doms, key=lambda d: (0 if d.get("source") in ("primary_target", "apex_domain") else (1 if d.get("ip") else 2), d.get("id", 0)))
        for d in sorted_doms:
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
            if f_mode == "qod_80":
                m_qod = re.search(r"QoD:\s*(\d+)%", conf_str)
                qod_num = int(m_qod.group(1)) if m_qod else (95 if "[CONFIRMED]" in title_str or "Confirmed" in conf_str else 80 if conf_str == "High" else 65)
                if qod_num < 80:
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

        if sorted_doms and hasattr(self, "dossier_view") and not preserve_if_unchanged:
            primary_dom = sorted_doms[0]["domain"]
            self._selected_domain = primary_dom
            self._set_styled_text(
                self.dossier_view,
                spectre_deep_modules.build_target_dossier(self.db, self.current_project_id, primary_dom),
            )
        if sorted_finds and hasattr(self, "finding_detail_view") and not preserve_if_unchanged:
            f0 = sorted_finds[0]
            self._set_styled_text(
                self.finding_detail_view,
                f"FINDING #{f0['id']}  |  {f0.get('severity', '').upper()} (CVSS {f0.get('cvss_score', '')})  |  STATUS: {f0.get('triage_status', '')}\n"
                + ("─" * 68)
                + f"\nTitle       : {f0.get('title', '')}\nTaxonomy    : {f0.get('cwe', '')}   |   {f0.get('owasp', '')}\n"
                + f"Target Asset: {f0.get('asset', '')}\n\n[TECHNICAL EVIDENCE / POC]\n{f0.get('evidence', '')}\n\n"
                + f"[ROOT CAUSE ANALYSIS]\n{f0.get('root_cause', '')}\n\n[REMEDIATION GUIDANCE]\n{f0.get('remediation', '')}",
            )

        if hasattr(self, "graph_area"):
            self.graph_area.queue_draw()


    def _draw_attack_graph(self, area, cr):
        import math
        alloc = area.get_allocation()
        w, h = alloc.width, alloc.height
        cr.set_source_rgb(0.05, 0.067, 0.09)
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

        cx, cy = w / 2.0, h / 2.0 + 10
        r_inner = min(w, h) * 0.22
        r_outer = min(w, h) * 0.40

        # Subtle Radar Concentric Rings
        cr.set_source_rgba(0.19, 0.22, 0.28, 0.45)
        cr.set_line_width(1.0)
        for r_ring in (r_inner, r_outer):
            cr.arc(cx, cy, r_ring, 0, 2 * math.pi)
            cr.stroke()

        # Header & Legend
        cr.set_source_rgb(0.90, 0.93, 0.95)
        cr.select_font_face("Sans", 0, 1)
        cr.set_font_size(12.5)
        cr.move_to(18, 26)
        cr.show_text(f"ATTACK SURFACE TOPOLOGY  —  {target}   ({len(doms)} Hosts  |  {len(ports)} Open Ports  |  {len(finds)} Findings)")

        legend_items = [
            ((0.18, 0.50, 0.96), "Primary Scope"),
            ((0.64, 0.44, 0.97), "Origin IP Node"),
            ((0.24, 0.72, 0.31), "Active Subdomain"),
            ((0.97, 0.32, 0.29), "High / Critical Asset"),
        ]
        lx = 18
        for col_rgb, l_txt in legend_items:
            cr.arc(lx + 5, h - 18, 4.5, 0, 2 * math.pi)
            cr.set_source_rgb(*col_rgb)
            cr.fill()
            cr.set_source_rgb(0.55, 0.58, 0.62)
            cr.set_font_size(10.5)
            cr.move_to(lx + 14, h - 14)
            cr.show_text(l_txt)
            lx += 145

        by_ip = {}
        for d in doms[:36]:
            ip = d.get("ip") or "Unresolved"
            by_ip.setdefault(ip, []).append(d["domain"])

        ips = list(by_ip.keys())[:12]
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


    def on_create_project(self, _btn, auto_start: bool = False, auto_mode: str = ""):
        raw_target = self.ent_ptarget.get_text().strip()
        if not raw_target:
            self.log_msg("[ERR] Asosiy nishon (Domain / IP) kiritilishi shart!")
            return
        target = ScopeGuard.extract_host(raw_target)
        apex_dom = ScopeGuard.extract_apex_domain(target)
        name = self.ent_pname.get_text().strip() or target
        default_scope_items = list(dict.fromkeys([target, apex_dom, f"*.{apex_dom}"]))
        in_sc = self.ent_pinscope.get_text().strip() or "\n".join(default_scope_items)
        out_sc = self.ent_poutscope.get_text().strip()
        code_p = self.ent_pcode.get_text().strip()
        pid = self.db.create_project(name, target, in_sc, out_sc, code_p)
        self.current_project_id = pid
        self._last_data_sig = None
        self.refresh_projects()
        self.load_bundle()
        self._switch_page("p_recon", self.nav_buttons[1])
        self.log_msg(f"[INIT] Yangi loyiha #{pid} yaratildi va faollashtirildi: {name} ({target})")
        launch_mode = auto_mode or ("recon" if auto_start else "")
        if launch_mode:
            self.on_run_agent(launch_mode)

    def on_run_agent(self, agent_type: str):
        if not self.current_project_id:
            self.log_msg("[ERR] Avval loyiha yarating yoki tanlang!")
            return
        pid = self.current_project_id
        self.is_running_job = True
        self._switch_page("p_recon", self.nav_buttons[1])
        self.recon_agent.session.headers.clear()
        self.recon_agent.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        })
        self.recon_agent.session.proxies.clear()

        auth = self.auth_entry.get_text().strip()
        auth_b = self.auth_b_entry.get_text().strip() if hasattr(self, "auth_b_entry") else ""
        if auth:
            if ":" in auth:
                k, v = auth.split(":", 1)
                self.recon_agent.session.headers[k.strip()] = v.strip()
            else:
                self.recon_agent.session.headers["Cookie"] = auth

        proxy_val = self.proxy_entry.get_text().strip() if hasattr(self, "proxy_entry") else ""
        if proxy_val:
            self.recon_agent.session.proxies.update({"http": proxy_val, "https": proxy_val})
            self.log_msg(f"[PROXY] Outbound Proxy ulandi: {proxy_val}")
        self.vuln_agent.configure_context(primary_auth=auth, secondary_auth=auth_b, proxy_url=proxy_val)


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





