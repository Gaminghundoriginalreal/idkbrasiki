# client_qt.py
"""
NovaShield – PyQt6 client

- Modern dark UI with sidebar navigation
- Connects to NovaShield backend (HTTP API)
- ALL antivirus features require an active plan
- Login/session is persisted between restarts (settings.json)
- On startup it:
    * Tries to restore your session with stored api_key
    * If api_key is invalid but username/password are stored, it auto-logins again
    * Checks a remote update-info script and shows an update box if something changed

Antivirus logic:
- Simple signature + heuristic scanner:
  * Hardcoded hash blacklist
  * Suspicious extensions & sizes

NOTE: This is still not a professional antivirus engine.
"""

import os
import json
import hashlib
import threading
import time
import platform
from pathlib import Path
from typing import List, Dict, Optional, Tuple

import requests

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QMainWindow,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QStackedWidget,
    QFileDialog,
    QTextEdit,
    QProgressBar,
    QLineEdit,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QRadioButton,
    QButtonGroup,
)

# -------------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------------

# Backend connection config
SERVER_IP = "91.89.111.120"
SERVER_PORT = 5050
BASE_URL = f"http://{SERVER_IP}:{SERVER_PORT}"

# Where we store login + session data
SETTINGS_FILE = "settings.json"

# Local client version (you can bump this when you change client_qt.py)
CURRENT_VERSION = "1.0.0"

# URL to remote update-info script (provided by you)
UPDATE_INFO_URL = "https://raw.githubusercontent.com/Gaminghundoriginalreal/idkbrasiki/refs/heads/main/download.py"


# -------------------------------------------------------------------------
# Simple AV engine (signatures + heuristics)
# -------------------------------------------------------------------------

# Example blacklist of SHA256 hashes (fill with known malware hashes if you want)
KNOWN_BAD_HASHES = {
    # Placeholder demo hash
    "0000000000000000000000000000000000000000000000000000000000000000": "Test.Dummy.Sample",
}

# File types considered suspicious if large
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi"}


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def simple_scan_file(path: Path) -> Tuple[bool, Optional[str]]:
    """
    Return (infected: bool, reason/signature)
    - True if in blacklist or suspicious based on heuristics
    """
    try:
        h = file_hash(path)
    except Exception:
        return False, None

    if h in KNOWN_BAD_HASHES:
        return True, KNOWN_BAD_HASHES[h]

    ext = path.suffix.lower()
    try:
        size = path.stat().st_size
    except Exception:
        size = 0

    # Simple heuristics: suspicious extension + size threshold
    if ext in SUSPICIOUS_EXTENSIONS and size > 50 * 1024:
        return True, f"Suspicious.{ext[1:].upper()}.Heuristic"

    return False, None


# -------------------------------------------------------------------------
# Worker Threads
# -------------------------------------------------------------------------

class ScanWorker(QThread):
    progress = pyqtSignal(int, int)  # current, total
    log_line = pyqtSignal(str)
    finished_scan = pyqtSignal(int, int, str)  # clean, infected, label

    def __init__(self, roots: List[Path], label: str, parent=None):
        super().__init__(parent)
        self.roots = roots
        self.label = label

    def run(self):
        files: List[Path] = []
        for root in self.roots:
            for p in root.rglob("*"):
                if p.is_file():
                    files.append(p)

        total = len(files)
        infected_count = 0
        clean_count = 0

        for i, path in enumerate(files, start=1):
            infected, reason = simple_scan_file(path)
            if infected:
                infected_count += 1
                self.log_line.emit(f"[INFECTED] {path}  —  {reason}\n")
            else:
                clean_count += 1

            self.progress.emit(i, total)

        self.finished_scan.emit(clean_count, infected_count, self.label)


class RealtimeWorker(QThread):
    log_line = pyqtSignal(str)

    def __init__(self, roots: List[Path], stop_flag: threading.Event, parent=None):
        super().__init__(parent)
        self.roots = roots
        self.stop_flag = stop_flag

    def run(self):
        seen: Dict[Path, float] = {}
        while not self.stop_flag.is_set():
            for root in self.roots:
                for path in root.rglob("*"):
                    if not path.is_file():
                        continue
                    try:
                        mtime = path.stat().st_mtime
                    except FileNotFoundError:
                        continue
                    if path not in seen or seen[path] < mtime:
                        seen[path] = mtime
                        infected, reason = simple_scan_file(path)
                        if infected:
                            msg = f"[BLOCKED] {path}  —  {reason}\n"
                        else:
                            msg = f"[OK] {path}\n"
                        self.log_line.emit(msg)
            self.msleep(3000)


# -------------------------------------------------------------------------
# UI helpers
# -------------------------------------------------------------------------

def hline():
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Sunken)
    line.setStyleSheet("color: #1f2933;")
    return line


class SidebarButton(QPushButton):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(36)
        self.setStyleSheet("""
            QPushButton {
                color: #e5e7eb;
                background-color: transparent;
                border: none;
                text-align: left;
                padding-left: 14px;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #020617;
            }
            QPushButton:pressed {
                background-color: #0f172a;
            }
        """)


class AccentButton(QPushButton):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("""
            QPushButton {
                background-color: #38bdf8;
                color: #020617;
                border-radius: 6px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0ea5e9;
            }
            QPushButton:pressed {
                background-color: #0369a1;
            }
        """)


# -------------------------------------------------------------------------
# Main Window
# -------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NovaShield")
        self.resize(1100, 650)

        self.api_key: Optional[str] = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None  # stored for auto-login if backend restarted
        self.current_plan: Optional[str] = None
        self.has_active_plan: bool = False

        self.realtime_stop_flag = threading.Event()
        self.realtime_worker: Optional[RealtimeWorker] = None

        self.update_hash: Optional[str] = None

        self._load_settings()
        self._build_ui()

        # Try to restore session
        if self.api_key:
            self.refresh_status(silent=True, allow_relogin=True)

        # Check for updates after UI is ready
        self.check_for_updates()

    # ------------------------------------------------------------------
    # Settings (session persistence)
    # ------------------------------------------------------------------

    def _load_settings(self):
        if not os.path.exists(SETTINGS_FILE):
            return
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.api_key = data.get("api_key")
            self.username = data.get("username")
            self.password = data.get("password")
            self.update_hash = data.get("update_hash")
        except Exception:
            self.api_key = None
            self.username = None
            self.password = None
            self.update_hash = None

    def _save_settings(self):
        data = {
            "api_key": self.api_key,
            "username": self.username,
            "password": self.password,
            "update_hash": self.update_hash,
        }
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _card(self):
        frame = QFrame()
        frame.setStyleSheet("background-color: #020617; border: 1px solid #1f2937; border-radius: 10px;")
        return frame

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setFixedWidth(260)
        sidebar.setStyleSheet("background-color: #020617; border-right: 1px solid #1f2937;")

        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(16, 16, 16, 16)

        # Brand
        title = QLabel("NovaShield")
        title.setStyleSheet("color: #38bdf8; font-size: 20pt; font-weight: bold;")
        subtitle = QLabel("Realtime protection")
        subtitle.setStyleSheet("color: #9ca3af; font-size: 9pt;")

        sb_layout.addWidget(title)
        sb_layout.addWidget(subtitle)
        sb_layout.addSpacing(10)

        # Status card
        status_frame = QFrame()
        status_frame.setStyleSheet("background-color: #020617; border: 1px solid #1f2937; border-radius: 8px;")
        status_layout = QVBoxLayout(status_frame)
        status_layout.setContentsMargins(10, 8, 10, 8)

        self.status_label = QLabel("Not signed in")
        self.status_label.setStyleSheet("color: #9ca3af; font-size: 9pt;")
        self.plan_label = QLabel("Plan: None • Protection locked")
        self.plan_label.setStyleSheet("color: #f97316; font-size: 9pt;")

        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.plan_label)

        sb_layout.addWidget(status_frame)
        sb_layout.addSpacing(10)

        # Nav buttons
        self.btn_dashboard = SidebarButton("  Dashboard")
        self.btn_scanner = SidebarButton("  Smart / Full Scan")
        self.btn_realtime = SidebarButton("  Real-Time Shield")
        self.btn_account = SidebarButton("  Account & Plans")

        sb_layout.addWidget(self.btn_dashboard)
        sb_layout.addWidget(self.btn_scanner)
        sb_layout.addWidget(self.btn_realtime)
        sb_layout.addWidget(self.btn_account)
        sb_layout.addWidget(hline())

        # Auth buttons
        auth_row = QHBoxLayout()
        self.btn_login = AccentButton("Sign in / Register")
        self.btn_logout = QPushButton("Sign out")
        self.btn_logout.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_logout.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #e5e7eb;
                border: 1px solid #4b5563;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #020617;
            }
        """)

        self.btn_login.clicked.connect(self.show_login_dialog)
        self.btn_logout.clicked.connect(self.logout)

        auth_row.addWidget(self.btn_login)
        auth_row.addWidget(self.btn_logout)

        sb_layout.addLayout(auth_row)

        sb_layout.addStretch()

        info = QLabel("All antivirus features require an active plan.")
        info.setStyleSheet("color: #6b7280; font-size: 8pt;")
        info.setWordWrap(True)
        sb_layout.addWidget(info)

        # Pages
        self.pages = QStackedWidget()
        self.pages.setStyleSheet("background-color: #020617;")

        self.page_dashboard = self._build_dashboard_page()
        self.page_scanner = self._build_scanner_page()
        self.page_realtime = self._build_realtime_page()
        self.page_account = self._build_account_page()

        self.pages.addWidget(self.page_dashboard)
        self.pages.addWidget(self.page_scanner)
        self.pages.addWidget(self.page_realtime)
        self.pages.addWidget(self.page_account)

        root_layout.addWidget(sidebar)
        root_layout.addWidget(self.pages, 1)

        # Connect nav buttons
        self.btn_dashboard.clicked.connect(lambda: self.pages.setCurrentWidget(self.page_dashboard))
        self.btn_scanner.clicked.connect(lambda: self.pages.setCurrentWidget(self.page_scanner))
        self.btn_realtime.clicked.connect(lambda: self.pages.setCurrentWidget(self.page_realtime))
        self.btn_account.clicked.connect(lambda: self.pages.setCurrentWidget(self.page_account))

    # ------------------------------------------------------------------
    # Dashboard Page (with update box)
    # ------------------------------------------------------------------

    def _build_dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)

        # Update box (hidden by default, shown when check_for_updates finds changes)
        self.update_box = self._card()
        ub_layout = QVBoxLayout(self.update_box)
        ub_layout.setContentsMargins(14, 12, 14, 12)
        self.update_title = QLabel("Update")
        self.update_title.setStyleSheet("color: #38bdf8; font-size: 12pt; font-weight: bold;")
        self.update_message = QLabel("")
        self.update_message.setStyleSheet("color: #e5e7eb; font-size: 9pt;")
        self.update_message.setWordWrap(True)
        ub_layout.addWidget(self.update_title)
        ub_layout.addWidget(self.update_message)
        self.update_box.setVisible(False)

        layout.addWidget(self.update_box)

        header = QLabel("Security overview")
        header.setStyleSheet("color: #e5e7eb; font-size: 18pt; font-weight: bold;")
        layout.addWidget(header)

        sub = QLabel("Status of your protection, subscription and recent activity.")
        sub.setStyleSheet("color: #9ca3af; font-size: 10pt;")
        layout.addWidget(sub)
        layout.addSpacing(12)

        row = QHBoxLayout()

        card_left = self._card()
        cl_layout = QVBoxLayout(card_left)
        cl_layout.setContentsMargins(14, 12, 14, 12)

        title = QLabel("Protection status")
        title.setStyleSheet("color: #e5e7eb; font-size: 12pt; font-weight: bold;")
        cl_layout.addWidget(title)

        self.overview_status = QLabel("Protection locked – no active plan")
        self.overview_status.setStyleSheet("color: #f97316; font-size: 9pt;")
        cl_layout.addWidget(self.overview_status)

        self.overview_realtime = QLabel("Real-time shield: Off")
        self.overview_realtime.setStyleSheet("color: #9ca3af; font-size: 9pt;")
        cl_layout.addWidget(self.overview_realtime)

        self.overview_last_scan = QLabel("Last scan: Never")
        self.overview_last_scan.setStyleSheet("color: #9ca3af; font-size: 9pt;")
        cl_layout.addWidget(self.overview_last_scan)

        cl_layout.addStretch()

        card_right = self._card()
        cr_layout = QVBoxLayout(card_right)
        cr_layout.setContentsMargins(14, 12, 14, 12)

        title2 = QLabel("Subscription")
        title2.setStyleSheet("color: #e5e7eb; font-size: 12pt; font-weight: bold;")
        cr_layout.addWidget(title2)

        self.overview_plan = QLabel("Plan: None (features locked)")
        self.overview_plan.setStyleSheet("color: #f97316; font-size: 9pt;")
        cr_layout.addWidget(self.overview_plan)

        cr_layout.addStretch()

        row.addWidget(card_left)
        row.addWidget(card_right)

        layout.addLayout(row)
        layout.addStretch()
        return page

    # ------------------------------------------------------------------
    # Scanner Page
    # ------------------------------------------------------------------

    def _build_scanner_page(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)

        # Left side controls
        left = self._card()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(14, 12, 14, 12)

        header = QLabel("Scanner")
        header.setStyleSheet("color: #e5e7eb; font-size: 14pt; font-weight: bold;")
        left_layout.addWidget(header)

        sub = QLabel("Run a smart scan, a full system scan or scan a custom folder.")
        sub.setStyleSheet("color: #9ca3af; font-size: 9pt;")
        sub.setWordWrap(True)
        left_layout.addWidget(sub)
        left_layout.addSpacing(10)

        # Smart scan
        smart_title = QLabel("Smart scan")
        smart_title.setStyleSheet("color: #e5e7eb; font-weight: bold;")
        left_layout.addWidget(smart_title)

        smart_desc = QLabel("Scans common user locations (Desktop, Downloads, Documents).")
        smart_desc.setStyleSheet("color: #9ca3af; font-size: 9pt;")
        smart_desc.setWordWrap(True)
        left_layout.addWidget(smart_desc)

        btn_smart = AccentButton("Run smart scan")
        btn_smart.clicked.connect(self.start_smart_scan)
        left_layout.addWidget(btn_smart)

        left_layout.addSpacing(10)

        # Full scan
        full_title = QLabel("Full system scan")
        full_title.setStyleSheet("color: #e5e7eb; font-weight: bold;")
        left_layout.addWidget(full_title)

        full_desc = QLabel("Scans your entire system drive. This can take a while.")
        full_desc.setStyleSheet("color: #9ca3af; font-size: 9pt;")
        full_desc.setWordWrap(True)
        left_layout.addWidget(full_desc)

        btn_full = QPushButton("Run full scan")
        btn_full.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_full.setStyleSheet("color: #e5e7eb; border-radius: 6px; padding: 6px 12px; border: 1px solid #4b5563;")
        btn_full.clicked.connect(self.start_full_scan)
        left_layout.addWidget(btn_full)

        left_layout.addSpacing(10)

        # Custom scan
        custom_title = QLabel("Custom folder")
        custom_title.setStyleSheet("color: #e5e7eb; font-weight: bold;")
        left_layout.addWidget(custom_title)

        self.custom_path_edit = QLineEdit()
        self.custom_path_edit.setPlaceholderText("Choose a folder...")
        self.custom_path_edit.setStyleSheet("background-color: #020617; color: #e5e7eb; border: 1px solid #4b5563; border-radius: 6px; padding: 4px 6px;")
        left_layout.addWidget(self.custom_path_edit)

        row_custom = QHBoxLayout()
        btn_browse = QPushButton("Browse")
        btn_browse.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_browse.setStyleSheet("color: #e5e7eb; border-radius: 6px; padding: 6px 12px; border: 1px solid #4b5563;")
        btn_browse.clicked.connect(self.browse_custom_folder)
        row_custom.addWidget(btn_browse)

        btn_scan_folder = QPushButton("Scan folder")
        btn_scan_folder.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_scan_folder.setStyleSheet("color: #e5e7eb; border-radius: 6px; padding: 6px 12px; border: 1px solid #4b5563;")
        btn_scan_folder.clicked.connect(self.start_custom_scan)
        row_custom.addWidget(btn_scan_folder)

        left_layout.addLayout(row_custom)

        left_layout.addStretch()

        # Right side results
        right = self._card()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(14, 12, 14, 12)

        title = QLabel("Scan results")
        title.setStyleSheet("color: #e5e7eb; font-size: 12pt; font-weight: bold;")
        right_layout.addWidget(title)

        self.scan_progress = QProgressBar()
        self.scan_progress.setTextVisible(False)
        self.scan_progress.setStyleSheet("""
            QProgressBar {
                background-color: #020617;
                border: 1px solid #1f2937;
                border-radius: 6px;
            }
            QProgressBar::chunk {
                background-color: #38bdf8;
                border-radius: 6px;
            }
        """)
        right_layout.addWidget(self.scan_progress)

        self.scan_log = QTextEdit()
        self.scan_log.setReadOnly(True)
        self.scan_log.setStyleSheet("background-color: #020617; color: #e5e7eb; border: none;")
        right_layout.addWidget(self.scan_log, 1)

        self.scan_summary = QLabel("No scans run yet.")
        self.scan_summary.setStyleSheet("color: #9ca3af; font-size: 9pt;")
        right_layout.addWidget(self.scan_summary)

        layout.addWidget(left, 0)
        layout.addWidget(right, 1)

        return page

    # ------------------------------------------------------------------
    # Realtime Page
    # ------------------------------------------------------------------

    def _build_realtime_page(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)

        left = self._card()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(14, 12, 14, 12)

        header = QLabel("Real-time shield")
        header.setStyleSheet("color: #e5e7eb; font-size: 14pt; font-weight: bold;")
        left_layout.addWidget(header)

        sub = QLabel("Monitors locations for new or changed files and scans them.")
        sub.setStyleSheet("color: #9ca3af; font-size: 9pt;")
        sub.setWordWrap(True)
        left_layout.addWidget(sub)

        left_layout.addSpacing(10)

        self.rt_mode_group = QButtonGroup(self)
        rb_profile = QRadioButton("User profile (Desktop, Downloads, Documents)")
        rb_full = QRadioButton("Full system drive")
        rb_custom = QRadioButton("Custom folder")
        rb_profile.setChecked(True)
        for rb in (rb_profile, rb_full, rb_custom):
            rb.setStyleSheet("color: #e5e7eb; font-size: 9pt;")
            self.rt_mode_group.addButton(rb)
            left_layout.addWidget(rb)

        self.rt_custom_edit = QLineEdit()
        self.rt_custom_edit.setPlaceholderText("Custom folder for shield...")
        self.rt_custom_edit.setStyleSheet("background-color: #020617; color: #e5e7eb; border: 1px solid #4b5563; border-radius: 6px; padding: 4px 6px;")
        left_layout.addWidget(self.rt_custom_edit)

        btn_rt_browse = QPushButton("Browse")
        btn_rt_browse.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_rt_browse.setStyleSheet("color: #e5e7eb; border-radius: 6px; padding: 6px 12px; border: 1px solid #4b5563;")
        btn_rt_browse.clicked.connect(self.browse_rt_folder)
        left_layout.addWidget(btn_rt_browse)

        self.rt_toggle = AccentButton("Enable real-time shield")
        self.rt_toggle.setCheckable(True)
        self.rt_toggle.toggled.connect(self.toggle_realtime)
        left_layout.addWidget(self.rt_toggle)

        self.rt_status = QLabel("Status: Shield disabled")
        self.rt_status.setStyleSheet("color: #9ca3af; font-size: 9pt;")
        left_layout.addWidget(self.rt_status)

        left_layout.addStretch()

        right = self._card()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(14, 12, 14, 12)

        title = QLabel("Shield log")
        title.setStyleSheet("color: #e5e7eb; font-size: 12pt; font-weight: bold;")
        right_layout.addWidget(title)

        self.rt_log = QTextEdit()
        self.rt_log.setReadOnly(True)
        self.rt_log.setStyleSheet("background-color: #020617; color: #e5e7eb; border: none;")
        right_layout.addWidget(self.rt_log, 1)

        layout.addWidget(left, 0)
        layout.addWidget(right, 1)

        return page

    # ------------------------------------------------------------------
    # Account Page
    # ------------------------------------------------------------------

    def _build_account_page(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)

        left = self._card()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(14, 12, 14, 12)

        header = QLabel("Account & plans")
        header.setStyleSheet("color: #e5e7eb; font-size: 14pt; font-weight: bold;")
        left_layout.addWidget(header)

        self.account_info = QLabel("Not signed in.")
        self.account_info.setStyleSheet("color: #9ca3af; font-size: 9pt;")
        self.account_info.setWordWrap(True)
        left_layout.addWidget(self.account_info)

        btn_refresh = AccentButton("Refresh status")
        btn_refresh.clicked.connect(self.refresh_status)
        left_layout.addWidget(btn_refresh)

        left_layout.addStretch()

        right = self._card()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(14, 12, 14, 12)

        title = QLabel("Available plans")
        title.setStyleSheet("color: #e5e7eb; font-size: 12pt; font-weight: bold;")
        right_layout.addWidget(title)

        self.plan_table = QTableWidget(0, 4)
        self.plan_table.setHorizontalHeaderLabels(["ID", "Name", "Price", "Description"])
        self.plan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.plan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.plan_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.plan_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.plan_table.verticalHeader().setVisible(False)
        self.plan_table.setShowGrid(False)
        self.plan_table.setStyleSheet("""
            QTableWidget {
                background-color: #020617;
                color: #e5e7eb;
                gridline-color: #1f2937;
            }
            QHeaderView::section {
                background-color: #020617;
                color: #9ca3af;
                border: none;
                padding: 4px;
            }
        """)
        right_layout.addWidget(self.plan_table, 1)

        buttons_row = QHBoxLayout()
        btn_load = QPushButton("Load plans")
        btn_load.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_load.setStyleSheet("color: #e5e7eb; border-radius: 6px; padding: 6px 12px; border: 1px solid #4b5563;")
        btn_load.clicked.connect(self.load_plans)
        buttons_row.addWidget(btn_load)

        btn_purchase = AccentButton("Purchase selected")
        btn_purchase.clicked.connect(self.purchase_plan)
        buttons_row.addWidget(btn_purchase)

        right_layout.addLayout(buttons_row)

        layout.addWidget(left, 0)
        layout.addWidget(right, 1)

        return page

    # ------------------------------------------------------------------
    # Auth / Plans / Status
    # ------------------------------------------------------------------

    def show_login_dialog(self):
        from PyQt6.QtWidgets import QDialog, QFormLayout

        dlg = QDialog(self)
        dlg.setWindowTitle("Sign in / Register")
        dlg.setStyleSheet("background-color: #020617; color: #e5e7eb;")

        form = QFormLayout(dlg)
        form.setContentsMargins(16, 16, 16, 16)

        user_edit = QLineEdit()
        user_edit.setStyleSheet("background-color: #020617; color: #e5e7eb; border: 1px solid #4b5563; border-radius: 6px; padding: 4px 6px;")
        pass_edit = QLineEdit()
        pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        pass_edit.setStyleSheet("background-color: #020617; color: #e5e7eb; border: 1px solid #4b5563; border-radius: 6px; padding: 4px 6px;")

        form.addRow("Username:", user_edit)
        form.addRow("Password:", pass_edit)

        row = QHBoxLayout()
        btn_register = QPushButton("Register")
        btn_register.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_register.setStyleSheet("color: #e5e7eb; border-radius: 6px; padding: 6px 12px; border: 1px solid #4b5563;")
        btn_login = AccentButton("Sign in")

        row.addWidget(btn_register)
        row.addWidget(btn_login)

        form.addRow(row)

        def do_register():
            username = user_edit.text().strip()
            password = pass_edit.text().strip()
            if not username or not password:
                QMessageBox.critical(self, "Error", "Please enter username and password.")
                return
            try:
                r = requests.post(f"{BASE_URL}/api/register", json={"username": username, "password": password}, timeout=5)
                data = r.json()
                if r.status_code == 200:
                    QMessageBox.information(self, "Success", "Registered. You can now sign in.")
                else:
                    QMessageBox.critical(self, "Error", data.get("error", "Unknown error"))
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

        def do_login():
            username = user_edit.text().strip()
            password = pass_edit.text().strip()
            if not username or not password:
                QMessageBox.critical(self, "Error", "Please enter username and password.")
                return
            try:
                r = requests.post(f"{BASE_URL}/api/login", json={"username": username, "password": password}, timeout=5)
                data = r.json()
                if r.status_code == 200:
                    self.api_key = data["api_key"]
                    self.username = username
                    self.password = password  # store for auto-login later
                    self._save_settings()
                    self.status_label.setText(f"Signed in as {username}")
                    self.refresh_status()
                    dlg.accept()
                else:
                    QMessageBox.critical(self, "Error", data.get("error", "Unknown error"))
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

        btn_register.clicked.connect(do_register)
        btn_login.clicked.connect(do_login)

        dlg.exec()

    def logout(self):
        self.api_key = None
        # We keep username/password so we can auto-login again later if user wants
        self.current_plan = None
        self.has_active_plan = False
        self._save_settings()
        self.status_label.setText("Not signed in")
        self.plan_label.setText("Plan: None • Protection locked")
        self.plan_label.setStyleSheet("color: #f97316; font-size: 9pt;")
        self.account_info.setText("Not signed in.")
        self.overview_status.setText("Protection locked – no active plan")
        self.overview_status.setStyleSheet("color: #f97316; font-size: 9pt;")
        self.overview_plan.setText("Plan: None (features locked)")
        self.overview_plan.setStyleSheet("color: #f97316; font-size: 9pt;")
        self.rt_status.setText("Status: Shield disabled")
        self.overview_realtime.setText("Real-time shield: Off")
        self.realtime_stop_flag.set()
        self.rt_toggle.setChecked(False)
        QMessageBox.information(self, "Signed out", "You have been signed out.")

    def refresh_status(self, silent: bool = False, allow_relogin: bool = False):
        if not self.api_key:
            self.account_info.setText("Not signed in.")
            self._update_plan_state(None)
            return
        try:
            r = requests.post(f"{BASE_URL}/api/status", json={"api_key": self.api_key}, timeout=5)
            data = r.json()
            if r.status_code == 200:
                plan = data.get("plan") or None
                balance = float(data.get("balance", 0.0))
                banned = bool(data.get("is_banned", False))
                self.account_info.setText(
                    f"User: {data['username']}\n"
                    f"Balance: {balance:.2f} €\n"
                    f"Active plan: {plan or 'None'}\n"
                    f"Banned: {banned}"
                )
                self._update_plan_state(plan)
            else:
                # If api_key invalid and we have username/password -> try auto-login
                err = data.get("error", "")
                if allow_relogin and "Invalid api_key" in err and self.username and self.password:
                    self._auto_login_after_restart()
                else:
                    self.account_info.setText(f"Error: {err or 'Unknown error'}")
                    self._update_plan_state(None)
                    if not silent:
                        QMessageBox.critical(self, "Error", err or "Unknown error")
        except Exception as e:
            self.account_info.setText(f"Error: {e}")
            self._update_plan_state(None)
            if not silent:
                QMessageBox.critical(self, "Error", str(e))

    def _auto_login_after_restart(self):
        # This is used when backend restarted and old api_key is invalid
        try:
            r = requests.post(
                f"{BASE_URL}/api/login",
                json={"username": self.username, "password": self.password},
                timeout=5,
            )
            data = r.json()
            if r.status_code == 200:
                self.api_key = data["api_key"]
                self._save_settings()
                self.status_label.setText(f"Signed in as {self.username}")
                # After getting new api_key, call refresh_status again (no infinite loop)
                self.refresh_status(silent=True, allow_relogin=False)
            else:
                self.account_info.setText(f"Error: {data.get('error', 'Unknown error')}")
        except Exception as e:
            self.account_info.setText(f"Error: {e}")

    def _update_plan_state(self, plan: Optional[str]):
        self.current_plan = plan
        self.has_active_plan = plan is not None
        if self.has_active_plan:
            self.plan_label.setText(f"Plan: {plan} • Protection unlocked")
            self.plan_label.setStyleSheet("color: #4ade80; font-size: 9pt;")
            self.overview_status.setText(f"Protection active – {plan} plan")
            self.overview_status.setStyleSheet("color: #4ade80; font-size: 9pt;")
            self.overview_plan.setText(f"Plan: {plan} (all features unlocked)")
            self.overview_plan.setStyleSheet("color: #4ade80; font-size: 9pt;")
        else:
            self.plan_label.setText("Plan: None • Protection locked")
            self.plan_label.setStyleSheet("color: #f97316; font-size: 9pt;")
            self.overview_status.setText("Protection locked – no active plan")
            self.overview_status.setStyleSheet("color: #f97316; font-size: 9pt;")
            self.overview_plan.setText("Plan: None (features locked)")
            self.overview_plan.setStyleSheet("color: #f97316; font-size: 9pt;")

    def load_plans(self):
        self.plan_table.setRowCount(0)
        try:
            r = requests.get(f"{BASE_URL}/api/plans", timeout=5)
            data = r.json()
            plans = data.get("plans", [])
            self.plan_table.setRowCount(len(plans))
            for row, p in enumerate(plans):
                self.plan_table.setItem(row, 0, QTableWidgetItem(p["id"]))
                self.plan_table.setItem(row, 1, QTableWidgetItem(p["name"]))
                self.plan_table.setItem(row, 2, QTableWidgetItem(f"{p['price']:.2f} €"))
                self.plan_table.setItem(row, 3, QTableWidgetItem(p["description"]))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def purchase_plan(self):
        if not self.api_key:
            QMessageBox.critical(self, "Error", "Please sign in first.")
            return
        row = self.plan_table.currentRow()
        if row < 0:
            QMessageBox.critical(self, "Error", "Please select a plan.")
            return
        plan_id_item = self.plan_table.item(row, 0)
        if not plan_id_item:
            QMessageBox.critical(self, "Error", "Invalid selection.")
            return
        plan_id = plan_id_item.text()
        try:
            r = requests.post(
                f"{BASE_URL}/api/purchase",
                json={"api_key": self.api_key, "plan_id": plan_id},
                timeout=5,
            )
            data = r.json()
            if r.status_code == 200:
                QMessageBox.information(self, "Success", f"Plan '{plan_id}' activated.")
                self.refresh_status()
            else:
                QMessageBox.critical(self, "Error", data.get("error", "Unknown error"))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ------------------------------------------------------------------
    # Scanner logic
    # ------------------------------------------------------------------

    def _require_plan(self) -> bool:
        if not self.api_key:
            QMessageBox.critical(self, "Locked", "Sign in and purchase a plan to use antivirus features.")
            return False
        if not self.has_active_plan:
            QMessageBox.critical(self, "Protection locked", "You need an active plan for antivirus features.")
            return False
        return True

    def browse_custom_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to scan")
        if folder:
            self.custom_path_edit.setText(folder)

    def _get_user_profile_roots(self) -> List[Path]:
        home = Path(os.path.expanduser("~"))
        candidates = [home / "Desktop", home / "Downloads", home / "Documents"]
        return [p for p in candidates if p.exists()]

    def _get_system_root(self) -> Path:
        system = platform.system().lower()
        if system == "windows":
            system_drive = os.environ.get("SystemDrive", "C:")
            root = Path(system_drive + os.sep)
        else:
            root = Path("/")
        return root

    def start_smart_scan(self):
        if not self._require_plan():
            return
        roots = self._get_user_profile_roots()
        if not roots:
            QMessageBox.critical(self, "Error", "Could not locate common user folders.")
            return
        self._start_scan(roots, "Smart scan")

    def start_full_scan(self):
        if not self._require_plan():
            return
        root = self._get_system_root()
        if not root.exists():
            QMessageBox.critical(self, "Error", "Could not determine system root.")
            return
        self._start_scan([root], "Full system scan")

    def start_custom_scan(self):
        if not self._require_plan():
            return
        folder = self.custom_path_edit.text().strip()
        if not folder or not os.path.isdir(folder):
            QMessageBox.critical(self, "Error", "Please choose a valid folder.")
            return
        self._start_scan([Path(folder)], "Folder scan")

    def _start_scan(self, roots: List[Path], label: str):
        self.scan_log.clear()
        self.scan_log.append(f"▶ {label} started\n")
        self.scan_summary.setText(f"{label} running…")
        self.scan_progress.setValue(0)

        self.scan_worker = ScanWorker(roots, label)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.log_line.connect(self._on_scan_log_line)
        self.scan_worker.finished_scan.connect(self._on_scan_finished)
        self.scan_worker.start()

    def _on_scan_progress(self, current: int, total: int):
        if total <= 0:
            self.scan_progress.setValue(0)
        else:
            self.scan_progress.setMaximum(total)
            self.scan_progress.setValue(current)

    def _on_scan_log_line(self, line: str):
        self.scan_log.moveCursor(self.scan_log.textCursor().MoveOperation.End)
        self.scan_log.insertPlainText(line)

    def _on_scan_finished(self, clean: int, infected: int, label: str):
        self.overview_last_scan.setText(f"Last scan: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self._report_scan(clean, infected)

        if infected == 0:
            text = (
                f"✓ {label} completed.\n"
                f"Clean objects: {clean} • Threats: {infected}"
            )
            color = "#4ade80"
        else:
            text = (
                f"⚠ {label} completed.\n"
                f"Clean objects: {clean} • Threats detected: {infected}"
            )
            color = "#f97373"
        self.scan_summary.setText(text)
        self.scan_summary.setStyleSheet(f"color: {color}; font-size: 9pt;")

    def _report_scan(self, clean: int, infected: int):
        if not self.api_key:
            return
        try:
            requests.post(
                f"{BASE_URL}/api/report_scan",
                json={"api_key": self.api_key, "clean": clean, "infected": infected},
                timeout=5,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Realtime logic
    # ------------------------------------------------------------------

    def browse_rt_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder for real-time shield")
        if folder:
            self.rt_custom_edit.setText(folder)

    def toggle_realtime(self, enabled: bool):
        if not enabled:
            self.realtime_stop_flag.set()
            self.rt_status.setText("Status: Shield disabled")
            self.overview_realtime.setText("Real-time shield: Off")
            self.rt_toggle.setText("Enable real-time shield")
            return

        if not self._require_plan():
            self.rt_toggle.setChecked(False)
            return

        # Determine roots
        checked_button = self.rt_mode_group.checkedButton()
        mode_text = checked_button.text() if checked_button else ""

        roots: List[Path] = []
        if "User profile" in mode_text:
            roots = self._get_user_profile_roots()
        elif "Full system" in mode_text:
            roots = [self._get_system_root()]
        else:
            folder = self.rt_custom_edit.text().strip()
            if not folder or not os.path.isdir(folder):
                QMessageBox.critical(self, "Error", "Please choose a valid custom folder.")
                self.rt_toggle.setChecked(False)
                return
            roots = [Path(folder)]

        if not roots:
            QMessageBox.critical(self, "Error", "Could not determine folders to protect.")
            self.rt_toggle.setChecked(False)
            return

        self.realtime_stop_flag.clear()
        self.realtime_worker = RealtimeWorker(roots, self.realtime_stop_flag)
        self.realtime_worker.log_line.connect(self._on_realtime_log_line)
        self.realtime_worker.start()

        self.rt_status.setText("Status: Shield active")
        self.overview_realtime.setText("Real-time shield: On")
        self.rt_toggle.setText("Disable real-time shield")

    def _on_realtime_log_line(self, line: str):
        self.rt_log.moveCursor(self.rt_log.textCursor().MoveOperation.End)
        self.rt_log.insertPlainText(line)

    # ------------------------------------------------------------------
    # Update checker (using your GitHub raw script as version source)
    # ------------------------------------------------------------------

    def check_for_updates(self):
        """
        Downloads the content at UPDATE_INFO_URL and compares its hash
        against the last stored hash. If it's different, we show a modern
        update box saying that an update is available.

        Aus Sicherheitsgründen wird der Code NICHT automatisch ausgeführt,
        sondern nur der Text/Hash als Info verwendet.
        """
        try:
            resp = requests.get(UPDATE_INFO_URL, timeout=5)
            if resp.status_code != 200:
                return
            content = resp.text
            new_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

            # If we have never seen this hash before, treat as "needs update"
            if self.update_hash and self.update_hash == new_hash:
                # No change
                return

            # Update available (or first time)
            self.update_hash = new_hash
            self._save_settings()

            # Show only a short preview of the first line as "latest version" info
            first_line = content.splitlines()[0].strip() if content.splitlines() else "New version available."

            self.update_title.setText("Need to update! Updating info…")
            self.update_message.setText(
                f"A newer version is available.\n\n"
                f"Latest info from server:\n{first_line}"
            )
            self.update_box.setStyleSheet(
                "background-color: #020617; border: 1px solid #38bdf8; border-radius: 10px;"
            )
            self.update_box.setVisible(True)

        except Exception:
            # Silently ignore update issues
            pass


def main():
    import sys
    app = QApplication(sys.argv)
    QApplication.setStyle("Fusion")
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
