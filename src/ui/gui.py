"""
Unearth Forensic Recovery Tool - GUI Interface
Production-ready version with all fixes
"""

import sys
import os
from pathlib import Path
from datetime import datetime
import random
from collections import Counter

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QTextEdit, QComboBox, QCheckBox,
    QStackedWidget, QListWidget, QListWidgetItem, QFileDialog,
    QMessageBox, QProgressBar, QDialog, QDialogButtonBox, QScrollArea,
    QGridLayout, QSizePolicy, QSplitter
)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor

# Try to import matplotlib for charts
try:
    import matplotlib
    matplotlib.use('QtAgg')
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not available, charts will be disabled")

try:
    import qtawesome as qta
    HAS_QTAWESOME = True
except ImportError:
    HAS_QTAWESOME = False
    print("Warning: qtawesome not available, using text icons")

# Try to import backend
try:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from app import UnearthApp
    from utils import (
        list_xfs_btrfs_partitions, list_external_drives,
        format_bytes, check_root_permissions
    )
    from core.metadata_extractor import MetadataExtractor
    BACKEND_AVAILABLE = True
except ImportError as e:
    print(f"Backend not available: {e}")
    BACKEND_AVAILABLE = False
    
    # Mock functions
    def list_xfs_btrfs_partitions():
        return []
    
    def list_external_drives():
        return []
    
    def format_bytes(size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    
    def check_root_permissions():
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def get_icon(name, color='#FFFFFF'):
    """Get icon - fallback to text if qtawesome not available"""
    if HAS_QTAWESOME:
        try:
            return qta.icon(name, color=color)
        except:
            pass
    # Return text-based icon
    from PyQt6.QtGui import QIcon
    return QIcon()


class BarChartWidget(QWidget):
    """Custom widget that draws horizontal bar charts using QPainter.
    Guaranteed to render in any Qt environment."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._items = []  # list of (label, count, color_hex)
        self.setMinimumHeight(200)
    
    def set_data(self, items):
        """Set chart data. items: list of (label, count, color_hex_string)"""
        self._items = items
        self.update()  # trigger repaint
    
    def paintEvent(self, event):
        from PyQt6.QtGui import QPainter, QColor, QFont, QPen
        from PyQt6.QtCore import QRectF, Qt
        
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Background
        painter.fillRect(self.rect(), QColor("#1E1E2E"))
        
        if not self._items:
            painter.setPen(QColor("#9CA3AF"))
            painter.setFont(QFont("Segoe UI", 13))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No Data")
            painter.end()
            return
        
        total = sum(c for _, c, _ in self._items)
        if total == 0:
            painter.setPen(QColor("#9CA3AF"))
            painter.setFont(QFont("Segoe UI", 13))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No Data")
            painter.end()
            return
        
        w = self.width()
        bar_x = 130  # left margin for labels
        bar_max_w = w - bar_x - 100  # leave space for percentage on right
        bar_height = 22
        row_spacing = 14
        row_height = bar_height + row_spacing
        y = 15
        
        label_font = QFont("Segoe UI", 10)
        pct_font = QFont("Segoe UI", 9)
        
        for label, count, color_hex in self._items:
            pct = (count / total) * 100
            bar_w = max(int((count / total) * bar_max_w), 6)
            
            # Label
            painter.setPen(QColor("#E5E7EB"))
            painter.setFont(label_font)
            painter.drawText(5, y, bar_x - 10, bar_height,
                             Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                             label)
            
            # Bar background track
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#2A2F3A"))
            painter.drawRoundedRect(QRectF(bar_x, y, bar_max_w, bar_height), 4, 4)
            
            # Bar fill
            painter.setBrush(QColor(color_hex))
            painter.drawRoundedRect(QRectF(bar_x, y, bar_w, bar_height), 4, 4)
            
            # Percentage text
            painter.setPen(QColor("#9CA3AF"))
            painter.setFont(pct_font)
            painter.drawText(int(bar_x + bar_max_w + 8), y, 90, bar_height,
                             Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                             f"{count} ({pct:.1f}%)")
            
            y += row_height
        
        painter.end()


class ScanWorker(QThread):
    """Background worker for scanning"""
    progress_updated = pyqtSignal(int, str)
    scan_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, app, session_id, file_filter="all",
                 enable_carving=True, carve_file_types=None):
        super().__init__()
        self.app = app
        self.session_id = session_id
        self.file_filter = file_filter  # "all", "deleted_only", or "active_only"
        # Carving options: whether to carve at all, and which file types
        self.enable_carving = enable_carving
        self.carve_file_types = carve_file_types  # None = all types, or list like ['jpg','pdf']
        
    def run(self):
        try:
            self.progress_updated.emit(10, "Detecting filesystem...")
            fs_type = self.app.detect_filesystem(self.session_id)
            
            self.progress_updated.emit(20, "Scanning filesystem...")
            
            def scan_progress(percent, msg):
                # Map 0-100 scan progress to 20-85 overall progress
                overall = 20 + int(percent * 0.65)
                self.progress_updated.emit(overall, msg)
                
            recovered = self.app.recover_deleted_files(
                self.session_id, 
                progress_callback=scan_progress,
                file_filter=self.file_filter
            )
            
            # --- File carving (optional) ---
            carved = []
            if self.enable_carving:
                self.progress_updated.emit(88, "Carving files...")
                carved = self.app.carve_files(self.session_id, file_types=self.carve_file_types)
            else:
                self.progress_updated.emit(90, "Skipping file carving")
            
            self.progress_updated.emit(100, "Scan complete!")
            self.scan_completed.emit({
                'recovered': recovered,
                'carved': carved
            })
        except Exception as e:
            self.error_occurred.emit(str(e))


class SidebarButton(QPushButton):
    """Custom sidebar button"""
    def __init__(self, icon_name, text, parent=None):
        super().__init__(parent)
        self.setText(f"  {text}")
        icon = get_icon(icon_name, '#9CA3AF')
        if not icon.isNull():
            self.setIcon(icon)
            self.setIconSize(QSize(18, 18))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setCheckable(True)
        self.setFixedHeight(40)
        self.setStyleSheet("""
            SidebarButton {
                background-color: transparent;
                color: #9CA3AF;
                text-align: left;
                padding-left: 15px;
                border: none;
                border-radius: 8px;
                font-size: 13px;
            }
            SidebarButton:hover {
                background-color: #2A2F3A;
                color: #FFFFFF;
            }
            SidebarButton:checked {
                background-color: #3B82F6;
                color: #FFFFFF;
            }
        """)


class UnearthGUI(QMainWindow):
    """Main Unearth GUI Application"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unearth - Forensic Data Recovery")
        self.setGeometry(100, 100, 1600, 900)
        
        # Initialize backend if available
        self.app = UnearthApp() if BACKEND_AVAILABLE else None
        self.current_session = None
        self.recovered_files = []
        self.carved_files = []
        self.scan_worker = None
        self.file_filter = "all"  # Filter: "all", "deleted_only", or "active_only"
        
        self.setup_ui()
        
        # Check permissions (warn but don't block)
        if not check_root_permissions() and BACKEND_AVAILABLE:
            self.show_permission_warning()
    
    def show_permission_warning(self):
        """Show permission warning"""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Limited Permissions")
        msg.setText("Running without elevated privileges")
        msg.setInformativeText(
            "Some features may be limited:\n"
            "• Cannot access raw disk devices\n"
            "• Scanning may be restricted\n\n"
            "For full functionality, run with sudo:\n"
            "  sudo python run.py"
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()
    
    def setup_ui(self):
        """Setup main UI"""
        central = QWidget()
        self.setCentralWidget(central)
        
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar
        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar)
        
        # Content stack
        self.content_stack = QStackedWidget()
        self.content_stack.setStyleSheet("background-color: #16161E;")
        
        # Add all views
        self.content_stack.addWidget(self.create_dashboard_view())
        self.content_stack.addWidget(self.create_recovered_files_view())
        self.content_stack.addWidget(self.create_timeline_view())
        self.content_stack.addWidget(self.create_keyword_search_view())
        self.content_stack.addWidget(self.create_integrity_view())
        self.content_stack.addWidget(self.create_metadata_view())
        self.content_stack.addWidget(self.create_report_view())
        
        main_layout.addWidget(self.content_stack, stretch=1)
    
    def create_sidebar(self):
        """Create sidebar"""
        sidebar = QFrame()
        sidebar.setFixedWidth(350)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #1E1E2E;
                border-right: 1px solid #2A2F3A;
            }
        """)
        
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(15, 20, 15, 20)
        layout.setSpacing(5)
        
        # Logo
        logo = QLabel("🔍 Meta Recover X")
        logo.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        logo.setStyleSheet("color: #FFFFFF; padding: 10px;")
        layout.addWidget(logo)
        
        layout.addSpacing(20)
        
        # Data Recovery Section
        section = QLabel("DATA RECOVERY")
        section.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        section.setStyleSheet("color: #6B7280; padding: 5px 15px;")
        layout.addWidget(section)
        
        # Navigation buttons
        self.btn_dashboard = SidebarButton('fa5s.th-large', "Dashboard")
        self.btn_dashboard.setChecked(True)
        self.btn_dashboard.clicked.connect(lambda: self.switch_view(0))
        
        self.btn_recovered = SidebarButton('fa5s.folder-open', "Recovered Files")
        self.btn_recovered.clicked.connect(lambda: self.switch_view(1))
        
        self.btn_timeline = SidebarButton('fa5s.chart-line', "File Timeline")
        self.btn_timeline.clicked.connect(lambda: self.switch_view(2))
        
        self.btn_keywords = SidebarButton('fa5s.search', "Keyword Search")
        self.btn_keywords.clicked.connect(lambda: self.switch_view(3))
        
        layout.addWidget(self.btn_dashboard)
        layout.addWidget(self.btn_recovered)
        layout.addWidget(self.btn_timeline)
        layout.addWidget(self.btn_keywords)
        
        layout.addSpacing(20)
        
        # Forensic Tools Section
        section2 = QLabel("FORENSIC TOOLS")
        section2.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        section2.setStyleSheet("color: #6B7280; padding: 5px 15px;")
        layout.addWidget(section2)
        
        self.btn_integrity = SidebarButton('fa5s.shield-alt', "Integrity Verification")
        self.btn_integrity.clicked.connect(lambda: self.switch_view(4))
        
        self.btn_metadata = SidebarButton('fa5s.info-circle', "Metadata Extraction")
        self.btn_metadata.clicked.connect(lambda: self.switch_view(5))
        
        self.btn_report = SidebarButton('fa5s.file-alt', "Report Generator")
        self.btn_report.clicked.connect(lambda: self.switch_view(6))
        
        layout.addWidget(self.btn_integrity)
        layout.addWidget(self.btn_metadata)
        layout.addWidget(self.btn_report)
        
        layout.addStretch()
        
        # Attach button
        self.attach_btn = QPushButton("+ Attach Source...")
        self.attach_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.attach_btn.clicked.connect(self.show_attach_menu)
        self.attach_btn.setStyleSheet("""
            QPushButton {
                background-color: #3B82F6;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-size: 13px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        layout.addWidget(self.attach_btn)
        
        return sidebar
    
    def switch_view(self, index):
        """Switch between views"""
        buttons = [
            self.btn_dashboard, self.btn_recovered, self.btn_timeline,
            self.btn_keywords, self.btn_integrity, self.btn_metadata, self.btn_report
        ]
        
        # Uncheck all
        for btn in buttons:
            btn.setChecked(False)
        
        # Check selected
        if 0 <= index < len(buttons):
            buttons[index].setChecked(True)
        
        self.content_stack.setCurrentIndex(index)
        
        # Refresh data for specific views
        if index == 1:
            self.refresh_recovered_files()
        elif index == 2:
            self.refresh_timeline()
    
    def show_attach_menu(self):
        """Show attachment options menu"""
        from PyQt6.QtWidgets import QMenu
        from PyQt6.QtGui import QAction
        
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 8px;
                padding: 5px;
            }
            QMenu::item {
                padding: 8px 20px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #3B82F6;
            }
        """)
        
        # Disk image
        image_action = QAction("📁 Disk Image File", self)
        image_action.triggered.connect(self.attach_disk_image)
        menu.addAction(image_action)
        
        # System partition
        partition_action = QAction("💾 System Partition", self)
        partition_action.triggered.connect(self.attach_system_partition)
        menu.addAction(partition_action)
        
        # External drive
        external_action = QAction("🔌 External Drive", self)
        external_action.triggered.connect(self.attach_external_drive)
        menu.addAction(external_action)
        
        # Show menu
        menu.exec(self.attach_btn.mapToGlobal(self.attach_btn.rect().bottomLeft()))
    
    def attach_disk_image(self):
        """Attach disk image file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Disk Image", "",
            "Disk Images (*.img *.raw *.dd *.e01);;All Files (*.*)"
        )
        
        if file_path:
            self.start_session(file_path, "Disk Image")
    
    def attach_system_partition(self):
        """Attach system partition"""
        partitions = list_xfs_btrfs_partitions()
        
        if not partitions:
            QMessageBox.information(
                self, "No Partitions Found",
                "No XFS or Btrfs partitions detected.\n\n"
                "Supported filesystems:\n• XFS\n• Btrfs\n\n"
                "Note: You may need elevated permissions to detect all partitions."
            )
            return
        
        # Show selection dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Partition")
        dialog.setStyleSheet("background-color: #16161E; color: #FFFFFF;")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(400)
        
        layout = QVBoxLayout(dialog)
        
        title = QLabel("Select XFS/Btrfs Partition to Analyze")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF; padding: 10px;")
        layout.addWidget(title)
        
        list_widget = QListWidget()
        list_widget.setStyleSheet("""
            QListWidget {
                background-color: #1E1E2E;
                color: #FFFFFF;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 10px;
                border-radius: 4px;
                margin: 2px;
            }
            QListWidget::item:selected {
                background-color: #3B82F6;
            }
            QListWidget::item:hover {
                background-color: #2A2F3A;
            }
        """)
        
        for p in partitions:
            is_mounted = p.get('mounted', True)
            mount_status = "🟢 Mounted" if is_mounted else "🔴 Unmounted"
            
            item_text = f"{p['device']} - {p['fstype'].upper()} [{mount_status}]"
            if is_mounted and p.get('mountpoint') and p['mountpoint'] != '(not mounted)':
                item_text += f"\n    📁 {p['mountpoint']}"
            if p.get('label'):
                item_text += f" ({p['label']})"
            item_text += f" - {format_bytes(p.get('total', 0))}"
            
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, p)
            list_widget.addItem(item)
        
        layout.addWidget(list_widget)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        buttons.setStyleSheet("""
            QPushButton {
                background-color: #3B82F6;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = list_widget.currentItem()
            if selected:
                p = selected.data(Qt.ItemDataRole.UserRole)
                self.start_session(p['device'], f"Partition ({p['fstype'].upper()})")
    
    def attach_external_drive(self):
        """Attach external drive with selection dialog"""
        external = list_external_drives()
        
        if not external:
            QMessageBox.information(
                self, "No External Drives",
                "No external/removable drives detected.\n\n"
                "Please ensure:\n"
                "• Drive is connected\n"
                "• Drive is recognized by system"
            )
            return
        
        # Show selection dialog (same style as partition selection)
        dialog = QDialog(self)
        dialog.setWindowTitle("Select External Drive")
        dialog.setMinimumSize(500, 350)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #1A1B2E;
                color: #FFFFFF;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        label = QLabel("Select an external drive to scan:")
        label.setStyleSheet("color: #FFFFFF; font-size: 14px; font-weight: bold;")
        layout.addWidget(label)
        
        list_widget = QListWidget()
        list_widget.setStyleSheet("""
            QListWidget {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 8px;
                padding: 5px;
                font-size: 13px;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #3A3F4A;
                border-radius: 4px;
                margin: 2px;
            }
            QListWidget::item:selected {
                background-color: #3B82F6;
            }
            QListWidget::item:hover {
                background-color: #2A2F3A;
            }
        """)
        
        for e in external:
            is_mounted = e.get('mounted', False)
            mount_status = "🟢 Mounted" if is_mounted else "🔴 Unmounted"
            fstype = e.get('fstype', 'unknown').upper() or 'Unknown FS'
            
            item_text = f"{e['device']} - {fstype} [{mount_status}]"
            if is_mounted and e.get('mountpoint') and e['mountpoint'] != '(not mounted)':
                item_text += f"\n    📁 {e['mountpoint']}"
            if e.get('label'):
                item_text += f" ({e['label']})"
            if e.get('total', 0) > 0:
                item_text += f" - {format_bytes(e.get('total', 0))}"
            
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, e)
            list_widget.addItem(item)
        
        layout.addWidget(list_widget)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        buttons.setStyleSheet("""
            QPushButton {
                background-color: #3B82F6;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = list_widget.currentItem()
            if selected:
                e = selected.data(Qt.ItemDataRole.UserRole)
                fstype = e.get('fstype', 'unknown').upper()
                self.start_session(e['device'], f"External Drive ({fstype})")
    
    def start_session(self, source_path, source_type):
        """Start recovery session"""
        output_dir = Path("data/recovered_output") / datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            
            if self.app and BACKEND_AVAILABLE:
                self.current_session = self.app.create_session(source_path, str(output_dir))
                
                # Show carving options dialog before starting the scan
                # This lets users choose whether to enable carving and which
                # file types to look for, avoiding the 300k MP4 problem
                enable_carving, carve_types = self._show_carving_options()
                self.start_scan(enable_carving=enable_carving, carve_file_types=carve_types)
            else:
                # Backend not available — can't run without it
                QMessageBox.critical(
                    self, "Backend Unavailable",
                    "The recovery backend could not be loaded.\n\n"
                    "Please ensure all dependencies are installed:\n"
                    "  pip install -r requirements.txt"
                )
                return
            
            self.switch_view(0)
            self.update_dashboard(source_path, source_type)
            
        except PermissionError:
            QMessageBox.critical(
                self, "Permission Denied",
                f"Cannot access: {source_path}\n\n"
                "Root privileges are required to access raw disk devices.\n\n"
                "Please restart the application using the launcher:\n"
                "  sudo python run.py --gui\n\n"
                "Alternatively, you can grant read access to the device:\n"
                f"  sudo chmod +r {source_path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start session:\n{str(e)}")
    
    def _show_carving_options(self):
        """
        Show a dialog letting the user configure file carving before scanning.
        
        Options:
        - Enable/disable carving entirely (checkbox at the top)
        - Select which file types to carve for (individual checkboxes)
        
        Returns:
            Tuple of (enable_carving: bool, file_types: list or None)
            - If carving is disabled, returns (False, None)
            - If all types selected, returns (True, None) meaning "carve everything"
            - If specific types selected, returns (True, ['jpg', 'png', ...]) 
        """
        dialog = QDialog(self)
        dialog.setWindowTitle("Carving Options")
        dialog.setStyleSheet("background-color: #16161E; color: #FFFFFF;")
        dialog.setMinimumWidth(450)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(12)
        
        # Title
        title = QLabel("File Carving Settings")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF; padding: 5px;")
        layout.addWidget(title)
        
        # Description
        desc = QLabel(
            "File carving scans raw disk data for file signatures.\n"
            "This can be slow on large partitions. You can disable it\n"
            "or select only the file types you need."
        )
        desc.setStyleSheet("color: #9CA3AF; font-size: 13px; padding: 0 5px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # -- Shared checkbox style --
        # Explicit indicator styling so checkboxes are clearly visible on dark backgrounds.
        # Checked = green indicator, unchecked = dark border, disabled = dimmed out.
        checkbox_style = """
            QCheckBox {
                spacing: 8px;
                color: #D1D5DB;
                font-size: 12px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid #4B5563;
                background-color: #1E1E2E;
            }
            QCheckBox::indicator:checked {
                background-color: #10B981;
                border-color: #10B981;
            }
            QCheckBox::indicator:disabled {
                background-color: #2A2F3A;
                border-color: #333844;
            }
            QCheckBox:disabled {
                color: #4B5563;
            }
        """
        
        # Master toggle: enable/disable carving
        enable_cb = QCheckBox("Enable file carving")
        enable_cb.setChecked(True)
        enable_cb.setStyleSheet(checkbox_style + """
            QCheckBox { font-size: 14px; font-weight: bold; color: #FFFFFF; padding: 5px; }
            QCheckBox::indicator:checked { background-color: #3B82F6; border-color: #3B82F6; }
        """)
        layout.addWidget(enable_cb)
        
        # --- File type selection area ---
        # Group the supported types into categories for cleaner UI
        # DOCX, XLSX, and ZIP are listed separately so users can toggle each
        # independently. All three use the same PK\x03\x04 carving signature
        # ('zip'), but the carved files are classified by internal structure.
        type_categories = {
            "Images": ['jpg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'heic'],
            "Documents": ['pdf', 'docx', 'xlsx', 'zip'],
            "Audio": ['mp3', 'mp3_id3'],
            "Video": ['mp4', 'avi'],
            "Archives": ['7z', 'rar'],
        }
        
        # Mapping from UI type keys to the actual carver signature key.
        # DOCX/XLSX/PPTX are all ZIP archives internally, so they share
        # the 'zip' carver signature.
        UI_TYPE_TO_CARVER = {
            'docx': 'zip',
            'xlsx': 'zip',
            'pptx': 'zip',
        }
        
        # Container for type checkboxes (disabled when carving is off)
        types_container = QWidget()
        types_layout = QVBoxLayout(types_container)
        types_layout.setContentsMargins(20, 0, 0, 0)
        
        # "Select All" checkbox for convenience
        select_all_cb = QCheckBox("Select All")
        select_all_cb.setChecked(True)
        select_all_cb.setStyleSheet(checkbox_style + """
            QCheckBox { font-size: 13px; font-weight: bold; color: #3B82F6; }
        """)
        types_layout.addWidget(select_all_cb)
        
        # Create checkboxes for each category and file type
        type_checkboxes = {}  # Maps type_key -> QCheckBox
        for category, types in type_categories.items():
            cat_label = QLabel(f"  {category}:")
            cat_label.setStyleSheet("color: #9CA3AF; font-size: 12px; margin-top: 4px;")
            types_layout.addWidget(cat_label)
            
            row = QHBoxLayout()
            for t in types:
                # Clean up display name
                display = t.upper().replace('_', ' ')
                if t == 'mp3_id3':
                    display = 'MP3 (ID3)'
                cb = QCheckBox(display)
                cb.setChecked(True)
                cb.setStyleSheet(checkbox_style)
                cb.setProperty('file_type', t)  # Store the UI type key
                type_checkboxes[t] = cb
                row.addWidget(cb)
            row.addStretch()
            types_layout.addLayout(row)
        
        layout.addWidget(types_container)
        
        # --- Wiring: enable/disable carving toggles the type selection ---
        # When carving is disabled, uncheck all types and grey them out.
        # When re-enabled, re-check all types so the user starts fresh.
        def toggle_types(checked):
            types_container.setEnabled(checked)
            # Auto-check/uncheck all type boxes to match the master toggle
            select_all_cb.setChecked(checked)
            for cb in type_checkboxes.values():
                cb.setChecked(checked)
        enable_cb.toggled.connect(toggle_types)
        
        # --- Wiring: "Select All" toggles all type checkboxes ---
        def toggle_all(checked):
            for cb in type_checkboxes.values():
                cb.setChecked(checked)
        select_all_cb.toggled.connect(toggle_all)
        
        # --- Buttons ---
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        start_btn = QPushButton("Start Scan")
        start_btn.setStyleSheet("""
            QPushButton {
                background-color: #10B981;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 10px 24px;
                font-weight: 600;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #059669;
            }
        """)
        start_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(start_btn)
        layout.addLayout(btn_layout)
        
        # Show dialog (always proceeds — scan starts regardless)
        dialog.exec()
        
        # --- Read the user's choices ---
        carving_enabled = enable_cb.isChecked()
        
        if not carving_enabled:
            return (False, None)
        
        # Collect selected file types, mapping UI keys back to carver keys
        selected_types = []
        for cb in type_checkboxes.values():
            if cb.isChecked():
                ui_type = cb.property('file_type')
                carver_type = UI_TYPE_TO_CARVER.get(ui_type, ui_type)
                if carver_type not in selected_types:
                    selected_types.append(carver_type)
        
        # If all types are selected, pass None (meaning "carve everything")
        # to avoid an unnecessarily long filter list
        all_carver_types = set()
        for t in type_checkboxes.keys():
            all_carver_types.add(UI_TYPE_TO_CARVER.get(t, t))
        if set(selected_types) == all_carver_types:
            return (True, None)
        
        # If nothing selected but carving enabled, treat as disabled
        if not selected_types:
            return (False, None)
        
        return (True, selected_types)
    
    def start_scan(self, enable_carving=True, carve_file_types=None):
        """Start background scan with optional carving configuration"""
        if not self.app or not self.current_session:
            return
        
        # Pass carving options to the worker thread
        self.scan_worker = ScanWorker(
            self.app, self.current_session, self.file_filter,
            enable_carving=enable_carving,
            carve_file_types=carve_file_types
        )
        self.scan_worker.progress_updated.connect(self.update_progress)
        self.scan_worker.scan_completed.connect(self.scan_complete)
        self.scan_worker.error_occurred.connect(self.scan_error)
        self.scan_worker.start()
    
    def scan_complete(self, results):
        """Handle scan completion - update dashboard with results"""
        self.recovered_files = results.get('recovered', [])
        self.carved_files = results.get('carved', [])
        
        # Hide progress, show results in dashboard
        self.progress_container.setVisible(False)
        self.status_label.setText("Scan Complete!")
        
        # Update dashboard stats and charts
        self.update_dashboard_stats()
        
        # Refresh all data views
        self.refresh_recovered_files()
        self.refresh_timeline()
        self.refresh_integrity_view()
        self.refresh_metadata_view()
    
    def scan_error(self, error):
        """Handle scan error"""
        QMessageBox.critical(self, "Scan Error", f"Error during scan:\n{error}")
    

    def update_dashboard(self, source_path, source_type):
        """Update dashboard when a session starts (before scan completes).
        
        Sets the dashboard into a 'scanning in progress' state:
        - Hides the welcome section
        - Shows progress bar and results section
        - Populates session details with source info
        - Sets stat cards to 'scanning' placeholder
        """
        # Transition from welcome to active dashboard
        self.welcome_section.setVisible(False)
        self.progress_container.setVisible(True)
        self.results_section.setVisible(True)
        
        # Set stat cards to scanning placeholders
        self.total_card.findChild(QLabel, "value").setText("...")
        self.deleted_card.findChild(QLabel, "value").setText("...")
        self.active_card.findChild(QLabel, "value").setText("...")
        self.carved_card.findChild(QLabel, "value").setText("...")
        
        # Get filesystem type from session if available
        fs_type = "Detecting..."
        if self.current_session and self.app:
            session = self.app.sessions.get(self.current_session)
            if session and session.fs_type:
                fs_type = session.fs_type.value.upper()
        
        # Populate session info with what we know so far
        self.session_details.setText(
            f"Source: {source_path}\n"
            f"Type: {source_type}\n"
            f"Filesystem: {fs_type}\n"
            f"Session: {self.current_session[:16] if self.current_session else 'N/A'}...\n"
            f"Status: Scanning in progress..."
        )
        
        # Reset charts to empty state
        self.status_chart_container._chart_widget.set_data([])
        self.type_chart_container._chart_widget.set_data([])
        self.integrity_chart_container._chart_widget.set_data([])
    
    # View Creators
    
    def create_dashboard_view(self):
        """Create dashboard view with stats and charts"""
        view = QWidget()
        main_layout = QVBoxLayout(view)
        main_layout.setContentsMargins(30, 25, 30, 30)
        main_layout.setSpacing(20)
        
        # Title
        title = QLabel("Dashboard")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        main_layout.addWidget(title)
        
        # Scrollable content area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollBar:vertical {
                background-color: #1E1E2E;
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background-color: #3A3F4A;
                border-radius: 5px;
            }
        """)
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)
        
        # Welcome section (shown when no data)
        self.welcome_section = QWidget()
        welcome_layout = QVBoxLayout(self.welcome_section)
        welcome_text = QLabel(
            "Welcome to Meta Recover X Forensic Recovery\n\n"
            "Click '+ Attach Source...' to begin recovery from:\n"
            "• Disk Image Files (.img, .raw, .dd, .e01)\n"
            "• System Partitions (XFS/Btrfs)\n"
            "• External Drives (USB with XFS/Btrfs)"
        )
        welcome_text.setStyleSheet("color: #9CA3AF; font-size: 14px;")
        welcome_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_layout.addWidget(welcome_text)
        scroll_layout.addWidget(self.welcome_section)
        
        # Hidden filter widgets for backward compatibility
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Files (Active + Deleted)", "all")
        self.filter_combo.hide()
        
        # Create dummy filter widgets (hidden) to prevent AttributeError
        self.source_filter = QComboBox()
        self.source_filter.addItem("📁 All Sources", "all")
        self.source_filter.hide()
        
        self.status_filter = QComboBox()
        self.status_filter.addItem("📊 All Status", "all")
        self.status_filter.hide()
        
        self.type_filter = QComboBox()
        self.type_filter.addItem("📄 All Types", "all")
        self.type_filter.hide()
        
        self.show_duplicates_check = QCheckBox()
        self.show_duplicates_check.hide()
        
        
        # Progress Section
        self.progress_container = QWidget()
        progress_layout = QVBoxLayout(self.progress_container)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #FFFFFF; font-weight: bold; font-size: 14px;")
        progress_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #2A2F3A;
                border-radius: 5px;
                text-align: center;
                background-color: #1E1E2E;
                color: white;
                min-height: 25px;
            }
            QProgressBar::chunk {
                background-color: #3B82F6;
            }
        """)
        self.progress_bar.setTextVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        self.progress_container.setVisible(False)
        scroll_layout.addWidget(self.progress_container)
        
        # Results Section (hidden until scan completes)
        self.results_section = QWidget()
        self.results_section.setVisible(False)
        results_layout = QVBoxLayout(self.results_section)
        results_layout.setSpacing(20)
        
        # --- Stats Cards Row ---
        stats_row = QWidget()
        stats_layout = QHBoxLayout(stats_row)
        stats_layout.setSpacing(15)
        
        # Total Files Card
        self.total_card = self._create_stat_card("Total Files", "0", "#3B82F6", "fa5s.folder-open")
        stats_layout.addWidget(self.total_card)
        
        # Likely Deleted Files Card (was Deleted Files)
        self.deleted_card = self._create_stat_card("Likely Deleted", "0", "#EF4444", "fa5s.trash")
        stats_layout.addWidget(self.deleted_card)
        
        # Duplicates Card (was Active Files) - shows carved files matching active
        self.active_card = self._create_stat_card("Duplicates", "0", "#6B7280", "fa5s.copy")
        stats_layout.addWidget(self.active_card)
        
        # Carved Files Card
        self.carved_card = self._create_stat_card("Carved Files", "0", "#F59E0B", "fa5s.search")
        stats_layout.addWidget(self.carved_card)
        
        results_layout.addWidget(stats_row)
        
        # --- Charts Row ---
        charts_row = QWidget()
        charts_layout = QHBoxLayout(charts_row)
        charts_layout.setSpacing(20)
        
        # File Status Chart (Pie)
        self.status_chart_container = self._create_chart_card("File Status Distribution")
        charts_layout.addWidget(self.status_chart_container)
        
        # File Type Chart (Pie)
        self.type_chart_container = self._create_chart_card("File Types Breakdown")
        charts_layout.addWidget(self.type_chart_container)
        
        # Integrity Verification Chart (Pie)
        self.integrity_chart_container = self._create_chart_card("Integrity Verification")
        charts_layout.addWidget(self.integrity_chart_container)
        
        results_layout.addWidget(charts_row)
        
        # --- Session Info Section ---
        session_info = QFrame()
        session_info.setStyleSheet("""
            QFrame {
                background-color: #1E1E2E;
                border: 1px solid #2A2F3A;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        session_layout = QVBoxLayout(session_info)
        
        session_title = QLabel("Session Information")
        session_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        session_title.setStyleSheet("color: #FFFFFF; border: none;")
        session_layout.addWidget(session_title)
        
        self.session_details = QLabel("No active session")
        self.session_details.setStyleSheet("color: #9CA3AF; font-size: 12px; border: none;")
        self.session_details.setWordWrap(True)
        session_layout.addWidget(self.session_details)
        
        results_layout.addWidget(session_info)
        
        scroll_layout.addWidget(self.results_section)
        scroll_layout.addStretch()
        
        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)
        
        return view
    
    def _create_stat_card(self, title, value, color, icon_name):
        """Create a statistics card widget"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #1E1E2E;
                border: 1px solid #2A2F3A;
                border-radius: 12px;
                border-left: 4px solid {color};
            }}
        """)
        card.setMinimumWidth(180)
        card.setMinimumHeight(100)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #9CA3AF; font-size: 12px; font-weight: bold;")
        layout.addWidget(title_label)
        
        # Value
        value_label = QLabel(value)
        value_label.setObjectName("value")
        value_label.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        layout.addWidget(value_label)
        
        return card
    
    def _create_chart_card(self, title):
        """Create a chart container card with QTextEdit for HTML charts"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #1E1E2E;
                border: 1px solid #2A2F3A;
                border-radius: 12px;
            }
        """)
        card.setMinimumHeight(300)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Title
        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #FFFFFF; border: none;")
        layout.addWidget(title_label)
        
        # QPainter-based chart widget
        chart_widget = BarChartWidget()
        chart_widget.setMinimumHeight(230)
        layout.addWidget(chart_widget)
        
        # Store reference for easy access
        card._chart_widget = chart_widget
        
        return card
    
    def update_dashboard_stats(self):
        """Update dashboard with current scan results"""
        # Hide welcome, show results
        self.welcome_section.setVisible(False)
        self.results_section.setVisible(True)
        
        # Get session data
        session = None
        all_files = []
        filtered_files = []
        
        if self.current_session and self.app:
            session = self.app.sessions.get(self.current_session)
            if session:
                all_files = session.all_files or []
                filtered_files = session.filtered_files or all_files
        
        # Calculate stats from session data
        carved_count = sum(1 for f in all_files if f.get('source') == 'carved')
        metadata_count = sum(1 for f in all_files if f.get('source') == 'metadata')
        likely_deleted = sum(1 for f in all_files if f.get('status') == 'likely_deleted' or f.get('deleted'))
        duplicates = sum(1 for f in all_files if f.get('is_duplicate', False))
        
        # Legacy stats for backward compatibility
        deleted_count = sum(1 for f in self.recovered_files if f.get('status') == 'deleted' or f.get('deleted'))
        active_count = sum(1 for f in self.recovered_files if f.get('status') == 'active')
        total_recovered = len(all_files) if all_files else len(self.recovered_files) + len(self.carved_files)
        
        # Calculate integrity stats
        verified_count = sum(1 for f in self.recovered_files if f.get('integrity_status') == 'verified')
        corrupted_count = sum(1 for f in self.recovered_files if f.get('integrity_status') == 'corrupted')
        unverified_count = sum(1 for f in self.recovered_files if f.get('integrity_status') == 'unverified')
        no_checksum_count = sum(1 for f in self.recovered_files if f.get('integrity_status') == 'no_checksum')
        
        # Update stat cards with new categorization
        self.total_card.findChild(QLabel, "value").setText(str(total_recovered))
        self.deleted_card.findChild(QLabel, "value").setText(str(likely_deleted))
        self.active_card.findChild(QLabel, "value").setText(str(duplicates))
        self.carved_card.findChild(QLabel, "value").setText(str(carved_count))
        
        # Update session details with filter info
        total_size = sum(f.get('size', 0) for f in all_files)
        self.session_details.setText(
            f"Session ID: {self.current_session[:16] if self.current_session else 'N/A'}...\n"
            f"Showing: {len(filtered_files)}/{len(all_files)} files\n"
            f"Total Size: {format_bytes(total_size)}\n"
            f"Carved: {carved_count} | Metadata: {metadata_count}"
        )
        
        # Update charts
        self._update_status_chart(likely_deleted, duplicates, carved_count - duplicates - likely_deleted)
        self._update_type_chart()
        self._update_integrity_chart(verified_count, corrupted_count, unverified_count, no_checksum_count)
    

    
    def _update_status_chart(self, deleted, active, carved):
        """Update the file status chart"""
        chart = self.status_chart_container._chart_widget
        items = []
        if deleted > 0:
            items.append(("Likely Deleted", deleted, "#EF4444"))
        if active > 0:
            items.append(("Duplicates", active, "#22C55E"))
        if carved > 0:
            items.append(("Carved (unique)", carved, "#F59E0B"))
        chart.set_data(items)
    
    def _update_type_chart(self):
        """Update the file type distribution chart"""
        chart = self.type_chart_container._chart_widget
        all_files = self.recovered_files + self.carved_files
        type_counts = Counter(f.get('type', 'unknown') for f in all_files)
        
        type_colors = {
            'jpg': '#3B82F6', 'jpeg': '#3B82F6', 'png': '#8B5CF6',
            'pdf': '#EC4899', 'zip': '#14B8A6', 'docx': '#F59E0B',
            'mp4': '#6366F1', 'mp3': '#A855F7', 'txt': '#06B6D4',
        }
        fallback_colors = ['#3B82F6', '#8B5CF6', '#EC4899', '#14B8A6', '#F59E0B', '#6366F1', '#9CA3AF']
        
        items = []
        for idx, (ftype, count) in enumerate(type_counts.most_common(7)):
            color = type_colors.get(ftype, fallback_colors[idx % len(fallback_colors)])
            items.append((ftype.upper(), count, color))
        chart.set_data(items)
    
    def _update_integrity_chart(self, verified, corrupted, unverified, no_checksum):
        """Update the integrity verification chart"""
        chart = self.integrity_chart_container._chart_widget
        items = []
        if verified > 0:
            items.append(("Verified", verified, "#22C55E"))
        if corrupted > 0:
            items.append(("Corrupted", corrupted, "#EF4444"))
        if unverified > 0:
            items.append(("Unverified", unverified, "#F59E0B"))
        if no_checksum > 0:
            items.append(("No Checksum", no_checksum, "#6B7280"))
        chart.set_data(items)
    
    def _get_combo_style(self):
        """Return consistent combo box styling"""
        return """
            QComboBox {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 6px;
                padding: 8px 15px;
                min-width: 150px;
                font-size: 13px;
            }
            QComboBox:hover {
                border-color: #3B82F6;
            }
            QComboBox::drop-down {
                border: none;
                padding-right: 10px;
            }
            QComboBox QAbstractItemView {
                background-color: #2A2F3A;
                color: #FFFFFF;
                selection-background-color: #3B82F6;
                border: 1px solid #3A3F4A;
            }
        """
    
    def on_filter_changed(self, index):
        """Handle legacy filter selection change"""
        self.file_filter = self.filter_combo.currentData()

    def on_dynamic_filter_changed(self):
        """Handle dynamic filter changes - applies filters without re-scanning"""
        if not self.current_session or not self.app:
            return
        
        # Get current filter values
        source = self.source_filter.currentData()
        status = self.status_filter.currentData()
        file_type = self.type_filter.currentData()
        show_duplicates = self.show_duplicates_check.isChecked()
        
        # Apply filters through app
        try:
            filtered_files = self.app.apply_filters(
                self.current_session,
                source=source,
                status=status,
                file_type=file_type,
                show_duplicates=show_duplicates
            )
            
            # Refresh the file table with filtered results
            self.refresh_recovered_files_from_filtered()
            
            # Update dashboard stats
            self.update_dashboard_stats()
            
        except Exception as e:
            self.logger.error(f"Filter error: {e}")
    
    def refresh_recovered_files_from_filtered(self):
        """Refresh file table using session.filtered_files"""
        if not self.current_session:
            return
        
        session = self.app.sessions.get(self.current_session)
        if not session:
            return
        
        # Use filtered files if available, otherwise all files
        files = session.filtered_files if session.filtered_files else session.all_files
        
        self.file_table.blockSignals(True)
        self.file_table.setRowCount(0)
        
        for file_info in files:
            row = self.file_table.rowCount()
            self.file_table.insertRow(row)
            
            # Name
            name = file_info.get('name', 'Unknown')
            name_item = QTableWidgetItem(name)
            self.file_table.setItem(row, 0, name_item)
            
            # Size
            size = file_info.get('size', 0)
            size_str = self._format_size(size)
            size_item = QTableWidgetItem(size_str)
            self.file_table.setItem(row, 1, size_item)
            
            # Type
            file_type = file_info.get('type', '')
            type_item = QTableWidgetItem(file_type.upper() if file_type else 'Unknown')
            self.file_table.setItem(row, 2, type_item)
            
            # Source (new column)
            source = file_info.get('source', 'unknown')
            if source == 'carved':
                source_text = "🔍 Carved"
                source_color = "#F59E0B"
            else:
                source_text = "📋 Metadata"
                source_color = "#3B82F6"
            source_item = QTableWidgetItem(source_text)
            source_item.setForeground(QColor(source_color))
            self.file_table.setItem(row, 3, source_item)
            
            # Status (new column)
            status = file_info.get('status', 'unknown')
            if file_info.get('deleted', False):
                status_text = "🗑️ Deleted"
                status_color = "#EF4444"
            elif file_info.get('is_duplicate', False):
                status_text = "📋 Active (Dup)"
                status_color = "#6B7280"
            elif status == 'likely_deleted':
                status_text = "❓ Likely Deleted"
                status_color = "#F59E0B"
            elif status == 'active':
                status_text = "✅ Active"
                status_color = "#22C55E"
            else:
                status_text = "❓ Unknown"
                status_color = "#9CA3AF"
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(QColor(status_color))
            self.file_table.setItem(row, 4, status_item)
        
        self.file_table.blockSignals(False)
        # Update row count label
        if hasattr(self, 'file_count_label'):
            total = len(session.all_files) if session.all_files else 0
            shown = len(files)
            self.file_count_label.setText(f"Showing {shown} of {total} files")
    
    def _format_size(self, size_bytes):
        """Format file size for display"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def update_progress(self, percent, message):
        """Update progress bar"""
        self.progress_container.setVisible(True)
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)

    
    def create_recovered_files_view(self):
        """Create recovered files view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        
        title = QLabel("Recovered Files")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        # Search bar
        search = QLineEdit()
        search.setPlaceholderText("Search files...")
        search.setStyleSheet("""
            QLineEdit {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 8px;
                padding: 10px;
                font-size: 13px;
            }
        """)
        search.textChanged.connect(self.filter_files)
        layout.addWidget(search)
        
        # Table - Updated columns for source/status display
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(5)
        self.file_table.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Source', 'Status'])
        self.file_table.horizontalHeader().setStretchLastSection(True)
        self.file_table.setStyleSheet("""
            QTableWidget {
                background-color: #1E1E2E;
                color: #FFFFFF;
                gridline-color: #2A2F3A;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #2A2F3A;
                color: #FFFFFF;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #3B82F6;
            }
        """)
        layout.addWidget(self.file_table)
        
        return view
    
    def refresh_recovered_files(self):
        """Refresh recovered files table"""
        all_files = self.recovered_files + self.carved_files
        self.file_table.blockSignals(True)
        self.file_table.setRowCount(len(all_files))
        
        for i, f in enumerate(all_files):
            # Column 0: Name
            self.file_table.setItem(i, 0, QTableWidgetItem(f.get('name', '')))
            
            # Column 1: Size
            self.file_table.setItem(i, 1, QTableWidgetItem(format_bytes(f.get('size', 0))))
            
            # Column 2: Type
            self.file_table.setItem(i, 2, QTableWidgetItem(f.get('type', '').upper()))
            
            # Column 3: Source (recovered vs carved)
            status = f.get('status', 'unknown')
            if status == 'carved':
                source_text = '🔍 Carved'
            elif status == 'deleted':
                source_text = '🗑️ Deleted'
            elif status == 'active':
                source_text = '✅ Active'
            else:
                source_text = status.capitalize()
            source_item = QTableWidgetItem(source_text)
            self.file_table.setItem(i, 3, source_item)
            
            # Column 4: Status (integrity)
            integrity = f.get('integrity_status', 'unverified')
            if integrity == 'verified':
                integrity_item = QTableWidgetItem('✓ VERIFIED')
                integrity_item.setForeground(QColor('#22C55E'))
            elif integrity == 'corrupted':
                integrity_item = QTableWidgetItem('✗ CORRUPTED')
                integrity_item.setForeground(QColor('#EF4444'))
            elif integrity == 'unverified':
                integrity_item = QTableWidgetItem('? UNVERIFIED')
                integrity_item.setForeground(QColor('#F59E0B'))
            else:
                integrity_item = QTableWidgetItem('- N/A')
                integrity_item.setForeground(QColor('#6B7280'))
            self.file_table.setItem(i, 4, integrity_item)
        self.file_table.blockSignals(False)
    
    def filter_files(self, text):
        """Filter files table"""
        for i in range(self.file_table.rowCount()):
            show = True
            if text:
                show = any(
                    text.lower() in (self.file_table.item(i, j).text().lower() if self.file_table.item(i, j) else '')
                    for j in range(self.file_table.columnCount())
                )
            self.file_table.setRowHidden(i, not show)
    
    def create_timeline_view(self):
        """Create timeline view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        
        title = QLabel("File Timeline")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        subtitle = QLabel("Temporal analysis of file activity based on timestamps")
        subtitle.setStyleSheet("color: #9CA3AF; margin-bottom: 10px;")
        layout.addWidget(subtitle)
        
        self.timeline_text = QTextEdit()
        self.timeline_text.setReadOnly(True)
        self.timeline_text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E2E;
                color: #FFFFFF;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
                padding: 15px;
                font-family: 'Courier New';
            }
        """)
        layout.addWidget(self.timeline_text)
        
        return view
    
    def refresh_timeline(self):
        """Refresh timeline with real recovered/carved file data"""
        all_files = self.recovered_files + self.carved_files
        
        if not all_files:
            self.timeline_text.setHtml(
                "<p style='color:#9CA3AF; text-align:center; padding-top:40px; font-size:15px;'>"
                "No file data available.<br/>Run a scan first to see the timeline.</p>"
            )
            return
        
        # Sort by modified timestamp (newest first)
        sorted_files = sorted(all_files, key=lambda x: x.get('modified', ''), reverse=True)
        
        # Summary stats
        total_size = sum(f.get('size', 0) for f in all_files)
        type_set = set(f.get('type', '?') for f in all_files)
        
        html = f"""
        <h3 style='color: #3B82F6; margin-bottom: 4px;'>File Activity Timeline</h3>
        <p style='color: #9CA3AF; margin-bottom: 12px;'>
            {len(all_files)} files &nbsp;|&nbsp; {len(type_set)} types &nbsp;|&nbsp; {format_bytes(total_size)} total
        </p>
        """
        
        for f in sorted_files:
            name = f.get('name', 'Unknown')
            ftype = f.get('type', '?').upper()
            size = f.get('size', 0)
            modified = f.get('modified', 'Unknown')
            status = f.get('status', 'unknown')
            
            # Status icon and color
            if status == 'carved':
                icon = '🔍'
                status_label = 'Carved'
                border_color = '#F59E0B'
            elif status == 'deleted':
                icon = '🗑️'
                status_label = 'Deleted'
                border_color = '#EF4444'
            elif status == 'active':
                icon = '✅'
                status_label = 'Active'
                border_color = '#22C55E'
            else:
                icon = '📄'
                status_label = status.capitalize()
                border_color = '#6B7280'
            
            # Format size
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1048576:
                size_str = f"{size/1024:.1f} KB"
            else:
                size_str = f"{size/1048576:.1f} MB"
            
            html += f"""
            <div style='margin: 6px 0; padding: 10px 12px; background-color: #2A2F3A;
                        border-radius: 8px; border-left: 3px solid {border_color};'>
                <div>
                    <span style='color: #3B82F6; font-size: 12px;'>{modified}</span>
                    <span style='color: {border_color}; float: right; font-size: 11px;'>{icon} {status_label}</span>
                </div>
                <div style='margin-top: 4px;'>
                    <span style='color: #FFFFFF; font-size: 13px;'>{name}</span>
                    <span style='color:#6B7280; font-size:11px; margin-left:8px;
                           background:#1E1E2E; padding:2px 6px; border-radius:4px;'>{ftype}</span>
                    <span style='color: #9CA3AF; font-size: 12px; float: right;'>{size_str}</span>
                </div>
            </div>
            """
        
        self.timeline_text.setHtml(html)
    
    def create_keyword_search_view(self):
        """Create keyword search view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        
        title = QLabel("Keyword Search")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        # Search input row: text field + search button
        search_layout = QHBoxLayout()
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("Enter keywords (comma-separated)")
        self.keyword_input.setStyleSheet("""
            QLineEdit {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
            }
        """)
        search_layout.addWidget(self.keyword_input)
        
        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self.perform_keyword_search)
        search_btn.setStyleSheet("""
            QPushButton {
                background-color: #3B82F6;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)
        
        # Options row: checkbox to toggle content search on/off
        # This lets users choose between a fast filename-only search
        # and a deeper (but slower) content-based search
        options_layout = QHBoxLayout()
        self.search_content_checkbox = QCheckBox("Search file contents (not just filenames)")
        self.search_content_checkbox.setChecked(True)  # Content search enabled by default
        self.search_content_checkbox.setStyleSheet("color: #9CA3AF; font-size: 13px;")
        options_layout.addWidget(self.search_content_checkbox)
        options_layout.addStretch()
        layout.addLayout(options_layout)
        
        # Results area: displays search matches as styled HTML
        self.search_results = QTextEdit()
        self.search_results.setReadOnly(True)
        self.search_results.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E2E;
                color: #FFFFFF;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        self.search_results.setHtml("<p style='color: #9CA3AF;'>Enter keywords and click Search...<br/><br/>"
                                    "<b>Tip:</b> Enable 'Search file contents' to find keywords "
                                    "inside recovered text files (e.g., 'password', 'confidential').</p>")
        layout.addWidget(self.search_results)
        
        return view
    
    def perform_keyword_search(self):
        """
        Perform keyword search across recovered files.
        
        Uses the centralized app.keyword_search() method which searches both
        filenames and file contents. Falls back to a local filename-only search
        if the backend or session is not available (e.g., demo mode).
        """
        keywords = self.keyword_input.text().strip()
        if not keywords:
            return
        
        # Split comma-separated keywords and clean whitespace
        keyword_list = [k.strip() for k in keywords.split(',') if k.strip()]
        
        # Check whether the user wants content search (from the checkbox)
        search_content = self.search_content_checkbox.isChecked()
        
        # --- Try using the backend's keyword_search method ---
        # This gives us filename + content matching with line numbers
        if self.app and self.current_session and BACKEND_AVAILABLE:
            try:
                results = self.app.keyword_search(
                    self.current_session,
                    keyword_list,
                    case_sensitive=False,
                    search_content=search_content
                )
                self._display_search_results(keywords, results, search_content)
                return
            except Exception as e:
                # If backend search fails, fall through to local fallback
                self.search_results.setHtml(
                    f"<p style='color: #EF4444;'>Search error: {str(e)}</p>"
                )
                return
        
        # --- Fallback: local filename-only search (no session / demo mode) ---
        # This preserves the original behaviour for when no backend is connected
        all_files = self.recovered_files + self.carved_files
        fallback_results = []
        for f in all_files:
            filename = f.get('name', '').lower()
            matched = [kw for kw in keyword_list if kw.lower() in filename]
            if matched:
                fallback_results.append({
                    'name': f.get('name', 'Unknown'),
                    'path': f.get('path', ''),
                    'size': f.get('size', 0),
                    'type': f.get('type', 'unknown'),
                    'match_type': 'filename',
                    'matched_keywords': matched,
                    'content_matches': [],
                })
        self._display_search_results(keywords, fallback_results, search_content=False)
    
    def _display_search_results(self, query: str, results: list, search_content: bool):
        """
        Render keyword search results as styled HTML in the search_results widget.
        
        Each result card shows:
        - The filename, file type, and size
        - The match type icon (📄 filename, 📝 content, or 📄📝 both)
        - Which keywords matched
        - For content matches: the line number and a snippet of the matching line
        
        Args:
            query: The original search query string (for display)
            results: List of match dicts from app.keyword_search()
            search_content: Whether content search was enabled (for the summary)
        """
        # -- Header section --
        mode_label = "filenames + contents" if search_content else "filenames only"
        html = f"<h3 style='color: #3B82F6;'>Search Results: {query}</h3>"
        html += f"<p style='color: #9CA3AF;'>Mode: {mode_label} | "
        html += f"Found <b>{len(results)}</b> matching file(s)</p><br/>"
        
        if not results:
            html += "<p style='color: #9CA3AF;'>No matches found. Try different keywords.</p>"
            self.search_results.setHtml(html)
            return
        
        # -- Render each matched file as a styled card --
        for result in results:
            # Choose an icon based on match type to make it visually scannable
            match_type = result.get('match_type', 'filename')
            if match_type == 'both':
                type_icon = "📄📝"  # Matched in both filename and content
                type_label = "Filename + Content"
                type_color = "#A78BFA"  # Purple for dual match
            elif match_type == 'content':
                type_icon = "📝"  # Matched only in content
                type_label = "Content Match"
                type_color = "#F59E0B"  # Amber for content
            else:
                type_icon = "📄"  # Matched only in filename
                type_label = "Filename Match"
                type_color = "#10B981"  # Green for filename
            
            # File size formatted for display
            size = result.get('size', 0)
            size_str = format_bytes(size)
            
            # List of matched keywords as styled tags
            matched_kws = ', '.join(result.get('matched_keywords', []))
            
            # Build the card HTML
            html += f"""
            <div style='margin: 10px 0; padding: 12px; background-color: #2A2F3A; 
                        border-radius: 8px; border-left: 4px solid {type_color};'>
                <div style='margin-bottom: 6px;'>
                    <span style='font-size: 14px;'>{type_icon}</span>
                    <span style='color: #FFFFFF; font-weight: bold; font-size: 14px;'>
                        {result.get('name', 'Unknown')}
                    </span>
                    <span style='color: {type_color}; font-size: 12px; margin-left: 8px;'>
                        [{type_label}]
                    </span>
                </div>
                <div style='color: #9CA3AF; font-size: 12px; margin-bottom: 4px;'>
                    Type: {result.get('type', 'unknown').upper()} | Size: {size_str} | 
                    Keywords: <span style='color: #F59E0B;'>{matched_kws}</span>
                </div>
            """
            
            # -- Content match snippets --
            # Show up to 5 content matches per file to avoid overwhelming output.
            # Each snippet shows line number and the matching line text.
            content_matches = result.get('content_matches', [])
            if content_matches:
                # Cap displayed snippets at 5 per file
                display_matches = content_matches[:5]
                remaining = len(content_matches) - 5
                
                html += "<div style='margin-top: 8px; padding: 8px; background-color: #1E1E2E; border-radius: 6px;'>"
                html += "<div style='color: #9CA3AF; font-size: 11px; margin-bottom: 4px;'>Content matches:</div>"
                
                for cm in display_matches:
                    line_num = cm.get('line_number', '?')
                    line_text = cm.get('line_text', '')
                    # Escape HTML special characters in the snippet to
                    # prevent broken rendering from file content
                    line_text = (line_text.replace('&', '&amp;')
                                         .replace('<', '&lt;')
                                         .replace('>', '&gt;'))
                    html += f"""
                    <div style='margin: 3px 0; font-family: monospace; font-size: 12px;'>
                        <span style='color: #6B7280;'>Line {line_num}:</span>
                        <span style='color: #D1D5DB;'>{line_text}</span>
                    </div>
                    """
                
                # If there were more matches, indicate how many were omitted
                if remaining > 0:
                    html += f"<div style='color: #6B7280; font-size: 11px; margin-top: 4px;'>... and {remaining} more match(es)</div>"
                
                html += "</div>"
            
            html += "</div>"  # Close the card div
        
        # -- Footer summary --
        total_content_hits = sum(len(r.get('content_matches', [])) for r in results)
        html += f"<br/><p style='color: #FFFFFF;'>"
        html += f"<strong>Summary:</strong> {len(results)} file(s) matched"
        if total_content_hits > 0:
            html += f" with {total_content_hits} content hit(s)"
        html += "</p>"
        
        self.search_results.setHtml(html)
    
    def create_integrity_view(self):
        """Create integrity verification view with per-file hash table"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        layout.setSpacing(15)
        
        title = QLabel("File Integrity Verification")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        # Summary section
        self.integrity_summary = QLabel("No files scanned yet. Attach a source and run a scan to see integrity results.")
        self.integrity_summary.setWordWrap(True)
        self.integrity_summary.setStyleSheet("""
            QLabel {
                color: #9CA3AF;
                background-color: #1E1E2E;
                border: 1px solid #2A2F3A;
                border-radius: 10px;
                padding: 18px;
                font-size: 13px;
            }
        """)
        layout.addWidget(self.integrity_summary)
        
        # Per-file integrity table
        self.integrity_table = QTableWidget()
        self.integrity_table.setColumnCount(4)
        self.integrity_table.setHorizontalHeaderLabels(['File Name', 'SHA-256 Hash', 'Status', 'Details'])
        self.integrity_table.horizontalHeader().setStretchLastSection(True)
        self.integrity_table.horizontalHeader().setSectionResizeMode(0, self.integrity_table.horizontalHeader().ResizeMode.Interactive)
        self.integrity_table.horizontalHeader().setSectionResizeMode(1, self.integrity_table.horizontalHeader().ResizeMode.Stretch)
        self.integrity_table.setColumnWidth(0, 220)
        self.integrity_table.setColumnWidth(2, 110)
        self.integrity_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.integrity_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.integrity_table.setAlternatingRowColors(True)
        self.integrity_table.setStyleSheet("""
            QTableWidget {
                background-color: #1E1E2E;
                alternate-background-color: #232333;
                color: #FFFFFF;
                gridline-color: #2A2F3A;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #2A2F3A;
                color: #FFFFFF;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 6px;
            }
            QTableWidget::item:selected {
                background-color: #3B82F6;
            }
        """)
        layout.addWidget(self.integrity_table)
        
        return view
    
    def refresh_integrity_view(self):
        """Refresh integrity table with real per-file hash and verification data"""
        all_files = self.recovered_files + self.carved_files
        
        if not all_files:
            self.integrity_summary.setText("No files scanned yet. Attach a source and run a scan to see integrity results.")
            self.integrity_table.setRowCount(0)
            return
        
        # Count statuses
        counts = {'verified': 0, 'corrupted': 0, 'unverified': 0, 'no_checksum': 0}
        for f in all_files:
            status = f.get('integrity_status', 'unverified')
            counts[status] = counts.get(status, 0) + 1
        
        total = len(all_files)
        summary_parts = [
            f"<b style='color:#FFFFFF;'>Total Files:</b> {total}",
            f"&nbsp;&nbsp;│&nbsp;&nbsp;<b style='color:#FFFFFF;'>Algorithm:</b> SHA-256",
        ]
        status_parts = []
        if counts['verified']:
            status_parts.append(f"<span style='color:#10B981;'>✓ {counts['verified']} Verified</span>")
        if counts['corrupted']:
            status_parts.append(f"<span style='color:#EF4444;'>✗ {counts['corrupted']} Corrupted</span>")
        if counts['unverified']:
            status_parts.append(f"<span style='color:#F59E0B;'>? {counts['unverified']} Unverified</span>")
        if counts['no_checksum']:
            status_parts.append(f"<span style='color:#6B7280;'>— {counts['no_checksum']} No Checksum</span>")
        
        summary_html = " &nbsp;│&nbsp; ".join(summary_parts)
        summary_html += "<br/>" + " &nbsp;&nbsp;│&nbsp;&nbsp; ".join(status_parts)
        self.integrity_summary.setText(summary_html)
        self.integrity_summary.setTextFormat(Qt.TextFormat.RichText)
        
        # Populate table
        self.integrity_table.setRowCount(total)
        for i, f in enumerate(all_files):
            # File name
            self.integrity_table.setItem(i, 0, QTableWidgetItem(f.get('name', 'unknown')))
            
            # SHA-256 hash
            file_hash = f.get('hash', '')
            hash_item = QTableWidgetItem(file_hash if file_hash else '—')
            hash_item.setFont(QFont("Consolas", 9))
            hash_item.setForeground(QColor("#9CA3AF"))
            self.integrity_table.setItem(i, 1, hash_item)
            
            # Status with color
            status = f.get('integrity_status', 'unverified')
            status_map = {
                'verified':    ('✓ Verified',    '#10B981'),
                'corrupted':   ('✗ Corrupted',   '#EF4444'),
                'unverified':  ('? Unverified',  '#F59E0B'),
                'no_checksum': ('— No Checksum', '#6B7280'),
            }
            label, color = status_map.get(status, ('? Unknown', '#6B7280'))
            status_item = QTableWidgetItem(label)
            status_item.setForeground(QColor(color))
            status_item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            self.integrity_table.setItem(i, 2, status_item)
            
            # Details
            details = f.get('integrity_details', '')
            self.integrity_table.setItem(i, 3, QTableWidgetItem(details if details else '—'))
    
    def create_metadata_view(self):
        """Create metadata view with file list and detail panel"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(5)
        
        title = QLabel("Metadata Extraction")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        title.setFixedHeight(30)
        layout.addWidget(title)
        
        # Summary label
        self.metadata_summary = QLabel("No files scanned yet. Attach a source and run a scan to see metadata.")
        self.metadata_summary.setWordWrap(True)
        self.metadata_summary.setStyleSheet("""
            QLabel {
                color: #9CA3AF;
                background-color: #1E1E2E;
                border: 1px solid #2A2F3A;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 13px;
            }
        """)
        self.metadata_summary.setFixedHeight(40)
        layout.addWidget(self.metadata_summary)
        
        # Split pane: file list (left) + detail (right)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: file list
        self.metadata_file_list = QTableWidget()
        self.metadata_file_list.setColumnCount(3)
        self.metadata_file_list.setHorizontalHeaderLabels(['File Name', 'Size', 'Type'])
        self.metadata_file_list.horizontalHeader().setStretchLastSection(True)
        self.metadata_file_list.setColumnWidth(0, 250)
        self.metadata_file_list.setColumnWidth(1, 90)
        self.metadata_file_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.metadata_file_list.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.metadata_file_list.setAlternatingRowColors(True)
        self.metadata_file_list.setStyleSheet("""
            QTableWidget {
                background-color: #1E1E2E;
                alternate-background-color: #232333;
                color: #FFFFFF;
                gridline-color: #2A2F3A;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #2A2F3A;
                color: #FFFFFF;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 6px;
            }
            QTableWidget::item:selected {
                background-color: #3B82F6;
            }
        """)
        self.metadata_file_list.currentCellChanged.connect(self.on_metadata_file_selected)
        splitter.addWidget(self.metadata_file_list)
        
        # Right: metadata detail
        self.metadata_detail = QTextEdit()
        self.metadata_detail.setReadOnly(True)
        self.metadata_detail.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E2E;
                color: #FFFFFF;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
                padding: 15px;
                font-size: 13px;
            }
        """)
        self.metadata_detail.setHtml("<p style='color:#6B7280;'>Select a file from the list to view its extracted metadata.</p>")
        splitter.addWidget(self.metadata_detail)
        
        splitter.setSizes([400, 600])
        splitter.setStyleSheet("QSplitter::handle { background-color: #2A2F3A; width: 2px; }")
        layout.addWidget(splitter)
        
        # Initialize extractor
        self.metadata_extractor = MetadataExtractor() if BACKEND_AVAILABLE else None
        
        return view
    
    def refresh_metadata_view(self):
        """Populate the metadata file list from recovered/carved files"""
        all_files = self.recovered_files + self.carved_files
        
        if not all_files:
            self.metadata_summary.setText("No files scanned yet. Attach a source and run a scan to see metadata.")
            self.metadata_file_list.setRowCount(0)
            self.metadata_detail.setHtml("<p style='color:#6B7280;'>No files available.</p>")
            return
        
        total = len(all_files)
        self.metadata_summary.setText(f"<b style='color:#FFFFFF;'>Files Available:</b> {total} &nbsp;│&nbsp; <span style='color:#9CA3AF;'>Select a file to extract and view its embedded metadata (EXIF, PDF info, Office properties, timestamps, etc.)</span>")
        self.metadata_summary.setTextFormat(Qt.TextFormat.RichText)
        
        self.metadata_file_list.setRowCount(total)
        for i, f in enumerate(all_files):
            self.metadata_file_list.setItem(i, 0, QTableWidgetItem(f.get('name', 'unknown')))
            self.metadata_file_list.setItem(i, 1, QTableWidgetItem(self._format_size(f.get('size', 0))))
            self.metadata_file_list.setItem(i, 2, QTableWidgetItem(f.get('type', 'unknown')))
        
        self.metadata_detail.setHtml("<p style='color:#6B7280;'>Select a file from the list to view its extracted metadata.</p>")
    
    def on_metadata_file_selected(self, row, col=0, prev_row=0, prev_col=0):
        """Handle file selection in metadata view — extract and display metadata"""
        if row < 0:
            return
        
        all_files = self.recovered_files + self.carved_files
        if row >= len(all_files):
            return
        
        file_info = all_files[row]
        file_path = file_info.get('path', '')
        file_name = file_info.get('name', 'unknown')
        
        ROW = "<tr><td style='padding:5px 10px; color:#9CA3AF; width:160px; vertical-align:top;'><b>{}</b></td><td style='padding:5px 10px;'>{}</td></tr>"
        SECTION = "<br/><h4 style='color:{}; margin-bottom:6px;'>{}</h4>"
        TABLE_OPEN = "<table style='color:#D1D5DB; width:100%; border-collapse:collapse;'>"
        TABLE_CLOSE = "</table>"
        
        html = []
        html.append(f"<h3 style='color:#3B82F6; margin-bottom:2px;'>{file_name}</h3>")
        html.append("<hr style='border-color:#2A2F3A;'/>")
        
        # ── Section 1: File Identity ──
        html.append(SECTION.format('#FFFFFF', '🏷️ File Identity'))
        html.append(TABLE_OPEN)
        html.append(ROW.format('File Name', file_name))
        html.append(ROW.format('File Size', self._format_size(file_info.get('size', 0))))
        html.append(ROW.format('File Size (bytes)', f"{file_info.get('size', 0):,} bytes"))
        html.append(ROW.format('File Extension', file_info.get('type', '—')))
        
        # MIME type detection
        import mimetypes
        mime_type, _ = mimetypes.guess_type(file_name)
        html.append(ROW.format('MIME Type', mime_type or 'application/octet-stream'))
        
        # File magic bytes (first 16 bytes as hex)
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, 'rb') as f:
                    magic = f.read(16)
                hex_str = ' '.join(f'{b:02X}' for b in magic)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in magic)
                html.append(ROW.format('Magic Bytes', f"<code style='color:#F59E0B;'>{hex_str}</code>"))
                html.append(ROW.format('ASCII Preview', f"<code>{ascii_str}</code>"))
            except Exception:
                pass
        
        html.append(ROW.format('SHA-256 Hash', f"<code style='font-size:11px;'>{file_info.get('hash', '—')}</code>"))
        html.append(TABLE_CLOSE)
        
        # ── Section 2: Recovery Details ──
        html.append(SECTION.format('#FFFFFF', '🔧 Recovery Details'))
        html.append(TABLE_OPEN)
        source = file_info.get('source', 'recovered' if 'inode' in file_info else 'carved')
        source_display = f"<span style='color:{'#10B981' if source == 'recovered' else '#F59E0B'};'>{'📂 Filesystem Recovery' if source == 'recovered' else '🔪 File Carving'}</span>"
        html.append(ROW.format('Recovery Source', source_display))
        
        status = file_info.get('status', '—')
        if status == 'deleted':
            status_display = "<span style='color:#EF4444;'>🗑️ Deleted</span>"
        elif status == 'active':
            status_display = "<span style='color:#10B981;'>✓ Active</span>"
        else:
            status_display = f"<span style='color:#F59E0B;'>{status}</span>"
        html.append(ROW.format('File Status', status_display))
        
        # Carving-specific fields
        if file_info.get('offset') is not None:
            offset_val = file_info['offset']
            html.append(ROW.format('Disk Offset', f"0x{offset_val:X} ({offset_val:,} bytes)"))
        if file_info.get('is_duplicate') is not None:
            dup_str = "Yes — duplicate of active file" if file_info['is_duplicate'] else "No"
            html.append(ROW.format('Duplicate', dup_str))
        
        # Recovery-specific fields
        if file_info.get('inode'):
            html.append(ROW.format('Inode', str(file_info['inode'])))
        if file_info.get('nlink') is not None:
            html.append(ROW.format('Hard Links', str(file_info['nlink'])))
        if file_info.get('extents') is not None:
            html.append(ROW.format('Data Extents', str(file_info['extents'])))
        if file_info.get('original_name'):
            html.append(ROW.format('Original Name', file_info['original_name']))
        
        # Integrity
        integrity = file_info.get('integrity_status', '—')
        integrity_map = {
            'verified': ('✓ Verified', '#10B981'),
            'corrupted': ('✗ Corrupted', '#EF4444'),
            'unverified': ('? Unverified', '#F59E0B'),
            'no_checksum': ('— No Checksum', '#6B7280'),
        }
        ilabel, icolor = integrity_map.get(integrity, (integrity, '#6B7280'))
        html.append(ROW.format('Integrity', f"<span style='color:{icolor};'>{ilabel}</span>"))
        if file_info.get('integrity_details'):
            html.append(ROW.format('Integrity Detail', file_info['integrity_details']))
        
        html.append(TABLE_CLOSE)
        
        # ── Section 3: Filesystem Metadata (if available) ──
        has_fs_meta = any(file_info.get(k) for k in ('mode', 'uid', 'gid', 'modified', 'accessed', 'changed'))
        if has_fs_meta:
            html.append(SECTION.format('#FFFFFF', '📁 Filesystem Metadata'))
            html.append(TABLE_OPEN)
            if file_info.get('mode'):
                html.append(ROW.format('Permissions', file_info['mode']))
            if file_info.get('uid') is not None:
                html.append(ROW.format('Owner (UID)', str(file_info['uid'])))
            if file_info.get('gid') is not None:
                html.append(ROW.format('Group (GID)', str(file_info['gid'])))
            if file_info.get('modified'):
                html.append(ROW.format('Modified', file_info['modified']))
            if file_info.get('accessed'):
                html.append(ROW.format('Accessed', file_info['accessed']))
            if file_info.get('changed'):
                html.append(ROW.format('Changed', file_info['changed']))
            html.append(TABLE_CLOSE)
        
        # ── Section 4: OS-level file stats ──
        if file_path and os.path.exists(file_path):
            try:
                stat = os.stat(file_path)
                html.append(SECTION.format('#FFFFFF', '💾 On-Disk File Info'))
                html.append(TABLE_OPEN)
                html.append(ROW.format('Saved Path', f"<code style='font-size:11px;'>{file_path}</code>"))
                html.append(ROW.format('Disk Size', self._format_size(stat.st_size)))
                html.append(ROW.format('Last Modified', datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')))
                html.append(ROW.format('Last Accessed', datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')))
                html.append(TABLE_CLOSE)
            except Exception:
                pass
        
        # ── Section 5: Embedded Metadata (from MetadataExtractor) ──
        if self.metadata_extractor and file_path and os.path.exists(file_path):
            try:
                embedded = self.metadata_extractor.extract(file_path)
                if embedded:
                    # Flatten nested dicts for display
                    flat = {}
                    skip_keys = {'file_path', 'file_name', 'file_size', 'error'}
                    for key, value in embedded.items():
                        if key in skip_keys:
                            continue
                        if isinstance(value, dict):
                            for sub_key, sub_val in value.items():
                                nice_key = sub_key.replace('_', ' ').title()
                                flat[nice_key] = sub_val
                        elif value is not None:
                            nice_key = key.replace('_', ' ').title()
                            flat[nice_key] = value
                    
                    if flat:
                        html.append(SECTION.format('#FFFFFF', '🔍 Embedded Metadata'))
                        html.append(TABLE_OPEN)
                        for key, value in flat.items():
                            display_val = str(value)
                            if len(display_val) > 300:
                                display_val = display_val[:300] + '…'
                            html.append(ROW.format(key, display_val))
                        html.append(TABLE_CLOSE)
                    else:
                        html.append(SECTION.format('#6B7280', '🔍 Embedded Metadata'))
                        html.append("<p style='color:#6B7280;'>No embedded metadata found in this file type.</p>")
            except Exception as e:
                html.append(f"<br/><p style='color:#EF4444;'>Error extracting metadata: {e}</p>")
        elif not file_path or not os.path.exists(file_path):
            html.append("<br/><p style='color:#6B7280;'>File not found on disk — cannot extract embedded metadata.</p>")
        
        self.metadata_detail.setHtml("".join(html))
    
    def create_report_view(self):
        """Create report generator view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        layout.setSpacing(20)
        
        title = QLabel("Forensic Report Generator")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        subtitle = QLabel("Generate comprehensive forensic reports for legal or corporate use")
        subtitle.setStyleSheet("color: #9CA3AF; font-size: 13px;")
        layout.addWidget(subtitle)
        
        # Options frame
        options_frame = QFrame()
        options_frame.setStyleSheet("""
            QFrame {
                background-color: #1E1E2E;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        options_layout = QVBoxLayout(options_frame)
        
        # Format selection
        format_label = QLabel("Report Format:")
        format_label.setStyleSheet("color: #FFFFFF; font-weight: bold; margin-bottom: 5px;")
        options_layout.addWidget(format_label)
        
        self.report_format = QComboBox()
        self.report_format.addItems(["PDF (Recommended)", "CSV (Data Export)", "JSON (Machine Readable)"])
        self.report_format.setStyleSheet("""
            QComboBox {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 8px;
                padding: 10px;
                font-size: 13px;
            }
        """)
        options_layout.addWidget(self.report_format)
        
        options_layout.addSpacing(15)
        
        # Options
        options_label = QLabel("Report Options:")
        options_label.setStyleSheet("color: #FFFFFF; font-weight: bold; margin-bottom: 5px;")
        options_layout.addWidget(options_label)
        
        self.include_images_cb = QCheckBox("Include file previews (PDF only)")
        self.include_images_cb.setChecked(True)
        self.include_images_cb.setStyleSheet("color: #FFFFFF; font-size: 13px;")
        options_layout.addWidget(self.include_images_cb)
        
        self.include_timeline_cb = QCheckBox("Include timeline visualization")
        self.include_timeline_cb.setChecked(True)
        self.include_timeline_cb.setStyleSheet("color: #FFFFFF; font-size: 13px;")
        options_layout.addWidget(self.include_timeline_cb)
        
        self.include_hashes_cb = QCheckBox("Include integrity hashes")
        self.include_hashes_cb.setChecked(True)
        self.include_hashes_cb.setStyleSheet("color: #FFFFFF; font-size: 13px;")
        options_layout.addWidget(self.include_hashes_cb)
        
        options_layout.addSpacing(20)
        
        # Generate button
        gen_btn = QPushButton("Generate Report")
        gen_btn.clicked.connect(self.generate_report)
        gen_btn.setStyleSheet("""
            QPushButton {
                background-color: #3B82F6;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 15px;
                font-size: 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        options_layout.addWidget(gen_btn)
        
        layout.addWidget(options_frame)
        
        # Info
        info_label = QLabel("Report Contents:")
        info_label.setStyleSheet("color: #FFFFFF; font-weight: bold; margin-top: 20px;")
        layout.addWidget(info_label)
        
        info_text = QLabel(
            "✓ Executive summary\n"
            "✓ Complete file inventory\n"
            "✓ Metadata and timestamps\n"
            "✓ Integrity verification hashes\n"
            "✓ Timeline visualization\n"
            "✓ Keyword search results\n"
            "✓ Chain of custody log"
        )
        info_text.setStyleSheet("color: #9CA3AF; font-size: 13px;")
        layout.addWidget(info_text)
        
        layout.addStretch()
        return view
    
    def generate_report(self):
        """Generate forensic report"""
        if not self.current_session:
            QMessageBox.warning(
                self, "No Session",
                "No active recovery session.\n\nPlease attach a source first."
            )
            return
        
        format_text = self.report_format.currentText()
        if "PDF" in format_text:
            report_format = "pdf"
        elif "CSV" in format_text:
            report_format = "csv"
        else:
            report_format = "json"
        
        try:
            if not self.app or not BACKEND_AVAILABLE:
                QMessageBox.warning(
                    self, "Backend Unavailable",
                    "Cannot generate report without a backend connection."
                )
                return
            
            report_path = self.app.generate_report(self.current_session, format=report_format)
            
            QMessageBox.information(
                self, "Report Generated",
                f"Forensic report generated successfully!\n\n"
                f"Format: {report_format.upper()}\n"
                f"Location: {report_path}\n\n"
                f"The report includes all selected options."
            )
        except Exception as e:
            QMessageBox.critical(
                self, "Error",
                f"Failed to generate report:\n{str(e)}"
            )


def apply_global_stylesheet(app):
    """Apply dark theme"""
    app.setStyle("Fusion")
    
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(22, 22, 30))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Base, QColor(30, 30, 46))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(42, 47, 58))
    palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Button, QColor(42, 47, 58))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Link, QColor(59, 130, 246))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(59, 130, 246))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    
    app.setPalette(palette)


def main():
    """Main entry point"""
    # Don't run with sudo warning
    if check_root_permissions():
        print("\n" + "="*60)
        print("⚠️  WARNING: Running with elevated permissions (sudo/root)")
        print("="*60)
        print("\nThis can cause issues with:")
        print("• GUI display (DBus errors)")
        print("• File permissions")
        print("• Security risks")
        print("\nRecommendation:")
        print("• Run as normal user: python run.py --gui")
        print("• App will request permissions when needed")
        print("="*60 + "\n")
        
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            print("Exiting...")
            sys.exit(0)
    
    app = QApplication(sys.argv)
    
    app.setApplicationName("Unearth")
    app.setOrganizationName("Unearth Forensics")
    
    apply_global_stylesheet(app)
    
    window = UnearthGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()