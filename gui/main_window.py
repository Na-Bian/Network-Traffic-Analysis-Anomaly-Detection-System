# gui/main_window.py
import json
import os
import shutil

from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWebEngineCore import QWebEngineSettings
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import *

from .html_helper import get_theme_colors, generate_placeholder_html, replace_cdn_with_local
from .tabs.anomaly_tabs import AnomalyTab
from .tabs.custom_rule_tab import CustomRuleTab
from .tabs.flow_sort_tab import FlowSortTab
from .tabs.path_tab import PathTab
from .tabs.subgraph_tab import SubgraphTab
from .task_handler import TaskHandler
from .translator import tr, lang_mgr
from .utils import resource_path, TempDirManager
from .worker import SubgraphWorker, PcapConvertWorker


class AdaptiveTabWidget(QTabWidget):
    """自适应大小的选项卡"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.currentChanged.connect(self.updateGeometry)

    def minimumSizeHint(self) -> QSize:
        if self.currentWidget() is not None:
            return self.currentWidget().minimumSizeHint()
        return super().minimumSizeHint()

    def sizeHint(self) -> QSize:
        if self.currentWidget() is not None:
            return self.currentWidget().sizeHint()
        return super().sizeHint()


def _generate_manual_theme_style(is_dark: bool) -> str:
    """根据深色/浅色模式生成手册的 CSS 覆盖样式"""
    if is_dark:
        return """
        <style>
            body {
                background-color: #1e1e1e !important;
                color: #e0e0e0 !important;
            }
            .container {
                background-color: #2d2d2d !important;
                box-shadow: 0 10px 30px rgba(0,0,0,0.5) !important;
            }
            .feature-card {
                background-color: #3c3c3c !important;
                border-color: #555 !important;
            }
            .feature-card .feature-title {
                color: #ffffff !important;
            }
            .feature-card p {
                color: #cccccc !important;
            }
            h1, h2, h3 {
                color: #ffffff !important;
            }
            .subhead, .subtitle {
                color: #aaaaaa !important;
            }
            table, th, td {
                border-color: #555 !important;
            }
            th {
                background-color: #3a3a3a !important;
            }
            td {
                background-color: #2d2d2d !important;
            }
            tr:nth-child(even) {
                background-color: #333333 !important;
            }
            code {
                background-color: #3c3c3c !important;
                color: #f08d49 !important;
                border-color: #666 !important;
            }
            .note, .tip, .warning {
                background-color: #3c3c3c !important;
                color: #e0e0e0 !important;
            }
            .note {
                border-left-color: #f9c74f !important;
            }
            .tip {
                border-left-color: #38bdf8 !important;
            }
            .warning {
                border-left-color: #f44336 !important;
            }
            a {
                color: #58a6ff !important;
            }
            .version {
                background-color: #3c3c3c !important;
                color: #aaaaaa !important;
            }
            .footer {
                color: #888888 !important;
            }
            ::-webkit-scrollbar {
                width: 8px;
                height: 8px;
                background-color: transparent;
            }
            ::-webkit-scrollbar-track {
                background: transparent;
                border-radius: 4px;
            }
            ::-webkit-scrollbar-thumb {
                background: rgba(255, 255, 255, 0.3);
                border-radius: 4px;
            }
            ::-webkit-scrollbar-thumb:hover {
                background: rgba(255, 255, 255, 0.5);
            }
            ::-webkit-scrollbar-thumb:active {
                background: rgba(255, 255, 255, 0.7);
            }
        </style>
        """
    else:
        return """
        <style>
            ::-webkit-scrollbar {
                width: 8px;
                height: 8px;
                background-color: transparent;
            }
            ::-webkit-scrollbar-track {
                background: transparent;
                border-radius: 4px;
            }
            ::-webkit-scrollbar-thumb {
                background: rgba(0, 0, 0, 0.2);
                border-radius: 4px;
            }
            ::-webkit-scrollbar-thumb:hover {
                background: rgba(0, 0, 0, 0.4);
            }
            ::-webkit-scrollbar-thumb:active {
                background: rgba(0, 0, 0, 0.6);
            }
        </style>
        """


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.web_view = None
        self.setWindowTitle(tr("app_title", "网络流量分析与异常检测系统"))
        self.resize(1280, 800)

        self.temp_manager = TempDirManager()
        self.data_file = None
        self.current_html = None
        self.has_graph = False
        self.is_data_available = False

        self.view_only_mode = False  # 只读模式

        self.full_graph_json_path = None
        self.full_graph_html_path = None
        self.current_json_path = None
        self.original_pcap_path = None
        self.converted_csv_path = None

        self.current_html_original_path = None  # 当前显示子图的原始HTML
        self.current_html_display_path = None  # 当前显示子图的显示HTML，将CDN替换为本地资源

        # 导出 actions
        self.export_pcap_csv_action = None
        self.export_full_graph_json_action = None
        self.export_full_graph_html_action = None
        self.export_subgraph_json_action = None
        self.export_subgraph_html_action = None

        self.task_handler = TaskHandler(self)  # 任务处理器

        self.init_ui()
        self.update_webview_theme(tr("waiting_data", "等待分析数据..."))
        QApplication.instance().paletteChanged.connect(self.on_palette_changed)
        lang_mgr.language_changed.connect(self.retranslate_ui)

    def set_view_only_mode(self, enabled: bool):
        """设置只读模式，启用/禁用所有功能按钮和输入控件"""
        self.view_only_mode = enabled

        # 递归禁用/启用所有子控件
        def set_children_enabled(widget: QWidget, enable: bool):
            widget.setEnabled(enable)
            for child in widget.findChildren(QWidget):
                set_children_enabled(child, enable)

        # 需要禁用/启用的顶层选项卡
        tabs_to_disable = [
            self.flow_sort_tab,
            self.path_tab,
            self.anomaly_tab,
            self.subgraph_tab,
            self.custom_rule_tab,
        ]

        enable_state = not enabled  # 控件是否可用（enabled=True时控件禁用，enable_state=False）

        for tab in tabs_to_disable:
            set_children_enabled(tab, enable_state)

        # 确保文件选择控件始终可用
        self.file_edit.setEnabled(True)
        self.browse_btn.setEnabled(True)

    def prepare_html_for_display(self, original_html_path):
        """为HTML文件注入主题样式，返回显示用的临时文件路径"""
        # 如果文件名已经包含 _display，说明已经是显示版本，直接返回
        if "_display." in os.path.basename(original_html_path):
            return original_html_path

        bgcolor, fontcolor = get_theme_colors()
        base, ext = os.path.splitext(os.path.basename(original_html_path))
        display_html_path = self.temp_manager.get_path(f"{base}_display{ext}")
        try:
            shutil.copy2(original_html_path, display_html_path)
            # 注入样式并替换CDN
            replace_cdn_with_local(display_html_path, bgcolor, fontcolor,
                                   log_callback=lambda msg: self.log_text.append(msg))
        except Exception as e:
            self.log_text.append(tr("prepare_html_failed", "准备HTML显示文件失败: {}").format(e))
            return original_html_path  # 失败时回退到原文件
        return display_html_path

    def retranslate_ui(self):
        """语言切换时更新界面文本"""
        self.setWindowTitle(tr("app_title", "网络流量分析与异常检测系统"))
        self.settings_menu.setTitle(tr("settings", "设置"))
        self.lang_menu.setTitle(tr("language", "语言 / Language"))
        self.action_zh_cn.setText(tr("lang_zh_CN", "简体中文"))
        self.action_zh_tw.setText(tr("lang_zh_TW", "繁体中文"))
        self.action_en.setText(tr("lang_en_US", "English"))
        self.thread_label.setText(tr("thread_count", "线程数:"))

        if not self.is_data_available:
            self.update_webview_theme(tr("waiting_data", "等待分析数据..."))

        QMessageBox.information(self, tr("info", "提示"),
                                tr("restart_required", "语言切换成功，部分界面可能需要重启生效。"))

    def init_ui(self):
        """初始化所有UI组件"""
        menubar = self.menuBar()

        # 文件菜单
        file_menu = menubar.addMenu(tr("file", "文件"))
        open_action = QAction(tr("open_file", "打开数据文件"), self)
        open_action.triggered.connect(self.browse_file)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        export_menu = file_menu.addMenu(tr("export_menu", "导出"))

        self.export_pcap_csv_action = QAction(tr("export_pcap_csv", "PCAP转换的CSV"), self)
        self.export_pcap_csv_action.triggered.connect(self.export_pcap_csv)
        export_menu.addAction(self.export_pcap_csv_action)

        full_graph_menu = export_menu.addMenu(tr("task_full_graph", "全网拓扑"))
        self.export_full_graph_json_action = QAction("JSON", self)
        self.export_full_graph_json_action.triggered.connect(lambda: self.export_graph("full", "json"))
        full_graph_menu.addAction(self.export_full_graph_json_action)
        self.export_full_graph_html_action = QAction("HTML", self)
        self.export_full_graph_html_action.triggered.connect(lambda: self.export_graph("full", "html"))
        full_graph_menu.addAction(self.export_full_graph_html_action)

        subgraph_menu = export_menu.addMenu(tr("export_current_subgraph", "当前子图"))
        self.export_subgraph_json_action = QAction("JSON", self)
        self.export_subgraph_json_action.triggered.connect(lambda: self.export_graph("current", "json"))
        subgraph_menu.addAction(self.export_subgraph_json_action)
        self.export_subgraph_html_action = QAction("HTML", self)
        self.export_subgraph_html_action.triggered.connect(lambda: self.export_graph("current", "html"))
        subgraph_menu.addAction(self.export_subgraph_html_action)

        # 初始时禁用所有导出动作，直到数据加载
        self.update_export_actions()

        # 设置菜单
        self.settings_menu = menubar.addMenu(tr("settings", "设置"))
        thread_widget = QWidget()
        thread_layout = QHBoxLayout(thread_widget)
        thread_layout.setContentsMargins(0, 0, 0, 0)
        self.thread_label = QLabel(tr("thread_count", "线程数:"))
        thread_layout.addWidget(self.thread_label)
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 4 if os.cpu_count() >= 4 else os.cpu_count())  # 默认使用4线程
        self.thread_spin.setValue(os.cpu_count())
        thread_layout.addWidget(self.thread_spin)
        thread_layout.addStretch()
        thread_action = QWidgetAction(self)
        thread_action.setDefaultWidget(thread_widget)
        self.settings_menu.addAction(thread_action)
        self.settings_menu.addSeparator()

        # 语言子菜单
        self.lang_menu = self.settings_menu.addMenu(tr("language", "语言 / Language"))
        self.action_zh_cn = QAction(tr("lang_zh_CN", "简体中文"), self)
        self.action_zh_cn.triggered.connect(lambda: lang_mgr.set_language("zh_CN"))
        self.lang_menu.addAction(self.action_zh_cn)
        self.action_zh_tw = QAction(tr("lang_zh_TW", "繁体中文"), self)
        self.action_zh_tw.triggered.connect(lambda: lang_mgr.set_language("zh_TW"))
        self.lang_menu.addAction(self.action_zh_tw)
        self.action_en = QAction(tr("lang_en_US", "English"), self)
        self.action_en.triggered.connect(lambda: lang_mgr.set_language("en_US"))
        self.lang_menu.addAction(self.action_en)

        # 帮助菜单
        help_menu = menubar.addMenu(tr("help", "帮助"))
        manual_action = QAction(tr("help_manual", "用户手册"), self)
        manual_action.triggered.connect(self.show_manual)
        about_action = QAction(tr("about", "关于"), self)
        about_action.triggered.connect(self.about)
        help_menu.addAction(manual_action)
        help_menu.addAction(about_action)

        # 中央部件
        central = QWidget()
        self.setCentralWidget(central)
        self.main_layout = QVBoxLayout(central)
        self.main_layout.setSpacing(5)
        self.main_layout.setContentsMargins(5, 5, 5, 5)

        # 文件选择行
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel(tr("data_file", "数据文件:")))
        self.file_edit = QLineEdit()
        self.file_edit.setReadOnly(True)
        file_layout.addWidget(self.file_edit)
        self.browse_btn = QPushButton(tr("browse", "浏览..."))
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)
        file_layout.addStretch()
        self.main_layout.addLayout(file_layout)

        # 主分割器
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_splitter.setChildrenCollapsible(False)

        self.left_splitter = QSplitter(Qt.Orientation.Vertical)
        self.left_splitter.setChildrenCollapsible(False)

        # 创建各个选项卡并添加到tabs
        self.tabs = AdaptiveTabWidget()
        self.flow_sort_tab = FlowSortTab()
        self.path_tab = PathTab()
        self.anomaly_tab = AnomalyTab()
        self.subgraph_tab = SubgraphTab()
        self.custom_rule_tab = CustomRuleTab()

        self.tabs.addTab(self.flow_sort_tab, tr("traffic_sorting", "流量排序"))
        self.tabs.addTab(self.path_tab, tr("path_search", "路径查找"))
        self.tabs.addTab(self.anomaly_tab, tr("anomaly_detection", "异常检测"))
        self.tabs.addTab(self.custom_rule_tab, tr("anomaly_tab_custom_rule", "自定义规则"))
        self.tabs.addTab(self.subgraph_tab, tr("subgraph_visualization", "子图可视化"))

        self.left_splitter.addWidget(self.tabs)
        self.tabs.setMinimumHeight(180)
        self.tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Ignored)

        # 输出选项卡
        self.output_tabs = QTabWidget()
        self.left_splitter.addWidget(self.output_tabs)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("font-family: Consolas, monospace; font-size: 12px;")
        self.output_tabs.addTab(self.log_text, tr("output_log_tab", "⚙️ 运行日志"))

        self.result_table = QTableWidget()
        self.result_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.result_table.horizontalHeader().setStretchLastSection(True)
        self.output_tabs.addTab(self.result_table, tr("output_table_tab", "📊 数据表格"))

        self.result_detail = QTextBrowser()
        self.result_detail.setStyleSheet("font-family: Consolas, monospace; font-size: 13px;")
        self.output_tabs.addTab(self.result_detail, tr("output_detail_tab", "🗺️ 路径与详情"))

        self.left_splitter.setSizes([140, 460])
        self.main_splitter.addWidget(self.left_splitter)

        # Web视图
        self.web_view = QWebEngineView()
        settings = self.web_view.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, True)
        self.main_splitter.addWidget(self.web_view)

        self.main_splitter.setSizes([390, 890])
        self.main_layout.addWidget(self.main_splitter, 1)

        # 连接按钮信号
        self.flow_sort_tab.flow_sort_btn.clicked.connect(self.run_flow_sort)
        self.path_tab.path_btn.clicked.connect(self.run_path_searching)
        self.anomaly_tab.port_scan_tab.detect_btn.clicked.connect(self.run_port_scan)
        self.anomaly_tab.ddos_tab.detect_btn.clicked.connect(self.run_ddos_detection)
        self.anomaly_tab.star_tab.detect_btn.clicked.connect(self.run_star_detection)
        self.subgraph_tab.generate_btn.clicked.connect(self.generate_subgraph)
        self.custom_rule_tab.detect_btn.clicked.connect(self.run_custom_rule)

        self.update_log_detail_theme()

    def update_export_actions(self):
        # PCAP导出可用：仅当有原始pcap且转换后的csv存在
        has_pcap = self.original_pcap_path is not None and os.path.exists(self.converted_csv_path)
        self.export_pcap_csv_action.setEnabled(has_pcap)

        # 全网拓扑导出可用：full_graph_json_path 或 full_graph_html_path 存在
        has_full = self.full_graph_json_path is not None or self.full_graph_html_path is not None
        self.export_full_graph_json_action.setEnabled(has_full and self.full_graph_json_path is not None)
        self.export_full_graph_html_action.setEnabled(has_full and self.full_graph_html_path is not None)

        # 当前子图导出可用：current_json_path 或 current_html_original_path 存在
        has_current = self.current_json_path is not None or self.current_html_original_path is not None
        self.export_subgraph_json_action.setEnabled(has_current and self.current_json_path is not None)
        self.export_subgraph_html_action.setEnabled(has_current and self.current_html_original_path is not None)

    # ---------- 文件操作 ----------
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            tr("open_file_dialog_title", "选择数据文件"),
            "",
            tr("file_filter",
               "支持的文件 (*.csv *.pcap *.json *.html);;CSV (*.csv);;PCAP (*.pcap);;JSON (*.json);;HTML (*.html)")
        )
        if file_path:
            self.load_file(file_path)

    def _convert_to_utf8_if_needed(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                f.read(1024)
            return file_path
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='gbk') as f:
                content = f.read()
            new_path = self.temp_manager.get_path(os.path.basename(file_path) + "_utf8.csv")
            with open(new_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return new_path

    def load_file(self, file_path):
        # 先退出任何可能的仅查看模式（但下面会根据文件类型重新设置）
        self.set_view_only_mode(False)

        # 检查文件是否为空
        if os.path.getsize(file_path) == 0:
            QMessageBox.warning(
                self,
                tr("invalid_data", "数据无效"),
                tr("empty_file", "选择的文件为空，无法加载！")
            )
            self.is_data_available = False
            return

        ext = os.path.splitext(file_path)[1].lower()

        # ---------- 处理 JSON/HTML 可视化文件 ----------
        if ext in ['.json', '.html']:
            # 进入仅查看模式，禁用分析按钮
            self.set_view_only_mode(True)

            # 清除数据文件相关状态
            self.data_file = None
            self.file_edit.clear()
            self.log_text.clear()
            self.result_table.clear()
            self.result_table.setRowCount(0)
            self.result_table.setColumnCount(0)
            self.result_detail.clear()
            self.has_graph = False
            self.is_data_available = False
            self.original_pcap_path = None
            self.converted_csv_path = None

            # 新增：清除之前分析模式产生的全网拓扑文件记录
            self.full_graph_json_path = None
            self.full_graph_html_path = None

            if ext == '.json':
                # 生成 HTML 并显示
                html_path = self.temp_manager.get_path(os.path.basename(file_path) + ".html")
                self.generate_html(file_path, html_path)
            else:  # .html
                display_html_path = self.prepare_html_for_display(file_path)
                self.display_html(display_html_path)
                self.current_html_original_path = file_path  # 原始文件路径不变
                self.current_json_path = None
                self.update_export_actions()

            self.log_text.append(tr("visual_file_loaded", "已加载可视化文件: {}").format(file_path))
            return

        # ---------- 原有 CSV/PCAP 处理（分析模式） ----------
        if ext == '.csv':
            new_path = self._convert_to_utf8_if_needed(file_path)
            if not os.path.exists(new_path) or os.path.getsize(new_path) == 0:
                QMessageBox.warning(
                    self,
                    tr("invalid_data", "数据无效"),
                    tr("encoding_conversion_failed", "文件编码转换失败，无法加载！")
                )
                return

            # 判断当前 CSV 是否来自 PCAP 转换
            if self.original_pcap_path is None:
                # 直接打开的 CSV，清除 PCAP 相关记录
                self.original_pcap_path = None
                self.converted_csv_path = None
            # 如果 original_pcap_path 不为空，说明是从 PCAP 转换而来，保留原有记录

            file_path = new_path

        # 通用数据文件设置（仅对分析模式有效）
        self.data_file = file_path
        self.file_edit.setText(file_path)
        self.log_text.clear()
        self.result_table.clear()
        self.result_table.setRowCount(0)
        self.result_table.setColumnCount(0)
        self.result_detail.clear()
        self.has_graph = False
        self.is_data_available = False
        self.update_webview_theme(tr("analyzing_data", "正在分析数据，请稍候..."))
        self.log_text.append(tr("loaded_file", "已加载文件: {}").format(file_path))

        if ext == '.pcap':
            self.convert_pcap(file_path)
        else:  # .csv
            self.show_full_graph()

    def convert_pcap(self, pcap_path):
        self.update_webview_theme(tr("parsing_pcap", "正在解析 PCAP 文件，请稍候..."))
        csv_path = self.temp_manager.get_path("converted.csv")
        self.pcap_worker = PcapConvertWorker(pcap_path, csv_path)

        def on_pcap_converted(csv_path):
            # 设置 PCAP 原始路径和转换后的 CSV 路径
            self.original_pcap_path = pcap_path
            self.converted_csv_path = csv_path
            # 加载转换后的 CSV
            self.load_file(csv_path)

        self.pcap_worker.success.connect(on_pcap_converted)
        self.pcap_worker.error.connect(
            lambda e: [
                QMessageBox.critical(
                    self,
                    tr("error", "错误"),
                    e
                ),
                setattr(self, 'is_data_available', False)
            ]
        )
        self.pcap_worker.start()

    def export_pcap_csv(self):
        if not self.original_pcap_path or not self.converted_csv_path or not os.path.exists(self.converted_csv_path):
            QMessageBox.warning(self, tr("export_error", "导出错误"),
                                tr("no_pcap_converted_data", "没有可用的PCAP转换数据，请先加载PCAP文件并完成转换。"))
            return
        # 构建默认文件名
        base = os.path.splitext(os.path.basename(self.original_pcap_path))[0]
        default_name = f"{base}_converted.csv"
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            tr("save_csv_file", "保存CSV文件"),
            default_name,
            tr("csv_files", "CSV文件 (*.csv)")
        )
        if save_path:
            try:
                shutil.copy2(self.converted_csv_path, save_path)
                QMessageBox.information(self, tr("export_success", "导出成功"),
                                        tr("file_saved_to", "文件已保存到: {}").format(save_path))
            except Exception as e:
                QMessageBox.critical(self, tr("export_error", "导出错误"),
                                     tr("save_failed", "保存失败: {}").format(e))

    def export_graph(self, which, fmt):
        if which == "full":
            json_path = self.full_graph_json_path
            html_path = self.full_graph_html_path  # 原始HTML路径
            base_name = "full_graph"
        elif which == "current":
            json_path = self.current_json_path
            html_path = self.current_html_original_path  # 原始HTML路径
            base_name = "subgraph"
        else:
            return

        src_path = json_path if fmt == "json" else html_path
        if not src_path or not os.path.exists(src_path):
            QMessageBox.warning(self, tr("export_error", "导出错误"),
                                tr("file_not_available", "要导出的文件不可用，请先生成对应图。"))
            return

        ext = "." + fmt
        default_name = f"{base_name}{ext}"
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            tr("save_file", "保存文件"),
            default_name,
            tr("{}_files", "{}文件 (*{})").format(fmt.upper(), ext)
        )
        if save_path:
            try:
                shutil.copy2(src_path, save_path)
                QMessageBox.information(self, tr("export_success", "导出成功"),
                                        tr("file_saved_to", "文件已保存到: {}").format(save_path))
            except Exception as e:
                QMessageBox.critical(self, tr("export_error", "导出错误"),
                                     tr("save_failed", "保存失败: {}").format(e))

    def show_full_graph(self):
        json_path = self.temp_manager.get_path("full_graph.json")
        html_path = self.temp_manager.get_path("full_graph.html")
        self.full_graph_json_path = json_path
        self.full_graph_html_path = html_path
        cmd = [
            resource_path("backend/NetworkAnalyzerCore.exe"),
            "--input", self.data_file,
            "--task", "full-graph",
            "--output-json", json_path,
            "--threads", str(self.thread_spin.value())
        ]

        def on_success_wrapper():
            self.generate_html(json_path, html_path)
            try:
                if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
                    with open(json_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    nodes = data.get('nodes', [])
                    self.is_data_available = len(nodes) > 0
            except Exception as e:
                self.is_data_available = False
                self.log_text.append(tr("data_validity_check_failed", "检查数据有效性失败: {}").format(e))

        self.task_handler.run_worker(cmd, task_type="full-graph", on_success=on_success_wrapper)

    # ---------- HTML生成与显示 ----------
    def generate_html(self, json_path, html_path):
        if not os.path.exists(json_path) or os.path.getsize(json_path) == 0:
            self.log_text.append(tr("generate_html_json_invalid", "错误：JSON 文件无效或未能成功生成。"))
            self.update_webview_theme(tr("generate_html_theme_invalid", "无法生成图表（JSON 文件无效）"))
            return
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            nodes = data.get('nodes', [])
            if len(nodes) == 0:
                self.log_text.append(tr("generate_html_no_nodes", "图中无任何节点，可能是数据文件中未包含有效 IP 地址。"))
                self.update_webview_theme(tr("generate_html_theme_no_data", "图中无数据"))
                return
        except Exception as e:
            self.log_text.append(tr("generate_html_read_failed", "读取 JSON 文件失败: {}").format(e))
            self.update_webview_theme(tr("generate_html_parse_failed", "解析 JSON 失败"))
            return

        bgcolor, fontcolor = get_theme_colors()
        self.log_text.append(tr("generate_html_rendering", "正在渲染图表，请稍候..."))

        self.subgraph_worker = SubgraphWorker(json_path, html_path, bgcolor, fontcolor)

        def on_render_success(generated_html_path):
            try:
                # generated_html_path 是原始HTML（CDN版本）
                # 生成显示用的HTML文件（替换CDN为本地资源）
                base, ext = os.path.splitext(generated_html_path)
                display_html_path = base + "_display" + ext
                # 复制原始文件到显示文件，然后替换
                shutil.copy2(generated_html_path, display_html_path)
                replace_cdn_with_local(display_html_path, bgcolor, fontcolor,
                                       log_callback=lambda msg: self.log_text.append(msg))
                # 加载显示文件
                self.display_html(display_html_path)
                self.log_text.append(tr("generate_html_success", "图表渲染完成！"))
                # 记录路径
                self.current_json_path = json_path
                self.current_html_original_path = generated_html_path
                self.current_html_display_path = display_html_path
                self.update_export_actions()
            except Exception as e:
                self.log_text.append(tr("generate_html_load_failed", "加载 HTML 失败: {}").format(e))

        self.subgraph_worker.success.connect(on_render_success)
        self.subgraph_worker.error.connect(lambda e: self.log_text.append(e))
        self.subgraph_worker.start()

    def display_html(self, html_file):
        if not os.path.exists(html_file):
            self.log_text.append(tr("display_html_file_not_exist", "错误：HTML 文件不存在 - {}").format(html_file))
            return
        try:
            url = QUrl.fromLocalFile(os.path.abspath(html_file))
            self.web_view.setUrl(url)
            self.has_graph = True
            self.log_text.append(tr("display_html_success", "子图已加载……"))
        except Exception as e:
            self.log_text.append(
                tr("display_html_failed_try_browser", "加载 HTML 失败: {}，正在使用系统浏览器打开").format(e))
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(html_file)))
            self.log_text.append(tr("display_html_opened_in_browser", "子图已在系统浏览器中打开"))

    def update_webview_theme(self, message=tr("waiting_data_loading", "等待数据加载...")):
        if self.has_graph:
            return
        bgcolor, text_color = get_theme_colors()
        html = generate_placeholder_html(message, bgcolor, text_color)
        self.web_view.setHtml(html)

    def on_palette_changed(self):
        self.update_webview_theme()
        self.update_log_detail_theme()

    def update_log_detail_theme(self):
        bg_color, text_color = get_theme_colors()
        border_color = "#444444" if bg_color == "#222222" else "#cccccc"
        header_bg = "#3a3a3a" if bg_color == "#222222" else "#e0e0e0"
        alt_bg = "#333333" if bg_color == "#222222" else "#f8f8f8"

        # 运行日志
        self.log_text.setStyleSheet(f"""
            QTextEdit {{    
                background-color: {bg_color}; color: {text_color}; border: 1px solid {border_color};
                font-family: Consolas, monospace; font-size: 12px;
            }}
            QTextEdit::selection {{ background-color: #4a6cf7; color: white; }}
        """)

        # 路径详情
        self.result_detail.setStyleSheet(f"""
            QTextBrowser {{
                background-color: {bg_color}; color: {text_color}; border: 1px solid {border_color};
                font-family: Consolas, monospace; font-size: 13px;
            }}
            QTextBrowser::selection {{ background-color: #4a6cf7; color: white; }}
        """)

        # 数据表格
        self.result_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {bg_color}; color: {text_color};
                border: 1px solid {border_color}; gridline-color: {border_color};
                alternate-background-color: {alt_bg};
            }}
            QTableWidget::item {{ background-color: {bg_color}; color: {text_color}; padding: 4px; }}
            QTableWidget::item:alternate {{ background-color: {alt_bg}; }}
            QTableWidget::item:selected {{ background-color: #4a6cf7; color: white; }}
            QHeaderView::section {{
                background-color: {header_bg}; color: {text_color};
                border: 1px solid {border_color}; padding: 4px;
            }}
        """)
        self.result_table.setAlternatingRowColors(True)

        # 主选项卡
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {border_color};
                background-color: {bg_color};
            }}
            QTabBar::tab {{
                background-color: {bg_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 4px;     
                padding: 4px 10px;       
                margin-right: 2px;   
            }}
            QTabBar::tab:selected {{
                background-color: {header_bg};
            }}
            QTabBar::tab:hover {{
                background-color: {border_color};
            }}
        """)

        # 输出选项卡
        self.output_tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {border_color};
                background-color: {bg_color};
            }}
            QTabBar::tab {{
                background-color: {bg_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 4px;
                padding: 4px 10px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {header_bg};
            }}
            QTabBar::tab:hover {{
                background-color: {border_color};
            }}
        """)

        # 分割器
        splitter_style = f"""
            QSplitter {{
                background-color: {bg_color};
                border: none;
                border-radius: 8px; 
                padding: 0px; 
            }}
            QSplitter::handle {{
                background-color: {border_color};
                width: 2px;
                height: 2px;
            }}
        """
        self.main_splitter.setStyleSheet(splitter_style)
        self.left_splitter.setStyleSheet(splitter_style)

        # Web视图
        webview_style = f"""
            QWebEngineView {{
                background-color: {bg_color};
                border: none;
                outline: none;
                margin: 0px;
                padding: 0px;
            }}
            QWebEngineView QScrollBar {{
                background-color: {bg_color};
                width: 8px;
                height: 8px;
            }}
            QWebEngineView QScrollBar::handle {{
                background-color: {border_color};
                border-radius: 4px;
            }}
            QWebEngineView QScrollBar::handle:hover {{ background-color: #777777; }}
        """
        self.web_view.setStyleSheet(webview_style)
        self.web_view.update()

    # ---------- 任务执行槽函数 ----------
    def run_flow_sort(self):
        if not self.is_data_valid():
            return
        index = self.flow_sort_tab.sort_type_combo.currentIndex()
        sort_types = ["total", "https", "outratio"]
        sort_type = sort_types[index] if 0 <= index < len(sort_types) else "total"
        base_cmd = [
            resource_path("backend/NetworkAnalyzerCore.exe"),
            "--task", "flow-sort",
            "--sort-type", sort_type
        ]
        if sort_type == "outratio":
            base_cmd += ["--ratio-threshold", str(self.flow_sort_tab.ratio_threshold_spin.value())]
        self.task_handler.execute_command(base_cmd, task_type="flow-sort", generate_graph=False)

    def run_path_searching(self):
        if not self.is_data_valid():
            return
        src = self.path_tab.path_src_edit.text().strip()
        dst = self.path_tab.path_dst_edit.text().strip()
        if not src or not dst:
            QMessageBox.warning(self, tr("path_search_warning_title", "警告"),
                                tr("path_search_need_src_dst", "请输入源IP和目的IP"))
            return
        if self.path_tab.compare_checkbox.isChecked():
            base_cmd = [
                resource_path("backend/NetworkAnalyzerCore.exe"),
                "--task", "compare-paths",
                "--src", src,
                "--dst", dst
            ]
            self.task_handler.execute_command(base_cmd, task_type="compare-paths", generate_graph=True,
                                              graph_name="compare_paths")
        else:
            index = self.path_tab.path_type_combo.currentIndex()
            path_types = ["min-congestion", "min-hop", "min-risk"]
            eng_type = path_types[index] if 0 <= index < len(path_types) else "min-congestion"
            base_cmd = [
                resource_path("backend/NetworkAnalyzerCore.exe"),
                "--task", eng_type,
                "--src", src,
                "--dst", dst
            ]
            self.task_handler.execute_command(base_cmd, task_type=eng_type, generate_graph=True, graph_name=eng_type)

    def run_port_scan(self):
        if not self.is_data_valid():
            return
        thr = self.anomaly_tab.port_scan_tab.threshold_spin.value()
        ratio = self.anomaly_tab.port_scan_tab.ratio_spin.value()
        base_cmd = [
            resource_path("backend/NetworkAnalyzerCore.exe"),
            "--task", "port-scan",
            "--threshold", str(thr),
            "--ratio-threshold", str(ratio)
        ]
        self.task_handler.execute_command(base_cmd, task_type="port-scan", generate_graph=True, graph_name="port_scan")

    def run_ddos_detection(self):
        if not self.is_data_valid():
            return
        thr = self.anomaly_tab.ddos_tab.neighbor_spin.value()
        base_cmd = [
            resource_path("backend/NetworkAnalyzerCore.exe"),
            "--task", "ddos-target",
            "--threshold", str(thr)
        ]
        traffic_str = self.anomaly_tab.ddos_tab.traffic_edit.text().strip()
        if traffic_str:
            try:
                val = int(traffic_str)
                unit_index = self.anomaly_tab.ddos_tab.traffic_unit.currentIndex()
                multipliers = [1, 1024, 1024 ** 2, 1024 ** 3]
                multiplier = multipliers[unit_index] if 0 <= unit_index < len(multipliers) else 1
                val *= multiplier
                base_cmd += ["--in-data-threshold", str(val)]
            except ValueError:
                QMessageBox.warning(self, tr("ddos_warning_title", "警告"),
                                    tr("ddos_traffic_must_be_int", "入流量阈值必须为整数"))
                return
        self.task_handler.execute_command(base_cmd, task_type="ddos-target", generate_graph=True, graph_name="ddos")

    def run_star_detection(self):
        if not self.is_data_valid():
            return
        thr = self.anomaly_tab.star_tab.threshold_spin.value()
        base_cmd = [
            resource_path("backend/NetworkAnalyzerCore.exe"),
            "--task", "star-structures",
            "--threshold", str(thr)
        ]
        self.task_handler.execute_command(base_cmd, task_type="star-structures", generate_graph=True, graph_name="star")

    def generate_subgraph(self):
        if not self.is_data_valid():
            return
        ip = self.subgraph_tab.ip_edit.text().strip()
        if not ip:
            QMessageBox.warning(self, tr("subgraph_warning_title", "警告"),
                                tr("subgraph_need_target_ip", "请输入目标IP"))
            return
        self.log_text.append(tr("subgraph_generating", "正在生成以 {} 为中心的子图...").format(ip))
        base_cmd = [
            resource_path("backend/NetworkAnalyzerCore.exe"),
            "--task", "subgraph",
            "--target", ip
        ]
        self.task_handler.execute_command(base_cmd, task_type="subgraph", generate_graph=True, graph_name="subgraph")

    def run_custom_rule(self):
        if not self.is_data_valid():
            return
        tab = self.custom_rule_tab
        rule_target = tab.target_ip_edit.text().strip()
        if not rule_target:
            QMessageBox.warning(self, tr("custom_rule_warning_title", "警告"),
                                tr("custom_rule_need_target_ip", "请输入目标IP"))
            return

        base_cmd = [
            resource_path("backend/NetworkAnalyzerCore.exe"),
            "--task", "custom-rule",
            "--rule-target", rule_target
        ]

        # 协议类型
        protocol_str = tab.protocol_edit.text().strip()
        if protocol_str:
            try:
                protocol_val = int(protocol_str)
                if protocol_val < 0 or protocol_val > 255:
                    QMessageBox.warning(self, tr("custom_rule_warning_title", "警告"),
                                        tr("custom_rule_protocol_range", "协议类型必须是0-255之间的整数"))
                    return
                base_cmd += ["--rule-protocol", str(protocol_val)]
            except ValueError:
                QMessageBox.warning(self, tr("custom_rule_warning_title", "警告"),
                                    tr("custom_rule_protocol_int", "协议类型必须为整数"))
                return

        # 规则类型
        rule_type_index = tab.rule_type_combo.currentIndex()
        rule_type_values = ["deny", "allow"]
        eng_rule_type = rule_type_values[rule_type_index] if 0 <= rule_type_index < len(rule_type_values) else "deny"
        base_cmd += ["--rule-type", eng_rule_type]

        # IP范围
        if tab.radio_cidr.isChecked():
            cidr = tab.cidr_edit.text().strip()
            if not cidr:
                QMessageBox.warning(self, tr("custom_rule_warning_title", "警告"),
                                    tr("custom_rule_need_cidr", "请输入CIDR范围"))
                return
            base_cmd += ["--range-cidr", cidr]
        else:
            start = tab.start_ip_edit.text().strip()
            end = tab.end_ip_edit.text().strip()
            if not start or not end:
                QMessageBox.warning(self, tr("custom_rule_warning_title", "警告"),
                                    tr("custom_rule_need_start_end", "请输入起始IP和结束IP"))
                return
            base_cmd += ["--range-start", start, "--range-end", end]

        # 源端口
        src_port = tab.src_port_edit.text().strip()
        if src_port:
            try:
                int(src_port)
                base_cmd += ["--rule-src-port", src_port]
            except ValueError:
                QMessageBox.warning(self, tr("custom_rule_warning_title", "警告"),
                                    tr("custom_rule_src_port_int", "源端口必须为整数"))
                return

        # 目的端口
        dst_port = tab.dst_port_edit.text().strip()
        if dst_port:
            try:
                int(dst_port)
                base_cmd += ["--rule-dst-port", dst_port]
            except ValueError:
                QMessageBox.warning(self, tr("custom_rule_warning_title", "警告"),
                                    tr("custom_rule_dst_port_int", "目的端口必须为整数"))
                return

        # 最大流量阈值
        max_traffic_str = tab.max_traffic_edit.text().strip()
        if max_traffic_str:
            try:
                val = int(max_traffic_str)
                unit_index = tab.max_traffic_unit.currentIndex()
                multipliers = [1, 1024, 1024 ** 2, 1024 ** 3]
                multiplier = multipliers[unit_index] if 0 <= unit_index < len(multipliers) else 1
                val *= multiplier
                base_cmd += ["--rule-max-traffic", str(val)]
            except ValueError:
                QMessageBox.warning(self, tr("custom_rule_warning_title", "警告"),
                                    tr("custom_rule_max_traffic_int", "最大流量阈值必须为整数"))
                return

        self.task_handler.execute_command(base_cmd, task_type="custom-rule", generate_graph=True,
                                          graph_name="custom_rule")

    def is_data_valid(self):
        if self.view_only_mode:
            QMessageBox.warning(self, tr("invalid_data", "数据无效"),
                                tr("view_only_mode_no_analysis", "当前处于可视化查看模式，无法进行分析操作。"))
            return False

        # 原有检查（数据文件存在、大小、有效性等）
        if not self.data_file or not os.path.exists(self.data_file):
            QMessageBox.warning(self, tr("invalid_data", "数据无效"),
                                tr("data_not_loaded", "未加载任何数据文件，请先加载有效数据！"))
            return False

        if os.path.getsize(self.data_file) == 0:
            QMessageBox.warning(self, tr("invalid_data", "数据无效"), tr("empty_file", "加载的文件为空，请重试！"))
            self.is_data_available = False
            return False

        if not self.is_data_available:
            QMessageBox.warning(self, tr("invalid_data", "数据无效"),
                                tr("no_valid_network_data", "加载的文件无有效网络流量数据，请重试！"))
            return False

        return True

    def about(self):
        QMessageBox.about(self, tr("about", "关于"),
                          tr("about_content",
                             "网络流量分析与异常检测系统\n华中科技大学网络空间安全学院 - 程序设计综合课程设计\n版本 1.0 | 2026年3月\n基于C++和PyQt6\n ©2026 那，边。版权所有。"))

    def show_manual(self):
        """显示用户手册对话框（支持多语言和主题适配）"""
        # 根据当前语言选择手册文件
        lang = lang_mgr.current_lang
        manual_path = resource_path(f"resources/manual/manual_{lang}.html")
        if not os.path.exists(manual_path):
            manual_path = resource_path("resources/manual/manual_zh_CN.html")  # 回退

        try:
            with open(manual_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
        except Exception as e:
            QMessageBox.warning(self, tr("error", "错误"),
                                tr("manual_load_failed", "无法加载用户手册: {}").format(e))
            return

        # 获取当前主题颜色并生成适配样式
        bg_color, text_color = get_theme_colors()
        is_dark = (bg_color == "#222222")
        style = _generate_manual_theme_style(is_dark)

        # 将样式注入到 HTML 的 <head> 中
        if '<head>' in html_content:
            html_content = html_content.replace('<head>', f'<head>{style}')
        else:
            html_content = f'<html><head>{style}</head><body>{html_content}</body></html>'

        # 创建对话框并显示
        dialog = QDialog(self)
        dialog.setWindowTitle(tr("manual_title", "用户手册"))
        dialog.resize(900, 700)
        layout = QVBoxLayout(dialog)
        web_view = QWebEngineView()
        web_view.setHtml(html_content)
        layout.addWidget(web_view)
        dialog.exec()
