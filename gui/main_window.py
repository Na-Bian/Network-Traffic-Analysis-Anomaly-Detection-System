# gui/main_window.py
import json
import os
import shutil
import sys

from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWebEngineCore import QWebEngineSettings
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import *
from qfluentwidgets import (
    Action,
    BodyLabel,
    CaptionLabel,
    CardWidget,
    CheckBox as FluentCheckBox,
    CommandBar,
    ComboBox as FluentComboBox,
    FluentIcon as FIF,
    FluentWindow,
    DropDownPushButton,
    HeaderCardWidget,
    LineEdit as FluentLineEdit,
    MessageBox,
    NavigationItemPosition,
    Pivot,
    PrimaryPushButton,
    PushButton,
    RoundMenu,
    ScrollArea,
    SpinBox as FluentSpinBox,
    StrongBodyLabel,
    SubtitleLabel,
    TableWidget,
    Theme,
    TitleLabel,
    isDarkTheme,
    qconfig,
    setTheme,
)

from .html_helper import get_theme_colors, generate_placeholder_html, replace_cdn_with_local
from .tabs.anomaly_tabs import AnomalyTab
from .tabs.custom_rule_tab import CustomRuleTab
from .tabs.flow_sort_tab import FlowSortTab
from .tabs.path_tab import PathTab
from .tabs.subgraph_tab import SubgraphTab
from .task_handler import TaskHandler
from .translator import tr, lang_mgr
from .utils import resource_path, core_executable_path, TempDirManager
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


def _patch_fluent_popup_composition():
    """Make qfluentwidgets popup menus stable on Windows setups with broken alpha composition."""
    if getattr(RoundMenu, "_network_analyzer_popup_patch", False):
        return

    original_init = RoundMenu.__init__

    def stable_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        if hasattr(self, "hBoxLayout"):
            self.hBoxLayout.setContentsMargins(0, 0, 0, 0)
        if hasattr(self, "view"):
            self.view.setGraphicsEffect(None)

    RoundMenu.__init__ = stable_init
    RoundMenu._network_analyzer_popup_patch = True


_patch_fluent_popup_composition()


class MainWindow(FluentWindow):
    def __init__(self):
        qconfig.set(qconfig.fontFamilies, ["Microsoft YaHei UI", "Microsoft YaHei", "Noto Sans SC", "Segoe UI"])
        super().__init__()
        self.setObjectName("NetworkAnalyzerWindow")
        self.setFont(QFont("Microsoft YaHei UI", 10))
        self.workbench_interface = None
        self.web_view = None
        self._centered_on_first_show = False
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
        self.quick_card_icons = []

        # 导出 actions
        self.export_pcap_csv_action = None
        self.export_full_graph_json_action = None
        self.export_full_graph_html_action = None
        self.export_subgraph_json_action = None
        self.export_subgraph_html_action = None
        self.full_graph_menu = None
        self.subgraph_menu = None
        self.export_command_button = None

        self.task_handler = TaskHandler(self)  # 任务处理器

        self.init_ui()
        self.update_webview_theme(tr("waiting_data", "等待分析数据..."))
        QApplication.instance().paletteChanged.connect(self.on_palette_changed)
        lang_mgr.language_changed.connect(self.retranslate_ui)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._centered_on_first_show:
            self._centered_on_first_show = True
            QTimer.singleShot(0, self.center_on_screen)

    def center_on_screen(self):
        """Place the window at the center of the active screen on first launch."""
        screen = self.windowHandle().screen() if self.windowHandle() else QApplication.primaryScreen()
        if screen is None:
            screen = QApplication.primaryScreen()
        if screen is None:
            return

        available_geometry = screen.availableGeometry()
        frame_geometry = self.frameGeometry()
        if frame_geometry.width() <= 0 or frame_geometry.height() <= 0:
            frame_geometry = QRect(QPoint(0, 0), self.size())

        frame_geometry.moveCenter(available_geometry.center())
        self.move(frame_geometry.topLeft())

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
        self.file_menu.setTitle(tr("file", "文件"))
        self.open_action.setText(tr("open_file", "打开数据文件"))
        self.export_menu.setTitle(tr("export_menu", "导出"))
        self.export_pcap_csv_action.setText(tr("export_pcap_csv", "PCAP转换的CSV"))
        self.full_graph_menu.setTitle(tr("task_full_graph", "全网拓扑"))
        self.subgraph_menu.setTitle(tr("export_current_subgraph", "当前子图"))
        self.export_full_graph_json_action.setText("JSON")
        self.export_full_graph_html_action.setText("HTML")
        self.export_subgraph_json_action.setText("JSON")
        self.export_subgraph_html_action.setText("HTML")
        self.settings_menu.setTitle(tr("settings", "设置"))
        self.lang_menu.setTitle(tr("language", "语言 / Language"))
        self.action_zh_cn.setText(tr("lang_zh_CN", "简体中文"))
        self.action_zh_tw.setText(tr("lang_zh_TW", "繁体中文"))
        self.action_en.setText(tr("lang_en_US", "English"))
        self.help_menu.setTitle(tr("help", "帮助"))
        self.manual_action.setText(tr("help_manual", "用户手册"))
        self.about_action.setText(tr("about", "关于"))
        self.open_command_action.setText(tr("open_file", "打开数据文件"))
        self.export_command_button.setText(tr("export_menu", "导出"))
        self.manual_command_action.setText(tr("help_manual", "用户手册"))
        self.thread_label.setText(tr("thread_count", "线程数:"))
        self.data_file_label.setText(tr("data_file", "数据文件:"))
        self.browse_btn.setText(tr("browse", "浏览..."))
        self.render_mode_label.setText(tr("render_mode_label", "渲染模式:"))
        self.render_mode_combo.setItemText(0, tr("render_mode_auto", "自动"))
        self.render_mode_combo.setItemText(1, tr("render_mode_vis", "vis-network"))
        self.render_mode_combo.setItemText(2, tr("render_mode_sigma", "Sigma"))
        self.top_k_edges_label.setText(tr("render_top_k_edges_label", "Top-K 边:"))
        self.top_k_edges_spin.setSpecialValueText(tr("render_top_k_edges_unlimited", "不限"))
        self.top_k_edges_spin.setToolTip(tr(
            "render_top_k_edges_tooltip",
            "仅保留流量最大的 K 条边；0 表示不限制。"
        ))
        self.aggregate_graph_checkbox.setText(tr("render_aggregate_large_graph", "超大图按 /24 网段聚合"))
        self.aggregate_graph_checkbox.setToolTip(tr(
            "render_aggregate_large_graph_tooltip",
            "当图规模很大且使用 Sigma 时，先显示网段级总览，点击节点展开局部子图。"
        ))

        self.flow_sort_tab.retranslate_ui()
        self.path_tab.retranslate_ui()
        self.anomaly_tab.retranslate_ui()
        self.custom_rule_tab.retranslate_ui()
        self.subgraph_tab.retranslate_ui()

        self.workbench_interface.title_label.setText(tr("nav_workbench", "工作台"))
        self.workbench_interface.subtitle_label.setText(tr("dashboard_subtitle", "从数据导入到拓扑分析的一站式入口"))
        self.topology_interface.title_label.setText(tr("nav_topology", "拓扑视图"))
        self.topology_interface.subtitle_label.setText(tr("topology_subtitle", "查看全网拓扑、子图和大图渲染结果"))
        self.traffic_interface.title_label.setText(tr("traffic_sorting", "流量排序"))
        self.traffic_interface.subtitle_label.setText(tr("traffic_subtitle", "按总流量、HTTPS 或出流量占比分析关键流"))
        self.path_interface.title_label.setText(tr("path_search", "路径查找"))
        self.path_interface.subtitle_label.setText(tr("path_subtitle", "比较最小拥塞、最小跳数和最小风险路径"))
        self.anomaly_interface.title_label.setText(tr("anomaly_detection", "异常检测"))
        self.anomaly_interface.subtitle_label.setText(tr("anomaly_subtitle", "端口扫描、DDoS 目标和星型结构检测"))
        self.rule_interface.title_label.setText(tr("anomaly_tab_custom_rule", "自定义规则"))
        self.rule_interface.subtitle_label.setText(tr("rule_subtitle", "用组合条件快速表达业务侧检测规则"))
        self.subgraph_interface.title_label.setText(tr("subgraph_visualization", "子图可视化"))
        self.subgraph_interface.subtitle_label.setText(tr("subgraph_subtitle", "围绕指定 IP 生成局部拓扑"))
        self.results_interface.title_label.setText(tr("nav_results", "结果中心"))
        self.results_interface.subtitle_label.setText(tr("results_subtitle", "运行日志、表格结果和路径详情"))
        self.settings_interface.title_label.setText(tr("settings", "设置"))
        self.settings_interface.subtitle_label.setText(tr("settings_subtitle", "语言、帮助和工程运行选项"))
        self.traffic_feature_card.setTitle(tr("traffic_sorting", "流量排序"))
        self.path_feature_card.setTitle(tr("path_search", "路径查找"))
        self.anomaly_feature_card.setTitle(tr("anomaly_detection", "异常检测"))
        self.rule_feature_card.setTitle(tr("anomaly_tab_custom_rule", "自定义规则"))
        self.subgraph_feature_card.setTitle(tr("subgraph_visualization", "子图可视化"))
        self.output_pivot.setItemText("log", tr("output_log_tab", "运行日志"))
        self.output_pivot.setItemText("table", tr("output_table_tab", "数据表格"))
        self.output_pivot.setItemText("detail", tr("output_detail_tab", "路径与详情"))
        self.lang_zh_cn_btn.setText(tr("lang_zh_CN", "简体中文"))
        self.lang_zh_tw_btn.setText(tr("lang_zh_TW", "繁体中文"))
        self.lang_en_btn.setText(tr("lang_en_US", "English"))
        self.manual_btn.setText(tr("help_manual", "用户手册"))
        self.about_btn.setText(tr("about", "关于"))
        self.theme_card.title_label.setText(tr("settings_theme_title", "外观主题"))
        self.theme_card.subtitle_label.setText(tr("settings_theme_desc", "手动切换浅色、深色，或跟随系统设置。"))
        self.runtime_card.title_label.setText(tr("settings_runtime_title", "运行参数"))
        self.runtime_card.subtitle_label.setText(tr("settings_runtime_desc", "调整后端分析任务使用的线程数量。"))
        self.language_card.title_label.setText(tr("language", "语言 / Language"))
        self.language_card.subtitle_label.setText(tr("settings_language_desc", "语言切换会立即更新界面文本。"))
        self.help_card.title_label.setText(tr("help", "帮助"))
        self.help_card.subtitle_label.setText(tr("settings_help_desc", "查看用户手册或软件版本信息。"))
        self.theme_label.setText(tr("settings_theme_label", "主题:"))
        with QSignalBlocker(self.theme_combo):
            self.theme_combo.setItemText(0, tr("settings_theme_auto", "跟随系统"))
            self.theme_combo.setItemText(1, tr("settings_theme_light", "浅色"))
            self.theme_combo.setItemText(2, tr("settings_theme_dark", "深色"))
        self._set_navigation_texts()
        self._refresh_quick_card_icons()

        if not self.is_data_available:
            self.update_webview_theme(tr("waiting_data", "等待分析数据..."))

    def init_ui(self):
        """初始化所有UI组件"""
        self._apply_window_effects()

        # 文件与导出动作
        self.file_menu = QMenu(tr("file", "文件"), self)
        self.open_action = QAction(tr("open_file", "打开数据文件"), self)
        self.open_action.triggered.connect(self.browse_file)
        self.file_menu.addAction(self.open_action)

        self.file_menu.addSeparator()

        self.export_menu = RoundMenu(tr("export_menu", "导出"), self)
        self.file_menu.addMenu(self.export_menu)

        self.export_pcap_csv_action = Action(FIF.SAVE, tr("export_pcap_csv", "PCAP转换的CSV"), self)
        self.export_pcap_csv_action.triggered.connect(self.export_pcap_csv)
        self.export_menu.addAction(self.export_pcap_csv_action)

        self.full_graph_menu = RoundMenu(tr("task_full_graph", "全网拓扑"), self)
        self.full_graph_menu.setIcon(FIF.GLOBE)
        self.export_full_graph_json_action = Action("JSON", self)
        self.export_full_graph_json_action.triggered.connect(lambda: self.export_graph("full", "json"))
        self.full_graph_menu.addAction(self.export_full_graph_json_action)
        self.export_full_graph_html_action = Action("HTML", self)
        self.export_full_graph_html_action.triggered.connect(lambda: self.export_graph("full", "html"))
        self.full_graph_menu.addAction(self.export_full_graph_html_action)
        self.export_menu.addMenu(self.full_graph_menu)

        self.subgraph_menu = RoundMenu(tr("export_current_subgraph", "当前子图"), self)
        self.subgraph_menu.setIcon(FIF.SHARE)
        self.export_subgraph_json_action = Action("JSON", self)
        self.export_subgraph_json_action.triggered.connect(lambda: self.export_graph("current", "json"))
        self.subgraph_menu.addAction(self.export_subgraph_json_action)
        self.export_subgraph_html_action = Action("HTML", self)
        self.export_subgraph_html_action.triggered.connect(lambda: self.export_graph("current", "html"))
        self.subgraph_menu.addAction(self.export_subgraph_html_action)
        self.export_menu.addMenu(self.subgraph_menu)

        # 初始时禁用所有导出动作，直到数据加载
        self.update_export_actions()

        # 语言子菜单
        self.settings_menu = QMenu(tr("settings", "设置"), self)
        self.lang_menu = QMenu(tr("language", "语言 / Language"), self)
        self.action_zh_cn = QAction(tr("lang_zh_CN", "简体中文"), self)
        self.action_zh_cn.triggered.connect(lambda: lang_mgr.set_language("zh_CN"))
        self.lang_menu.addAction(self.action_zh_cn)
        self.action_zh_tw = QAction(tr("lang_zh_TW", "繁体中文"), self)
        self.action_zh_tw.triggered.connect(lambda: lang_mgr.set_language("zh_TW"))
        self.lang_menu.addAction(self.action_zh_tw)
        self.action_en = QAction(tr("lang_en_US", "English"), self)
        self.action_en.triggered.connect(lambda: lang_mgr.set_language("en_US"))
        self.lang_menu.addAction(self.action_en)
        self.settings_menu.addMenu(self.lang_menu)

        # 帮助菜单
        self.help_menu = QMenu(tr("help", "帮助"), self)
        self.manual_action = QAction(tr("help_manual", "用户手册"), self)
        self.manual_action.triggered.connect(self.show_manual)
        self.about_action = QAction(tr("about", "关于"), self)
        self.about_action.triggered.connect(self.about)
        self.help_menu.addAction(self.manual_action)
        self.help_menu.addAction(self.about_action)

        # 页面与功能控件
        self.flow_sort_tab = FlowSortTab()
        self.path_tab = PathTab()
        self.anomaly_tab = AnomalyTab()
        self.subgraph_tab = SubgraphTab()
        self.custom_rule_tab = CustomRuleTab()

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("font-family: Consolas, monospace; font-size: 12px;")

        self.result_table = TableWidget()
        self.result_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.result_table.horizontalHeader().setStretchLastSection(True)

        self.result_detail = QTextBrowser()
        self.result_detail.setStyleSheet("font-family: Consolas, monospace; font-size: 13px;")

        self.web_view = QWebEngineView()
        settings = self.web_view.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, True)

        self._build_fluent_pages()

        # 连接按钮信号
        self.flow_sort_tab.flow_sort_btn.clicked.connect(self.run_flow_sort)
        self.path_tab.path_btn.clicked.connect(self.run_path_searching)
        self.anomaly_tab.port_scan_tab.detect_btn.clicked.connect(self.run_port_scan)
        self.anomaly_tab.ddos_tab.detect_btn.clicked.connect(self.run_ddos_detection)
        self.anomaly_tab.star_tab.detect_btn.clicked.connect(self.run_star_detection)
        self.subgraph_tab.generate_btn.clicked.connect(self.generate_subgraph)
        self.custom_rule_tab.detect_btn.clicked.connect(self.run_custom_rule)

        self.update_log_detail_theme()

    def _create_page(self, object_name, title, subtitle):
        page = ScrollArea(self)
        page.setObjectName(object_name)
        page.setWidgetResizable(True)
        page.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget(page)
        content.setObjectName(f"{object_name}_content")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 18, 32, 28)
        layout.setSpacing(16)

        title_label = TitleLabel(title)
        subtitle_label = CaptionLabel(subtitle)
        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)

        page.setWidget(content)
        page.viewport().setAutoFillBackground(False)
        page.content_widget = content
        page.page_layout = layout
        page.title_label = title_label
        page.subtitle_label = subtitle_label
        return page

    def _create_card(self, title, subtitle=None):
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 16, 20, 18)
        layout.setSpacing(10)
        title_label = StrongBodyLabel(title)
        layout.addWidget(title_label)
        subtitle_label = None
        if subtitle:
            subtitle_label = CaptionLabel(subtitle)
            layout.addWidget(subtitle_label)
        card.card_layout = layout
        card.title_label = title_label
        card.subtitle_label = subtitle_label
        return card

    def _switch_to_interface(self, interface):
        self.switchTo(interface)

    def _set_navigation_texts(self):
        items = [
            (self.workbench_interface, tr("nav_workbench", "工作台")),
            (self.topology_interface, tr("nav_topology", "拓扑视图")),
            (self.traffic_interface, tr("traffic_sorting", "流量排序")),
            (self.path_interface, tr("path_search", "路径查找")),
            (self.anomaly_interface, tr("anomaly_detection", "异常检测")),
            (self.rule_interface, tr("anomaly_tab_custom_rule", "自定义规则")),
            (self.subgraph_interface, tr("subgraph_visualization", "子图可视化")),
            (self.results_interface, tr("nav_results", "结果中心")),
            (self.settings_interface, tr("settings", "设置")),
        ]
        for interface, text in items:
            item = self.navigationInterface.widget(interface.objectName())
            if item and hasattr(item, "setText"):
                item.setText(text)

    def _add_quick_card(self, parent_layout, icon, title, description, button_text, target):
        card = CardWidget()
        card.setMinimumHeight(118)
        layout = QHBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(14)

        icon_label = QLabel()
        icon_label.setFixedSize(36, 36)
        icon_label.setFixedWidth(36)
        layout.addWidget(icon_label)
        self.quick_card_icons.append((icon_label, icon))

        text_layout = QVBoxLayout()
        text_layout.setSpacing(3)
        title_label = StrongBodyLabel(title)
        desc_label = CaptionLabel(description)
        desc_label.setWordWrap(True)
        text_layout.addWidget(title_label)
        text_layout.addWidget(desc_label)
        layout.addLayout(text_layout, 1)

        button = PushButton(button_text)
        button.clicked.connect(lambda: self._switch_to_interface(target))
        layout.addWidget(button)
        parent_layout.addWidget(card)
        return card

    def _refresh_quick_card_icons(self):
        theme = Theme.DARK if isDarkTheme() else Theme.LIGHT
        for label, icon in self.quick_card_icons:
            label.setPixmap(icon.icon(theme=theme).pixmap(30, 30))

    def _build_fluent_pages(self):
        self.workbench_interface = self._create_page(
            "dashboard",
            tr("nav_workbench", "工作台"),
            tr("dashboard_subtitle", "从数据导入到拓扑分析的一站式入口")
        )
        self.topology_interface = self._create_page(
            "topology",
            tr("nav_topology", "拓扑视图"),
            tr("topology_subtitle", "查看全网拓扑、子图和大图渲染结果")
        )
        self.traffic_interface = self._create_page(
            "traffic",
            tr("traffic_sorting", "流量排序"),
            tr("traffic_subtitle", "按总流量、HTTPS 或出流量占比分析关键流")
        )
        self.path_interface = self._create_page(
            "path",
            tr("path_search", "路径查找"),
            tr("path_subtitle", "比较最小拥塞、最小跳数和最小风险路径")
        )
        self.anomaly_interface = self._create_page(
            "anomaly",
            tr("anomaly_detection", "异常检测"),
            tr("anomaly_subtitle", "端口扫描、DDoS 目标和星型结构检测")
        )
        self.rule_interface = self._create_page(
            "rules",
            tr("anomaly_tab_custom_rule", "自定义规则"),
            tr("rule_subtitle", "用组合条件快速表达业务侧检测规则")
        )
        self.subgraph_interface = self._create_page(
            "subgraph",
            tr("subgraph_visualization", "子图可视化"),
            tr("subgraph_subtitle", "围绕指定 IP 生成局部拓扑")
        )
        self.results_interface = self._create_page(
            "results",
            tr("nav_results", "结果中心"),
            tr("results_subtitle", "运行日志、表格结果和路径详情")
        )
        self.settings_interface = self._create_page(
            "settings",
            tr("settings", "设置"),
            tr("settings_subtitle", "语言、帮助和工程运行选项")
        )

        self.addSubInterface(self.workbench_interface, FIF.HOME, tr("nav_workbench", "工作台"))
        self.addSubInterface(self.topology_interface, FIF.GLOBE, tr("nav_topology", "拓扑视图"))
        self.addSubInterface(self.traffic_interface, FIF.SPEED_HIGH, tr("traffic_sorting", "流量排序"))
        self.addSubInterface(self.path_interface, FIF.CONNECT, tr("path_search", "路径查找"))
        self.addSubInterface(self.anomaly_interface, FIF.ROBOT, tr("anomaly_detection", "异常检测"))
        self.addSubInterface(self.rule_interface, FIF.CODE, tr("anomaly_tab_custom_rule", "自定义规则"))
        self.addSubInterface(self.subgraph_interface, FIF.SHARE, tr("subgraph_visualization", "子图可视化"))
        self.addSubInterface(self.results_interface, FIF.DOCUMENT, tr("nav_results", "结果中心"))
        self.addSubInterface(
            self.settings_interface,
            FIF.SETTING,
            tr("settings", "设置"),
            NavigationItemPosition.BOTTOM
        )

        self._build_dashboard_page()
        self._build_topology_page()
        self.traffic_feature_card = self._build_feature_page(
            self.traffic_interface, self.flow_sort_tab, tr("traffic_sorting", "流量排序")
        )
        self.path_feature_card = self._build_feature_page(
            self.path_interface, self.path_tab, tr("path_search", "路径查找")
        )
        self.anomaly_feature_card = self._build_feature_page(
            self.anomaly_interface, self.anomaly_tab, tr("anomaly_detection", "异常检测")
        )
        self.rule_feature_card = self._build_feature_page(
            self.rule_interface, self.custom_rule_tab, tr("anomaly_tab_custom_rule", "自定义规则")
        )
        self.subgraph_feature_card = self._build_feature_page(
            self.subgraph_interface, self.subgraph_tab, tr("subgraph_visualization", "子图可视化")
        )
        self._build_results_page()
        self._build_settings_page()
        self.navigationInterface.setExpandWidth(228)
        self.navigationInterface.setMinimumExpandWidth(180)
        self.navigationInterface.expand(useAni=False)

    def _build_dashboard_page(self):
        layout = self.workbench_interface.page_layout

        command_card = self._create_card(
            tr("dashboard_command_title", "开始分析"),
            tr("dashboard_command_desc", "选择数据文件后，系统会自动生成全网拓扑并激活分析功能。")
        )
        command_bar = CommandBar()
        command_bar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.open_command_action = Action(FIF.FOLDER, tr("open_file", "打开数据文件"), self)
        self.open_command_action.triggered.connect(self.browse_file)
        self.manual_command_action = Action(FIF.HELP, tr("help_manual", "用户手册"), self)
        self.manual_command_action.triggered.connect(self.show_manual)
        command_bar.addAction(self.open_command_action)
        self.export_command_button = DropDownPushButton(FIF.SAVE, tr("export_menu", "导出"))
        self.export_command_button.setMenu(self.export_menu)
        command_bar.addWidget(self.export_command_button)
        command_bar.addAction(self.manual_command_action)
        command_card.card_layout.addWidget(command_bar)

        file_layout = QHBoxLayout()
        file_layout.setSpacing(10)
        self.data_file_label = BodyLabel(tr("data_file", "数据文件:"))
        file_layout.addWidget(self.data_file_label)
        self.file_edit = FluentLineEdit()
        self.file_edit.setReadOnly(True)
        file_layout.addWidget(self.file_edit, 1)
        self.browse_btn = PushButton(tr("browse", "浏览..."))
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)
        command_card.card_layout.addLayout(file_layout)

        layout.addWidget(command_card)

        quick_layout = QVBoxLayout()
        quick_layout.setSpacing(12)
        self._add_quick_card(
            quick_layout, FIF.GLOBE,
            tr("quick_topology_title", "拓扑总览"),
            tr("quick_topology_desc", "查看自动生成的网络拓扑，并调整大图渲染策略。"),
            tr("quick_open", "打开"),
            self.topology_interface
        )
        self._add_quick_card(
            quick_layout, FIF.ROBOT,
            tr("quick_anomaly_title", "异常研判"),
            tr("quick_anomaly_desc", "集中运行端口扫描、DDoS 和星型结构检测。"),
            tr("quick_open", "打开"),
            self.anomaly_interface
        )
        self._add_quick_card(
            quick_layout, FIF.DOCUMENT,
            tr("quick_results_title", "结果中心"),
            tr("quick_results_desc", "查看运行日志、表格输出和路径详情。"),
            tr("quick_open", "打开"),
            self.results_interface
        )
        layout.addLayout(quick_layout)
        layout.addStretch()

    def _build_topology_page(self):
        layout = self.topology_interface.page_layout
        render_card = self._create_card(
            tr("render_settings_title", "渲染控制"),
            tr("render_settings_desc", "根据图规模选择 vis-network 或 Sigma，并对超大图启用降载策略。")
        )

        render_layout = QHBoxLayout()
        render_layout.setSpacing(10)
        self.render_mode_label = BodyLabel(tr("render_mode_label", "渲染模式:"))
        render_layout.addWidget(self.render_mode_label)
        self.render_mode_combo = FluentComboBox()
        self.render_mode_combo.addItem(tr("render_mode_auto", "自动"), "auto")
        self.render_mode_combo.addItem(tr("render_mode_vis", "vis-network"), "vis")
        self.render_mode_combo.addItem(tr("render_mode_sigma", "Sigma"), "sigma")
        self.render_mode_combo.setMinimumWidth(150)
        render_layout.addWidget(self.render_mode_combo)

        self.top_k_edges_label = BodyLabel(tr("render_top_k_edges_label", "Top-K 边:"))
        render_layout.addWidget(self.top_k_edges_label)
        self.top_k_edges_spin = FluentSpinBox()
        self.top_k_edges_spin.setRange(0, 1000000)
        self.top_k_edges_spin.setSingleStep(1000)
        self.top_k_edges_spin.setSpecialValueText(tr("render_top_k_edges_unlimited", "不限"))
        self.top_k_edges_spin.setToolTip(tr(
            "render_top_k_edges_tooltip",
            "仅保留流量最大的 K 条边；0 表示不限制。"
        ))
        render_layout.addWidget(self.top_k_edges_spin)

        self.aggregate_graph_checkbox = FluentCheckBox(tr("render_aggregate_large_graph", "超大图按 /24 网段聚合"))
        self.aggregate_graph_checkbox.setChecked(True)
        self.aggregate_graph_checkbox.setToolTip(tr(
            "render_aggregate_large_graph_tooltip",
            "当图规模很大且使用 Sigma 时，先显示网段级总览，点击节点展开局部子图。"
        ))
        render_layout.addWidget(self.aggregate_graph_checkbox)
        render_layout.addStretch()
        render_card.card_layout.addLayout(render_layout)
        layout.addWidget(render_card)

        graph_card = CardWidget()
        graph_card.setMinimumHeight(520)
        graph_layout = QVBoxLayout(graph_card)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        self.web_view.setMinimumHeight(500)
        graph_layout.addWidget(self.web_view)
        layout.addWidget(graph_card, 1)

    def _build_feature_page(self, page, widget, title):
        card = HeaderCardWidget()
        card.setTitle(title)
        card.viewLayout.setContentsMargins(22, 18, 22, 20)
        card.viewLayout.addWidget(widget)
        page.page_layout.addWidget(card)
        page.page_layout.addStretch()
        return card

    def _build_results_page(self):
        layout = self.results_interface.page_layout
        self.output_pivot = Pivot()
        self.output_stack = QStackedWidget()
        self.output_stack.addWidget(self.log_text)
        self.output_stack.addWidget(self.result_table)
        self.output_stack.addWidget(self.result_detail)

        self.output_pivot.addItem("log", tr("output_log_tab", "运行日志"), lambda: self.output_stack.setCurrentWidget(self.log_text))
        self.output_pivot.addItem("table", tr("output_table_tab", "数据表格"), lambda: self.output_stack.setCurrentWidget(self.result_table))
        self.output_pivot.addItem("detail", tr("output_detail_tab", "路径与详情"), lambda: self.output_stack.setCurrentWidget(self.result_detail))
        self.output_pivot.setCurrentItem("log")
        self.output_stack.setCurrentWidget(self.log_text)

        layout.addWidget(self.output_pivot)
        layout.addWidget(self.output_stack, 1)

    def _build_settings_page(self):
        layout = self.settings_interface.page_layout
        self.theme_card = self._create_card(
            tr("settings_theme_title", "外观主题"),
            tr("settings_theme_desc", "手动切换浅色、深色，或跟随系统设置。")
        )
        theme_layout = QHBoxLayout()
        theme_layout.setSpacing(10)
        self.theme_label = BodyLabel(tr("settings_theme_label", "主题:"))
        self.theme_combo = FluentComboBox()
        self.theme_combo.addItem(tr("settings_theme_auto", "跟随系统"), "auto")
        self.theme_combo.addItem(tr("settings_theme_light", "浅色"), "light")
        self.theme_combo.addItem(tr("settings_theme_dark", "深色"), "dark")
        self.theme_combo.setMinimumWidth(180)
        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        theme_layout.addWidget(self.theme_label)
        theme_layout.addWidget(self.theme_combo)
        theme_layout.addStretch()
        self.theme_card.card_layout.addLayout(theme_layout)
        layout.addWidget(self.theme_card)

        self.runtime_card = self._create_card(
            tr("settings_runtime_title", "运行参数"),
            tr("settings_runtime_desc", "调整后端分析任务使用的线程数量。")
        )
        runtime_layout = QHBoxLayout()
        runtime_layout.setSpacing(10)
        self.thread_label = BodyLabel(tr("thread_count", "线程数:"))
        runtime_layout.addWidget(self.thread_label)
        self.thread_spin = FluentSpinBox()
        max_threads = max(1, os.cpu_count() or 1)
        self.thread_spin.setRange(1, max_threads)
        self.thread_spin.setValue(min(4, max_threads))
        self.thread_spin.setFixedWidth(120)
        runtime_layout.addWidget(self.thread_spin)
        runtime_layout.addStretch()
        self.runtime_card.card_layout.addLayout(runtime_layout)
        layout.addWidget(self.runtime_card)

        self.language_card = self._create_card(
            tr("language", "语言 / Language"),
            tr("settings_language_desc", "语言切换会立即更新界面文本。")
        )
        lang_layout = QHBoxLayout()
        lang_layout.setSpacing(10)
        self.lang_zh_cn_btn = PushButton(tr("lang_zh_CN", "简体中文"))
        self.lang_zh_tw_btn = PushButton(tr("lang_zh_TW", "繁体中文"))
        self.lang_en_btn = PushButton(tr("lang_en_US", "English"))
        self.lang_zh_cn_btn.clicked.connect(lambda: lang_mgr.set_language("zh_CN"))
        self.lang_zh_tw_btn.clicked.connect(lambda: lang_mgr.set_language("zh_TW"))
        self.lang_en_btn.clicked.connect(lambda: lang_mgr.set_language("en_US"))
        lang_layout.addWidget(self.lang_zh_cn_btn)
        lang_layout.addWidget(self.lang_zh_tw_btn)
        lang_layout.addWidget(self.lang_en_btn)
        lang_layout.addStretch()
        self.language_card.card_layout.addLayout(lang_layout)
        layout.addWidget(self.language_card)

        self.help_card = self._create_card(
            tr("help", "帮助"),
            tr("settings_help_desc", "查看用户手册或软件版本信息。")
        )
        help_layout = QHBoxLayout()
        self.manual_btn = PushButton(FIF.HELP, tr("help_manual", "用户手册"))
        self.about_btn = PushButton(FIF.INFO, tr("about", "关于"))
        self.manual_btn.clicked.connect(self.show_manual)
        self.about_btn.clicked.connect(self.about)
        help_layout.addWidget(self.manual_btn)
        help_layout.addWidget(self.about_btn)
        help_layout.addStretch()
        self.help_card.card_layout.addLayout(help_layout)
        layout.addWidget(self.help_card)
        layout.addStretch()

    def _on_theme_changed(self):
        theme = ["auto", "light", "dark"][max(0, min(self.theme_combo.currentIndex(), 2))]
        if theme == "dark":
            setTheme(Theme.DARK, save=True)
        elif theme == "light":
            setTheme(Theme.LIGHT, save=True)
        else:
            setTheme(Theme.AUTO, save=True)
        self._apply_window_effects()
        self.update_webview_theme()
        self.update_log_detail_theme()
        self._refresh_quick_card_icons()
        QApplication.style().unpolish(self)
        QApplication.style().polish(self)
        self.update()

    def _apply_window_effects(self):
        """Enable Win11 Mica while keeping qfluent popup composition stable."""
        is_win11 = sys.platform == "win32" and sys.getwindowsversion().build >= 22000
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, is_win11)
        self.setMicaEffectEnabled(is_win11)

        if not is_win11:
            return

        try:
            self.windowEffect.addShadowEffect(self.winId())
        except Exception:
            pass

        try:
            import ctypes

            DWMWA_WINDOW_CORNER_PREFERENCE = 33
            DWMWCP_ROUND = 2
            preference = ctypes.c_int(DWMWCP_ROUND)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                int(self.winId()),
                DWMWA_WINDOW_CORNER_PREFERENCE,
                ctypes.byref(preference),
                ctypes.sizeof(preference)
            )
        except Exception:
            pass

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
            core_executable_path(),
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
    def _render_options(self):
        render_mode = ["auto", "vis", "sigma"][max(0, min(self.render_mode_combo.currentIndex(), 2))]
        return {
            "render_mode": render_mode,
            "top_k_edges": self.top_k_edges_spin.value(),
            "aggregate_large_graph": self.aggregate_graph_checkbox.isChecked(),
        }

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

        self.subgraph_worker = SubgraphWorker(
            json_path,
            html_path,
            bgcolor,
            fontcolor,
            render_options=self._render_options(),
        )

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
        self.subgraph_worker.info.connect(self._handle_render_info)
        self.subgraph_worker.error.connect(lambda e: self.log_text.append(e))
        self.subgraph_worker.start()

    def _handle_render_info(self, message):
        if not message.startswith("render_mode:"):
            self.log_text.append(message)
            return
        _, renderer, mode, nodes, edges = message.split(":", 4)
        mode_label = {
            "interactive": tr("render_mode_interactive", "交互模式"),
            "balanced": tr("render_mode_balanced", "均衡模式"),
            "performance": tr("render_mode_performance", "性能模式")
        }.get(mode, mode)
        self.log_text.append(
            tr("render_mode_summary", "渲染器: {}，模式: {}，节点: {}，边: {}").format(
                renderer, mode_label, nodes, edges
            )
        )

    def display_html(self, html_file):
        if not os.path.exists(html_file):
            self.log_text.append(tr("display_html_file_not_exist", "错误：HTML 文件不存在 - {}").format(html_file))
            return
        try:
            url = QUrl.fromLocalFile(os.path.abspath(html_file))
            self.web_view.setUrl(url)
            self.has_graph = True
            self.switchTo(self.topology_interface)
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
        dark = isDarkTheme()
        mica_enabled = self.isMicaEffectEnabled()
        window_bg = "transparent" if mica_enabled else bg_color
        page_bg = "#202020" if dark else "#f5f7fb"
        scroll_bg = "transparent" if mica_enabled else bg_color
        surface_color = "#2b2b2b" if dark else "#ffffff"
        card_color = "#323232" if dark else "#f7f9fc"
        border_color = "#4a4a4a" if dark else "#d8dce5"
        header_bg = "#3a3a3a" if dark else "#eef3fb"
        alt_bg = "#303030" if dark else "#f8fbff"
        hover_bg = "#3d3d3d" if dark else "#eef6ff"
        accent = "#0078d4"

        self.setStyleSheet(f"""
            #NetworkAnalyzerWindow {{
                background-color: {window_bg};
                color: {text_color};
            }}
            ScrollArea, QScrollArea {{
                background-color: {scroll_bg};
                border: none;
            }}
            QWidget#customRuleContent {{
                background-color: {page_bg};
                color: {text_color};
            }}
            QStackedWidget {{
                background-color: transparent;
                border: none;
            }}
            QWidget#dashboard_content,
            QWidget#topology_content,
            QWidget#traffic_content,
            QWidget#path_content,
            QWidget#anomaly_content,
            QWidget#rules_content,
            QWidget#subgraph_content,
            QWidget#results_content,
            QWidget#settings_content {{
                background-color: {page_bg};
                color: {text_color};
            }}
            CardWidget {{
                background-color: {surface_color};
                border: 1px solid {border_color};
                border-radius: 8px;
            }}
            QToolButton {{
                background-color: {card_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 6px;
                padding: 7px 12px;
            }}
            QToolButton:hover {{
                background-color: {hover_bg};
                border-color: {accent};
            }}
            QGroupBox {{
                background-color: {card_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 8px;
                margin-top: 14px;
                padding: 14px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                color: {accent};
                background-color: {card_color};
            }}
            QLabel:disabled, BodyLabel:disabled {{
                color: {"#8a8a8a" if dark else "#8f96a3"};
            }}
            LineEdit:disabled, ComboBox:disabled, SpinBox:disabled, DoubleSpinBox:disabled {{
                color: {"#8a8a8a" if dark else "#8f96a3"};
                background-color: {"#282828" if dark else "#eef1f6"};
                border-color: {"#3b3b3b" if dark else "#d7dce5"};
            }}
        """)

        # 运行日志
        self.log_text.setStyleSheet(f"""
            QTextEdit {{    
                background-color: {surface_color}; color: {text_color}; border: 1px solid {border_color};
                border-radius: 8px; padding: 6px;
                font-family: Consolas, monospace; font-size: 12px;
            }}
            QTextEdit::selection {{ background-color: {accent}; color: white; }}
        """)

        # 路径详情
        self.result_detail.setStyleSheet(f"""
            QTextBrowser {{
                background-color: {surface_color}; color: {text_color}; border: 1px solid {border_color};
                border-radius: 8px; padding: 6px;
                font-family: Consolas, monospace; font-size: 13px;
            }}
            QTextBrowser::selection {{ background-color: {accent}; color: white; }}
        """)

        # 数据表格
        self.result_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {surface_color}; color: {text_color};
                border: 1px solid {border_color}; gridline-color: {border_color};
                border-radius: 8px;
                alternate-background-color: {alt_bg};
            }}
            QTableWidget::item {{ background-color: {surface_color}; color: {text_color}; padding: 6px; }}
            QTableWidget::item:alternate {{ background-color: {alt_bg}; }}
            QTableWidget::item:selected {{ background-color: {accent}; color: white; }}
            QHeaderView::section {{
                background-color: {header_bg}; color: {text_color};
                border: none; border-bottom: 1px solid {border_color}; padding: 7px;
            }}
        """)
        self.result_table.setAlternatingRowColors(True)

        self.output_stack.setStyleSheet(f"""
            QStackedWidget {{
                background-color: transparent;
                border: none;
            }}
        """)

        # Web视图
        webview_style = f"""
            QWebEngineView {{
                background-color: {surface_color};
                border: 1px solid {border_color};
                border-radius: 8px;
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
    @staticmethod
    def _core_command(task, *args):
        return [
            core_executable_path(),
            "--task", task,
            *args,
        ]

    @staticmethod
    def _combo_value(combo, values, default):
        index = combo.currentIndex()
        return values[index] if 0 <= index < len(values) else default

    @staticmethod
    def _scaled_bytes(value_text, unit_index):
        multipliers = [1, 1024, 1024 ** 2, 1024 ** 3]
        multiplier = multipliers[unit_index] if 0 <= unit_index < len(multipliers) else 1
        return int(value_text) * multiplier

    def _execute_task(self, task_type, *args, generate_graph=False, graph_name=None):
        base_cmd = self._core_command(task_type, *args)
        self.switchTo(self.results_interface)
        self.task_handler.execute_command(
            base_cmd,
            task_type=task_type,
            generate_graph=generate_graph,
            graph_name=graph_name,
        )

    def run_flow_sort(self):
        if not self.is_data_valid():
            return
        sort_type = self._combo_value(
            self.flow_sort_tab.sort_type_combo,
            ["total", "https", "outratio"],
            "total",
        )
        base_cmd = self._core_command("flow-sort", "--sort-type", sort_type)
        if sort_type == "outratio":
            base_cmd += ["--ratio-threshold", str(self.flow_sort_tab.ratio_threshold_spin.value())]
        self.switchTo(self.results_interface)
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
            base_cmd = self._core_command("compare-paths", "--src", src, "--dst", dst)
            self.switchTo(self.results_interface)
            self.task_handler.execute_command(base_cmd, task_type="compare-paths", generate_graph=True,
                                              graph_name="compare_paths")
        else:
            eng_type = self._combo_value(
                self.path_tab.path_type_combo,
                ["min-congestion", "min-hop", "min-risk"],
                "min-congestion",
            )
            self._execute_task(eng_type, "--src", src, "--dst", dst, generate_graph=True, graph_name=eng_type)

    def run_port_scan(self):
        if not self.is_data_valid():
            return
        tab = self.anomaly_tab.port_scan_tab
        args = [
            "--threshold", str(tab.threshold_spin.value()),
            "--ratio-threshold", str(tab.ratio_spin.value()),
        ]
        min_traffic_str = tab.min_traffic_edit.text().strip()
        if min_traffic_str:
            try:
                min_traffic = self._scaled_bytes(min_traffic_str, tab.min_traffic_unit.currentIndex())
                args += ["--min-traffic", str(min_traffic)]
            except ValueError:
                QMessageBox.warning(self, tr("port_scan_warning_title", "警告"),
                                    tr("port_scan_min_traffic_int", "最小总流量必须为整数"))
                return
        self._execute_task("port-scan", *args, generate_graph=True, graph_name="port_scan")

    def run_ddos_detection(self):
        if not self.is_data_valid():
            return
        thr = self.anomaly_tab.ddos_tab.neighbor_spin.value()
        base_cmd = self._core_command(
            "ddos-target",
            "--threshold", str(thr),
            "--in-ratio-threshold", str(self.anomaly_tab.ddos_tab.in_ratio_spin.value()),
        )
        traffic_str = self.anomaly_tab.ddos_tab.traffic_edit.text().strip()
        if traffic_str:
            try:
                val = self._scaled_bytes(traffic_str, self.anomaly_tab.ddos_tab.traffic_unit.currentIndex())
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
        self._execute_task("star-structures", "--threshold", str(thr), generate_graph=True, graph_name="star")

    def generate_subgraph(self):
        if not self.is_data_valid():
            return
        ip = self.subgraph_tab.ip_edit.text().strip()
        if not ip:
            QMessageBox.warning(self, tr("subgraph_warning_title", "警告"),
                                tr("subgraph_need_target_ip", "请输入目标IP"))
            return
        self.log_text.append(tr("subgraph_generating", "正在生成以 {} 为中心的子图...").format(ip))
        self._execute_task("subgraph", "--target", ip, generate_graph=True, graph_name="subgraph")

    def run_custom_rule(self):
        if not self.is_data_valid():
            return
        tab = self.custom_rule_tab
        rule_target = tab.target_ip_edit.text().strip()
        if not rule_target:
            QMessageBox.warning(self, tr("custom_rule_warning_title", "警告"),
                                tr("custom_rule_need_target_ip", "请输入目标IP"))
            return

        base_cmd = self._core_command("custom-rule", "--rule-target", rule_target)

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
        eng_rule_type = self._combo_value(tab.rule_type_combo, ["deny", "allow"], "deny")
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
                val = self._scaled_bytes(max_traffic_str, tab.max_traffic_unit.currentIndex())
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
        box = MessageBox(
            tr("about", "关于"),
            tr(
                "about_content",
                "网络流量分析与异常检测系统\n"
                "华中科技大学网络空间安全学院 - 程序设计综合课程设计\n"
                "版本 1.0 | 2026年3月\n"
                "基于 C++、PyQt6 和 PyQt-Fluent-Widgets\n"
                "©2026 那，边。版权所有。"
            ),
            self
        )
        box.yesButton.setText(tr("ok", "确定"))
        box.cancelButton.hide()
        box.exec()

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
