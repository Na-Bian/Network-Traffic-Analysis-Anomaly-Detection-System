# gui/main_window.py
import ipaddress
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
    ComboBox as FluentComboBox,
    FluentIcon as FIF,
    DropDownPushButton,
    HeaderCardWidget,
    LineEdit as FluentLineEdit,
    MSFluentWindow,
    MessageBox,
    NavigationItemPosition,
    Pivot,
    PushButton,
    RoundMenu,
    ScrollArea,
    SpinBox as FluentSpinBox,
    StrongBodyLabel,
    TableWidget,
    Theme,
    TitleLabel,
    TransparentToolButton,
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
            html {
                background-color: #1e1e1e !important;
            }
            body {
                background-color: #1e1e1e !important;
                color: #e0e0e0 !important;
            }
            .container {
                background-color: #2d2d2d !important;
                box-shadow: 0 10px 30px rgba(0,0,0,0.5) !important;
            }
            h1, h2, h3, p, li, ol, ul, strong, span, div {
                color: inherit !important;
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
            h2 {
                background: linear-gradient(90deg, rgba(49, 105, 196, 0.22), transparent) !important;
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
            tr:nth-child(odd) {
                background-color: #2d2d2d !important;
            }
            code {
                background-color: #3c3c3c !important;
                color: #f08d49 !important;
                border-color: #666 !important;
            }
            pre {
                background-color: #161b22 !important;
                color: #dfe7f3 !important;
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
            .shortcut {
                background-color: #343c47 !important;
                color: #dce6f3 !important;
                border-color: #4c5969 !important;
            }
            .footer {
                color: #888888 !important;
                border-top-color: #454545 !important;
            }
            hr {
                border-top-color: #454545 !important;
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


def _patch_ms_navigation_bar_metrics():
    """Keep MSFluentWindow navigation content centered after increasing item height."""
    try:
        import qfluentwidgets.components.navigation.navigation_bar as nav_bar
    except Exception:
        return

    button_class = nav_bar.NavigationBarPushButton
    if getattr(button_class, "_network_analyzer_metrics_patch", False):
        return

    def centered_offset(self):
        return max(0, int((self.height() - 58) / 2))

    def indicator_rect(self):
        offset = centered_offset(self)
        return QRectF(0, 16 + offset, 4, 24)

    def draw_background(self, painter: QPainter):
        if self.isSelected or self.isAboutSelected:
            painter.setBrush(QColor(255, 255, 255, 42) if nav_bar.isDarkTheme() else Qt.GlobalColor.white)
            painter.drawRoundedRect(self.rect(), 5, 5)

            if not self.isAboutSelected:
                painter.setBrush(nav_bar.autoFallbackThemeColor(self.lightSelectedColor, self.darkSelectedColor))
                offset = centered_offset(self)
                if not self.isPressed:
                    painter.drawRoundedRect(0, 16 + offset, 4, 24, 2, 2)
                else:
                    painter.drawRoundedRect(0, 19 + offset, 4, 18, 2, 2)
        elif self.isPressed or self.isEnter:
            c = 255 if nav_bar.isDarkTheme() else 0
            alpha = 9 if self.isEnter else 6
            painter.setBrush(QColor(c, c, c, alpha))
            painter.drawRoundedRect(self.rect(), 5, 5)

    def draw_icon(self, painter: QPainter):
        if (self.isPressed or not self.isEnter) and not (self.isSelected or self.isAboutSelected):
            painter.setOpacity(0.6)
        if not self.isEnabled():
            painter.setOpacity(0.4)

        offset = centered_offset(self)
        icon_x = (self.width() - 20) / 2
        if self._isSelectedTextVisible:
            rect = QRectF(icon_x, 13 + offset, 20, 20)
        else:
            rect = QRectF(icon_x, 13 + offset + self.iconAni.offset, 20, 20)

        selected_icon = self._selectedIcon or self._icon
        if isinstance(selected_icon, nav_bar.FluentIconBase) and (self.isSelected or self.isAboutSelected):
            color = nav_bar.autoFallbackThemeColor(self.lightSelectedColor, self.darkSelectedColor)
            selected_icon.render(painter, rect, fill=color.name())
        elif self.isSelected or self.isAboutSelected:
            nav_bar.drawIcon(selected_icon, painter, rect)
        else:
            nav_bar.drawIcon(self._icon, painter, rect)

    def draw_text(self, painter: QPainter):
        if self.isSelected and not self._isSelectedTextVisible:
            return

        if self.isSelected or self.isAboutSelected:
            painter.setPen(nav_bar.autoFallbackThemeColor(self.lightSelectedColor, self.darkSelectedColor))
        else:
            painter.setPen(Qt.GlobalColor.white if nav_bar.isDarkTheme() else Qt.GlobalColor.black)

        painter.setFont(self.font())
        rect = QRect(0, 32 + centered_offset(self), self.width(), 26)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.text())

    button_class.indicatorRect = indicator_rect
    button_class._drawBackground = draw_background
    button_class._drawIcon = draw_icon
    button_class._drawText = draw_text
    button_class._network_analyzer_metrics_patch = True


_patch_fluent_popup_composition()
_patch_ms_navigation_bar_metrics()


class MainWindow(MSFluentWindow):
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
        self.quick_card_texts = []
        self.dashboard_metric_texts = []
        self.dashboard_current_file_name = None
        self.dashboard_status_key = "dashboard_ready"
        self.dashboard_status_default = "等待导入数据"

        # 导出 actions
        self.export_pcap_csv_action = None
        self.export_full_graph_json_action = None
        self.export_full_graph_html_action = None
        self.export_subgraph_json_action = None
        self.export_subgraph_html_action = None
        self.full_graph_menu = None
        self.subgraph_menu = None
        self.export_command_button = None
        self.open_command_button = None
        self.manual_command_button = None
        self.title_back_button = None

        self.task_handler = TaskHandler(self)  # 任务处理器

        self.init_ui()
        self.update_webview_theme(tr("waiting_data", "等待分析数据..."))
        QApplication.instance().paletteChanged.connect(self.on_palette_changed)
        qconfig.themeChangedFinished.connect(self._refresh_theme_visuals)
        lang_mgr.language_changed.connect(self.retranslate_ui)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._centered_on_first_show:
            self._centered_on_first_show = True
            QTimer.singleShot(0, self.center_on_screen)
        QTimer.singleShot(0, self._refresh_theme_visuals)
        QTimer.singleShot(0, self._refresh_titlebar_layout)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._refresh_titlebar_layout()
        self._refresh_dashboard_headline_metrics()

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
        if self.open_command_button:
            self.open_command_button.setText(tr("open_file", "打开数据文件"))
        if self.export_command_button:
            self.export_command_button.setText(tr("export_menu", "导出"))
        if self.manual_command_button:
            self.manual_command_button.setText(tr("help_manual", "用户手册"))
        if self.title_back_button:
            self.title_back_button.setToolTip(tr("nav_back", "返回"))
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
        if hasattr(self, "render_card"):
            self.render_card.title_label.setText(tr("render_settings_title", "渲染控制"))
            self.render_card.subtitle_label.setText(
                tr("render_settings_desc", "根据图规模选择 vis-network 或 Sigma，并对超大图启用降载策略。")
            )

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
        self.results_interface.subtitle_label.setText(tr("results_subtitle", "查看任务输出"))
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
        self._retranslate_dashboard_cards()
        self._set_navigation_texts()
        self._refresh_quick_card_icons()
        self._refresh_compact_control_widths()
        self._refresh_dashboard_headline_metrics()

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
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.result_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.result_table.setWordWrap(False)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.verticalHeader().setDefaultSectionSize(40)
        self.result_table.horizontalHeader().setStretchLastSection(False)
        self.result_table.horizontalHeader().setHighlightSections(False)
        self.result_table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)

        self.result_detail = QTextBrowser()
        self.result_detail.setStyleSheet("font-family: Consolas, monospace; font-size: 13px;")

        self.web_view = QWebEngineView()
        settings = self.web_view.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, True)

        self._build_fluent_pages()
        self._apply_shell_polish()
        self._refresh_compact_control_widths()

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
        layout.setContentsMargins(40, 26, 40, 34)
        layout.setSpacing(18)

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
        layout.setContentsMargins(26, 22, 26, 24)
        layout.setSpacing(14)
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

    def _nav_label(self, key, default, short_key=None, short_default=None):
        if short_key and not hasattr(self.navigationInterface, "setExpandWidth"):
            return tr(short_key, short_default or default)
        return tr(key, default)

    def _set_navigation_texts(self):
        items = [
            (self.workbench_interface, self._nav_label("nav_workbench", "工作台", "nav_workbench_short", "工作台")),
            (self.topology_interface, self._nav_label("nav_topology", "拓扑视图", "nav_topology_short", "拓扑")),
            (self.traffic_interface, self._nav_label("traffic_sorting", "流量排序", "nav_traffic_short", "流量")),
            (self.path_interface, self._nav_label("path_search", "路径查找", "nav_path_short", "路径")),
            (self.anomaly_interface, self._nav_label("anomaly_detection", "异常检测", "nav_anomaly_short", "异常")),
            (self.rule_interface, self._nav_label("anomaly_tab_custom_rule", "自定义规则", "nav_rule_short", "规则")),
            (self.subgraph_interface,
             self._nav_label("subgraph_visualization", "子图可视化", "nav_subgraph_short", "子图")),
            (self.results_interface, self._nav_label("nav_results", "结果中心", "nav_results_short", "结果")),
            (self.settings_interface, self._nav_label("settings", "设置", "nav_settings_short", "设置")),
        ]
        for interface, text in items:
            item = self.navigationInterface.widget(interface.objectName())
            if item and hasattr(item, "setText"):
                item.setText(text)

    def _retranslate_dashboard_cards(self):
        if hasattr(self, "dashboard_command_title_label"):
            self.dashboard_command_title_label.setText(tr("dashboard_command_title", "开始分析"))
            self.dashboard_command_desc_label.setText(
                tr("dashboard_command_desc", "选择数据文件后，系统会自动生成全网拓扑并激活分析功能。")
            )
            self._refresh_dashboard_file_caption()
            self.dashboard_status_label.setText(
                tr(self.dashboard_status_key, self.dashboard_status_default)
            )

        for label, value, title_key, title_default, desc_key, desc_default in self.dashboard_metric_texts:
            label.setText(tr(title_key, title_default))
            value.setText(tr(desc_key, desc_default))

        for title_label, desc_label, button, title_key, title_default, desc_key, desc_default in self.quick_card_texts:
            title_label.setText(tr(title_key, title_default))
            desc_label.setText(tr(desc_key, desc_default))
            button.setText(tr("quick_open", "打开"))

    def _set_dashboard_status(self, key, default):
        self.dashboard_status_key = key
        self.dashboard_status_default = default
        if hasattr(self, "dashboard_status_label"):
            self.dashboard_status_label.setText(tr(key, default))

    def _refresh_dashboard_file_caption(self):
        if not hasattr(self, "dashboard_file_caption"):
            return

        file_name = self.dashboard_current_file_name or tr("dashboard_current_file_empty", "未选择文件")
        self.dashboard_file_caption.setText(
            tr("dashboard_current_file_display", "当前数据文件：{}").format(file_name)
        )

    def _set_dashboard_current_file(self, file_path=None):
        self.dashboard_current_file_name = os.path.basename(file_path) if file_path else None
        self._refresh_dashboard_file_caption()

    def _refresh_dashboard_headline_metrics(self):
        if not hasattr(self, "dashboard_headline_label"):
            return

        label = self.dashboard_headline_label
        text = label.text().strip()
        if not text:
            return

        available_width = label.maximumWidth()
        if hasattr(self, "dashboard_hero_text_container") and self.dashboard_hero_text_container.width() > 0:
            available_width = min(available_width, self.dashboard_hero_text_container.width())

        is_english = lang_mgr.current_lang == "en_US"
        label.setWordWrap(is_english)
        label.setMaximumWidth(760 if is_english else 880)

        base_size = 22 if is_english else 21
        min_size = 19 if is_english else 18

        font = label.font()
        if is_english:
            wrapped_font = QFont(font)
            wrapped_font.setPointSize(base_size)
            label.setFont(wrapped_font)
            return

        for point_size in range(base_size, min_size - 1, -1):
            test_font = QFont(font)
            test_font.setPointSize(point_size)
            if QFontMetrics(test_font).horizontalAdvance(text) <= max(320, available_width - 8):
                label.setFont(test_font)
                return

        fallback_font = QFont(font)
        fallback_font.setPointSize(min_size)
        label.setFont(fallback_font)

    def _refresh_compact_control_widths(self):
        fm = self.fontMetrics()

        def text_width(text):
            return fm.horizontalAdvance(text) + 1

        if self.theme_combo is not None:
            theme_texts = [self.theme_combo.itemText(i) for i in range(self.theme_combo.count())]
            combo_width = max((text_width(text) for text in theme_texts), default=120) + 58
            self.theme_combo.setFixedWidth(max(148, min(220, combo_width)))

        if self.thread_spin is not None:
            max_threads = max(1, os.cpu_count() or 1)
            spin_width = text_width(str(max_threads)) + 88
            self.thread_spin.setFixedWidth(max(110, min(148, spin_width)))

        for button in (self.lang_zh_cn_btn, self.lang_zh_tw_btn, self.lang_en_btn):
            if button is None:
                continue
            button.setMinimumWidth(max(106, min(156, text_width(button.text()) + 34)))

        if self.manual_btn is not None:
            self.manual_btn.setMinimumWidth(max(110, min(154, text_width(self.manual_btn.text()) + 44)))
        if self.about_btn is not None:
            self.about_btn.setMinimumWidth(max(92, min(132, text_width(self.about_btn.text()) + 44)))

        if self.open_command_button is not None:
            self.open_command_button.setFixedWidth(max(152, min(214, text_width(self.open_command_button.text()) + 62)))
        if self.export_command_button is not None:
            self.export_command_button.setFixedWidth(
                max(118, min(156, text_width(self.export_command_button.text()) + 76)))
        if self.manual_command_button is not None:
            self.manual_command_button.setFixedWidth(
                max(140, min(198, text_width(self.manual_command_button.text()) + 62)))

    def _create_metric_card(self, parent_layout, icon, title_key, title_default, desc_key, desc_default):
        card = CardWidget()
        card.setObjectName("dashboardMetricCard")
        card.setMinimumHeight(96)
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout = QHBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        icon_label = QLabel()
        icon_label.setFixedSize(30, 30)
        icon_label.setPixmap(icon.icon(theme=Theme.DARK if isDarkTheme() else Theme.LIGHT).pixmap(28, 28))
        layout.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)
        self.quick_card_icons.append((icon_label, icon))

        text_layout = QVBoxLayout()
        text_layout.setSpacing(3)
        title_label = StrongBodyLabel(tr(title_key, title_default))
        title_label.setWordWrap(True)
        value_label = CaptionLabel(tr(desc_key, desc_default))
        value_label.setWordWrap(True)
        text_layout.addWidget(title_label)
        text_layout.addWidget(value_label)
        layout.addLayout(text_layout, 1)
        parent_layout.addWidget(card)
        self.dashboard_metric_texts.append(
            (title_label, value_label, title_key, title_default, desc_key, desc_default)
        )
        return card

    def _add_quick_card(self, parent_layout, icon, title, description, button_text, target,
                        title_key=None, title_default=None, desc_key=None, desc_default=None):
        card = CardWidget()
        card.setObjectName("dashboardQuickCard")
        card.setMinimumHeight(126)
        layout = QHBoxLayout(card)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(16)

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
        if title_key and desc_key:
            self.quick_card_texts.append(
                (title_label, desc_label, button, title_key, title_default or title, desc_key,
                 desc_default or description)
            )
        return card

    def _refresh_quick_card_icons(self):
        theme = Theme.DARK if isDarkTheme() else Theme.LIGHT
        for label, icon in self.quick_card_icons:
            label.setPixmap(icon.icon(theme=theme).pixmap(30, 30))

    def _refresh_theme_visuals(self):
        self._apply_window_effects()
        self.update_webview_theme()
        self.update_log_detail_theme()
        self._refresh_titlebar_theme()
        self._refresh_navigation_visuals()
        self._refresh_quick_card_icons()
        self.update()

    def _apply_shell_polish(self):
        if hasattr(self, "titleBar") and self.titleBar is not None:
            self.titleBar.setFixedHeight(48)
            if hasattr(self.titleBar, "hBoxLayout"):
                self.titleBar.hBoxLayout.setContentsMargins(20, 0, 14, 0)
                self.titleBar.hBoxLayout.setSpacing(0)
            if hasattr(self.titleBar, "iconLabel"):
                self.titleBar.iconLabel.setFixedSize(18, 18)
            if hasattr(self.titleBar, "titleLabel"):
                self.titleBar.titleLabel.setStyleSheet(
                    "font-size: 13px; font-weight: 600; background: transparent;"
                )
                self.titleBar.titleLabel.setContentsMargins(12, 0, 12, 0)
                self.titleBar.titleLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
            self._ensure_titlebar_back_button()

        self._refresh_titlebar_layout()

        if hasattr(self, "navigationInterface") and self.navigationInterface is not None:
            nav = self.navigationInterface
            if hasattr(nav, "setExpandWidth"):
                nav.setExpandWidth(244)
                nav.setMinimumExpandWidth(196)
                nav.expand(useAni=False)
            else:
                nav.setMinimumWidth(112)
                nav.setMaximumWidth(128)
            self._refresh_navigation_visuals()

    def _ensure_titlebar_back_button(self):
        if self.title_back_button is not None or not hasattr(self.titleBar, "hBoxLayout"):
            return

        self.title_back_button = TransparentToolButton(FIF.LEFT_ARROW, self.titleBar)
        self.title_back_button.setObjectName("titleBackButton")
        self.title_back_button.setToolTip(tr("nav_back", "返回"))
        self.title_back_button.setFixedSize(38, 38)
        self.title_back_button.clicked.connect(self._go_back_to_workbench)
        self.titleBar.hBoxLayout.insertWidget(0, self.title_back_button, 0, Qt.AlignmentFlag.AlignVCenter)

    def _go_back_to_workbench(self):
        if self.workbench_interface is not None:
            self.switchTo(self.workbench_interface)

    def _refresh_titlebar_layout(self):
        if not hasattr(self, "titleBar") or self.titleBar is None or not hasattr(self.titleBar, "titleLabel"):
            return

        title_label = self.titleBar.titleLabel
        metrics = title_label.fontMetrics()
        natural_width = metrics.horizontalAdvance(title_label.text()) + 28
        available_width = max(220, self.width() - 340)
        title_label.setFixedWidth(min(natural_width, available_width))

    def _refresh_navigation_visuals(self):
        if not hasattr(self, "navigationInterface") or self.navigationInterface is None:
            return

        for interface in (
                self.workbench_interface,
                self.topology_interface,
                self.traffic_interface,
                self.path_interface,
                self.anomaly_interface,
                self.rule_interface,
                self.subgraph_interface,
                self.results_interface,
                self.settings_interface,
        ):
            item = self.navigationInterface.widget(interface.objectName())
            if not item:
                continue
            is_ms_nav = not hasattr(self.navigationInterface, "setExpandWidth")
            if is_ms_nav:
                item.setFixedSize(96, 76)
            else:
                item.setMinimumHeight(40)
            item.setProperty("isEnterEnabled", True)
            if hasattr(item, "setIconSize"):
                item.setIconSize(QSize(24, 24) if is_ms_nav else QSize(18, 18))
            item.setStyleSheet(
                "font-size: 13px; font-weight: 500; border-radius: 8px; padding: 6px 4px;"
            )

    def _refresh_titlebar_theme(self):
        if not hasattr(self, "titleBar") or self.titleBar is None:
            return

        dark = isDarkTheme()
        titlebar_bg = QColor("#1f1f1f" if dark else "#f8fbff")
        hover_bg = QColor("#2d2d2d" if dark else "#edf5ff")
        pressed_bg = QColor("#3a3a3a" if dark else "#dfeeff")
        text_color = QColor("#ffffff" if dark else "#000000")

        self.titleBar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.titleBar.setStyleSheet(
            f"background-color: {titlebar_bg.name()}; border: none;"
        )

        for button in (self.titleBar.minBtn, self.titleBar.maxBtn):
            button.setNormalBackgroundColor(titlebar_bg)
            button.setHoverBackgroundColor(hover_bg)
            button.setPressedBackgroundColor(pressed_bg)
            button.setNormalColor(text_color)
            button.setHoverColor(text_color)
            button.setPressedColor(text_color)

        self.titleBar.closeBtn.setNormalBackgroundColor(titlebar_bg)
        self.titleBar.closeBtn.setNormalColor(text_color)

    def _show_fluent_dialog(self, title, content, level="info"):
        box = MessageBox(title, content, self)
        box.yesButton.setText(tr("ok", "确定"))
        box.cancelButton.hide()
        box.hideCancelButton()
        box.setMinimumWidth(460)
        box.setContentCopyable(level == "error")

        if level == "success":
            box.yesButton.setText(tr("done", "完成"))
        elif level == "warning":
            box.yesButton.setText(tr("got_it", "知道了"))
        elif level == "error":
            box.yesButton.setText(tr("close", "关闭"))

        box.exec()

    def _show_warning_dialog(self, title, content):
        self._show_fluent_dialog(title, content, level="warning")

    def _show_error_dialog(self, title, content):
        self._show_fluent_dialog(title, content, level="error")

    def _show_success_dialog(self, title, content):
        self._show_fluent_dialog(title, content, level="success")

    def show_output_route(self, route_key):
        widgets = {
            "log": getattr(self, "log_text", None),
            "table": getattr(self, "result_table", None),
            "detail": getattr(self, "result_detail", None),
        }
        widget = widgets.get(route_key)
        if widget is None:
            return

        def apply_route():
            if hasattr(self, "output_stack") and self.output_stack is not None:
                self.output_stack.setCurrentWidget(widget)
            if hasattr(self, "output_pivot") and self.output_pivot is not None:
                self.output_pivot.setCurrentItem(route_key)

        apply_route()
        if hasattr(self, "results_interface") and self.results_interface is not None:
            self.switchTo(self.results_interface)
        QTimer.singleShot(0, apply_route)

    def configure_result_table(self, headers, width_weights=None):
        self.result_table.clear()
        self.result_table.setRowCount(0)
        self.result_table.setColumnCount(len(headers))
        self.result_table.setHorizontalHeaderLabels(headers)

        header = self.result_table.horizontalHeader()
        default_weights = width_weights or [1] * len(headers)
        total_weight = max(1, sum(default_weights))
        table_width = max(900, self.result_table.viewport().width(), self.width() - 420)

        for index, weight in enumerate(default_weights):
            width = int(table_width * weight / total_weight)
            header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
            self.result_table.setColumnWidth(index, max(110, width))

        if headers:
            last_index = len(headers) - 1
            header.setSectionResizeMode(last_index, QHeaderView.ResizeMode.Stretch)

    @staticmethod
    def centered_table_item(text):
        item = QTableWidgetItem(text)
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        return item

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
            tr("results_subtitle", "查看任务输出")
        )
        self.settings_interface = self._create_page(
            "settings",
            tr("settings", "设置"),
            tr("settings_subtitle", "语言、帮助和工程运行选项")
        )

        self.addSubInterface(
            self.workbench_interface, FIF.HOME,
            self._nav_label("nav_workbench", "工作台", "nav_workbench_short", "工作台")
        )
        self.addSubInterface(
            self.topology_interface, FIF.GLOBE,
            self._nav_label("nav_topology", "拓扑视图", "nav_topology_short", "拓扑")
        )
        self.addSubInterface(
            self.traffic_interface, FIF.SPEED_HIGH,
            self._nav_label("traffic_sorting", "流量排序", "nav_traffic_short", "流量")
        )
        self.addSubInterface(
            self.path_interface, FIF.CONNECT,
            self._nav_label("path_search", "路径查找", "nav_path_short", "路径")
        )
        self.addSubInterface(
            self.anomaly_interface, FIF.ROBOT,
            self._nav_label("anomaly_detection", "异常检测", "nav_anomaly_short", "异常")
        )
        self.addSubInterface(
            self.rule_interface, FIF.CODE,
            self._nav_label("anomaly_tab_custom_rule", "自定义规则", "nav_rule_short", "规则")
        )
        self.addSubInterface(
            self.subgraph_interface, FIF.SHARE,
            self._nav_label("subgraph_visualization", "子图可视化", "nav_subgraph_short", "子图")
        )
        self.addSubInterface(
            self.results_interface, FIF.DOCUMENT,
            self._nav_label("nav_results", "结果中心", "nav_results_short", "结果")
        )
        self.addSubInterface(
            self.settings_interface,
            FIF.SETTING,
            self._nav_label("settings", "设置", "nav_settings_short", "设置"),
            position=NavigationItemPosition.BOTTOM
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
        self._refresh_quick_card_icons()

    def _build_dashboard_page(self):
        layout = self.workbench_interface.page_layout

        dashboard_shell = QWidget()
        dashboard_shell.setObjectName("dashboardStartShell")
        shell_layout = QHBoxLayout(dashboard_shell)
        shell_layout.setContentsMargins(0, 18, 0, 0)
        shell_layout.setSpacing(0)

        command_card = CardWidget()
        command_card.setObjectName("dashboardActionPanel")
        command_card.setMinimumWidth(0)
        command_card.setMaximumWidth(16777215)
        command_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        command_layout = QVBoxLayout(command_card)
        command_layout.setContentsMargins(32, 30, 32, 30)
        command_layout.setSpacing(18)

        self.dashboard_command_title_label = TitleLabel(tr("dashboard_command_title", "开始分析"))
        self.dashboard_command_title_label.setObjectName("dashboardCommandTitle")
        self.dashboard_command_desc_label = BodyLabel(
            tr("dashboard_command_desc", "选择数据文件后，系统会自动生成全网拓扑并激活分析功能。")
        )
        self.dashboard_command_desc_label.setObjectName("dashboardCommandDesc")
        self.dashboard_command_desc_label.setWordWrap(True)
        command_layout.addWidget(self.dashboard_command_title_label)
        command_layout.addWidget(self.dashboard_command_desc_label)

        command_bar = QWidget()
        command_bar_layout = QHBoxLayout(command_bar)
        command_bar_layout.setContentsMargins(0, 0, 0, 0)
        command_bar_layout.setSpacing(12)
        self.open_command_button = PushButton(FIF.FOLDER, tr("open_file", "打开数据文件"))
        self.open_command_button.setObjectName("dashboardCommandButton")
        self.open_command_button.setFixedHeight(40)
        self.open_command_button.clicked.connect(self.browse_file)
        command_bar_layout.addWidget(self.open_command_button)
        self.export_command_button = DropDownPushButton(FIF.SAVE, tr("export_menu", "导出"))
        self.export_command_button.setObjectName("dashboardCommandButton")
        self.export_command_button.setMenu(self.export_menu)
        self.export_command_button.setFixedHeight(40)
        command_bar_layout.addWidget(self.export_command_button)
        self.manual_command_button = PushButton(FIF.HELP, tr("help_manual", "用户手册"))
        self.manual_command_button.setObjectName("dashboardCommandButton")
        self.manual_command_button.setFixedHeight(40)
        self.manual_command_button.clicked.connect(self.show_manual)
        command_bar_layout.addWidget(self.manual_command_button)
        command_bar_layout.addStretch()
        command_layout.addWidget(command_bar)

        file_layout = QHBoxLayout()
        file_layout.setSpacing(10)
        self.data_file_label = BodyLabel(tr("data_file", "数据文件:"))
        file_layout.addWidget(self.data_file_label)
        self.file_edit = FluentLineEdit()
        self.file_edit.setReadOnly(True)
        self.file_edit.setFixedHeight(42)
        file_layout.addWidget(self.file_edit, 1)
        self.browse_btn = PushButton(tr("browse", "浏览..."))
        self.browse_btn.clicked.connect(self.browse_file)
        self.browse_btn.setFixedHeight(40)
        file_layout.addWidget(self.browse_btn)
        command_layout.addLayout(file_layout)

        divider = QFrame()
        divider.setObjectName("dashboardDivider")
        divider.setFrameShape(QFrame.Shape.HLine)
        command_layout.addWidget(divider)

        status_layout = QHBoxLayout()
        status_layout.setSpacing(8)
        self.dashboard_file_caption = CaptionLabel()
        self.dashboard_file_caption.setObjectName("dashboardFileCaption")
        self.dashboard_status_label = StrongBodyLabel(tr("dashboard_ready", "等待导入数据"))
        self.dashboard_status_label.setObjectName("dashboardStatus")
        self._refresh_dashboard_file_caption()
        status_layout.addWidget(self.dashboard_file_caption)
        status_layout.addStretch()
        status_layout.addWidget(self.dashboard_status_label)
        command_layout.addLayout(status_layout)

        shell_layout.addWidget(command_card)
        layout.addWidget(dashboard_shell)

        metric_layout = QHBoxLayout()
        metric_layout.setSpacing(16)
        self._create_metric_card(
            metric_layout, FIF.GLOBE,
            "dashboard_metric_topology_title", "拓扑洞察",
            "dashboard_metric_topology_desc", "自动生成全网拓扑，支持大图渲染策略。"
        )
        self._create_metric_card(
            metric_layout, FIF.ROBOT,
            "dashboard_metric_detection_title", "异常检测",
            "dashboard_metric_detection_desc", "端口扫描、DDoS 和星型结构集中研判。"
        )
        self._create_metric_card(
            metric_layout, FIF.SAVE,
            "dashboard_metric_export_title", "结果导出",
            "dashboard_metric_export_desc", "导出 CSV、JSON 与 HTML，便于复盘展示。"
        )
        layout.addLayout(metric_layout)

        quick_layout = QVBoxLayout()
        quick_layout.setSpacing(16)
        self._add_quick_card(
            quick_layout, FIF.GLOBE,
            tr("quick_topology_title", "拓扑总览"),
            tr("quick_topology_desc", "查看自动生成的网络拓扑，并调整大图渲染策略。"),
            tr("quick_open", "打开"),
            self.topology_interface,
            "quick_topology_title", "拓扑总览",
            "quick_topology_desc", "查看自动生成的网络拓扑，并调整大图渲染策略。"
        )
        self._add_quick_card(
            quick_layout, FIF.ROBOT,
            tr("quick_anomaly_title", "异常研判"),
            tr("quick_anomaly_desc", "集中运行端口扫描、DDoS 和星型结构检测。"),
            tr("quick_open", "打开"),
            self.anomaly_interface,
            "quick_anomaly_title", "异常研判",
            "quick_anomaly_desc", "集中运行端口扫描、DDoS 和星型结构检测。"
        )
        self._add_quick_card(
            quick_layout, FIF.DOCUMENT,
            tr("quick_results_title", "结果中心"),
            tr("quick_results_desc", "查看运行日志、表格输出和路径详情。"),
            tr("quick_open", "打开"),
            self.results_interface,
            "quick_results_title", "结果中心",
            "quick_results_desc", "查看运行日志、表格输出和路径详情。"
        )
        layout.addLayout(quick_layout)
        layout.addStretch()

    def _build_topology_page(self):
        layout = self.topology_interface.page_layout
        self.render_card = self._create_card(
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
        self.render_card.card_layout.addLayout(render_layout)
        layout.addWidget(self.render_card)

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
        shell_card = CardWidget()
        shell_card.setObjectName("resultsShellCard")
        shell_layout = QVBoxLayout(shell_card)
        shell_layout.setContentsMargins(20, 18, 20, 20)
        shell_layout.setSpacing(14)
        self.output_pivot = Pivot()
        self.output_stack = QStackedWidget()
        self.output_stack.addWidget(self.log_text)
        self.output_stack.addWidget(self.result_table)
        self.output_stack.addWidget(self.result_detail)

        self.output_pivot.addItem("log", tr("output_log_tab", "运行日志"),
                                  lambda: self.output_stack.setCurrentWidget(self.log_text))
        self.output_pivot.addItem("table", tr("output_table_tab", "数据表格"),
                                  lambda: self.output_stack.setCurrentWidget(self.result_table))
        self.output_pivot.addItem("detail", tr("output_detail_tab", "路径与详情"),
                                  lambda: self.output_stack.setCurrentWidget(self.result_detail))
        self.output_pivot.setCurrentItem("log")
        self.output_stack.setCurrentWidget(self.log_text)

        shell_layout.addWidget(self.output_pivot)
        shell_layout.addWidget(self.output_stack, 1)
        layout.addWidget(shell_card, 1)

    def _build_settings_page(self):
        layout = self.settings_interface.page_layout
        self.theme_card = self._create_card(
            tr("settings_theme_title", "外观主题"),
            tr("settings_theme_desc", "手动切换浅色、深色，或跟随系统设置。")
        )
        self.theme_card.setObjectName("settingsPrimaryCard")
        theme_layout = QHBoxLayout()
        theme_layout.setSpacing(10)
        self.theme_label = BodyLabel(tr("settings_theme_label", "主题:"))
        self.theme_combo = FluentComboBox()
        self.theme_combo.addItem(tr("settings_theme_auto", "跟随系统"), "auto")
        self.theme_combo.addItem(tr("settings_theme_light", "浅色"), "light")
        self.theme_combo.addItem(tr("settings_theme_dark", "深色"), "dark")
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
        self.runtime_card.setObjectName("settingsSecondaryCard")
        runtime_layout = QHBoxLayout()
        runtime_layout.setSpacing(10)
        self.thread_label = BodyLabel(tr("thread_count", "线程数:"))
        runtime_layout.addWidget(self.thread_label)
        self.thread_spin = FluentSpinBox()
        max_threads = max(1, os.cpu_count() or 1)
        self.thread_spin.setRange(1, max_threads)
        self.thread_spin.setValue(min(4, max_threads))
        runtime_layout.addWidget(self.thread_spin)
        runtime_layout.addStretch()
        self.runtime_card.card_layout.addLayout(runtime_layout)
        layout.addWidget(self.runtime_card)

        self.language_card = self._create_card(
            tr("language", "语言 / Language"),
            tr("settings_language_desc", "语言切换会立即更新界面文本。")
        )
        self.language_card.setObjectName("settingsSecondaryCard")
        lang_layout = QHBoxLayout()
        lang_layout.setSpacing(10)
        self.lang_zh_cn_btn = PushButton(tr("lang_zh_CN", "简体中文"))
        self.lang_zh_tw_btn = PushButton(tr("lang_zh_TW", "繁体中文"))
        self.lang_en_btn = PushButton(tr("lang_en_US", "English"))
        for button in (self.lang_zh_cn_btn, self.lang_zh_tw_btn, self.lang_en_btn):
            button.setFixedHeight(30)
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
        self.help_card.setObjectName("settingsSecondaryCard")
        help_layout = QHBoxLayout()
        self.manual_btn = PushButton(FIF.HELP, tr("help_manual", "用户手册"))
        self.about_btn = PushButton(FIF.INFO, tr("about", "关于"))
        self.manual_btn.setFixedHeight(30)
        self.about_btn.setFixedHeight(30)
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

    def _apply_window_effects(self):
        """Enable Win11 Mica while keeping popup composition patched separately."""
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
        self._set_dashboard_current_file(file_path)
        self._set_dashboard_status("dashboard_loading", "正在准备数据")

        # 检查文件是否为空
        if os.path.getsize(file_path) == 0:
            self._show_warning_dialog(
                tr("invalid_data", "数据无效"),
                tr("empty_file", "选择的文件为空，无法加载！")
            )
            self.is_data_available = False
            self._set_dashboard_status("dashboard_invalid", "数据不可用")
            return

        ext = os.path.splitext(file_path)[1].lower()

        # ---------- 处理 JSON/HTML 可视化文件 ----------
        if ext in ['.json', '.html']:
            # 进入仅查看模式，禁用分析按钮
            self.set_view_only_mode(True)

            # 清除数据文件相关状态
            self.data_file = None
            self.file_edit.setText(file_path)
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
            self._set_dashboard_status("dashboard_view_only", "当前为仅查看模式")
            return

        # ---------- 原有 CSV/PCAP 处理（分析模式） ----------
        if ext == '.csv':
            new_path = self._convert_to_utf8_if_needed(file_path)
            if not os.path.exists(new_path) or os.path.getsize(new_path) == 0:
                self._show_warning_dialog(
                    tr("invalid_data", "数据无效"),
                    tr("encoding_conversion_failed", "文件编码转换失败，无法加载！")
                )
                self._set_dashboard_status("dashboard_invalid", "数据不可用")
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
        self._set_dashboard_status("dashboard_loaded", "数据已就绪")

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
                self._show_error_dialog(
                    tr("error", "错误"),
                    e
                ),
                setattr(self, 'is_data_available', False),
                self._set_dashboard_status("dashboard_invalid", "数据不可用")
            ]
        )
        self.pcap_worker.start()

    def export_pcap_csv(self):
        if not self.original_pcap_path or not self.converted_csv_path or not os.path.exists(self.converted_csv_path):
            self._show_warning_dialog(
                tr("export_error", "导出错误"),
                tr("no_pcap_converted_data", "没有可用的PCAP转换数据，请先加载PCAP文件并完成转换。")
            )
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
                self._show_success_dialog(
                    tr("export_success", "导出成功"),
                    tr("file_saved_to", "文件已保存到: {}").format(save_path)
                )
            except Exception as e:
                self._show_error_dialog(
                    tr("export_error", "导出错误"),
                    tr("save_failed", "保存失败: {}").format(e)
                )

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
            self._show_warning_dialog(
                tr("export_error", "导出错误"),
                tr("file_not_available", "要导出的文件不可用，请先生成对应图。")
            )
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
                self._show_success_dialog(
                    tr("export_success", "导出成功"),
                    tr("file_saved_to", "文件已保存到: {}").format(save_path)
                )
            except Exception as e:
                self._show_error_dialog(
                    tr("export_error", "导出错误"),
                    tr("save_failed", "保存失败: {}").format(e)
                )

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
                if getattr(self, "_suppress_next_empty_graph_notice", False):
                    self._suppress_next_empty_graph_notice = False
                else:
                    self._show_warning_dialog(
                        tr("empty_graph_title", "未找到可视化节点"),
                        tr(
                            "empty_graph_content",
                            "当前任务没有生成可视化节点。请检查数据文件是否包含有效 IP，或调整目标 IP、检测阈值后重试。"
                        )
                    )
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
        page_bg = "#1f1f1f" if dark else "#f4f8fc"
        scroll_bg = "transparent" if mica_enabled else bg_color
        surface_color = "#2a2d31" if dark else "#ffffff"
        card_color = "#32353a" if dark else "#f7f9fc"
        border_color = "#464b53" if dark else "#d7dde7"
        nav_bg = "#1d2026" if dark else "#f8fbff"
        nav_hover = "#2b3038" if dark else "#edf5ff"
        nav_pressed = "#343a44" if dark else "#dfeeff"
        nav_selected = "#263241" if dark else "#e4f1ff"
        hero_bg = "#262a30" if dark else "#f8fbff"
        panel_bg = "#2d3138" if dark else "#ffffff"
        subtle_text = "#c4c9d4" if dark else "#617082"
        header_bg = "#39404a" if dark else "#eef3fb"
        alt_bg = "#2f3339" if dark else "#f8fbff"
        hover_bg = "#3b414a" if dark else "#eef6ff"
        accent = "#0078d4"
        primary_bg = "#1780df" if dark else "#2a84e8"
        primary_hover = "#2a8ae7" if dark else "#4493ed"
        primary_pressed = "#076bc5" if dark else "#1f76d7"
        strong_text = "#f3f6fb" if dark else "#122033"

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
            NavigationInterface,
            NavigationPanel {{
                background-color: {nav_bg};
                border-right: 1px solid {border_color};
            }}
            NavigationWidget {{
                background-color: transparent;
                border-radius: 8px;
                margin: 3px 10px;
                padding-left: 10px;
                color: {text_color};
            }}
            NavigationWidget:hover {{
                background-color: {nav_hover};
            }}
            NavigationWidget:pressed {{
                background-color: {nav_pressed};
            }}
            NavigationWidget[isSelected=true] {{
                background-color: {nav_selected};
                font-weight: 600;
            }}
            CardWidget#dashboardHeroCard {{
                background-color: {hero_bg};
                border: 1px solid {border_color};
                border-radius: 14px;
            }}
            QWidget#dashboardStartShell {{
                background: transparent;
            }}
            CardWidget#dashboardActionPanel {{
                background-color: {panel_bg};
                border: 1px solid {border_color};
                border-radius: 8px;
            }}
            QFrame#dashboardDivider {{
                background-color: {border_color};
                min-height: 1px;
                max-height: 1px;
                border: none;
            }}
            CardWidget#dashboardMetricCard,
            CardWidget#dashboardQuickCard {{
                background-color: {surface_color};
                border: 1px solid {border_color};
                border-radius: 12px;
            }}
            CardWidget#settingsPrimaryCard {{
                background-color: {panel_bg};
                border: 1px solid {border_color};
                border-radius: 12px;
            }}
            CardWidget#settingsSecondaryCard {{
                background-color: {surface_color};
                border: 1px solid {border_color};
                border-radius: 12px;
            }}
            CardWidget#resultsShellCard {{
                background-color: {panel_bg};
                border: 1px solid {border_color};
                border-radius: 14px;
            }}
            CardWidget {{
                background-color: {surface_color};
                border: 1px solid {border_color};
                border-radius: 10px;
            }}
            QLabel#dashboardKicker {{
                color: {accent};
                font-size: 12px;
                font-weight: 600;
                letter-spacing: 0;
            }}
            TitleLabel {{
                color: {strong_text};
            }}
            QLabel#dashboardCommandTitle {{
                color: {strong_text};
                font-size: 28px;
                font-weight: 700;
            }}
            QLabel#dashboardCommandDesc {{
                color: {subtle_text};
                font-size: 14px;
            }}
            StrongBodyLabel {{
                color: {strong_text};
            }}
            QLabel#dashboardBody,
            QLabel#dashboardFileCaption {{
                color: {subtle_text};
            }}
            QLabel#dashboardStatus {{
                color: {accent};
                font-size: 14px;
                font-weight: 600;
            }}
            #dashboardCommandButton {{
                font-size: 13px;
                font-weight: 500;
            }}
            Pivot {{
                background: transparent;
                border: none;
            }}
            Pivot > QWidget {{
                background: transparent;
            }}
            qfluentwidgets--PivotItem {{
                padding: 8px 14px;
                border-radius: 8px;
                color: {subtle_text};
                background: transparent;
                font-weight: 500;
            }}
            qfluentwidgets--PivotItem:hover {{
                background-color: {hover_bg};
                color: {strong_text};
            }}
            qfluentwidgets--PivotItem[isSelected=true] {{
                background-color: {panel_bg};
                color: {strong_text};
                border: 1px solid {border_color};
                font-weight: 600;
            }}
            PushButton, PrimaryPushButton, DropDownPushButton {{
                min-height: 30px;
                border-radius: 7px;
                padding: 2px 10px;
                font-weight: 500;
            }}
            PrimaryPushButton {{
                background-color: {primary_bg};
                border: 1px solid {primary_bg};
                color: white;
            }}
            PrimaryPushButton:hover {{
                background-color: {primary_hover};
                border-color: {primary_hover};
            }}
            PrimaryPushButton:pressed {{
                background-color: {primary_pressed};
                border-color: {primary_pressed};
            }}
            LineEdit, ComboBox, SpinBox, DoubleSpinBox {{
                min-height: 32px;
                border-radius: 7px;
            }}
            HeaderCardWidget {{
                background-color: {surface_color};
                border: 1px solid {border_color};
                border-radius: 12px;
            }}
            HeaderCardWidget > QLabel {{
                color: {strong_text};
            }}
            PopUpAniStackedWidget CardWidget {{
                background-color: {surface_color};
                border: 1px solid {border_color};
                border-radius: 10px;
            }}
            QGroupBox {{
                background-color: {card_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 10px;
                margin-top: 14px;
                padding: 16px;
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

    def _show_invalid_input(self, content):
        self._show_warning_dialog(tr("invalid_input_title", "输入格式有误"), content)

    def _is_valid_ipv4(self, value, label):
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            self._show_invalid_input(
                tr("invalid_ipv4_format", "{} 格式不正确：{}。请输入完整 IPv4 地址，例如 192.168.1.100。").format(
                    label, value or tr("empty_value", "空值")
                )
            )
            return False

    def _is_valid_cidr(self, value):
        try:
            ipaddress.IPv4Network(value, strict=False)
            return True
        except ValueError:
            self._show_invalid_input(
                tr("invalid_cidr_format", "CIDR 范围格式不正确：{}。请输入类似 192.168.1.0/24 的 IPv4 网段。").format(
                    value or tr("empty_value", "空值")
                )
            )
            return False

    def _validate_ip_range(self, start, end):
        if not self._is_valid_ipv4(start, tr("custom_rule_start_ip_name", "起始IP")):
            return False
        if not self._is_valid_ipv4(end, tr("custom_rule_end_ip_name", "结束IP")):
            return False
        if int(ipaddress.IPv4Address(start)) > int(ipaddress.IPv4Address(end)):
            self._show_invalid_input(
                tr("invalid_ip_range_order", "起始 IP 不能大于结束 IP，请检查 IP 范围。")
            )
            return False
        return True

    def _parse_int_input(self, value_text, label, minimum=None, maximum=None):
        try:
            value = int(value_text)
        except ValueError:
            self._show_invalid_input(
                tr("invalid_integer_format", "{} 必须为整数。").format(label)
            )
            return None
        if minimum is not None and value < minimum:
            self._show_invalid_input(
                tr("invalid_integer_min", "{} 不能小于 {}。").format(label, minimum)
            )
            return None
        if maximum is not None and value > maximum:
            self._show_invalid_input(
                tr("invalid_integer_range", "{} 必须在 {} 到 {} 之间。").format(label, minimum, maximum)
            )
            return None
        return value

    def _parse_scaled_bytes_input(self, value_text, unit_index, label):
        value = self._parse_int_input(value_text, label, minimum=0)
        if value is None:
            return None
        multipliers = [1, 1024, 1024 ** 2, 1024 ** 3]
        multiplier = multipliers[unit_index] if 0 <= unit_index < len(multipliers) else 1
        return value * multiplier

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
            self._show_warning_dialog(
                tr("path_search_warning_title", "警告"),
                tr("path_search_need_src_dst", "请输入源IP和目的IP")
            )
            return
        if not self._is_valid_ipv4(src, tr("src_ip_name", "源IP")):
            return
        if not self._is_valid_ipv4(dst, tr("dst_ip_name", "目的IP")):
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
            min_traffic = self._parse_scaled_bytes_input(
                min_traffic_str,
                tab.min_traffic_unit.currentIndex(),
                tr("port_scan_min_traffic_name", "最小总流量")
            )
            if min_traffic is None:
                return
            args += ["--min-traffic", str(min_traffic)]
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
            val = self._parse_scaled_bytes_input(
                traffic_str,
                self.anomaly_tab.ddos_tab.traffic_unit.currentIndex(),
                tr("ddos_traffic_name", "入流量阈值")
            )
            if val is None:
                return
            base_cmd += ["--in-data-threshold", str(val)]
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
            self._show_warning_dialog(
                tr("subgraph_warning_title", "警告"),
                tr("subgraph_need_target_ip", "请输入目标IP")
            )
            return
        if not self._is_valid_ipv4(ip, tr("target_ip_name", "目标IP")):
            return
        self.log_text.append(tr("subgraph_generating", "正在生成以 {} 为中心的子图...").format(ip))
        self._execute_task("subgraph", "--target", ip, generate_graph=True, graph_name="subgraph")

    def run_custom_rule(self):
        if not self.is_data_valid():
            return
        tab = self.custom_rule_tab
        rule_target = tab.target_ip_edit.text().strip()
        if not rule_target:
            self._show_warning_dialog(
                tr("custom_rule_warning_title", "警告"),
                tr("custom_rule_need_target_ip", "请输入目标IP")
            )
            return
        if not self._is_valid_ipv4(rule_target, tr("target_ip_name", "目标IP")):
            return

        base_cmd = self._core_command("custom-rule", "--rule-target", rule_target)

        # 协议类型
        protocol_str = tab.protocol_edit.text().strip()
        if protocol_str:
            protocol_val = self._parse_int_input(
                protocol_str,
                tr("custom_rule_protocol_name", "协议类型"),
                minimum=0,
                maximum=255
            )
            if protocol_val is None:
                return
            base_cmd += ["--rule-protocol", str(protocol_val)]

        # 规则类型
        eng_rule_type = self._combo_value(tab.rule_type_combo, ["deny", "allow"], "deny")
        base_cmd += ["--rule-type", eng_rule_type]

        # IP范围
        if tab.radio_cidr.isChecked():
            cidr = tab.cidr_edit.text().strip()
            if not cidr:
                self._show_warning_dialog(
                    tr("custom_rule_warning_title", "警告"),
                    tr("custom_rule_need_cidr", "请输入CIDR范围")
                )
                return
            if not self._is_valid_cidr(cidr):
                return
            base_cmd += ["--range-cidr", cidr]
        else:
            start = tab.start_ip_edit.text().strip()
            end = tab.end_ip_edit.text().strip()
            if not start or not end:
                self._show_warning_dialog(
                    tr("custom_rule_warning_title", "警告"),
                    tr("custom_rule_need_start_end", "请输入起始IP和结束IP")
                )
                return
            if not self._validate_ip_range(start, end):
                return
            base_cmd += ["--range-start", start, "--range-end", end]

        # 源端口
        src_port = tab.src_port_edit.text().strip()
        if src_port:
            parsed_port = self._parse_int_input(src_port, tr("custom_rule_src_port_name", "源端口"), minimum=0,
                                                maximum=65535)
            if parsed_port is None:
                return
            base_cmd += ["--rule-src-port", str(parsed_port)]

        # 目的端口
        dst_port = tab.dst_port_edit.text().strip()
        if dst_port:
            parsed_port = self._parse_int_input(dst_port, tr("custom_rule_dst_port_name", "目的端口"), minimum=0,
                                                maximum=65535)
            if parsed_port is None:
                return
            base_cmd += ["--rule-dst-port", str(parsed_port)]

        # 最大流量阈值
        max_traffic_str = tab.max_traffic_edit.text().strip()
        if max_traffic_str:
            val = self._parse_scaled_bytes_input(
                max_traffic_str,
                tab.max_traffic_unit.currentIndex(),
                tr("custom_rule_max_traffic_name", "最大流量阈值")
            )
            if val is None:
                return
            base_cmd += ["--rule-max-traffic", str(val)]

        self.task_handler.execute_command(base_cmd, task_type="custom-rule", generate_graph=True,
                                          graph_name="custom_rule")

    def is_data_valid(self):
        if self.view_only_mode:
            self._show_warning_dialog(
                tr("invalid_data", "数据无效"),
                tr("view_only_mode_no_analysis", "当前处于可视化查看模式，无法进行分析操作。")
            )
            return False

        # 原有检查（数据文件存在、大小、有效性等）
        if not self.data_file or not os.path.exists(self.data_file):
            self._show_warning_dialog(
                tr("invalid_data", "数据无效"),
                tr("data_not_loaded", "未加载任何数据文件，请先加载有效数据！")
            )
            return False

        if os.path.getsize(self.data_file) == 0:
            self._show_warning_dialog(
                tr("invalid_data", "数据无效"),
                tr("empty_file", "加载的文件为空，请重试！")
            )
            self.is_data_available = False
            return False

        if not self.is_data_available:
            self._show_warning_dialog(
                tr("invalid_data", "数据无效"),
                tr("no_valid_network_data", "加载的文件无有效网络流量数据，请重试！")
            )
            return False

        return True

    def about(self):
        dark = isDarkTheme()
        bg = "#1f1f1f" if dark else "#f5f7fb"
        border = "#464b53" if dark else "#d7dde7"
        subtle = "#c4c9d4" if dark else "#627183"
        strong = "#f3f6fb" if dark else "#122033"
        accent = "#0078d4"

        dialog = QDialog(self)
        dialog.setWindowTitle(tr("about", "关于"))
        dialog.resize(720, 430)
        dialog.setWindowIcon(QIcon(resource_path("resources/icon.ico")))

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 18, 24, 18)
        layout.setSpacing(18)

        dialog.setStyleSheet(f"""
            QDialog {{
                background-color: {bg};
                color: {strong};
            }}
            QLabel#aboutName {{
                color: {strong};
                font-size: 21px;
                font-weight: 600;
            }}
            QLabel#aboutBuild, QLabel#aboutParagraph {{
                color: {strong};
                font-size: 13px;
            }}
            QLabel#aboutMuted {{
                color: {subtle};
                font-size: 13px;
            }}
            QLabel#aboutLink {{
                color: {accent};
                font-size: 13px;
            }}
            QFrame#aboutDivider {{
                background-color: {border};
                min-height: 1px;
                max-height: 1px;
            }}
            PushButton {{
                min-height: 32px;
                padding: 2px 16px;
            }}
        """)

        top_row = QHBoxLayout()
        top_row.setSpacing(18)

        icon_label = QLabel()
        icon_label.setFixedSize(96, 96)
        icon = QIcon(resource_path("resources/icon.ico"))
        icon_label.setPixmap(icon.pixmap(88, 88))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
        top_row.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)

        text_col = QVBoxLayout()
        text_col.setSpacing(10)

        name_label = QLabel(tr("app_title", "网络流量分析与异常检测系统"))
        name_label.setObjectName("aboutName")
        build_label = QLabel(tr("about_version", "版本 2.1 | 2026年4月"))
        build_label.setObjectName("aboutBuild")
        build_label.setWordWrap(True)

        subtitle_label = QLabel(tr("about_subtitle", "华中科技大学网络空间安全学院 · 程序设计综合课程设计"))
        subtitle_label.setObjectName("aboutParagraph")
        subtitle_label.setWordWrap(True)

        intro_label = QLabel(tr("about_intro", "一个面向课程设计与工程化演示的网络流量分析桌面应用。"))
        intro_label.setObjectName("aboutMuted")
        intro_label.setWordWrap(True)

        stack_label = QLabel(
            f"{tr('about_stack_label', '技术栈')}: {tr('about_stack_value', 'C++ · PyQt6 · PyQt-Fluent-Widgets')}"
        )
        stack_label.setObjectName("aboutParagraph")
        stack_label.setWordWrap(True)

        focus_label = QLabel(
            f"{tr('about_focus_label', '定位')}: {tr('about_focus_value', '网络流量分析、异常检测与拓扑可视化')}"
        )
        focus_label.setObjectName("aboutParagraph")
        focus_label.setWordWrap(True)

        github_label = QLabel(
            f"GitHub: <a href=\"https://github.com/Na-Bian/Network-Traffic-Analysis-Anomaly-Detection-System\" "
            f"style=\"color:{accent}; text-decoration:none;\">"
            "Na-Bian/Network-Traffic-Analysis-Anomaly-Detection-System</a>"
        )
        github_label.setObjectName("aboutLink")
        github_label.setTextFormat(Qt.TextFormat.RichText)
        github_label.setOpenExternalLinks(True)
        github_label.setWordWrap(True)

        copyright_label = QLabel(tr("about_copyright_value", "©2026 那，边。版权所有。"))
        copyright_label.setObjectName("aboutMuted")
        copyright_label.setWordWrap(True)

        text_col.addWidget(name_label)
        text_col.addWidget(build_label)
        text_col.addSpacing(6)
        text_col.addWidget(subtitle_label)
        text_col.addWidget(intro_label)
        text_col.addSpacing(4)
        text_col.addWidget(stack_label)
        text_col.addWidget(focus_label)
        text_col.addWidget(github_label)
        text_col.addStretch()
        text_col.addWidget(copyright_label)
        top_row.addLayout(text_col, 1)
        layout.addLayout(top_row)

        divider = QFrame()
        divider.setObjectName("aboutDivider")
        layout.addWidget(divider)

        footer = QHBoxLayout()
        footer.addStretch()
        copy_close_btn = PushButton(tr("about_copy_and_close", "复制并关闭"))
        copy_close_btn.setFixedWidth(132)
        copy_close_btn.clicked.connect(
            lambda: (
                QApplication.clipboard().setText(
                    "\n".join([
                        tr("app_title", "网络流量分析与异常检测系统"),
                        tr("about_version", "版本 2.1 | 2026年4月"),
                        tr("about_subtitle", "华中科技大学网络空间安全学院 · 程序设计综合课程设计"),
                        tr("about_intro", "一个面向课程设计与工程化演示的网络流量分析桌面应用。"),
                        f"{tr('about_stack_label', '技术栈')}: {tr('about_stack_value', 'C++ · PyQt6 · PyQt-Fluent-Widgets')}",
                        f"{tr('about_focus_label', '定位')}: {tr('about_focus_value', '网络流量分析、异常检测与拓扑可视化')}",
                        "GitHub: https://github.com/Na-Bian/Network-Traffic-Analysis-Anomaly-Detection-System",
                        tr("about_copyright_value", "©2026 那，边。版权所有。"),
                    ])
                ),
                dialog.accept(),
            )
        )
        footer.addWidget(copy_close_btn)
        close_btn = PushButton(tr("close", "关闭"))
        close_btn.setFixedWidth(104)
        close_btn.clicked.connect(dialog.accept)
        footer.addWidget(close_btn)

        layout.addLayout(footer)
        dialog.exec()

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
            self._show_error_dialog(
                tr("error", "错误"),
                tr("manual_load_failed", "无法加载用户手册: {}").format(e)
            )
            return

        # 获取当前主题颜色并生成适配样式
        bg_color, text_color = get_theme_colors()
        is_dark = isDarkTheme()
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
        dialog.setStyleSheet(
            f"background-color: {'#1f1f1f' if is_dark else '#f5f7fb'}; color: {text_color};"
        )
        layout = QVBoxLayout(dialog)
        web_view = QWebEngineView()
        web_view.setHtml(html_content)
        layout.addWidget(web_view)
        dialog.exec()
