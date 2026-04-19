# gui/tabs/anomaly_tabs.py
from PyQt6.QtCore import QSignalBlocker
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QGridLayout, QStackedWidget, QSizePolicy
from qfluentwidgets import BodyLabel, ComboBox, DoubleSpinBox, LineEdit, Pivot, PrimaryPushButton, SpinBox

from ..translator import tr


def _emphasize_primary_button(button):
    font = QFont(button.font())
    font.setPointSize(max(font.pointSize(), 11))
    font.setWeight(QFont.Weight.DemiBold)
    button.setFont(font)


class PortScanTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setHorizontalSpacing(18)
        layout.setVerticalSpacing(14)

        self.threshold_label = BodyLabel()
        self.threshold_label.setMinimumWidth(130)
        layout.addWidget(self.threshold_label, 0, 0)
        self.threshold_spin = SpinBox()
        self.threshold_spin.setRange(1, 1000)
        self.threshold_spin.setValue(20)
        self.threshold_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.threshold_spin.setMinimumHeight(38)
        layout.addWidget(self.threshold_spin, 0, 1, 1, 2)

        self.ratio_label = BodyLabel()
        self.ratio_label.setMinimumWidth(130)
        layout.addWidget(self.ratio_label, 1, 0)
        self.ratio_spin = DoubleSpinBox()
        self.ratio_spin.setRange(0.0, 1.0)
        self.ratio_spin.setValue(0.8)
        self.ratio_spin.setSingleStep(0.05)
        self.ratio_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.ratio_spin.setMinimumHeight(38)
        layout.addWidget(self.ratio_spin, 1, 1, 1, 2)

        self.min_traffic_label = BodyLabel()
        self.min_traffic_label.setMinimumWidth(130)
        layout.addWidget(self.min_traffic_label, 2, 0)
        self.min_traffic_edit = LineEdit()
        self.min_traffic_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.min_traffic_edit.setMinimumHeight(38)
        layout.addWidget(self.min_traffic_edit, 2, 1)
        self.min_traffic_unit = ComboBox()
        self.min_traffic_unit.setMinimumHeight(38)
        self.min_traffic_unit.setCurrentIndex(1)
        self.min_traffic_unit.setMinimumWidth(92)
        layout.addWidget(self.min_traffic_unit, 2, 2)

        self.detect_btn = PrimaryPushButton()
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.detect_btn.setMinimumHeight(40)
        _emphasize_primary_button(self.detect_btn)
        layout.addWidget(self.detect_btn, 3, 0, 1, 3)
        layout.setColumnStretch(1, 1)
        self.retranslate_ui()

    def retranslate_ui(self):
        unit_index = self.min_traffic_unit.currentIndex()
        self.threshold_label.setText(tr("port_scan_threshold_label", "端口数阈值:"))
        self.ratio_label.setText(tr("outratio_threshold_label", "出流量占比阈值:"))
        self.min_traffic_label.setText(tr("port_scan_min_traffic_label", "最小总流量:"))
        self.min_traffic_edit.setPlaceholderText(tr("port_scan_min_traffic_placeholder", "留空表示不限制"))
        with QSignalBlocker(self.min_traffic_unit):
            self.min_traffic_unit.clear()
            self.min_traffic_unit.addItems([tr("ddos_unit_bytes", "字节"), "KB", "MB", "GB"])
            self.min_traffic_unit.setCurrentIndex(unit_index if unit_index >= 0 else 1)
        self.detect_btn.setText(tr("port_scan_button", "检测"))


class DDosTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setHorizontalSpacing(18)
        layout.setVerticalSpacing(14)

        self.neighbor_label = BodyLabel()
        self.neighbor_label.setMinimumWidth(130)
        layout.addWidget(self.neighbor_label, 0, 0)
        self.neighbor_spin = SpinBox()
        self.neighbor_spin.setRange(1, 1000)
        self.neighbor_spin.setValue(20)
        self.neighbor_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.neighbor_spin.setMinimumHeight(38)
        layout.addWidget(self.neighbor_spin, 0, 1, 1, 2)

        self.traffic_label = BodyLabel()
        self.traffic_label.setMinimumWidth(130)
        layout.addWidget(self.traffic_label, 1, 0)
        self.traffic_edit = LineEdit()
        self.traffic_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.traffic_edit.setMinimumHeight(38)
        layout.addWidget(self.traffic_edit, 1, 1)

        self.traffic_unit = ComboBox()
        self.traffic_unit.setMinimumHeight(38)
        self.traffic_unit.setMinimumWidth(92)
        self.traffic_unit.setCurrentIndex(2)
        layout.addWidget(self.traffic_unit, 1, 2)

        self.in_ratio_label = BodyLabel()
        self.in_ratio_label.setMinimumWidth(130)
        layout.addWidget(self.in_ratio_label, 2, 0)
        self.in_ratio_spin = DoubleSpinBox()
        self.in_ratio_spin.setRange(0.0, 1.0)
        self.in_ratio_spin.setValue(0.8)
        self.in_ratio_spin.setSingleStep(0.05)
        self.in_ratio_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.in_ratio_spin.setMinimumHeight(38)
        layout.addWidget(self.in_ratio_spin, 2, 1, 1, 2)

        self.detect_btn = PrimaryPushButton()
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.detect_btn.setMinimumHeight(40)
        _emphasize_primary_button(self.detect_btn)
        layout.addWidget(self.detect_btn, 3, 0, 1, 3)
        layout.setColumnStretch(1, 1)
        self.retranslate_ui()

    def retranslate_ui(self):
        unit_index = self.traffic_unit.currentIndex()
        self.neighbor_label.setText(tr("ddos_neighbor_threshold_label", "邻居数阈值:"))
        self.traffic_label.setText(tr("ddos_traffic_threshold_label", "入流量阈值:"))
        self.traffic_edit.setPlaceholderText(tr("ddos_traffic_placeholder", "例如：1024"))
        self.in_ratio_label.setText(tr("ddos_in_ratio_threshold_label", "入流量占比阈值:"))
        with QSignalBlocker(self.traffic_unit):
            self.traffic_unit.clear()
            self.traffic_unit.addItems([tr("ddos_unit_bytes", "字节"), "KB", "MB", "GB"])
            self.traffic_unit.setCurrentIndex(unit_index if unit_index >= 0 else 2)
        self.detect_btn.setText(tr("ddos_button", "检测"))


class StarTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setHorizontalSpacing(18)
        layout.setVerticalSpacing(14)

        self.threshold_label = BodyLabel()
        self.threshold_label.setMinimumWidth(130)
        layout.addWidget(self.threshold_label, 0, 0)
        self.threshold_spin = SpinBox()
        self.threshold_spin.setRange(1, 1000)
        self.threshold_spin.setValue(20)
        self.threshold_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.threshold_spin.setMinimumHeight(38)
        layout.addWidget(self.threshold_spin, 0, 1)

        self.detect_btn = PrimaryPushButton()
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.detect_btn.setMinimumHeight(40)
        _emphasize_primary_button(self.detect_btn)
        layout.addWidget(self.detect_btn, 1, 0, 1, 2)
        layout.setColumnStretch(1, 1)
        self.retranslate_ui()

    def retranslate_ui(self):
        self.threshold_label.setText(tr("star_threshold_label", "叶子节点数阈值:"))
        self.detect_btn.setText(tr("star_button", "检测"))


class AnomalyTab(QWidget):
    """包含端口扫描、DDoS、星型结构的容器选项卡"""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(10)

        self.pivot = Pivot()
        self.pivot.setItemFontSize(15)
        self.pivot.setContentsMargins(0, 2, 0, 6)
        self.stack_widget = QStackedWidget()
        self.port_scan_tab = PortScanTab()
        self.ddos_tab = DDosTab()
        self.star_tab = StarTab()

        self.stack_widget.addWidget(self.port_scan_tab)
        self.stack_widget.addWidget(self.ddos_tab)
        self.stack_widget.addWidget(self.star_tab)

        self.pivot.addItem("port_scan", tr("anomaly_tab_port_scan", "端口扫描"),
                           lambda: self.stack_widget.setCurrentWidget(self.port_scan_tab))
        self.pivot.addItem("ddos", tr("anomaly_tab_ddos", "DDoS目标"),
                           lambda: self.stack_widget.setCurrentWidget(self.ddos_tab))
        self.pivot.addItem("star", tr("anomaly_tab_star", "星型结构"),
                           lambda: self.stack_widget.setCurrentWidget(self.star_tab))
        self.pivot.setCurrentItem("port_scan")
        self.stack_widget.setCurrentWidget(self.port_scan_tab)

        layout.addWidget(self.pivot)
        layout.addWidget(self.stack_widget)

    def retranslate_ui(self):
        self.port_scan_tab.retranslate_ui()
        self.ddos_tab.retranslate_ui()
        self.star_tab.retranslate_ui()
        self.pivot.setItemText("port_scan", tr("anomaly_tab_port_scan", "端口扫描"))
        self.pivot.setItemText("ddos", tr("anomaly_tab_ddos", "DDoS目标"))
        self.pivot.setItemText("star", tr("anomaly_tab_star", "星型结构"))
