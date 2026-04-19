# gui/tabs/anomaly_tabs.py
from PyQt6.QtCore import QSignalBlocker
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget, QSizePolicy
from qfluentwidgets import BodyLabel, ComboBox, DoubleSpinBox, LineEdit, Pivot, PrimaryPushButton, SpinBox

from ..translator import tr


class PortScanTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(8)

        threshold_row = QHBoxLayout()
        self.threshold_label = BodyLabel()
        threshold_row.addWidget(self.threshold_label)
        self.threshold_spin = SpinBox()
        self.threshold_spin.setRange(1, 1000)
        self.threshold_spin.setValue(20)
        self.threshold_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        threshold_row.addWidget(self.threshold_spin)
        layout.addLayout(threshold_row)
        ratio_row = QHBoxLayout()
        self.ratio_label = BodyLabel()
        ratio_row.addWidget(self.ratio_label)
        self.ratio_spin = DoubleSpinBox()
        self.ratio_spin.setRange(0.0, 1.0)
        self.ratio_spin.setValue(0.8)
        self.ratio_spin.setSingleStep(0.05)
        self.ratio_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        ratio_row.addWidget(self.ratio_spin)
        layout.addLayout(ratio_row)

        traffic_row = QHBoxLayout()
        self.min_traffic_label = BodyLabel()
        traffic_row.addWidget(self.min_traffic_label)
        self.min_traffic_edit = LineEdit()
        self.min_traffic_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        traffic_row.addWidget(self.min_traffic_edit)
        self.min_traffic_unit = ComboBox()
        self.min_traffic_unit.setCurrentIndex(1)
        traffic_row.addWidget(self.min_traffic_unit)
        layout.addLayout(traffic_row)

        self.detect_btn = PrimaryPushButton()
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.detect_btn)
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
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(8)

        neighbor_row = QHBoxLayout()
        self.neighbor_label = BodyLabel()
        neighbor_row.addWidget(self.neighbor_label)
        self.neighbor_spin = SpinBox()
        self.neighbor_spin.setRange(1, 1000)
        self.neighbor_spin.setValue(20)
        self.neighbor_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        neighbor_row.addWidget(self.neighbor_spin)
        layout.addLayout(neighbor_row)

        traffic_row = QHBoxLayout()
        self.traffic_label = BodyLabel()
        traffic_row.addWidget(self.traffic_label)
        self.traffic_edit = LineEdit()
        self.traffic_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        traffic_row.addWidget(self.traffic_edit)

        self.traffic_unit = ComboBox()
        self.traffic_unit.setCurrentIndex(2)
        traffic_row.addWidget(self.traffic_unit)
        layout.addLayout(traffic_row)

        ratio_row = QHBoxLayout()
        self.in_ratio_label = BodyLabel()
        ratio_row.addWidget(self.in_ratio_label)
        self.in_ratio_spin = DoubleSpinBox()
        self.in_ratio_spin.setRange(0.0, 1.0)
        self.in_ratio_spin.setValue(0.8)
        self.in_ratio_spin.setSingleStep(0.05)
        self.in_ratio_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        ratio_row.addWidget(self.in_ratio_spin)
        layout.addLayout(ratio_row)

        self.detect_btn = PrimaryPushButton()
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.detect_btn)
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
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(8)

        threshold_row = QHBoxLayout()
        self.threshold_label = BodyLabel()
        threshold_row.addWidget(self.threshold_label)
        self.threshold_spin = SpinBox()
        self.threshold_spin.setRange(1, 1000)
        self.threshold_spin.setValue(20)
        self.threshold_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        threshold_row.addWidget(self.threshold_spin)
        layout.addLayout(threshold_row)

        self.detect_btn = PrimaryPushButton()
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.detect_btn)
        self.retranslate_ui()

    def retranslate_ui(self):
        self.threshold_label.setText(tr("star_threshold_label", "叶子节点数阈值:"))
        self.detect_btn.setText(tr("star_button", "检测"))


class AnomalyTab(QWidget):
    """包含端口扫描、DDoS、星型结构的容器选项卡"""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)

        self.pivot = Pivot()
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
