# gui/tabs/anomaly_tabs.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QSpinBox,
                             QLineEdit, QComboBox, QPushButton, QTabWidget, QSizePolicy, QDoubleSpinBox)

from ..translator import tr


class PortScanTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(8)

        threshold_row = QHBoxLayout()
        threshold_row.addWidget(QLabel(tr("port_scan_threshold_label", "端口数阈值:")))
        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(1, 1000)
        self.threshold_spin.setValue(20)
        self.threshold_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        threshold_row.addWidget(self.threshold_spin)
        layout.addLayout(threshold_row)
        ratio_row = QHBoxLayout()
        ratio_row.addWidget(QLabel(tr("outratio_threshold_label", "出流量占比阈值:")))
        self.ratio_spin = QDoubleSpinBox()
        self.ratio_spin.setRange(0.0, 1.0)
        self.ratio_spin.setValue(0.8)
        self.ratio_spin.setSingleStep(0.05)
        self.ratio_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        ratio_row.addWidget(self.ratio_spin)
        layout.addLayout(ratio_row)

        self.detect_btn = QPushButton(tr("port_scan_button", "检测"))
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.detect_btn)


class DDosTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(8)

        neighbor_row = QHBoxLayout()
        neighbor_row.addWidget(QLabel(tr("ddos_neighbor_threshold_label", "邻居数阈值:")))
        self.neighbor_spin = QSpinBox()
        self.neighbor_spin.setRange(1, 1000)
        self.neighbor_spin.setValue(20)
        self.neighbor_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        neighbor_row.addWidget(self.neighbor_spin)
        layout.addLayout(neighbor_row)

        traffic_row = QHBoxLayout()
        traffic_row.addWidget(QLabel(tr("ddos_traffic_threshold_label", "入流量阈值:")))
        self.traffic_edit = QLineEdit()
        self.traffic_edit.setPlaceholderText(tr("ddos_traffic_placeholder", "例如：1024"))
        self.traffic_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        traffic_row.addWidget(self.traffic_edit)

        self.traffic_unit = QComboBox()
        self.traffic_unit.addItems([
            tr("ddos_unit_bytes", "字节"), "KB", "MB", "GB"
        ])
        self.traffic_unit.setCurrentIndex(2)
        traffic_row.addWidget(self.traffic_unit)
        layout.addLayout(traffic_row)

        self.detect_btn = QPushButton(tr("ddos_button", "检测"))
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.detect_btn)


class StarTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(8)

        threshold_row = QHBoxLayout()
        threshold_row.addWidget(QLabel(tr("star_threshold_label", "叶子节点数阈值:")))
        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(1, 1000)
        self.threshold_spin.setValue(20)
        self.threshold_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        threshold_row.addWidget(self.threshold_spin)
        layout.addLayout(threshold_row)

        self.detect_btn = QPushButton(tr("star_button", "检测"))
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.detect_btn)


class AnomalyTab(QWidget):
    """包含端口扫描、DDoS、星型结构的容器选项卡"""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)

        self.tab_widget = QTabWidget()
        self.port_scan_tab = PortScanTab()
        self.ddos_tab = DDosTab()
        self.star_tab = StarTab()

        self.tab_widget.addTab(self.port_scan_tab, tr("anomaly_tab_port_scan", "端口扫描"))
        self.tab_widget.addTab(self.ddos_tab, tr("anomaly_tab_ddos", "DDoS目标"))
        self.tab_widget.addTab(self.star_tab, tr("anomaly_tab_star", "星型结构"))

        layout.addWidget(self.tab_widget)
