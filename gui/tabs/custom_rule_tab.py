# gui/tabs/custom_rule_tab.py
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QScrollArea, QWidget, QGridLayout, QLabel, QLineEdit,
                             QGroupBox, QVBoxLayout, QHBoxLayout, QRadioButton, QComboBox, QPushButton, QSizePolicy)

from ..translator import tr


class CustomRuleTab(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        content = QWidget()
        layout = QGridLayout(content)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)

        # 目标IP (行0)
        layout.addWidget(QLabel(tr("custom_rule_target_ip_label", "目标IP:")), 0, 0)
        self.target_ip_edit = QLineEdit()
        self.target_ip_edit.setPlaceholderText(tr("custom_rule_target_ip_placeholder", "例如：192.168.1.100"))
        self.target_ip_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.target_ip_edit, 0, 1, 1, 2)

        # IP范围组 (行1)
        self.range_group = QGroupBox(tr("custom_rule_ip_range_group", "IP范围"))
        range_layout = QVBoxLayout(self.range_group)
        range_layout.setContentsMargins(3, 3, 3, 3)
        range_layout.setSpacing(2)

        self.radio_cidr = QRadioButton(tr("custom_rule_radio_cidr", "CIDR"))
        self.radio_cidr.setChecked(True)
        self.radio_cidr.toggled.connect(self.on_range_toggled)
        range_layout.addWidget(self.radio_cidr)

        self.cidr_edit = QLineEdit()
        self.cidr_edit.setPlaceholderText(tr("custom_rule_cidr_placeholder", "例如：192.168.1.0/24"))
        range_layout.addWidget(self.cidr_edit)

        self.radio_start_end = QRadioButton(tr("custom_rule_radio_start_end", "起始IP - 结束IP"))
        range_layout.addWidget(self.radio_start_end)

        start_end_layout = QHBoxLayout()
        start_end_layout.setContentsMargins(0, 0, 0, 0)
        start_end_layout.setSpacing(2)
        self.start_ip_edit = QLineEdit()
        self.start_ip_edit.setPlaceholderText(tr("custom_rule_start_ip_placeholder", "起始IP"))
        self.start_ip_edit.setEnabled(False)
        self.start_ip_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        start_end_layout.addWidget(self.start_ip_edit)
        start_end_layout.addWidget(QLabel(tr("custom_rule_to_label", "至")))
        self.end_ip_edit = QLineEdit()
        self.end_ip_edit.setPlaceholderText(tr("custom_rule_end_ip_placeholder", "结束IP"))
        self.end_ip_edit.setEnabled(False)
        self.end_ip_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        start_end_layout.addWidget(self.end_ip_edit)
        range_layout.addLayout(start_end_layout)

        layout.addWidget(self.range_group, 1, 0, 1, 3)

        # 可选参数组 (行2)
        self.optional_group = QGroupBox(tr("custom_rule_optional_group", "可选参数"))
        optional_layout = QGridLayout(self.optional_group)
        optional_layout.setContentsMargins(3, 3, 3, 3)
        optional_layout.setSpacing(2)

        # 协议类型
        optional_layout.addWidget(QLabel(tr("custom_rule_protocol_label", "协议类型:")), 0, 0)
        self.protocol_edit = QLineEdit()
        self.protocol_edit.setPlaceholderText(tr("custom_rule_protocol_placeholder", "例如：6 (TCP)"))
        self.protocol_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        optional_layout.addWidget(self.protocol_edit, 0, 1)

        # 源端口
        optional_layout.addWidget(QLabel(tr("custom_rule_src_port_label", "源端口:")), 1, 0)
        self.src_port_edit = QLineEdit()
        self.src_port_edit.setPlaceholderText(tr("custom_rule_src_port_placeholder", "例如：443"))
        self.src_port_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        optional_layout.addWidget(self.src_port_edit, 1, 1)

        # 目的端口
        optional_layout.addWidget(QLabel(tr("custom_rule_dst_port_label", "目的端口:")), 2, 0)
        self.dst_port_edit = QLineEdit()
        self.dst_port_edit.setPlaceholderText(tr("custom_rule_dst_port_placeholder", "例如：80"))
        self.dst_port_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        optional_layout.addWidget(self.dst_port_edit, 2, 1)

        # 最大流量阈值
        optional_layout.addWidget(QLabel(tr("custom_rule_max_traffic_label", "最大流量阈值:")), 3, 0)
        max_traffic_hbox = QHBoxLayout()
        self.max_traffic_edit = QLineEdit()
        self.max_traffic_edit.setPlaceholderText(tr("custom_rule_max_traffic_placeholder", "例如：1024"))
        self.max_traffic_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        max_traffic_hbox.addWidget(self.max_traffic_edit)

        self.max_traffic_unit = QComboBox()
        self.max_traffic_unit.addItems([
            tr("custom_rule_unit_bytes", "字节"), "KB", "MB", "GB"
        ])
        self.max_traffic_unit.setCurrentIndex(1)
        max_traffic_hbox.addWidget(self.max_traffic_unit)

        optional_layout.addLayout(max_traffic_hbox, 3, 1)

        layout.addWidget(self.optional_group, 2, 0, 1, 3)

        # 规则类型 (行3)
        layout.addWidget(QLabel(tr("custom_rule_type_label", "规则类型:")), 3, 0)
        self.rule_type_combo = QComboBox()
        self.rule_type_combo.addItems([
            tr("custom_rule_type_deny", "拒绝"),
            tr("custom_rule_type_allow", "允许")
        ])
        self.rule_type_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.rule_type_combo, 3, 1, 1, 2)

        # 检测按钮 (行4)
        self.detect_btn = QPushButton(tr("custom_rule_button", "检测违规记录"))
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.detect_btn, 4, 0, 1, 3)

        layout.setColumnStretch(1, 1)
        self.setWidget(content)

    def on_range_toggled(self):
        if self.radio_cidr.isChecked():
            self.cidr_edit.setEnabled(True)
            self.start_ip_edit.setEnabled(False)
            self.end_ip_edit.setEnabled(False)
        else:
            self.cidr_edit.setEnabled(False)
            self.start_ip_edit.setEnabled(True)
            self.end_ip_edit.setEnabled(True)
