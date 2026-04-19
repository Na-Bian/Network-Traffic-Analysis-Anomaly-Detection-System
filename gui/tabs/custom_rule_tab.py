# gui/tabs/custom_rule_tab.py
from PyQt6.QtCore import QSignalBlocker
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QWidget, QGridLayout, QGroupBox, QVBoxLayout, QHBoxLayout, QSizePolicy
from qfluentwidgets import BodyLabel, ComboBox, LineEdit, PrimaryPushButton, RadioButton

from ..translator import tr


def _emphasize_primary_button(button):
    font = QFont(button.font())
    font.setPointSize(max(font.pointSize(), 11))
    font.setWeight(QFont.Weight.DemiBold)
    button.setFont(font)


class CustomRuleTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("customRuleContent")

        layout = QGridLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setHorizontalSpacing(18)
        layout.setVerticalSpacing(14)

        # 目标IP (行0)
        self.target_ip_label = BodyLabel()
        self.target_ip_label.setMinimumWidth(130)
        layout.addWidget(self.target_ip_label, 0, 0)
        self.target_ip_edit = LineEdit()
        self.target_ip_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.target_ip_edit.setMinimumHeight(38)
        layout.addWidget(self.target_ip_edit, 0, 1, 1, 2)

        # IP范围组 (行1)
        self.range_group = QGroupBox()
        range_layout = QVBoxLayout(self.range_group)
        range_layout.setContentsMargins(18, 18, 18, 18)
        range_layout.setSpacing(12)

        self.radio_cidr = RadioButton()
        self.radio_cidr.setChecked(True)
        self.radio_cidr.toggled.connect(self.on_range_toggled)
        range_layout.addWidget(self.radio_cidr)

        self.cidr_edit = LineEdit()
        self.cidr_edit.setMinimumHeight(38)
        range_layout.addWidget(self.cidr_edit)

        self.radio_start_end = RadioButton()
        range_layout.addWidget(self.radio_start_end)

        start_end_layout = QHBoxLayout()
        start_end_layout.setContentsMargins(0, 0, 0, 0)
        start_end_layout.setSpacing(10)
        self.start_ip_edit = LineEdit()
        self.start_ip_edit.setEnabled(False)
        self.start_ip_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.start_ip_edit.setMinimumHeight(38)
        start_end_layout.addWidget(self.start_ip_edit)
        self.to_label = BodyLabel()
        start_end_layout.addWidget(self.to_label)
        self.end_ip_edit = LineEdit()
        self.end_ip_edit.setEnabled(False)
        self.end_ip_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.end_ip_edit.setMinimumHeight(38)
        start_end_layout.addWidget(self.end_ip_edit)
        range_layout.addLayout(start_end_layout)

        layout.addWidget(self.range_group, 1, 0, 1, 3)

        # 可选参数组 (行2)
        self.optional_group = QGroupBox()
        optional_layout = QGridLayout(self.optional_group)
        optional_layout.setContentsMargins(18, 18, 18, 18)
        optional_layout.setHorizontalSpacing(18)
        optional_layout.setVerticalSpacing(12)

        # 协议类型
        self.protocol_label = BodyLabel()
        self.protocol_label.setMinimumWidth(130)
        optional_layout.addWidget(self.protocol_label, 0, 0)
        self.protocol_edit = LineEdit()
        self.protocol_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.protocol_edit.setMinimumHeight(38)
        optional_layout.addWidget(self.protocol_edit, 0, 1)

        # 源端口
        self.src_port_label = BodyLabel()
        self.src_port_label.setMinimumWidth(130)
        optional_layout.addWidget(self.src_port_label, 1, 0)
        self.src_port_edit = LineEdit()
        self.src_port_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.src_port_edit.setMinimumHeight(38)
        optional_layout.addWidget(self.src_port_edit, 1, 1)

        # 目的端口
        self.dst_port_label = BodyLabel()
        self.dst_port_label.setMinimumWidth(130)
        optional_layout.addWidget(self.dst_port_label, 2, 0)
        self.dst_port_edit = LineEdit()
        self.dst_port_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.dst_port_edit.setMinimumHeight(38)
        optional_layout.addWidget(self.dst_port_edit, 2, 1)

        # 最大流量阈值
        self.max_traffic_label = BodyLabel()
        self.max_traffic_label.setMinimumWidth(130)
        optional_layout.addWidget(self.max_traffic_label, 3, 0)
        max_traffic_hbox = QHBoxLayout()
        max_traffic_hbox.setContentsMargins(0, 0, 0, 0)
        max_traffic_hbox.setSpacing(10)
        self.max_traffic_edit = LineEdit()
        self.max_traffic_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.max_traffic_edit.setMinimumHeight(38)
        max_traffic_hbox.addWidget(self.max_traffic_edit)

        self.max_traffic_unit = ComboBox()
        self.max_traffic_unit.setMinimumHeight(38)
        self.max_traffic_unit.setMinimumWidth(92)
        self.max_traffic_unit.setCurrentIndex(1)
        max_traffic_hbox.addWidget(self.max_traffic_unit)

        optional_layout.addLayout(max_traffic_hbox, 3, 1)

        layout.addWidget(self.optional_group, 2, 0, 1, 3)

        # 规则类型 (行3)
        self.rule_type_label = BodyLabel()
        self.rule_type_label.setMinimumWidth(130)
        layout.addWidget(self.rule_type_label, 3, 0)
        self.rule_type_combo = ComboBox()
        self.rule_type_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.rule_type_combo.setMinimumHeight(38)
        layout.addWidget(self.rule_type_combo, 3, 1, 1, 2)

        self.rule_semantics_label = BodyLabel()
        self.rule_semantics_label.setWordWrap(True)
        layout.addWidget(self.rule_semantics_label, 4, 0, 1, 3)

        # 检测按钮 (行5)
        self.detect_btn = PrimaryPushButton()
        self.detect_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.detect_btn.setMinimumHeight(40)
        _emphasize_primary_button(self.detect_btn)
        layout.addWidget(self.detect_btn, 5, 0, 1, 3)

        layout.setColumnStretch(1, 1)
        self.retranslate_ui()

    def on_range_toggled(self):
        if self.radio_cidr.isChecked():
            self.cidr_edit.setEnabled(True)
            self.start_ip_edit.setEnabled(False)
            self.end_ip_edit.setEnabled(False)
        else:
            self.cidr_edit.setEnabled(False)
            self.start_ip_edit.setEnabled(True)
            self.end_ip_edit.setEnabled(True)

    def retranslate_ui(self):
        rule_type_index = self.rule_type_combo.currentIndex()
        max_traffic_unit_index = self.max_traffic_unit.currentIndex()

        self.target_ip_label.setText(tr("custom_rule_target_ip_label", "目标IP:"))
        self.target_ip_edit.setPlaceholderText(tr("custom_rule_target_ip_placeholder", "例如：192.168.1.100"))
        self.range_group.setTitle(tr("custom_rule_ip_range_group", "IP范围"))
        self.radio_cidr.setText(tr("custom_rule_radio_cidr", "CIDR"))
        self.cidr_edit.setPlaceholderText(tr("custom_rule_cidr_placeholder", "例如：192.168.1.0/24"))
        self.radio_start_end.setText(tr("custom_rule_radio_start_end", "起始IP - 结束IP"))
        self.start_ip_edit.setPlaceholderText(tr("custom_rule_start_ip_placeholder", "起始IP"))
        self.to_label.setText(tr("custom_rule_to_label", "至"))
        self.end_ip_edit.setPlaceholderText(tr("custom_rule_end_ip_placeholder", "结束IP"))

        self.optional_group.setTitle(tr("custom_rule_optional_group", "可选参数"))
        self.protocol_label.setText(tr("custom_rule_protocol_label", "协议类型:"))
        self.protocol_edit.setPlaceholderText(tr("custom_rule_protocol_placeholder", "例如：6 (TCP)"))
        self.src_port_label.setText(tr("custom_rule_src_port_label", "源端口:"))
        self.src_port_edit.setPlaceholderText(tr("custom_rule_src_port_placeholder", "例如：443"))
        self.dst_port_label.setText(tr("custom_rule_dst_port_label", "目的端口:"))
        self.dst_port_edit.setPlaceholderText(tr("custom_rule_dst_port_placeholder", "例如：80"))
        self.max_traffic_label.setText(tr("custom_rule_max_traffic_label", "最大流量阈值:"))
        self.max_traffic_edit.setPlaceholderText(tr("custom_rule_max_traffic_placeholder", "例如：1024"))
        with QSignalBlocker(self.max_traffic_unit):
            self.max_traffic_unit.clear()
            self.max_traffic_unit.addItems([tr("custom_rule_unit_bytes", "字节"), "KB", "MB", "GB"])
            self.max_traffic_unit.setCurrentIndex(max_traffic_unit_index if max_traffic_unit_index >= 0 else 1)

        self.rule_type_label.setText(tr("custom_rule_type_label", "规则类型:"))
        with QSignalBlocker(self.rule_type_combo):
            self.rule_type_combo.clear()
            self.rule_type_combo.addItems([
                tr("custom_rule_type_deny", "拒绝"),
                tr("custom_rule_type_allow", "允许")
            ])
            if rule_type_index >= 0:
                self.rule_type_combo.setCurrentIndex(min(rule_type_index, self.rule_type_combo.count() - 1))
        self.rule_semantics_label.setText(
            tr("custom_rule_semantics_hint", "IP范围、协议和端口会作为组合条件匹配；拒绝规则命中即违规，允许规则未命中即违规。")
        )
        self.detect_btn.setText(tr("custom_rule_button", "检测违规记录"))
