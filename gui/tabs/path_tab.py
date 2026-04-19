# gui/tabs/path_tab.py
from PyQt6.QtCore import QSignalBlocker
from PyQt6.QtWidgets import QWidget, QGridLayout, QSizePolicy
from qfluentwidgets import BodyLabel, CheckBox, ComboBox, LineEdit, PrimaryPushButton

from ..translator import tr


class PathTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setHorizontalSpacing(18)
        layout.setVerticalSpacing(14)

        self.path_type_label = BodyLabel()
        self.path_type_label.setMinimumWidth(130)
        layout.addWidget(self.path_type_label, 0, 0)
        self.path_type_combo = ComboBox()
        self.path_type_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.path_type_combo.setMinimumHeight(38)
        layout.addWidget(self.path_type_combo, 0, 1)

        self.src_ip_label = BodyLabel()
        self.src_ip_label.setMinimumWidth(130)
        layout.addWidget(self.src_ip_label, 1, 0)
        self.path_src_edit = LineEdit()
        self.path_src_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.path_src_edit.setMinimumHeight(38)
        layout.addWidget(self.path_src_edit, 1, 1)

        self.dst_ip_label = BodyLabel()
        self.dst_ip_label.setMinimumWidth(130)
        layout.addWidget(self.dst_ip_label, 2, 0)
        self.path_dst_edit = LineEdit()
        self.path_dst_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.path_dst_edit.setMinimumHeight(38)
        layout.addWidget(self.path_dst_edit, 2, 1)

        self.compare_checkbox = CheckBox()
        self.compare_checkbox.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.compare_checkbox.toggled.connect(self.on_compare_toggled)
        self.compare_checkbox.setContentsMargins(0, 4, 0, 2)
        layout.addWidget(self.compare_checkbox, 3, 0, 1, 2)

        self.path_btn = PrimaryPushButton()
        self.path_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.path_btn.setMinimumHeight(40)
        layout.addWidget(self.path_btn, 4, 0, 1, 2)

        layout.setColumnStretch(1, 1)
        self.retranslate_ui()

    def on_compare_toggled(self, checked):
        self.path_type_combo.setEnabled(not checked)

    def retranslate_ui(self):
        current_index = self.path_type_combo.currentIndex()
        self.path_type_label.setText(tr("path_type_label", "路径类型:"))
        with QSignalBlocker(self.path_type_combo):
            self.path_type_combo.clear()
            self.path_type_combo.addItems([
                tr("path_min_congestion", "最小拥塞"),
                tr("path_min_hop", "最小跳数"),
                tr("path_min_risk", "最小风险")
            ])
            if current_index >= 0:
                self.path_type_combo.setCurrentIndex(min(current_index, self.path_type_combo.count() - 1))
        self.src_ip_label.setText(tr("src_ip_label", "源IP:"))
        self.dst_ip_label.setText(tr("dst_ip_label", "目的IP:"))
        self.compare_checkbox.setText(tr("compare_strategies_checkbox", "对比三种策略"))
        self.path_btn.setText(tr("path_search_button", "查找路径"))
