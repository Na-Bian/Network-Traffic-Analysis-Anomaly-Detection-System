# gui/tabs/path_tab.py
from PyQt6.QtWidgets import QWidget, QGridLayout, QLabel, QComboBox, QLineEdit, QCheckBox, QPushButton, QSizePolicy

from ..translator import tr


class PathTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)

        layout.addWidget(QLabel(tr("path_type_label", "路径类型:")), 0, 0)
        self.path_type_combo = QComboBox()
        self.path_type_combo.addItems([
            tr("path_min_congestion", "最小拥塞"),
            tr("path_min_hop", "最小跳数"),
            tr("path_min_risk", "最小风险")
        ])
        self.path_type_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.path_type_combo, 0, 1)

        layout.addWidget(QLabel(tr("src_ip_label", "源IP:")), 1, 0)
        self.path_src_edit = QLineEdit()
        self.path_src_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.path_src_edit, 1, 1)

        layout.addWidget(QLabel(tr("dst_ip_label", "目的IP:")), 2, 0)
        self.path_dst_edit = QLineEdit()
        self.path_dst_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.path_dst_edit, 2, 1)

        self.compare_checkbox = QCheckBox(tr("compare_strategies_checkbox", "对比三种策略"))
        self.compare_checkbox.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.compare_checkbox.toggled.connect(self.on_compare_toggled)
        layout.addWidget(self.compare_checkbox, 3, 0, 1, 2)

        self.path_btn = QPushButton(tr("path_search_button", "查找路径"))
        self.path_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.path_btn, 4, 0, 1, 2)

        layout.setColumnStretch(1, 1)

    def on_compare_toggled(self, checked):
        self.path_type_combo.setEnabled(not checked)
