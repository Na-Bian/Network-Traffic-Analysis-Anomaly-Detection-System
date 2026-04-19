# gui/tabs/subgraph_tab.py
from PyQt6.QtWidgets import QWidget, QGridLayout, QSizePolicy
from qfluentwidgets import BodyLabel, LineEdit, PrimaryPushButton

from ..translator import tr


class SubgraphTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setHorizontalSpacing(18)
        layout.setVerticalSpacing(14)

        self.target_ip_label = BodyLabel()
        self.target_ip_label.setMinimumWidth(130)
        layout.addWidget(self.target_ip_label, 0, 0)
        self.ip_edit = LineEdit()
        self.ip_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.ip_edit.setMinimumHeight(38)
        layout.addWidget(self.ip_edit, 0, 1)

        self.generate_btn = PrimaryPushButton()
        self.generate_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.generate_btn.setMinimumHeight(40)
        layout.addWidget(self.generate_btn, 1, 0, 1, 2)
        layout.setColumnStretch(1, 1)
        self.retranslate_ui()

    def retranslate_ui(self):
        self.target_ip_label.setText(tr("subgraph_target_ip_label", "目标IP:"))
        self.generate_btn.setText(tr("subgraph_generate_button", "生成子图"))
