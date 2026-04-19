# gui/tabs/subgraph_tab.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QSizePolicy
from qfluentwidgets import BodyLabel, LineEdit, PrimaryPushButton

from ..translator import tr


class SubgraphTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(5)

        row1 = QHBoxLayout()
        row1.setSpacing(3)
        self.target_ip_label = BodyLabel()
        row1.addWidget(self.target_ip_label)
        self.ip_edit = LineEdit()
        self.ip_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        row1.addWidget(self.ip_edit)
        layout.addLayout(row1)

        self.generate_btn = PrimaryPushButton()
        self.generate_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.generate_btn)
        self.retranslate_ui()

    def retranslate_ui(self):
        self.target_ip_label.setText(tr("subgraph_target_ip_label", "目标IP:"))
        self.generate_btn.setText(tr("subgraph_generate_button", "生成子图"))
