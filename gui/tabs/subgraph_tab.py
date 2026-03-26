# gui/tabs/subgraph_tab.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy

from ..translator import tr


class SubgraphTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(5)

        row1 = QHBoxLayout()
        row1.setSpacing(3)
        row1.addWidget(QLabel(tr("subgraph_target_ip_label", "目标IP:")))
        self.ip_edit = QLineEdit()
        self.ip_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        row1.addWidget(self.ip_edit)
        layout.addLayout(row1)

        self.generate_btn = QPushButton(tr("subgraph_generate_button", "生成子图"))
        self.generate_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.generate_btn)
