# gui/tabs/flow_sort_tab.py
from PyQt6.QtCore import QSignalBlocker
from PyQt6.QtWidgets import QWidget, QGridLayout, QSizePolicy
from qfluentwidgets import BodyLabel, ComboBox, DoubleSpinBox, PrimaryPushButton

from ..translator import tr


class FlowSortTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)

        self.sort_type_label = BodyLabel()
        layout.addWidget(self.sort_type_label, 0, 0)
        self.sort_type_combo = ComboBox()
        self.sort_type_combo.currentTextChanged.connect(self.on_sort_type_changed)
        self.sort_type_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.sort_type_combo, 0, 1)

        self.ratio_label = BodyLabel()
        self.ratio_threshold_spin = DoubleSpinBox()
        self.ratio_threshold_spin.setRange(0.0, 1.0)
        self.ratio_threshold_spin.setValue(0.8)
        self.ratio_threshold_spin.setSingleStep(0.05)
        self.ratio_threshold_spin.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.ratio_label.setVisible(False)
        self.ratio_threshold_spin.setVisible(False)
        layout.addWidget(self.ratio_label, 1, 0)
        layout.addWidget(self.ratio_threshold_spin, 1, 1)

        self.flow_sort_btn = PrimaryPushButton()
        self.flow_sort_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.flow_sort_btn, 2, 0, 1, 2)

        layout.setColumnStretch(1, 1)
        self.retranslate_ui()

    def on_sort_type_changed(self, text):
        is_outratio = self.sort_type_combo.currentIndex() == 2
        self.ratio_label.setVisible(is_outratio)
        self.ratio_threshold_spin.setVisible(is_outratio)

    def retranslate_ui(self):
        current_index = self.sort_type_combo.currentIndex()
        self.sort_type_label.setText(tr("sort_type_label", "排序类型:"))
        with QSignalBlocker(self.sort_type_combo):
            self.sort_type_combo.clear()
            self.sort_type_combo.addItems([
                tr("flow_sort_total", "总流量"),
                tr("flow_sort_https", "HTTPS"),
                tr("flow_sort_outratio", "出流量")
            ])
            if current_index >= 0:
                self.sort_type_combo.setCurrentIndex(min(current_index, self.sort_type_combo.count() - 1))
        self.ratio_label.setText(tr("outratio_threshold_label", "出流量占比阈值:"))
        self.flow_sort_btn.setText(tr("flow_sort_button", "执行流量排序"))
        self.on_sort_type_changed(self.sort_type_combo.currentText())
