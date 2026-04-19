# main.py
import sys
import traceback

from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import QApplication
from qfluentwidgets import Theme, qconfig, setTheme, setThemeColor

from gui.utils import resource_path


def excepthook(exc_type, exc_value, exc_tb):
    """全局异常处理器，捕获未处理的异常并打印详细信息"""
    traceback.print_exception(exc_type, exc_value, exc_tb)
    sys.exit(1)


sys.excepthook = excepthook

from gui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    setTheme(Theme.AUTO)
    setThemeColor("#0078d4")
    qconfig.set(qconfig.fontFamilies, ["Microsoft YaHei UI", "Microsoft YaHei", "Noto Sans SC", "Segoe UI"])
    app.setFont(QFont("Microsoft YaHei UI", 10))
    app.setWindowIcon(QIcon(resource_path("resources/icon.ico")))  # 设置程序图标
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
