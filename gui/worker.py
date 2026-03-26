# gui/worker.py
import os
import subprocess
import sys

from PyQt6.QtCore import QThread, pyqtSignal

from backend.readPcap import save_to_csv
from backend.subgraph import generate_html as generate_pyvis_html


# 连接C++后端
class AnalyzerWorker(QThread):
    output = pyqtSignal(str)
    error = pyqtSignal(str)
    success = pyqtSignal()  # 新增：专门用于标志执行成功的信号

    def __init__(self, cmd, parent=None):
        super().__init__(parent)
        self.cmd = cmd

    def run(self):
        try:
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            exe_dir = os.path.dirname(self.cmd[0])
            proc = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,  # 分开捕获
                cwd=exe_dir,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,
                creationflags=flags
            )

            # 使用线程同时读取 stdout 和 stderr
            def read_stream(stream, is_error):
                for line in iter(stream.readline, ''):
                    line = line.strip()
                    if line:
                        if is_error:
                            self.error.emit(line)  # 错误信息用error信号
                        else:
                            self.output.emit(line)

            from threading import Thread
            Thread(target=read_stream, args=(proc.stdout, False), daemon=True).start()
            Thread(target=read_stream, args=(proc.stderr, True), daemon=True).start()

            proc.wait()

            if proc.returncode != 0:
                self.error.emit(f"进程退出，返回码: {proc.returncode}")
            else:
                self.success.emit()

        except Exception as e:
            self.error.emit(f"启动进程失败: {str(e)} (错误码: {e.winerror if hasattr(e, 'winerror') else '未知'})")


# 子图绘制工作线程
class SubgraphWorker(QThread):
    success = pyqtSignal(str)  # 成功后传回 html_path
    error = pyqtSignal(str)

    def __init__(self, json_path, html_path, bgcolor, fontcolor, parent=None):
        super().__init__(parent)
        self.json_path = json_path
        self.html_path = html_path
        self.bgcolor = bgcolor
        self.fontcolor = fontcolor

    def run(self):
        try:
            generate_pyvis_html(self.json_path, self.html_path, self.bgcolor, self.fontcolor)
            self.success.emit(self.html_path)
        except Exception as e:
            self.error.emit(f"生成子图失败: {str(e)}")


# PCAP文件处理工作线程
class PcapConvertWorker(QThread):
    success = pyqtSignal(str)  # 成功信号，传递生成的 csv 路径
    error = pyqtSignal(str)  # 错误信号

    def __init__(self, pcap_path, csv_path, parent=None):
        super().__init__(parent)
        self.pcap_path = pcap_path
        self.csv_path = csv_path

    def run(self):
        try:
            save_to_csv(self.pcap_path, self.csv_path)
            self.success.emit(self.csv_path)
        except Exception as e:
            self.error.emit(str(e))
