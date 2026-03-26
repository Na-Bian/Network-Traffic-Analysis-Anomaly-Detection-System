# gui/utils.py
import atexit
import os
import shutil
import sys
import tempfile


def resource_path(relative_path):
    """获取资源文件的绝对路径"""
    try:
        base_path = sys._MEIPASS  # 打包后临时解压目录
    except:
        base_path = os.path.abspath(".")  # 开发环境根目录
    return os.path.join(base_path, relative_path)


class TempDirManager:
    """管理临时目录，确保程序结束时自动清理"""

    def __init__(self):
        # 记录主目录，方便以后管理
        self.base_temp = tempfile.gettempdir()
        self.temp_dir = tempfile.mkdtemp(prefix="NetAna_")
        # 确保目录存在
        if not os.path.exists(self.temp_dir):
            os.makedirs(self.temp_dir)

        atexit.register(self.cleanup)

    def cleanup(self):
        """清理临时目录"""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            print(f"临时文件清理失败: {e}")

    def get_path(self, filename):
        """返回临时目录下的完整路径"""
        # 加上引号处理，防止路径中有空格导致 C++ 或 subprocess 报错
        return os.path.join(self.temp_dir, filename)
