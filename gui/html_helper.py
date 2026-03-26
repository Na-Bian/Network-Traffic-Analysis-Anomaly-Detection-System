# gui/html_helper.py
import os

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import QApplication

from .utils import resource_path


def get_theme_colors():
    """获取当前系统主题的背景色和文字颜色"""
    palette = QApplication.palette()
    window_color = palette.color(QPalette.ColorRole.Window)
    brightness = (window_color.red() * 299 + window_color.green() * 587 + window_color.blue() * 114) / 1000
    is_dark = brightness < 128
    bg_color = "#222222" if is_dark else "#ffffff"
    text_color = "white" if is_dark else "black"
    return bg_color, text_color


def generate_placeholder_html(message, bg_color, text_color):
    """生成占位HTML"""
    return f"""
    <html style='background-color:{bg_color}; margin:0; padding:0; width:100%; height:100%;'>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    </head>
    <body style='background-color:{bg_color}; color:{text_color}; margin:0; padding:0; width:100%; height:100vh; display:flex; align-items:center; justify-content:center;'>
        {message}
    </body>
    </html>
    """


def replace_cdn_with_local(html_path, bg_color, text_color, log_callback=None):
    """将HTML中的CDN链接替换为本地资源，并注入主题样式"""
    try:
        with open(html_path, 'r', encoding='utf-8') as f:
            content = f.read()

        is_dark = bg_color == "#222222"
        thumb_color = "rgba(255, 255, 255, 0.3)" if is_dark else "rgba(0, 0, 0, 0.2)"
        thumb_hover = "rgba(255, 255, 255, 0.5)" if is_dark else "rgba(0, 0, 0, 0.4)"
        thumb_active = "rgba(255, 255, 255, 0.7)" if is_dark else "rgba(0, 0, 0, 0.6)"

        inject_style = f"""
        <style>
            html, body {{
                background-color: {bg_color} !important;
                margin: 0 !important;
                padding: 0 !important;
                width: 100% !important;
                height: 100% !important;
            }}
            ::-webkit-scrollbar {{
                width: 8px;
                height: 8px;
                background-color: transparent;
            }}
            ::-webkit-scrollbar-track {{
                background: transparent;
                border-radius: 4px;
            }}
            ::-webkit-scrollbar-thumb {{
                background: {thumb_color};
                border-radius: 4px;
            }}
            ::-webkit-scrollbar-thumb:hover {{
                background: {thumb_hover};
            }}
            ::-webkit-scrollbar-thumb:active {{
                background: {thumb_active};
            }}
        </style>
        """

        if '<head>' in content:
            content = content.replace('<head>', f'<head>{inject_style}')
        else:
            content = content.replace('<html>', f'<html>{inject_style}')

        def to_file_url(relative_path):
            abs_path = os.path.abspath(relative_path)
            return QUrl.fromLocalFile(abs_path).toString()

        # CDN替换映射
        replacements = [
            ("https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/dist/vis-network.min.css",
             to_file_url(resource_path("resources/vis/vis-network.min.css"))),
            ("https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/vis-network.min.js",
             to_file_url(resource_path("resources/vis/vis-network.min.js"))),
            ("https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/css/bootstrap.min.css",
             to_file_url(resource_path("resources/bootstrap/bootstrap.min.css"))),
            ("https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/js/bootstrap.bundle.min.js",
             to_file_url(resource_path("resources/bootstrap/bootstrap.bundle.min.js")))
        ]
        for cdn, local in replacements:
            content = content.replace(cdn, local)

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        if log_callback:
            log_callback(f"替换CDN链接时出错: {e}")
        return False
