# analyzer.spec
# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_all

# 使用 collect_all 自动处理 pyvis 的数据文件、二进制文件和隐藏导入
pyvis_datas, pyvis_binaries, pyvis_hiddenimports = collect_all('pyvis')

block_cipher = None

# 补充必要的隐藏导入（尤其是 WebEngine）
additional_hiddenimports = [
    'PyQt6.QtWebEngine',
    'PyQt6.QtWebEngineWidgets',
]

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[
        ('backend/NetworkAnalyzerCore.exe', 'backend'),
    ] + pyvis_binaries,
    datas=[
        ('gui/*.py', 'gui'),
        ('backend/readPcap.py', 'backend'),
        ('backend/subgraph.py', 'backend'),
        ('resources', 'resources'),
        ('lang_config.json', '.'),   # 加入语言配置文件
    ] + pyvis_datas,
    hiddenimports=pyvis_hiddenimports + additional_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'unittest'],   # 排除无用模块减小体积
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NetworkAnalyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,               # 不显示控制台窗口
    icon='resources/icon.ico',
)

coll = COLLECT(
    exe,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NetworkAnalyzer'
)