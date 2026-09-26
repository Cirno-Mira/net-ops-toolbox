# -*- coding: utf-8 -*-
"""
打包成单文件 exe
================

用法：

    python build_exe.py                   # 发布：单文件、无控制台
    python build_exe.py --debug           # 排查：单文件 + 控制台 + bootloader 日志
    python build_exe.py --debug --onedir  # 排查：单目录版本

产物：`dist/NetOpsToolbox.exe`，单文件、免安装、带图标。

PyInstaller 对 scapy / zeroconf 这类「运行时才 import、还带数据文件」的库识别不全，
另外 conda 环境的 OpenSSL 等运行库不在搜索路径里，所以这里都显式带上。
需要额外依赖时在 HIDDEN / COLLECT_ALL / CONDA_DLLS 里各加一行即可。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP_NAME = "NetOpsToolbox"
ICON = os.path.join(HERE, "assets", "app.ico")

# 运行时才 import、PyInstaller 静态分析看不到的模块
HIDDEN = [
    "PyQt5.sip",
    "scapy.all",
    "scapy.layers.all",
    "scapy.layers.l2",
    "scapy.layers.inet",
    "scapy.layers.inet6",
    "scapy.layers.dns",
    "scapy.arch.windows",
    "dns.resolver",
    "dns.rdatatype",
    "dns.message",
    "zeroconf",
    "zeroconf._utils.net",
    "mac_vendor_lookup",
    "cryptography",
    "cryptography.x509",
    "paramiko",
    "pymysql",
    "urllib3",
    "winreg",
]

# 整个包连数据文件一起收集（scapy 的协议/服务表等）
COLLECT_ALL = ["scapy", "zeroconf"]

# 附带资源：源目录;包内目录（Windows 用分号）
# 自检脚本一起打进去，这样 exe 也能跑 --selftest（打包后没控制台，见 --selftest-out）
DATAS = [
    ("assets", "assets"),
    ("selftest_core.py", "."),
    ("selftest_ui.py", "."),
]

# conda 把 OpenSSL / zlib / ffi 这些运行库放在 Library\bin，而不是解释器根目录，
# PyInstaller 顺着 pyd 找不到它们（会打印 "Library not found"）。
# 缺了这些，exe 一旦用到 ssl / hashlib / ctypes 就会直接崩，所以显式带上。
CONDA_DLLS = [
    "libssl-3-x64.dll",
    "libcrypto-3-x64.dll",
    "liblzma.dll",
    "libbz2.dll",
    "ffi.dll",
    "sqlite3.dll",
    "zlib1.dll",
    "libz.dll",
    "libexpat.dll",
    "libiconv-2.dll",
]


def _conda_bin() -> str:
    """conda 环境下 Library\\bin 的位置（非 conda 环境返回空串）。"""
    cand = os.path.join(sys.prefix, "Library", "bin")
    return cand if os.path.isdir(cand) else ""


def build(debug: bool = False, onefile: bool = True) -> int:
    """
    debug=True 时改成「控制台 + bootloader 调试输出」，用来排查打包后启动即退出的问题。
    onefile 控制单文件 / 单目录，debug 模式下默认沿用调用方给的值。
    """
    for mod in ("PyInstaller",):
        try:
            __import__(mod)
        except ImportError:
            print(f"缺少 {mod}，先执行：pip install pyinstaller -i "
                  f"https://mirrors.aliyun.com/pypi/simple/")
            return 1

    if not os.path.exists(ICON):
        print("找不到 assets/app.ico，先执行：python tools/make_icon.py")
        return 1

    name = f"{APP_NAME}Debug" if debug else APP_NAME
    out_dir = os.path.join(HERE, "dist_debug" if debug else "dist")

    # 每次都从干净状态开始，避免上次的缓存混进来
    for d in ("build", out_dir):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
    for f in (f"{APP_NAME}.spec", f"{APP_NAME}Debug.spec"):
        p = os.path.join(HERE, f)
        if os.path.exists(p):
            os.remove(p)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile" if onefile else "--onedir",
        "--windowed" if not debug else "--console",
        "--name", name,
        "--icon", ICON,
        "--distpath", out_dir,
        "--workpath", os.path.join(HERE, "build"),
        "--specpath", HERE,
    ]
    if debug:
        cmd += ["--debug", "bootloader", "--log-level", "DEBUG"]
    for src, dst in DATAS:
        cmd += ["--add-data", f"{os.path.join(HERE, src)}{os.pathsep}{dst}"]

    bin_dir = _conda_bin()
    if bin_dir:
        for name in CONDA_DLLS:
            src = os.path.join(bin_dir, name)
            if os.path.exists(src):
                cmd += ["--add-binary", f"{src}{os.pathsep}."]

    for mod in COLLECT_ALL:
        cmd += ["--collect-all", mod]
    for mod in HIDDEN:
        cmd += ["--hidden-import", mod]
    cmd += [
        "--exclude-module", "tkinter",
        "--exclude-module", "matplotlib",
        "--exclude-module", "PyQt5.QtWebEngineWidgets",
        os.path.join(HERE, "main.py"),
    ]

    print("执行：\n  " + " ".join(f'"{c}"' if " " in c else c for c in cmd) + "\n")
    rc = subprocess.call(cmd, cwd=HERE)
    if rc != 0:
        print(f"\n打包失败，PyInstaller 退出码 {rc}")
        return rc

    exe = os.path.join(out_dir, f"{name}.exe")
    if not os.path.exists(exe):
        exe = os.path.join(out_dir, name, f"{name}.exe")   # 单目录模式
    if os.path.exists(exe):
        size = os.path.getsize(exe) / 1024 / 1024
        print(f"\n完成：{exe}   （{size:.1f} MB）")
    else:
        print("\n打包结束，但没有找到 exe，请检查上面的输出。")
        return 1
    return 0


if __name__ == "__main__":
    _debug = "--debug" in sys.argv
    _onefile = "--onedir" not in sys.argv
    sys.exit(build(debug=_debug, onefile=_onefile))
