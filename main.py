# -*- coding: utf-8 -*-
"""
网络运维工具箱 · NetOps Toolbox
================================

浅色多巴胺风格的 PyQt5 网络运维 / CTF 工具链：

  🎯 资产发现      ARP / Ping 扫描，识别 IP、MAC、厂商、主机名、开放端口
  🔎 端口扫描      TCP connect 扫描 + Banner 抓取
  ⚡ ARP 流量牵引   双向中间人 / 单向断网；DNS 引流；停止自动恢复
  🕵 流量劫持      内建 HTTP/HTTPS 透明代理：看请求、改包、重放、断点
  📡 抓包分析      scapy 实时抓包，可落盘 pcap、可编辑重放
  🧰 运维工具      本机信息 / Ping / 路由追踪 / DNS / WOL / HTTP / 子网 / 时间

运行
----
    conda activate ai
    python main.py                 # 启动（默认自动请求管理员权限）
    双击 启动.vbs                  # 同样效果，且完全不会出现 cmd 黑窗

    python main.py --selftest      # 核心层 + 界面层自检
    python main.py --no-elevate    # 本次不自动提权

    # 打包成 exe 后没有控制台，把自检结果写进文件：
    NetOpsToolbox.exe --selftest --selftest-out=selftest.txt

说明
----
* 自动提权用 pythonw.exe 拉起，不弹控制台窗口；UAC 被拒绝也能以普通权限继续运行。
* ARP / 抓包 / 透明代理需要管理员 + Npcap；其余功能普通权限即可。
* ARP 流量牵引只能用于**你本人拥有或已获书面授权**的网络。
"""

from __future__ import annotations

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.version import APP_NAME, APP_ORG, APP_VERSION   # noqa: E402


def _fix_stdio() -> None:
    """pythonw 启动时没有 stdout/stderr，print 会抛异常；这里兜一下。"""
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")


def _write_crash(text: str) -> None:
    try:
        from core.paths import app_path
        with open(app_path("crash.log"), "a", encoding="utf-8") as fh:
            fh.write(f"\n===== {datetime.now():%Y-%m-%d %H:%M:%S} =====\n{text}\n")
    except Exception:
        pass


# 「上次是否正常退出」的标记文件。
# native 崩溃（wpcap.dll / Qt 那类访问违例）不会走 Python 的异常处理，
# atexit 也不会执行，只能靠这个标记事后判断。
def _run_marker() -> str:
    from core.paths import app_path
    return app_path(".running")


def _mark_running() -> str:
    """写入运行标记；若上次的标记仍在，说明上次是异常退出，返回上次的时间。"""
    marker = _run_marker()
    prev = ""
    if os.path.exists(marker):
        try:
            with open(marker, "r", encoding="utf-8") as fh:
                prev = fh.read().strip().replace("\n", " ")
        except OSError:
            prev = "未知时间"
    try:
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} pid={os.getpid()}")
    except OSError:
        pass
    return prev


def _clear_run_marker() -> None:
    try:
        os.remove(_run_marker())
    except OSError:
        pass


def _atexit_cleanup() -> None:
    """退出前务必释放 Npcap 常驻句柄 —— 否则解释器退出时句柄还在被用，就会 native 崩。"""
    try:
        from core import rawsock
        rawsock.close_all()
    except Exception:
        pass
    _clear_run_marker()


def _install_excepthooks() -> None:
    """
    关键：PyQt5 遇到「槽函数里未捕获的异常」会直接调用 abort() 把进程干掉
    （退出码 0xC0000409）。界面用 pythonw 启动时没有控制台，看起来就是「闪退」。

    装上自定义 excepthook 后 PyQt5 不会再 abort，异常会交给该钩子处理：
    写进界面日志面板 + crash.log，程序继续跑。
    """
    import threading
    import traceback

    def _hook(exc_type, exc, tb):
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        try:
            from core.logging_bus import log
            log(f"未捕获异常：{exc_type.__name__}: {exc}（堆栈已写入 crash.log）",
                "error", "crash")
        except Exception:
            pass
        _write_crash(text)
        try:
            sys.stderr.write(text)
        except Exception:
            pass

    sys.excepthook = _hook
    # 工作线程里没接住的异常也一样记录下来（默认只会打到不可见的 stderr）
    threading.excepthook = lambda args: _hook(args.exc_type, args.exc_value,
                                              args.exc_traceback)


class _Tee:
    """把输出同时写往下游流和文件（打包成 --windowed 后没有控制台，只能落盘看）。"""

    def __init__(self, stream, handle):
        self._stream = stream
        self._handle = handle

    def write(self, text):
        for target in (self._stream, self._handle):
            try:
                target.write(text)
            except Exception:
                pass
        # 随时落盘：万一自检中途挂了，文件里也留得下已经跑完的部分
        self.flush()
        return len(text)

    def flush(self):
        for target in (self._stream, self._handle):
            try:
                target.flush()
            except Exception:
                pass


def _run_selftest(argv: list) -> int:
    """跑两个自检脚本。--selftest-out=路径 可把结果同时写进文件。"""
    import runpy

    from core.paths import app_path, resource_path

    out_path = ""
    for arg in argv:
        if arg.startswith("--selftest-out="):
            out_path = arg.split("=", 1)[1].strip()

    handle = None
    if out_path:
        if not os.path.isabs(out_path):
            out_path = app_path(out_path)
        try:
            handle = open(out_path, "w", encoding="utf-8")
            sys.stdout = _Tee(sys.stdout, handle)
            sys.stderr = _Tee(sys.stderr, handle)
        except OSError as exc:
            print(f"自检结果无法写入 {out_path}：{exc}")

    rc = 0
    # runpy 会把 sys.modules["__main__"] 换成正在执行的脚本本身，
    # 所以先把入口模块存到一个固定名字下，自检脚本用这个名字取。
    entry = sys.modules.get("__main__")
    if entry is not None:
        sys.modules.setdefault("netops_entry", entry)

    for name in ("selftest_core.py", "selftest_ui.py"):
        # 源码运行和打包运行都能找到：resource_path 会自动指向项目根 / _MEIPASS
        path = ""
        for cand in (resource_path(name),
                     os.path.join(os.path.dirname(os.path.abspath(__file__)), name)):
            if os.path.exists(cand):
                path = cand
                break
        if not path:
            continue
        print(f"\n{'#' * 62}\n##########  {name}  ##########\n{'#' * 62}")
        try:
            runpy.run_path(path, run_name="__main__")
        except SystemExit as exc:
            rc = max(rc, int(exc.code or 0))

    print(f"\n>>> 自检结束，退出码 {rc}")
    # 自检不是界面运行，顺手清掉上次遗留的运行标记，
    # 免得下次开界面时误报「上次未正常退出」。
    _clear_run_marker()
    if handle is not None:
        try:
            handle.flush()
            handle.close()
        except Exception:
            pass
    return rc


def main() -> int:
    _fix_stdio()
    _install_excepthooks()
    argv = sys.argv

    if "--selftest" in argv:
        return _run_selftest(argv)

    try:
        from PyQt5.QtCore import Qt
        from PyQt5.QtGui import QIcon
        from PyQt5.QtWidgets import QApplication
    except ImportError as exc:
        sys.stderr.write("没有找到 PyQt5，请先安装：\n    pip install PyQt5\n"
                         f"（原始错误：{exc}）\n")
        return 2

    # ---- 启动自动提权（用 pythonw，不会有 cmd 黑窗） ----
    from core import appconfig
    from core import hostinfo as HI

    already_elevated = "--elevated" in argv
    if (appconfig.CFG.get("auto_elevate", True) and not HI.is_admin()
            and not already_elevated and "--no-elevate" not in argv):
        if HI.relaunch_as_admin(["--elevated"]):
            return 0            # 提权实例已接管，本进程退出
        # UAC 被拒绝：继续用普通权限跑，不再重试

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    # Windows 任务栏图标需要显式设置 AppUserModelID，否则会归到 python.exe 上
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "NetOps.Toolbox")
        except Exception:
            pass

    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_ORG)
    app.setApplicationVersion(APP_VERSION)

    from core.paths import icon_path
    _icon = icon_path()
    if _icon:
        app.setWindowIcon(QIcon(_icon))

    import atexit
    atexit.register(_atexit_cleanup)
    prev_run = _mark_running()

    from ui.main_window import MainWindow
    win = MainWindow()
    if prev_run:
        from core.logging_bus import log
        log(f"上次运行（{prev_run}）未正常退出，可能是崩溃。"
            f"native 崩溃不会留下 Python 堆栈，详见 crash.log", "warn", "app")
    win.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
