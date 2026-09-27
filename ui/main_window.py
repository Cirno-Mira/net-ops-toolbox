# -*- coding: utf-8 -*-
"""
主窗口
======

布局：
    ┌──────────────────────────────────────────────────────┐
    │ 标题 + 权限/Npcap/网卡 徽章 + 以管理员重启 + 刷新环境    │
    ├───────────────┬──────────────────────────────────────┤
    │ 左侧导航树      │  当前工具页面                          │
    │ （整条工具链）  │                                       │
    ├───────────────┴──────────────────────────────────────┤
    │ 运行日志（可拖动改变高度）                              │
    └──────────────────────────────────────────────────────┘

设计上刻意做成「一棵树平铺所有工具」，不再用「标签页里再套一层列表」，
避免要找半天。
"""

from __future__ import annotations

import atexit
import time

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QApplication, QHBoxLayout, QLabel, QMainWindow,
                             QMessageBox, QPushButton, QSplitter, QStackedWidget,
                             QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

import theme
from core import arpmitm as M
from core import hostinfo as HI
from core.logging_bus import log
from core.version import APP_TITLE, APP_VERSION
from ui.tab_arp import ArpTab
from ui.tab_assets import AssetsTab
from ui.tab_capture import CaptureTab
from ui.tab_diag import DiagTab
from ui.tab_dirbrute import DirBruteTab
from ui.tab_fakeserv import FakeservTab
from ui.tab_hash import HashTab
from ui.tab_mitm import MitmTab
from ui.tab_ports import PortsTab
from ui.tab_report import ReportTab
from ui.tab_tools import ToolsTab
from ui.tab_tunnel import TunnelTab
from ui.tab_vuln import VulnTab
from ui.widgets import Badge, LogBridge, LogPanel

WORKFLOW_HINT = (
    "常用流程\n"
    "① 资产发现 → 扫出设备\n"
    "② 选中设备 → 送进 ARP 页\n"
    "③ ARP 页开牵引（勾 DNS 引流）\n"
    "④ 看「流量劫持」页的请求\n"
    "⑤ 安全体检 / 抓包做深入分析\n"
    "⑥ 报告导出 → 汇总成交付文档"
)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_TITLE} v{APP_VERSION}")
        self.resize(1400, 920)
        self.setMinimumSize(1000, 680)

        from core.paths import icon_path
        _ico = icon_path()
        if _ico:
            self.setWindowIcon(QIcon(_ico))

        root = QWidget()
        root.setObjectName("Root")
        root.setAttribute(Qt.WA_StyledBackground, True)
        root.setStyleSheet(theme.make_qss())
        self.setCentralWidget(root)

        outer = QVBoxLayout(root)
        outer.setContentsMargins(12, 10, 12, 8)
        outer.setSpacing(8)
        outer.addWidget(self._build_header())

        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self._build_body())
        self.log_panel = LogPanel()
        self.splitter.addWidget(self.log_panel)
        self.splitter.setSizes([660, 200])
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 1)
        outer.addWidget(self.splitter, 1)

        # 日志桥接
        self.log_bridge = LogBridge(self)
        self.log_bridge.message.connect(self.log_panel.append)

        # 页面联动
        self.tab_assets.send_to_ports.connect(self._to_ports)
        self.tab_assets.send_to_arp.connect(self._to_arp)
        self.tab_arp.mitm_requested.connect(self._on_mitm_requested)

        # 退出时无论如何都要把 ARP 表恢复
        atexit.register(M.emergency_restore_all)

        self.refresh_env()
        self.tab_diag.bind(self.tab_arp, self.tab_mitm)
        self.tab_report.bind(self)
        # 让各页能把「刚做了什么」写进崩溃现场文件
        for page in (self.tab_arp, self.tab_mitm, self.tab_capture,
                     self.tab_tunnel, self.tab_fakeserv, self.tab_vuln,
                     self.tab_dirbrute, self.tab_hash, self.tab_assets,
                     self.tab_ports):
            page.note_action = self.note_action
        self.show_page(self.tab_assets)
        log("网络运维工具箱已启动", "success", "app")
        if HI.is_admin():
            log("已获得管理员权限：ARP 扫描 / 牵引 / 抓包 / 透明代理全部可用",
                "success", "app")
        else:
            log("当前不是管理员：ARP 扫描 / 牵引 / 抓包 / 透明代理不可用，"
                "可在设置里关掉自动提权", "warn", "app")

    # ---------------- 顶部 ----------------

    def _build_header(self) -> QWidget:
        box = QWidget()
        lay = QHBoxLayout(box)
        lay.setContentsMargins(4, 0, 4, 0)
        lay.setSpacing(10)

        col = QVBoxLayout()
        col.setSpacing(1)
        head = QHBoxLayout()
        head.setSpacing(8)
        title = QLabel("网络运维工具箱")
        title.setObjectName("H1")
        head.addWidget(title)
        head.addWidget(Badge(f"v{APP_VERSION}", "idle"))
        head.addStretch(1)
        sub = QLabel("资产发现 · 端口扫描 · ARP 牵引/断网 · 流量劫持改包 · 抓包重放 · 运维工具")
        sub.setObjectName("Sub")
        col.addLayout(head)
        col.addWidget(sub)
        lay.addLayout(col)
        lay.addSpacing(14)

        self.badge_admin = Badge("权限检测中…", "idle")
        self.badge_npcap = Badge("Npcap 检测中…", "idle")
        self.badge_net = Badge("网卡检测中…", "idle")
        for b in (self.badge_admin, self.badge_npcap, self.badge_net):
            lay.addWidget(b)
        lay.addStretch(1)

        self.btn_elevate = QPushButton("🛡 以管理员身份重启")
        self.btn_elevate.setObjectName("Primary")
        self.btn_elevate.clicked.connect(self._elevate)
        lay.addWidget(self.btn_elevate)

        btn_refresh = QPushButton("刷新环境")
        btn_refresh.setObjectName("Ghost")
        btn_refresh.clicked.connect(self.refresh_env)
        lay.addWidget(btn_refresh)
        return box

    # ---------------- 主体：左侧导航树 + 右侧页面 ----------------

    def _build_body(self) -> QWidget:
        body = QWidget()
        lay = QHBoxLayout(body)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        # 先建好所有页面对象
        self.tab_assets = AssetsTab()
        self.tab_ports = PortsTab()
        self.tab_arp = ArpTab()
        self.tab_mitm = MitmTab()
        self.tab_capture = CaptureTab()
        self.tab_tools = ToolsTab()
        self.tab_diag = DiagTab()
        self.tab_dirbrute = DirBruteTab()
        self.tab_tunnel = TunnelTab()
        self.tab_fakeserv = FakeservTab()
        self.tab_vuln = VulnTab()
        self.tab_report = ReportTab()
        self.tab_hash = HashTab()

        self.stack = QStackedWidget()

        # 左侧导航：整条工具链平铺成一棵树
        self.nav = QTreeWidget()
        self.nav.setHeaderHidden(True)
        self.nav.setIndentation(12)
        self.nav.setMinimumWidth(210)
        self.nav.setMaximumWidth(300)
        self.nav.setToolTip("所有工具都在这棵树里，点一下即可切换")
        self._nav_of = {}          # 页面 widget -> 树节点

        nav_spec = [
            ("🔍 发现与扫描", [
                ("🎯 资产发现", self.tab_assets,
                 "扫局域网，识别 IP / MAC / 厂商 / 主机名 / 开放端口"),
                ("🔎 端口扫描", self.tab_ports,
                 "TCP 连接扫描 + Banner 抓取，多种预设"),
                ("📂 目录爆破", self.tab_dirbrute,
                 "常见路径 / 接口爆破，自动过滤软 404"),
            ]),
            ("⚡ 攻击与劫持", [
                ("⚡ ARP 牵引 / 断网", self.tab_arp,
                 "双向中间人 / 单向抓包 / 断网攻击（arp death），含 DNS 引流"),
                ("🕵 流量劫持", self.tab_mitm,
                 "查看并修改被牵引设备的请求，可重放、下断点"),
                ("🕳 穿透隧道", self.tab_tunnel,
                 "端口转发（TCP/UDP）+ 正/反向 shell 交互控制台"),
                ("🎭 假服务", self.tab_fakeserv,
                 "一键起 DNS / HTTP 服务，配合引流做取证演示"),
            ]),
            ("🛡 检测与报告", [
                ("🛡 安全体检", self.tab_vuln,
                 "未授权访问 / 错误配置的快速指纹扫描（只检测不利用）"),
                ("📄 报告导出", self.tab_report,
                 "把各页结果汇总成 Markdown / HTML 报告"),
            ]),
            ("📡 分析与诊断", [
                ("📡 抓包分析", self.tab_capture,
                 "实时抓包、TCP 会话重组、流量统计、选中包编辑重放"),
                ("🩺 环境自检", self.tab_diag,
                 "权限 / 网卡 / 端口 / 防火墙体检，以及无害的发包自检"),
            ]),
            ("🔐 密码工具", [
                ("🔑 哈希与字典", self.tab_hash,
                 "哈希识别 / 爆破，以及社工字典生成"),
            ]),
            ("🧰 运维工具", [(name, page, "") for name, page in self.tab_tools.pages()]),
        ]

        for group_title, items in nav_spec:
            group = QTreeWidgetItem([group_title])
            group.setFlags(Qt.ItemIsEnabled)          # 分组标题不可选
            self.nav.addTopLevelItem(group)
            for title, widget, tip in items:
                item = QTreeWidgetItem([title])
                if tip:
                    item.setToolTip(0, tip)
                group.addChild(item)
                if widget is not None:
                    idx = self.stack.addWidget(widget)
                    item.setData(0, Qt.UserRole, idx)
                    self._nav_of[widget] = item
        self.nav.expandAll()
        self.nav.currentItemChanged.connect(self._on_nav_changed)

        # 侧栏底部：使用流程提示
        side = QWidget()
        side_lay = QVBoxLayout(side)
        side_lay.setContentsMargins(0, 0, 0, 0)
        side_lay.setSpacing(6)
        side_lay.addWidget(self.nav, 1)
        hint = QLabel(WORKFLOW_HINT)
        hint.setObjectName("Dim")
        hint.setWordWrap(True)
        hint.setStyleSheet(
            "background: rgba(255,255,255,0.75); border:1px solid #EFE6FF;"
            "border-radius:12px; padding:8px 10px;")
        side_lay.addWidget(hint)

        lay.addWidget(side)
        lay.addWidget(self.stack, 1)
        return body

    def _on_nav_changed(self, current, _previous):
        if current is None:
            return
        idx = current.data(0, Qt.UserRole)
        if idx is not None:
            self.stack.setCurrentIndex(int(idx))
        self.note_action(f"切到页面：{current.text(0)}")

    # ---------------- 崩溃现场记录 ----------------

    @staticmethod
    def _marker_path() -> str:
        from core.paths import app_path
        return app_path(".running")

    def note_action(self, text: str) -> None:
        """
        把「当前在哪个页面、刚做了什么」追加到运行标记文件。

        native 崩溃（wpcap.dll / Qt 那种）不会留 Python 堆栈，
        但标记文件会留下最后一步，下次启动时能看出崩在哪。
        """
        try:
            with open(self._marker_path(), "a", encoding="utf-8") as fh:
                fh.write(f"\n  {time.strftime('%H:%M:%S')} {text}")
        except Exception:
            pass

    def show_page(self, widget):
        """按页面对象切换（供页面联动用）。"""
        item = self._nav_of.get(widget)
        if item is not None:
            self.nav.setCurrentItem(item)
            self.stack.setCurrentWidget(widget)

    # ---------------- 环境 ----------------

    def refresh_env(self):
        admin = HI.is_admin()
        if admin:
            self.badge_admin.set_state("管理员 ✅", "ok")
            self.badge_admin.setToolTip("ARP 扫描 / 牵引 / 抓包 / 透明代理全部可用")
            self.btn_elevate.setEnabled(False)
            self.btn_elevate.setText("🛡 已是管理员")
        else:
            self.badge_admin.set_state("普通用户 ⚠", "warn")
            self.badge_admin.setToolTip(
                "ARP 扫描 / 牵引 / 抓包 / 透明代理需要管理员权限")
            self.btn_elevate.setEnabled(True)
            self.btn_elevate.setText("🛡 以管理员身份重启")

        ok, why = HI.npcap_ready()
        self.badge_npcap.set_state("Npcap ✅" if ok else "Npcap ⚠", "ok" if ok else "warn")
        self.badge_npcap.setToolTip(why)

        prim = HI.primary_iface()
        if prim:
            self.badge_net.set_state(f"{prim.alias} {prim.ip}", "info")
            self.badge_net.setToolTip(
                f"网段 {prim.cidr}\n网关 {prim.gateway or '-'}\nMAC {prim.mac or '-'}")
        else:
            self.badge_net.set_state("没有可用网卡", "error")

    def _elevate(self):
        if HI.is_admin():
            return
        ans = QMessageBox.question(
            self, "以管理员身份重启",
            "将弹出 UAC 授权窗口，同意后会以管理员身份重启本工具箱。\n"
            "当前窗口会关闭（正在运行的抓包/牵引会先停止并恢复）。\n\n继续吗？",
            QMessageBox.Yes | QMessageBox.No)
        if ans != QMessageBox.Yes:
            return
        self.shutdown_children()
        if HI.relaunch_as_admin():
            QApplication.quit()
        else:
            QMessageBox.warning(self, "启动失败", "UAC 提权被取消或失败")

    # ---------------- 页面联动 ----------------

    def _to_ports(self, ips: list):
        self.tab_ports.set_targets(ips)
        self.show_page(self.tab_ports)
        log(f"已把 {len(ips)} 个目标送入端口扫描页", "info", "app")

    def _to_arp(self, ips: list):
        assets = getattr(self.tab_assets, "assets", {})
        items = [{"ip": ip,
                  "mac": assets[ip].mac if ip in assets else "",
                  "note": assets[ip].hostname if ip in assets else ""}
                 for ip in ips]
        self.tab_arp.set_candidates(items)
        self.show_page(self.tab_arp)
        log(f"已把 {len(ips)} 个目标送入 ARP 牵引页", "info", "app")

    def _on_mitm_requested(self, info: dict):
        """ARP 页请求联动启动透明代理。"""
        self.tab_mitm.arp_iface = info.get("iface")
        self.tab_mitm.dns_probe = lambda: (
            self.tab_arp.dns is not None,
            self.tab_arp.dns.stats["spoofed"] if self.tab_arp.dns else 0)

        if self.tab_mitm.proxy is not None and self.tab_mitm.proxy.running:
            log("透明代理已经在运行", "info", "app")
        else:
            self.tab_mitm.toggle_proxy()

        self.show_page(self.tab_mitm)
        self.tab_mitm.run_diag()          # 自动自检，直接把链路状态摆出来
        log("已切到「流量劫持」页：代理监听 80/443，被牵引设备访问网站时请求会出现在这里；"
            "如果一直没有流量，点「🔍 引流自检」看卡在哪一步", "info", "app")

    # ---------------- 退出 ----------------

    def shutdown_children(self):
        """
        退出前把所有还在跑的东西停下来。

        顺序很重要：先停业务线程，再等 QThread 结束，最后释放 Npcap 句柄。
        否则解释器退出时还有线程在碰已释放的 pcap 句柄，就会在 wpcap.dll 里
        出现 native 级别的崩溃（「指令引用了 0x0 内存」这种），Python 完全兜不住。
        """
        for name, fn in (("ARP 牵引", self.tab_arp.shutdown),
                         ("透明代理", self.tab_mitm.shutdown),
                         ("抓包", self.tab_capture.shutdown),
                         ("穿透隧道", getattr(self.tab_tunnel, "shutdown", None)),
                         ("假服务", getattr(self.tab_fakeserv, "shutdown", None))):
            if fn is None:
                continue
            try:
                fn()
            except Exception as exc:
                log(f"停止{name}出错：{exc}", "error", "app")

        # 兜底：所有页面里可能残留的 QThread 工作线程，统一要求停止并等待
        pages = [self.tab_assets, self.tab_ports, self.tab_vuln,
                 self.tab_dirbrute, self.tab_hash, self.tab_tools,
                 self.tab_arp, self.tab_mitm, self.tab_capture,
                 self.tab_tunnel, self.tab_fakeserv]
        for page in pages:
            for meth in ("stop_scan", "stop_all", "stop", "stop_worker"):
                fn = getattr(page, meth, None)
                if callable(fn):
                    try:
                        fn()
                    except Exception:
                        pass
        for page in pages:
            worker = getattr(page, "worker", None)
            if worker is not None and hasattr(worker, "isRunning"):
                try:
                    if worker.isRunning():
                        worker.wait(3000)
                except Exception:
                    pass
            for attr in ("ping_worker", "trace_worker"):
                w2 = getattr(page, attr, None)
                stop_fn = getattr(w2, "stop", None)
                if callable(stop_fn):
                    try:
                        stop_fn()
                    except Exception:
                        pass

        try:
            M.emergency_restore_all()
        except Exception:
            pass
        # 最后释放常驻的 Npcap 发包句柄
        try:
            from core import rawsock
            rawsock.close_all()
        except Exception:
            pass

    def closeEvent(self, ev):
        if self.tab_arp.is_running():
            ans = QMessageBox.question(
                self, "ARP 牵引还在运行",
                "正在对目标做 ARP 流量牵引。关闭前会先停止并恢复目标与网关的 ARP 表。\n\n"
                "确定关闭吗？", QMessageBox.Yes | QMessageBox.No)
            if ans != QMessageBox.Yes:
                ev.ignore()
                return
        self.shutdown_children()
        ev.accept()
