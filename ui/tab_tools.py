# -*- coding: utf-8 -*-
"""
运维工具页
==========

左边导航列表 + 右边堆叠页面（QStackedWidget）：
本机信息 / Ping 延迟 / 路由追踪 / DNS 查询 / Wake-on-LAN /
HTTP(S) 探测 / 子网计算器 / 时间校准。
"""

from __future__ import annotations

import threading

from PyQt5.QtCore import QObject, Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtWidgets import (QComboBox, QFormLayout, QHBoxLayout, QLabel,
                             QLineEdit, QMessageBox, QPlainTextEdit,
                             QPushButton, QSpinBox, QTabWidget,
                             QVBoxLayout, QWidget)

from core import appconfig
from core import hostinfo as HI
from core import subnet as SN
from core import tools as T
from core.logging_bus import log
from ui.widgets import (Badge, Card, Sparkline, label, make_table, safe_slot,
                        set_row)
from theme import C_MINT, C_PINK, C_RED, C_TEXT_DIM, C_YELLOW


# --------------------------------------------------------------------------- #
# 通用小工具：把核心层回调桥接成 Qt 信号
# --------------------------------------------------------------------------- #

class Emitter(QObject):
    anything = pyqtSignal(object)


class TraceWorker(QThread):
    hop = pyqtSignal(object)
    done = pyqtSignal(object)

    def __init__(self, host, max_hops, timeout_ms, cancel, parent=None):
        super().__init__(parent)
        self.host = host
        self.max_hops = max_hops
        self.timeout_ms = timeout_ms
        self.cancel = cancel

    def run(self):
        try:
            hops = T.traceroute(self.host, self.max_hops, self.timeout_ms,
                                on_hop=lambda h: self.hop.emit(h), cancel=self.cancel)
        except Exception as exc:
            log(f"路由追踪失败：{exc}", "error", "tools")
            hops = []
        self.done.emit(hops)


class DnsMultiWorker(QThread):
    """
    多服务器 DNS 对比 / DoH 域名解析的工人线程。

    ⚠ 结果一律用 pyqtSignal 送回主线程的槽函数，**不要**在工作线程里用
    QTimer.singleShot 排队（本代码库有过这个坑：没有事件循环的线程里排的队
    永远不触发，界面就卡死在「查询中…」）。信号跨线程是队列连接，稳。
    """

    done = pyqtSignal(object)

    def __init__(self, name, rtype, servers, timeout, resolve_only=False, parent=None):
        super().__init__(parent)
        self.name = name
        self.rtype = rtype
        self.servers = list(servers)
        self.timeout = timeout
        self.resolve_only = resolve_only

    def run(self):
        payload = {"kind": "query", "name": self.name, "rtype": self.rtype, "value": []}
        try:
            if self.resolve_only:
                payload["kind"] = "resolve"
                payload["value"] = T.resolve_dns_hosts(self.servers, self.timeout)
            else:
                payload["value"] = T.dns_query_multi(self.name, self.rtype,
                                                     self.servers, self.timeout)
        except Exception as exc:
            # 正常路径不会走到这里（核心层已经自己兜住每台服务器的异常），
            # 兜一层是为了万一还有漏网的，界面也不会闪退。
            log(f"多服务器 DNS 查询线程出错：{type(exc).__name__}: {exc}", "error", "tools")
            payload["kind"] = "error"
            payload["value"] = f"{type(exc).__name__}: {exc}"
        self.done.emit(payload)


# --------------------------------------------------------------------------- #
# 主页面
# --------------------------------------------------------------------------- #

class ToolsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ping_worker: T.PingWorker | None = None
        self.ping_bridge = Emitter()
        self.ping_bridge.anything.connect(self._on_ping_reply)
        self.trace_worker: TraceWorker | None = None
        self.trace_cancel = threading.Event()
        self.dns_multi_worker: DnsMultiWorker | None = None
        self._build()

    def _build(self):
        """
        这个类只负责「造页面」，不再自己做二级导航 —— 页面全部交给主窗口的
        左侧导航树，避免出现「标签页里再套一层列表」的两层导航。
        """
        self._pages = [
            ("🖥 本机信息", self._page_local()),
            ("📶 Ping 延迟", self._page_ping()),
            ("🧭 路由追踪", self._page_trace()),
            ("🌐 DNS 查询", self._page_dns()),
            ("⏻ 网络唤醒", self._page_wol()),
            ("🔗 HTTP 探测", self._page_http()),
            ("🧮 子网计算", self._page_subnet()),
            ("⏱ 时间校准", self._page_ntp()),
        ]

    def pages(self) -> list:
        return self._pages

    # ---------------- 1. 本机信息 ----------------

    def _page_local(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        card = Card("🖥 本机网络信息")
        row = QHBoxLayout()
        self.btn_local = QPushButton("刷新")
        self.btn_local.setObjectName("Primary")
        self.btn_local.clicked.connect(self.refresh_local)
        row.addWidget(self.btn_local)
        row.addStretch(1)
        card.add(row)

        self.lbl_local = QLabel("点击刷新读取")
        self.lbl_local.setWordWrap(True)
        self.lbl_local.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card.add(self.lbl_local)

        self.tbl_iface = make_table(["名称", "IP/掩码", "MAC", "网关", "网段", "描述"], 5)
        self.tbl_iface.setMinimumHeight(160)
        card.add(self.tbl_iface)
        lay.addWidget(card)
        lay.addStretch(1)
        return w

    def refresh_local(self):
        self.btn_local.setEnabled(False)
        try:
            info = T.local_info(with_public=True)
        finally:
            self.btn_local.setEnabled(True)
        lines = [f"<b>{k}</b>：{v}" for k, v in info.items() if k != "网卡"]
        self.lbl_local.setText("<br>".join(lines))
        t = self.tbl_iface
        t.setRowCount(0)
        t.setSortingEnabled(False)
        for i, n in enumerate(info["网卡"]):
            t.insertRow(i)
            set_row(t, i, [n["名称"], n["IP"], n["MAC"], n["网关"], n["网段"], n["描述"]])
        t.setSortingEnabled(True)
        log("已刷新本机网络信息", "success", "tools")

    # ---------------- 2. Ping ----------------

    def _page_ping(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        card = Card("📶 持续 Ping（延迟曲线）")
        r = QHBoxLayout()
        r.setSpacing(6)
        r.addWidget(label("目标", "Dim"))
        self.ed_ping = QLineEdit()
        self.ed_ping.setPlaceholderText("192.168.5.1 或 www.baidu.com")
        self.ed_ping.returnPressed.connect(self.toggle_ping)
        r.addWidget(self.ed_ping, 1)
        r.addWidget(label("间隔", "Dim"))
        self.sp_ping_interval = QSpinBox()
        self.sp_ping_interval.setRange(1, 10)
        self.sp_ping_interval.setValue(1)
        self.sp_ping_interval.setSuffix(" 秒")
        r.addWidget(self.sp_ping_interval)
        self.btn_ping = QPushButton("▶ 开始")
        self.btn_ping.setObjectName("Primary")
        self.btn_ping.clicked.connect(self.toggle_ping)
        r.addWidget(self.btn_ping)
        card.add(r)

        self.spark = Sparkline()
        card.add(self.spark)
        self.lbl_ping = label("未开始", "Dim")
        card.add(self.lbl_ping)
        lay.addWidget(card)

        self.txt_ping = QPlainTextEdit()
        self.txt_ping.setReadOnly(True)
        self.txt_ping.setMaximumBlockCount(500)
        self.txt_ping.setMinimumHeight(140)
        lay.addWidget(self.txt_ping, 1)

        self.ping_timer = QTimer(self)
        self.ping_timer.setInterval(1000)
        self.ping_timer.timeout.connect(self._refresh_ping_stats)
        return w

    def toggle_ping(self):
        if self.ping_worker is not None:
            self.ping_worker.stop()
            self.ping_worker = None
            self.ping_timer.stop()
            self.btn_ping.setText("▶ 开始")
            self.btn_ping.setObjectName("Primary")
            self.btn_ping.setStyleSheet("")
            log("已停止 ping", "info", "tools")
            return
        host = self.ed_ping.text().strip()
        if not host:
            QMessageBox.information(self, "缺少目标", "请填写要 ping 的主机")
            return
        self.spark.clear()
        self.txt_ping.clear()
        self.ping_worker = T.PingWorker(
            host, interval=self.sp_ping_interval.value(), timeout_ms=1500,
            on_reply=lambda seq, rtt: self.ping_bridge.anything.emit((seq, rtt)))
        self.ping_worker.start()
        self.ping_timer.start()
        self.btn_ping.setText("■ 停止")
        log(f"开始持续 ping {host}", "info", "tools")

    def _on_ping_reply(self, payload):
        seq, rtt = payload
        self.spark.push(rtt)
        if rtt is None:
            self.txt_ping.appendPlainText(f"#{seq:<5} 请求超时")
        else:
            self.txt_ping.appendPlainText(f"#{seq:<5} 来自目标的回复: 时间={rtt:.0f}ms")
        sb = self.txt_ping.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _refresh_ping_stats(self):
        if self.ping_worker is None:
            return
        s = self.ping_worker.stats
        self.lbl_ping.setText(
            f"已发 {s['sent']}  已收 {s['recv']}  丢包 {s['loss']:.0f}%   "
            f"最小 {s['min']:.0f}ms  平均 {s['avg']:.0f}ms  最大 {s['max']:.0f}ms")

    # ---------------- 3. 路由追踪 ----------------

    def _page_trace(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        card = Card("🧭 路由追踪 (tracert)")
        r = QHBoxLayout()
        r.setSpacing(6)
        r.addWidget(label("目标", "Dim"))
        self.ed_trace = QLineEdit()
        self.ed_trace.setPlaceholderText("8.8.8.8 或 www.baidu.com")
        r.addWidget(self.ed_trace, 1)
        r.addWidget(label("最大跳数", "Dim"))
        self.sp_hops = QSpinBox()
        self.sp_hops.setRange(1, 64)
        self.sp_hops.setValue(30)
        r.addWidget(self.sp_hops)
        self.btn_trace = QPushButton("▶ 开始追踪")
        self.btn_trace.setObjectName("Primary")
        self.btn_trace.clicked.connect(self.start_trace)
        r.addWidget(self.btn_trace)
        card.add(r)
        self.lbl_trace = label("就绪", "Dim")
        card.add(self.lbl_trace)
        lay.addWidget(card)

        self.tbl_trace = make_table(["跳", "IP 地址", "延迟 1", "延迟 2", "延迟 3"], 1)
        lay.addWidget(self.tbl_trace, 1)
        return w

    def start_trace(self):
        if self.trace_worker is not None and self.trace_worker.isRunning():
            return
        host = self.ed_trace.text().strip()
        if not host:
            QMessageBox.information(self, "缺少目标", "请填写要追踪的目标")
            return
        self.tbl_trace.setRowCount(0)
        self.lbl_trace.setText(f"正在追踪 {host} …")
        self.trace_cancel = threading.Event()
        self.trace_worker = TraceWorker(host, self.sp_hops.value(), 1000,
                                        self.trace_cancel, self)
        self.trace_worker.hop.connect(self._on_hop)
        self.trace_worker.done.connect(
            lambda hops: self.lbl_trace.setText(f"完成，共 {len(hops)} 跳"))
        self.trace_worker.start()

    def _on_hop(self, hop: dict):
        t = self.tbl_trace
        t.setSortingEnabled(False)
        r = t.rowCount()
        t.insertRow(r)
        rtt = hop["rtt"] + ["", "", ""]
        set_row(t, r, [hop["hop"], hop["ip"], rtt[0], rtt[1], rtt[2]],
                {1: C_MINT if hop["ip"] != "*" else C_TEXT_DIM})
        t.setSortingEnabled(True)

    # ---------------- 4. DNS ----------------

    def _page_dns(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        card = Card("🌐 DNS 查询")
        r = QHBoxLayout()
        r.setSpacing(6)
        r.addWidget(label("域名/IP", "Dim"))
        self.ed_dns = QLineEdit()
        self.ed_dns.setPlaceholderText("www.example.com")
        self.ed_dns.returnPressed.connect(self.do_dns)
        r.addWidget(self.ed_dns, 1)
        r.addWidget(label("类型", "Dim"))
        self.cmb_dns_type = QComboBox()
        self.cmb_dns_type.addItems(T.DNS_TYPES)
        r.addWidget(self.cmb_dns_type)
        r.addWidget(label("DNS 服务器", "Dim"))
        self.ed_dns_server = QLineEdit()
        self.ed_dns_server.setPlaceholderText("留空=系统 DNS")
        self.ed_dns_server.setFixedWidth(140)
        r.addWidget(self.ed_dns_server)
        self.btn_dns = QPushButton("查询")
        self.btn_dns.setObjectName("Primary")
        self.btn_dns.clicked.connect(self.do_dns)
        r.addWidget(self.btn_dns)
        card.add(r)
        self.lbl_dns = label("就绪", "Dim")
        card.add(self.lbl_dns)
        lay.addWidget(card)

        self.txt_dns = QPlainTextEdit()
        self.txt_dns.setReadOnly(True)
        self.txt_dns.setMinimumHeight(90)
        lay.addWidget(self.txt_dns, 1)

        # 多服务器对比：一次并发问一堆 DNS，并排看谁跟谁不一样
        lay.addWidget(self._build_dns_multi(), 2)
        return w

    def _build_dns_multi(self) -> QWidget:
        """
        多服务器 DNS 对比区。

        用途：分区域解析（CDN 给不同地区不同 IP）、DNS 劫持（某台结果明显不对）、
        内网解析器、以及哪台服务器已经死了 —— 这些一台一台问是看不出来的，
        必须把多台的结果并排放。
        """
        card = Card("🌐 多服务器 DNS 对比")
        card.setMinimumHeight(320)

        r = QHBoxLayout()
        r.setSpacing(6)
        r.addWidget(label("预设", "Dim"))
        self.cmb_dns_preset = QComboBox()
        self.cmb_dns_preset.addItems(list(T.DNS_PRESETS))
        self.cmb_dns_preset.setToolTip("选一个预设会自动填下面的服务器列表，填完可以随便改")
        self.cmb_dns_preset.currentIndexChanged.connect(self.on_dns_preset)
        r.addWidget(self.cmb_dns_preset)

        self.btn_dns_multi = QPushButton("🔍 查询所有服务器")
        self.btn_dns_multi.setObjectName("Primary")
        self.btn_dns_multi.setToolTip("用上面「域名/IP」和「类型」里的条件，"
                                     "并发问下面列出的每一台服务器")
        self.btn_dns_multi.clicked.connect(self.do_dns_multi)
        r.addWidget(self.btn_dns_multi)

        self.btn_dns_resolve = QPushButton("解析域名为 IP")
        self.btn_dns_resolve.setObjectName("Ghost")
        self.btn_dns_resolve.setToolTip("预设「DoH 服务器地址」里填的是域名、不是 IP，"
                                        "点这里把它们解析成 IP 再查询")
        self.btn_dns_resolve.clicked.connect(self.do_dns_resolve)
        r.addWidget(self.btn_dns_resolve)
        r.addStretch(1)

        r.addWidget(label("超时", "Dim"))
        self.sp_dns_timeout = QSpinBox()
        self.sp_dns_timeout.setRange(1, 30)
        self.sp_dns_timeout.setValue(5)
        self.sp_dns_timeout.setSuffix(" 秒")
        self.sp_dns_timeout.setToolTip("只影响多服务器对比；死的服务器拖满这个时间就判定超时")
        r.addWidget(self.sp_dns_timeout)
        self.badge_dns_multi = Badge("待查询", "idle")
        r.addWidget(self.badge_dns_multi)
        card.add(r)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("服务器（逗号 / 空格 / 换行分隔）", "Dim"))
        r2.addStretch(1)
        self.lbl_dns_preset = label("", "Dim")
        r2.addWidget(self.lbl_dns_preset)
        card.add(r2)

        self.ed_dns_multi_servers = QPlainTextEdit()
        self.ed_dns_multi_servers.setPlaceholderText("223.5.5.5, 119.29.29.29, 8.8.8.8, 1.1.1.1")
        self.ed_dns_multi_servers.setFixedHeight(56)
        self.ed_dns_multi_servers.setToolTip("想查哪几台就写哪几台，顺序按你写的来；\n"
                                             "写错了会直接报错，不会偷偷跳过（免得对比结论骗人）")
        card.add(self.ed_dns_multi_servers)

        self.lbl_dns_summary = label("就绪", "Dim")
        self.lbl_dns_summary.setWordWrap(True)
        self.lbl_dns_summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card.add(self.lbl_dns_summary)

        self.tbl_dns_multi = make_table(["服务器", "名称", "状态", "耗时(ms)", "记录"], 4)
        self.tbl_dns_multi.setMinimumHeight(170)
        # 关掉点击表头排序：行序保持用户填写的顺序（第 3 行就是第 3 台），
        # 而且「耗时」是文本，按字符串排也会排错（"100" < "20"）。
        self.tbl_dns_multi.setSortingEnabled(False)
        self.tbl_dns_multi.setToolTip("跟多数派不一致的行会标粉，查不到/超时的行标黄")
        card.add(self.tbl_dns_multi)

        # 恢复上次用的服务器列表；没有就按第一个预设填
        saved = str(appconfig.CFG.get("dns_multi_servers", "") or "").strip()
        if saved:
            self.ed_dns_multi_servers.setPlainText(saved)
            self.lbl_dns_preset.setText("（已恢复上次用的服务器列表）")
        else:
            self.on_dns_preset()
        return card

    @safe_slot
    def on_dns_preset(self):
        preset = self.cmb_dns_preset.currentText()
        self.ed_dns_multi_servers.setPlainText(", ".join(T.DNS_PRESETS.get(preset, [])))
        self.lbl_dns_preset.setText(T.DNS_PRESET_NOTES.get(preset, ""))

    def _dns_multi_server_list(self) -> list[str] | None:
        """读服务器输入框；不合法/为空就在摘要行上报错并返回 None。"""
        try:
            servers = T.parse_dns_servers(self.ed_dns_multi_servers.toPlainText())
        except ValueError as exc:
            self.lbl_dns_summary.setText(f"❌ {exc}")
            self.lbl_dns_summary.setStyleSheet(f"color:{C_RED};")
            self.badge_dns_multi.set_state("服务器列表有误", "error")
            log(f"DNS 服务器列表有误：{exc}", "warn", "tools")
            return None
        if not servers:
            self.lbl_dns_summary.setText("❌ 请先填至少一台 DNS 服务器（或选一个预设）")
            self.lbl_dns_summary.setStyleSheet(f"color:{C_RED};")
            self.badge_dns_multi.set_state("没有服务器", "error")
            return None
        return servers

    @safe_slot
    def do_dns_multi(self):
        if self.dns_multi_worker is not None and self.dns_multi_worker.isRunning():
            return
        name = self.ed_dns.text().strip()
        if not name:
            QMessageBox.information(self, "缺少域名",
                                    "请先在上面的「域名/IP」框里填要查的域名")
            return
        servers = self._dns_multi_server_list()
        if servers is None:
            return

        rtype = self.cmb_dns_type.currentText()
        self.tbl_dns_multi.setRowCount(0)
        self.lbl_dns_summary.setText(
            f"正在并发查询 {len(servers)} 台服务器（{name} {rtype}）…")
        self.lbl_dns_summary.setStyleSheet(f"color:{C_TEXT_DIM};")
        self.badge_dns_multi.set_state("查询中…", "info")
        self.btn_dns_multi.setEnabled(False)

        # 顺手记住这次的服务器列表（下次打开直接恢复）
        appconfig.CFG.set("dns_multi_servers", ", ".join(servers))
        appconfig.CFG.save()

        self.dns_multi_worker = DnsMultiWorker(name, rtype, servers,
                                               float(self.sp_dns_timeout.value()))
        self.dns_multi_worker.done.connect(self._on_dns_multi_done)
        self.dns_multi_worker.start()

    @safe_slot
    def do_dns_resolve(self):
        """把服务器框里的域名（DoH 预设）解析成 IP。"""
        if self.dns_multi_worker is not None and self.dns_multi_worker.isRunning():
            return
        hosts = T.split_dns_servers(self.ed_dns_multi_servers.toPlainText())
        if not hosts:
            self.lbl_dns_summary.setText("❌ 请先填要解析的域名或 IP")
            self.lbl_dns_summary.setStyleSheet(f"color:{C_RED};")
            return
        self.lbl_dns_summary.setText(f"正在解析 {len(hosts)} 个名字 …")
        self.lbl_dns_summary.setStyleSheet(f"color:{C_TEXT_DIM};")
        self.badge_dns_multi.set_state("解析中…", "info")
        self.btn_dns_multi.setEnabled(False)
        self.btn_dns_resolve.setEnabled(False)
        self.dns_multi_worker = DnsMultiWorker("", "A", hosts,
                                               float(self.sp_dns_timeout.value()),
                                               resolve_only=True)
        self.dns_multi_worker.done.connect(self._on_dns_multi_done)
        self.dns_multi_worker.start()

    @safe_slot
    def _on_dns_multi_done(self, payload: dict):
        """工人线程的结果一律从这里回到主线程（信号队列连接）。"""
        self.btn_dns_multi.setEnabled(True)
        self.btn_dns_resolve.setEnabled(True)
        kind = payload.get("kind")
        if kind == "resolve":
            self._show_dns_resolved(payload.get("value") or ([], []))
            return
        if kind == "error":
            self.lbl_dns_summary.setText(f"❌ 查询失败：{payload.get('value')}")
            self.lbl_dns_summary.setStyleSheet(f"color:{C_RED};")
            self.badge_dns_multi.set_state("查询失败", "error")
            return
        self._show_dns_multi(payload.get("name", ""), payload.get("rtype", ""),
                             payload.get("value") or [])

    def _show_dns_resolved(self, value):
        ips, missing = value
        if ips:
            self.ed_dns_multi_servers.setPlainText(", ".join(ips))
        msg = f"已解析出 {len(ips)} 个 IP"
        if missing:
            msg += f"；解析不出：{'、'.join(missing[:6])}"
        self.lbl_dns_summary.setText(("✅ " if ips else "❌ ") + msg)
        self.lbl_dns_summary.setStyleSheet(f"color:{C_MINT if not missing else C_YELLOW};")
        self.badge_dns_multi.set_state("解析完成" if not missing else "部分解析失败",
                                      "ok" if not missing else "warn")
        log(f"DNS 域名解析：{msg}", "info" if not missing else "warn", "tools")

    def _show_dns_multi(self, name: str, rtype: str, results: list):
        """把逐台结果铺进表格：与多数派不一致的标粉，失败/超时的标黄。"""
        stat = T.dns_consistency(results)
        disagree = set(stat["disagree_servers"])

        t = self.tbl_dns_multi
        t.setRowCount(0)
        for i, res in enumerate(results):
            t.insertRow(i)
            records = "；".join(res["records"]) if res["records"] else (res["error"] or "—")
            colors = {}
            if not res["ok"]:
                colors = {0: C_YELLOW, 2: C_YELLOW, 4: C_YELLOW}      # 死服务器/超时
            elif res["server"] in disagree:
                colors = {0: C_PINK, 2: C_PINK, 4: C_PINK}            # 跟多数派不一样
            set_row(t, i, [res["server"], res["label"], res["status"],
                           f"{res['rtt_ms']:.0f}", records], colors)

        if stat["total"] and not stat["answered"]:
            color, kind, badge = C_RED, "error", "全部无应答"
        elif stat["consistent"]:
            color, kind, badge = C_MINT, "ok", "全部一致"
        else:
            color, kind, badge = C_YELLOW, "warn", "有分歧"
        line = (f"{name} {rtype} · {stat['verdict']} · "
                f"共 {stat['total']} 台，{stat['answered']} 台有应答")
        if len(stat["groups"]) > 1:
            same = f"{stat['groups'][0]['count']} 台相同"
            line += f"；多数派（{same}）：{'；'.join(stat['majority_records'])[:80] or '—'}"
        self.lbl_dns_summary.setText(line)
        self.lbl_dns_summary.setStyleSheet(f"color:{color};")
        self.badge_dns_multi.set_state(badge, kind)
        log(f"多服务器 DNS 对比 {name} {rtype}：{stat['verdict']}", "info", "tools")

    def do_dns(self):
        name = self.ed_dns.text().strip()
        if not name:
            return
        rtype = self.cmb_dns_type.currentText()
        server = self.ed_dns_server.text().strip()
        self.lbl_dns.setText(f"查询 {name} {rtype} …")
        self.txt_dns.appendPlainText(f"\n===== {name}  {rtype} =====")
        records = T.dns_query(name, rtype, server)
        for rec in records:
            self.txt_dns.appendPlainText(f"  {rec}")
        self.lbl_dns.setText(f"完成，{len(records)} 条结果")
        log(f"DNS {rtype} {name} -> {records[:3]}", "info", "tools")

    # ---------------- 5. WOL ----------------

    def _page_wol(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        card = Card("⏻ 网络唤醒 (Wake-on-LAN)")
        form = QFormLayout()
        self.ed_wol_mac = QLineEdit()
        self.ed_wol_mac.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        form.addRow("目标 MAC", self.ed_wol_mac)
        self.ed_wol_bc = QLineEdit("255.255.255.255")
        form.addRow("广播地址", self.ed_wol_bc)
        self.sp_wol_port = QSpinBox()
        self.sp_wol_port.setRange(1, 65535)
        self.sp_wol_port.setValue(9)
        form.addRow("端口", self.sp_wol_port)
        card.add(form)
        btn = QPushButton("发送魔术包")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.do_wol)
        card.add(btn)
        self.lbl_wol = label("填入目标网卡的 MAC 地址即可唤醒（需目标主板开启 WOL）", "Dim")
        self.lbl_wol.setWordWrap(True)
        card.add(self.lbl_wol)
        lay.addWidget(card)
        lay.addStretch(1)
        return w

    def do_wol(self):
        ok, msg = T.wake_on_lan(self.ed_wol_mac.text().strip(),
                                self.ed_wol_bc.text().strip(),
                                self.sp_wol_port.value())
        self.lbl_wol.setText(msg)
        self.lbl_wol.setStyleSheet(f"color:{C_MINT if ok else C_RED};")
        log(msg, "success" if ok else "error", "tools")

    # ---------------- 6. HTTP ----------------

    def _page_http(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        card = Card("🔗 HTTP(S) 探测")
        r = QHBoxLayout()
        r.setSpacing(6)
        self.ed_http = QLineEdit()
        self.ed_http.setPlaceholderText("http://192.168.5.1 或 https://www.example.com")
        self.ed_http.returnPressed.connect(self.do_http)
        r.addWidget(self.ed_http, 1)
        btn = QPushButton("探测")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.do_http)
        r.addWidget(btn)
        card.add(r)
        self.lbl_http = label("检查状态码、响应时间、Server、标题、TLS 证书到期时间", "Dim")
        self.lbl_http.setWordWrap(True)
        card.add(self.lbl_http)
        lay.addWidget(card)

        self.txt_http = QPlainTextEdit()
        self.txt_http.setReadOnly(True)
        lay.addWidget(self.txt_http, 1)
        return w

    def do_http(self):
        url = self.ed_http.text().strip()
        if not url:
            return
        self.lbl_http.setText(f"探测 {url} …")
        self.txt_http.appendPlainText(f"\n===== {url} =====")
        res = T.http_probe(url)
        for k, v in res.items():
            self.txt_http.appendPlainText(f"  {k}: {v}")
        self.lbl_http.setText(f"完成：HTTP {res.get('status')}")
        log(f"HTTP 探测 {url} -> {res.get('status')}", "info", "tools")

    # ---------------- 7. 子网计算 ----------------

    def _page_subnet(self) -> QWidget:
        """子网页：算网段 / 切子网 / VLSM 划分 / CIDR 汇总 / 区间转 CIDR。"""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        card = Card("🧮 子网计算与划分")
        r = QHBoxLayout()
        r.setSpacing(6)
        r.addWidget(label("网段", "Dim"))
        self.ed_subnet = QLineEdit("192.168.5.0/24")
        self.ed_subnet.setPlaceholderText(
            "192.168.5.0/24 、192.168.5.22/24 、192.168.5.22 、192.168.5.0 255.255.255.0")
        self.ed_subnet.returnPressed.connect(self.do_subnet)
        r.addWidget(self.ed_subnet, 1)
        btn = QPushButton("计算")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.do_subnet)
        r.addWidget(btn)
        btn_iface = QPushButton("填本机网段")
        btn_iface.setObjectName("Ghost")
        btn_iface.clicked.connect(self._subnet_from_iface)
        r.addWidget(btn_iface)
        card.add(r)
        lay.addWidget(card)

        self.sub_tabs = QTabWidget()
        self.sub_tabs.addTab(self._subnet_calc_tab(), "网段信息")
        self.sub_tabs.addTab(self._subnet_split_tab(), "切子网")
        self.sub_tabs.addTab(self._subnet_vlsm_tab(), "VLSM 划分")
        self.sub_tabs.addTab(self._subnet_sum_tab(), "CIDR 汇总")
        lay.addWidget(self.sub_tabs, 1)

        self.do_subnet()
        return w

    # ---- 网段信息 ----

    def _subnet_calc_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        self.lbl_subnet = QLabel("输入 CIDR，例如 192.168.5.22/24")
        self.lbl_subnet.setWordWrap(True)
        self.lbl_subnet.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.lbl_subnet)
        lay.addStretch(1)
        return w

    def _subnet_from_iface(self) -> None:
        i = HI.primary_iface()
        if i and i.ip:
            self.ed_subnet.setText(f"{i.ip}/{i.prefix}")

    def do_subnet(self):
        try:
            info = SN.describe(self.ed_subnet.text().strip())
        except Exception as exc:
            self.lbl_subnet.setText(f"❌ 解析失败：{exc}")
            return
        blocks = [
            ("网段", f"<b>{info['cidr']}</b>（{info['summary']}）"),
            ("子网掩码", f"{info['netmask']}　二进制 {info['binary_mask']}"),
            ("通配符掩码", f"{info['wildcard']}　（ACL / 路由里用）"),
            ("网络地址", f"{info['network']}　{info['binary_network']}"),
            ("广播地址", info["broadcast"]),
            ("可用范围", f"{info['first']} ~ {info['last']}"),
            ("地址总数", f"{info['total']:,}"),
            ("可用主机数", f"{info['usable']:,}"),
            ("反查区", info["reverse_zone"]),
            ("地址类别", info["addr_class"]),
            ("网段性质", info["reserved"]),
            ("十六进制 / 整数", f"{info['hex']}　{info['int']:,}"),
        ]
        html = "<br>".join(f"<b>{k}</b>：{v}" for k, v in blocks)
        html += f"<br><br><span style='color:{C_TEXT_DIM}'>{info['explain']}</span>"
        self.lbl_subnet.setText(html)

    # ---- 切子网 ----

    def _subnet_split_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(8)

        r1 = QHBoxLayout()
        r1.addWidget(label("方式", "Dim"))
        self.cmb_split_mode = QComboBox()
        self.cmb_split_mode.addItems(["按新前缀切", "按子网数量切"])
        r1.addWidget(self.cmb_split_mode)
        r1.addWidget(label("新前缀 /", "Dim"))
        self.sp_split_prefix = QSpinBox()
        self.sp_split_prefix.setRange(1, 32)
        self.sp_split_prefix.setValue(26)
        r1.addWidget(self.sp_split_prefix)
        r1.addWidget(label("或要几个", "Dim"))
        self.sp_split_count = QSpinBox()
        self.sp_split_count.setRange(1, 4096)
        self.sp_split_count.setValue(4)
        r1.addWidget(self.sp_split_count)
        btn = QPushButton("划分")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.do_split)
        r1.addWidget(btn)
        r1.addStretch(1)
        lay.addLayout(r1)

        self.lbl_split = label("按上面填的前缀或数量切分当前网段", "Dim")
        lay.addWidget(self.lbl_split)
        self.tbl_split = make_table(["#", "子网", "掩码", "可用范围", "可用数"], 3)
        lay.addWidget(self.tbl_split, 1)
        return w

    def do_split(self):
        try:
            if self.cmb_split_mode.currentIndex() == 0:
                nets = SN.split(self.ed_subnet.text().strip(),
                                self.sp_split_prefix.value())
                head = f"切成 {len(nets)} 个等长子网"
            else:
                prefix, nets = SN.split_by_count(self.ed_subnet.text().strip(),
                                                 self.sp_split_count.value())
                head = f"自动选 /{prefix}，共切出 {len(nets)} 个子网"
        except Exception as exc:
            self.lbl_split.setText(f"❌ {exc}")
            self.lbl_split.setStyleSheet(f"color:{C_RED};")
            self.tbl_split.setRowCount(0)
            return

        self.lbl_split.setText(f"✅ {head}（{self.ed_subnet.text().strip()}）")
        self.lbl_split.setStyleSheet(f"color:{C_MINT};")
        t = self.tbl_split
        t.setSortingEnabled(False)
        t.setRowCount(0)
        for i, n in enumerate(nets, 1):
            first, last = SN.usable_range(n)
            row = t.rowCount()
            t.insertRow(row)
            set_row(t, row, [str(i), str(n), str(n.netmask),
                             f"{first} ~ {last}", f"{max(0, n.num_addresses - 2):,}"])
        t.setSortingEnabled(True)

    # ---- VLSM ----

    def _subnet_vlsm_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(8)
        lay.addWidget(label("每行一段：名称,需要的主机数（例如「办公区,100」）", "Dim"))
        self.ed_vlsm = QPlainTextEdit()
        self.ed_vlsm.setPlaceholderText("办公区,100\n监控,50\n核心设备,10\n设备互联,2")
        self.ed_vlsm.setPlainText("办公区,100\n监控,50\n核心设备,10\n设备互联,2")
        self.ed_vlsm.setMaximumHeight(110)
        lay.addWidget(self.ed_vlsm)
        r = QHBoxLayout()
        btn = QPushButton("按上面的网段划分")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.do_vlsm)
        r.addWidget(btn)
        r.addStretch(1)
        lay.addLayout(r)
        self.lbl_vlsm = label("按需求从大到小依次分配，尽量少浪费地址", "Dim")
        lay.addWidget(self.lbl_vlsm)
        self.tbl_vlsm = make_table(["名称", "需要", "分配", "掩码", "可用范围", "可用数", "说明"], 4)
        lay.addWidget(self.tbl_vlsm, 1)
        return w

    def do_vlsm(self):
        needs = []
        for ln in self.ed_vlsm.toPlainText().splitlines():
            ln = ln.strip()
            if not ln:
                continue
            name, _, cnt = ln.replace("，", ",").partition(",")
            name = name.strip()
            try:
                needs.append((name, int(cnt.strip() or "0")))
            except ValueError:
                self.lbl_vlsm.setText(f"❌ 看不懂这一行：{ln}")
                self.lbl_vlsm.setStyleSheet(f"color:{C_RED};")
                return
        if not needs:
            self.lbl_vlsm.setText("❌ 至少写一段需求")
            self.lbl_vlsm.setStyleSheet(f"color:{C_RED};")
            return
        try:
            rows = SN.vlsm(self.ed_subnet.text().strip(), needs)
        except Exception as exc:
            self.lbl_vlsm.setText(f"❌ {exc}")
            self.lbl_vlsm.setStyleSheet(f"color:{C_RED};")
            return

        bad = [r for r in rows if r["error"]]
        self.lbl_vlsm.setText(
            f"✅ 已划分 {len(rows) - len(bad)}/{len(rows)} 段"
            + (f"，{len(bad)} 段空间不够" if bad else "，全部装得下"))
        self.lbl_vlsm.setStyleSheet(f"color:{C_RED};" if bad else f"color:{C_MINT};")

        t = self.tbl_vlsm
        t.setSortingEnabled(False)
        t.setRowCount(0)
        for r in rows:
            row = t.rowCount()
            t.insertRow(row)
            colors = {6: C_RED} if r["error"] else {2: C_MINT}
            set_row(t, row, [r["name"], r["need"], r["cidr"], r["netmask"],
                             f"{r['first']} ~ {r['last']}" if r["cidr"] != "-" else "-",
                             r["usable"], r["error"] or "OK"], colors)
        t.setSortingEnabled(True)

    # ---- CIDR 汇总 ----

    def _subnet_sum_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(8)
        lay.addWidget(label("一行一个网段；也可以写成「起始IP-结束IP」把区间转成 CIDR", "Dim"))
        self.ed_sum = QPlainTextEdit()
        self.ed_sum.setPlaceholderText("192.168.0.0/25\n192.168.0.128/25\n10.0.0.5-10.0.0.200")
        self.ed_sum.setMaximumHeight(120)
        lay.addWidget(self.ed_sum)
        r = QHBoxLayout()
        btn = QPushButton("汇总 / 转换")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.do_summarize)
        r.addWidget(btn)
        r.addStretch(1)
        lay.addLayout(r)
        self.lbl_sum = label("汇总会把能合并的网段并成最少的几条路由；"
                             "区间会转成最少的 CIDR，写防火墙白名单很省事", "Dim")
        self.lbl_sum.setWordWrap(True)
        lay.addWidget(self.lbl_sum)
        self.tbl_sum = make_table(["#", "结果", "掩码", "可用范围", "可用数"], 3)
        lay.addWidget(self.tbl_sum, 1)
        return w

    def do_summarize(self):
        nets, ranges = [], []
        for ln in self.ed_sum.toPlainText().splitlines():
            ln = ln.strip()
            if not ln:
                continue
            if "/" not in ln and "-" in ln:
                a, _, b = ln.partition("-")
                ranges.append((a.strip(), b.strip()))
            else:
                nets.append(ln)

        out = []
        try:
            if nets:
                before = len(nets)
                merged = SN.summarize(nets)
                out.append((f"汇总：{before} 条 -> {len(merged)} 条", merged))
            for a, b in ranges:
                cidrs = SN.range_to_cidrs(a, b)
                out.append((f"区间 {a} ~ {b} -> {len(cidrs)} 条 CIDR", cidrs))
        except Exception as exc:
            self.lbl_sum.setText(f"❌ {exc}")
            self.lbl_sum.setStyleSheet(f"color:{C_RED};")
            return

        if not out:
            self.lbl_sum.setText("❌ 没填内容")
            self.lbl_sum.setStyleSheet(f"color:{C_RED};")
            return

        self.lbl_sum.setText("✅ " + "；".join(h for h, _ in out))
        self.lbl_sum.setStyleSheet(f"color:{C_MINT};")

        t = self.tbl_sum
        t.setSortingEnabled(False)
        t.setRowCount(0)
        idx = 0
        for head, items in out:
            for n in items:
                idx += 1
                first, last = SN.usable_range(n)
                row = t.rowCount()
                t.insertRow(row)
                set_row(t, row, [str(idx), str(n), str(n.netmask),
                                 f"{first} ~ {last}",
                                 f"{max(0, n.num_addresses - 2):,}"])
        t.setSortingEnabled(True)

    # ---------------- 8. 时间校准 ----------------

    def _page_ntp(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        card = Card("⏱ SNTP 时间校准")
        r = QHBoxLayout()
        r.setSpacing(6)
        r.addWidget(label("NTP 服务器", "Dim"))
        self.ed_ntp = QLineEdit("ntp.aliyun.com")
        self.ed_ntp.setFixedWidth(200)
        r.addWidget(self.ed_ntp)
        btn = QPushButton("校准")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.do_ntp)
        r.addWidget(btn)
        r.addStretch(1)
        card.add(r)
        self.lbl_ntp = QLabel("对比本机时间与 NTP 服务器时间")
        self.lbl_ntp.setWordWrap(True)
        card.add(self.lbl_ntp)
        lay.addWidget(card)
        lay.addStretch(1)
        return w

    def do_ntp(self):
        res = T.sntp_offset(self.ed_ntp.text().strip())
        if not res.get("ok"):
            self.lbl_ntp.setText(f"❌ 失败：{res.get('msg')}")
            self.lbl_ntp.setStyleSheet(f"color:{C_RED};")
            return
        off = res["偏差秒"]
        color = C_MINT if abs(off) < 1 else (C_YELLOW if abs(off) < 5 else C_RED)
        rows = [(k, v) for k, v in res.items() if k not in ("ok", "偏差秒")]
        self.lbl_ntp.setText("<br>".join(f"<b>{k}</b>：{v}" for k, v in rows))
        self.lbl_ntp.setStyleSheet(f"color:{color};")
        log(f"时间校准：偏差 {res['偏差']}", "info", "tools")
