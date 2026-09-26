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
                             QPushButton, QSpinBox,
                             QVBoxLayout, QWidget)

from core import hostinfo as HI
from core import tools as T
from core.logging_bus import log
from ui.widgets import Card, Sparkline, label, make_table, set_row
from theme import C_MINT, C_RED, C_TEXT_DIM, C_YELLOW


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
        lay.addWidget(self.txt_dns, 1)
        return w

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
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        card = Card("🧮 子网计算器")
        r = QHBoxLayout()
        r.setSpacing(6)
        self.ed_subnet = QLineEdit("192.168.5.0/24")
        self.ed_subnet.returnPressed.connect(self.do_subnet)
        r.addWidget(self.ed_subnet, 1)
        btn = QPushButton("计算")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.do_subnet)
        r.addWidget(btn)
        card.add(r)
        self.lbl_subnet = QLabel("输入 CIDR，例如 192.168.5.22/24")
        self.lbl_subnet.setWordWrap(True)
        self.lbl_subnet.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card.add(self.lbl_subnet)
        lay.addWidget(card)
        lay.addStretch(1)
        self.do_subnet()
        return w

    def do_subnet(self):
        try:
            info = HI.subnet_info(self.ed_subnet.text().strip())
        except Exception as exc:
            self.lbl_subnet.setText(f"❌ 解析失败：{exc}")
            return
        rows = [
            ("网络地址", info["network"]), ("子网掩码", info["netmask"]),
            ("前缀长度", f"/{info['prefix']}"), ("广播地址", info["broadcast"]),
            ("可用范围", f"{info['first']} ~ {info['last']}"),
            ("地址总数", info["total"]), ("可用主机数", info["usable"]),
            ("是否私有", "是" if info["is_private"] else "否"),
            ("可扫描主机数", f"{info['scannable']}（单次扫描上限）"),
        ]
        self.lbl_subnet.setText("<br>".join(f"<b>{k}</b>：{v}" for k, v in rows))

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
