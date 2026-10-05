# -*- coding: utf-8 -*-
"""
DHCP 三件套（审计 / 耗尽测试 / 假 DHCP）
========================================

一页放三个子标签，从左到右按「危险程度」递增：

    ① DHCP 审计（被动）      只听不发。看看到底是谁在给这个 LAN 发地址。
    ② 地址池耗尽测试         用随机 MAC 把服务器的可分配地址占掉，验证池子有多大。
    ③ 假 DHCP 服务器         自己抢答 OFFER / ACK，把网关和 DNS 发给别人。

⚠ 后两个是**主动**功能：在别人的网络里用会把整个 LAN 搞离线，
   所以开始按钮在勾选顶部红色授权确认之前一直是灰的。

界面约定与其它页保持一致：
* 顶部的红色横幅 + 必须勾选的复选框（复制自 tab_arp.py）；
* 危险操作开始前弹一次确认框；
* 工作线程只往对象的 records 里追加，界面用 QTimer 定时把新行刷进表格 ——
  这样既不会丢掉任何一条记录，也不会让工作线程直接碰 Qt 控件。
"""

from __future__ import annotations

import csv
import time

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFrame,
                             QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                             QPushButton, QSpinBox, QTabWidget, QVBoxLayout,
                             QWidget)

from core import dhcpx as D
from core.logging_bus import log
from ui.widgets import Badge, Card, label, make_table, safe_slot, set_row
from theme import C_MINT, C_RED, C_TEXT_DIM, C_YELLOW

AUDIT_HEADERS = ["时间", "客户端 MAC", "请求地址", "分配地址", "服务器", "主机名", "类型"]
STARVE_HEADERS = ["时间", "客户端 MAC", "请求地址", "分配地址", "服务器", "主机名", "类型"]
ROGUE_HEADERS = ["时间", "客户端 MAC", "请求地址", "分配地址", "服务器", "主机名", "类型"]

AUTH_WARNING = (
    "「地址池耗尽测试」会用伪造的 MAC 把 DHCP 服务器的地址池占满，"
    "「假 DHCP 服务器」会给整个网段发我们指定的网关和 DNS —— "
    "这两个功能都能让一整个 LAN 上不了网，属于攻击行为。\n"
    "请只在**你本人拥有、或已获得书面授权**的网络里使用，并且事先想清楚怎么恢复："
    "停掉之后，客户端要等租期到期（或重连网络）才会回到真正的 DHCP 服务器。"
)


def _make_iface_combo() -> QComboBox:
    c = QComboBox()
    c.setMinimumWidth(330)
    c.setToolTip("DHCP 是二层广播协议，必须选对接到目标网段的那块网卡")
    return c


def _make_row(*widgets, spacing: int = 6) -> QHBoxLayout:
    """一行控件（末尾自动补一个弹簧）。"""
    row = QHBoxLayout()
    row.setSpacing(spacing)
    for w in widgets:
        if isinstance(w, QWidget):
            row.addWidget(w)
        else:
            row.addLayout(w)
    row.addStretch(1)
    return row


class DhcpTab(QWidget):
    """
    DHCP 页。

    对外接口（主窗口用）：

        tab = DhcpTab()
        tab.status_text()    -> 状态栏文案
        tab.is_running()     -> 有没有 worker 在跑
        tab.shutdown()       -> 关窗口时停掉所有 worker
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.audit: D.DhcpAudit | None = None
        self.starve: D.DhcpStarve | None = None
        self.rogue: D.RogueDhcp | None = None
        # 表格里已经画到第几条（worker 的 records 会一直追加，只画新增的）
        self._audit_shown = 0
        self._starve_shown = 0
        self._rogue_shown = 0
        # 服务器 IP 是「自动跟着网卡填的」还是用户自己改的
        self._auto_server_ip = True
        self._ifaces = []
        self._build()
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh_all)

    # ================= 界面 =================

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)
        outer.addWidget(self._build_warning())
        outer.addWidget(self._build_intro())

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_audit(), "① DHCP 审计（被动）")
        self.tabs.addTab(self._build_starve(), "② 地址池耗尽测试")
        self.tabs.addTab(self._build_rogue(), "③ 假 DHCP 服务器")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        outer.addWidget(self.tabs, 1)

        self.reload_ifaces()
        self._refresh_buttons()

    def _build_warning(self) -> QWidget:
        """红色授权横幅：勾选之前所有「开始」按钮都是灰的。"""
        w = QFrame()
        w.setObjectName("Card")
        w.setStyleSheet(f"QFrame#Card {{ background-color:#FFEAEA;"
                        f" border:1px solid {C_RED}; border-radius:14px; }}")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(4)
        t = QLabel("⚠️ 这三个功能都可能让整个 LAN 掉线，只能用于你本人拥有、或已获得书面授权的网络")
        t.setStyleSheet(f"color:{C_RED}; font-weight:800; font-size:10.5pt;")
        t.setWordWrap(True)
        lay.addWidget(t)
        d = QLabel(AUTH_WARNING)
        d.setWordWrap(True)
        d.setObjectName("Dim")
        lay.addWidget(d)
        row = QHBoxLayout()
        self.chk_auth = QCheckBox("我已获得该网络的测试授权，并已通知使用者、理解上述风险")
        self.chk_auth.setStyleSheet("font-weight:700;")
        self.chk_auth.toggled.connect(self._refresh_buttons)
        row.addWidget(self.chk_auth)
        row.addStretch(1)
        lay.addLayout(row)
        return w

    def _build_intro(self) -> QWidget:
        card = Card("🧭 这一页怎么用")
        t = QLabel(
            "① **被动审计**：一个包都不发，只记录「哪台服务器把哪个地址发给了谁」。"
            "怀疑 LAN 上有第二个（甚至来路不明的）DHCP 服务器时，先跑这个。\n"
            "② **地址池耗尽测试**：用伪造 MAC 反复 DISCOVER（可选再 REQUEST）把池子占满，"
            "用来验证测试网段的地址容量与 DHCP 防护是否生效。\n"
            "③ **假 DHCP 服务器**：自己抢答 OFFER / ACK，把指定的网关和 DNS 发出去 —— "
            "配合「流量劫持」页可以演示假 DHCP 能把流量引到哪里。")
        t.setWordWrap(True)
        t.setObjectName("Dim")
        card.add(t)
        self.badge_priv = Badge("检查权限中…", "idle")
        self.lbl_priv = label("", "Dim")
        self.lbl_priv.setWordWrap(True)
        card.add(_make_row(label("运行条件", "Dim"), self.badge_priv))
        card.add(self.lbl_priv)
        btn = QPushButton("重新检查权限 / 刷新网卡")
        btn.setObjectName("Ghost")
        btn.clicked.connect(self.reload_ifaces)
        card.add(btn)
        return card

    # ---------------- ① 审计 ----------------

    def _build_audit(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        card = Card("① DHCP 审计（被动监听，不发任何数据包）")
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("网卡", "Dim"))
        self.cmb_iface_audit = _make_iface_combo()
        r1.addWidget(self.cmb_iface_audit, 1)
        self.btn_audit_start = QPushButton("▶ 开始审计")
        self.btn_audit_start.setObjectName("Primary")
        self.btn_audit_start.setMinimumHeight(34)
        self.btn_audit_start.clicked.connect(self.start_audit)
        self.btn_audit_stop = QPushButton("■ 停止")
        self.btn_audit_stop.setObjectName("Success")
        self.btn_audit_stop.setMinimumHeight(34)
        self.btn_audit_stop.setEnabled(False)
        self.btn_audit_stop.clicked.connect(self.stop_audit)
        r1.addWidget(self.btn_audit_start)
        r1.addWidget(self.btn_audit_stop)
        self.badge_audit = Badge("未启动", "idle")
        r1.addWidget(self.badge_audit)
        card.add(r1)

        self.lbl_audit_stats = label("未启动", "Dim")
        self.lbl_audit_stats.setWordWrap(True)
        card.add(self.lbl_audit_stats)
        self.lbl_audit_servers = label("还没发现 DHCP 服务器", "Dim")
        self.lbl_audit_servers.setWordWrap(True)
        card.add(self.lbl_audit_servers)

        bar = QHBoxLayout()
        bar.setSpacing(6)
        bar.addWidget(label("📋 发现的租约", "CardT"))
        bar.addStretch(1)
        self.lbl_audit_count = label("0 条", "Dim")
        bar.addWidget(self.lbl_audit_count)
        b_export = QPushButton("导出 CSV")
        b_export.setObjectName("Ghost")
        b_export.clicked.connect(self.export_audit_csv)
        bar.addWidget(b_export)
        b_clear = QPushButton("清空")
        b_clear.setObjectName("Ghost")
        b_clear.clicked.connect(self.clear_audit)
        bar.addWidget(b_clear)
        card.add(bar)

        self.tbl_audit = make_table(AUDIT_HEADERS, stretch_col=5)
        self.tbl_audit.setSortingEnabled(False)      # 实时追加时不能开排序，否则行会错位
        self.tbl_audit.setColumnWidth(0, 80)
        self.tbl_audit.setColumnWidth(1, 150)
        self.tbl_audit.setColumnWidth(2, 120)
        self.tbl_audit.setColumnWidth(3, 120)
        self.tbl_audit.setColumnWidth(4, 120)
        self.tbl_audit.setColumnWidth(6, 80)
        card.add(self.tbl_audit)
        lay.addWidget(card, 1)
        return page

    # ---------------- ② 耗尽测试 ----------------

    def _build_starve(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        card = Card("② 地址池耗尽测试（伪造 MAC 占满地址池）")
        warn = QLabel("⚠ 这个功能会把服务器的可分配地址占光，同一网段的新设备上不了网。"
                      "停止只是停止发包；已占用的地址要等服务器租期到期才会释放。")
        warn.setWordWrap(True)
        warn.setStyleSheet(f"color:{C_RED}; font-weight:700;")
        card.add(warn)

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("网卡", "Dim"))
        self.cmb_iface_starve = _make_iface_combo()
        r1.addWidget(self.cmb_iface_starve, 1)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("MAC 前缀", "Dim"))
        self.ed_prefix = QLineEdit()
        self.ed_prefix.setPlaceholderText("de:ad:be")
        self.ed_prefix.setFixedWidth(120)
        self.ed_prefix.setToolTip(
            "伪造 MAC 的前三个字节，方便在 Wireshark 里一眼认出是我们发的；\n"
            "留空则完全随机。注意别撞上真实设备的地址（推荐 de:ad:be / 02:00:00 这类）。")
        r2.addWidget(self.ed_prefix)
        r2.addWidget(label("要占多少地址", "Dim"))
        self.sp_count = QSpinBox()
        self.sp_count.setRange(1, D.MAX_COUNT)
        self.sp_count.setValue(50)
        self.sp_count.setToolTip("想占掉多少个地址（受服务器池子大小限制）")
        r2.addWidget(self.sp_count)
        r2.addWidget(label("发包速率", "Dim"))
        self.sp_rate = QSpinBox()
        self.sp_rate.setRange(1, int(D.MAX_RATE))
        self.sp_rate.setValue(20)
        self.sp_rate.setSuffix(" /秒")
        self.sp_rate.setToolTip("每秒最多发多少个 DISCOVER。速率越高越快占满，"
                                "但更容易被 DHCP 防护 / 交换机风暴抑制盯上。")
        r2.addWidget(self.sp_rate)
        r2.addStretch(1)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(6)
        self.chk_request = QCheckBox("收到 OFFER 后补一个 REQUEST（真正把地址占下来）")
        self.chk_request.setChecked(True)
        self.chk_request.setToolTip(
            "不补 REQUEST 的话，服务器可能只回 OFFER、不把地址记进租约表，"
            "实际占用量会明显偏低。")
        r3.addWidget(self.chk_request)
        r3.addStretch(1)
        self.btn_starve_start = QPushButton("⚡ 开始耗尽测试")
        self.btn_starve_start.setObjectName("Danger")
        self.btn_starve_start.setMinimumHeight(34)
        self.btn_starve_start.clicked.connect(self.start_starve)
        self.btn_starve_stop = QPushButton("■ 停止")
        self.btn_starve_stop.setObjectName("Success")
        self.btn_starve_stop.setMinimumHeight(34)
        self.btn_starve_stop.setEnabled(False)
        self.btn_starve_stop.clicked.connect(self.stop_starve)
        r3.addWidget(self.btn_starve_start)
        r3.addWidget(self.btn_starve_stop)
        self.badge_starve = Badge("未启动", "idle")
        r3.addWidget(self.badge_starve)
        card.add(r3)

        self.lbl_starve_stats = label("未启动", "Dim")
        self.lbl_starve_stats.setWordWrap(True)
        card.add(self.lbl_starve_stats)
        lay.addWidget(card)

        card2 = Card("📊 已占下的地址（收到 ACK 才算数）")
        bar = QHBoxLayout()
        bar.setSpacing(6)
        bar.addStretch(1)
        self.lbl_starve_taken = label("0 个", "Dim")
        bar.addWidget(self.lbl_starve_taken)
        b_clear = QPushButton("清空")
        b_clear.setObjectName("Ghost")
        b_clear.clicked.connect(self.clear_starve)
        bar.addWidget(b_clear)
        card2.add(bar)
        self.tbl_starve = make_table(STARVE_HEADERS, stretch_col=5)
        self.tbl_starve.setSortingEnabled(False)
        self.tbl_starve.setColumnWidth(0, 80)
        self.tbl_starve.setColumnWidth(1, 150)
        self.tbl_starve.setColumnWidth(2, 120)
        self.tbl_starve.setColumnWidth(3, 120)
        self.tbl_starve.setColumnWidth(4, 120)
        self.tbl_starve.setColumnWidth(6, 80)
        card2.add(self.tbl_starve)
        lay.addWidget(card2, 1)
        return page

    # ---------------- ③ 假 DHCP ----------------

    def _build_rogue(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        card = Card("③ 假 DHCP 服务器（抢答 OFFER / ACK，下发我们指定的配置）")
        warn = QLabel("⚠ 启动后，这个网段里凡是发 DISCOVER 的设备都会拿到我们下发的网关和 DNS。"
                      "网关 / DNS 指向本机就相当于把它的流量引过来（配合「流量劫持」页使用）；"
                      "填错会让对方彻底上不了网。")
        warn.setWordWrap(True)
        warn.setStyleSheet(f"color:{C_RED}; font-weight:700;")
        card.add(warn)

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("网卡", "Dim"))
        self.cmb_iface_rogue = _make_iface_combo()
        r1.addWidget(self.cmb_iface_rogue, 1)
        r1.addWidget(label("服务器 IP", "Dim"))
        self.ed_server_ip = QLineEdit()
        self.ed_server_ip.setFixedWidth(130)
        self.ed_server_ip.setPlaceholderText("留空 = 用网卡 IP")
        self.ed_server_ip.setToolTip("我们自称的 DHCP 服务器地址，一般就是这块网卡的 IP")
        r1.addWidget(self.ed_server_ip)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("地址池", "Dim"))
        self.ed_pool = QLineEdit(D.DEFAULT_POOL)
        self.ed_pool.setMinimumWidth(260)
        self.ed_pool.setToolTip("发给客户端的地址范围，支持：\n"
                                "192.168.50.100-192.168.50.200（完整区间）\n"
                                "192.168.50.100-200（尾段简写）\n"
                                "192.168.50.0/24（网段，自动去掉网络号/广播号）")
        r2.addWidget(self.ed_pool, 1)
        r2.addWidget(label("掩码", "Dim"))
        self.ed_mask = QLineEdit(D.DEFAULT_MASK)
        self.ed_mask.setFixedWidth(130)
        r2.addWidget(self.ed_mask)
        r2.addWidget(label("租期", "Dim"))
        self.sp_lease = QSpinBox()
        self.sp_lease.setRange(30, 86400)
        self.sp_lease.setValue(D.DEFAULT_LEASE_TIME)
        self.sp_lease.setSuffix(" 秒")
        self.sp_lease.setToolTip("租期越短，停止后客户端越快回到真正的 DHCP 服务器")
        r2.addWidget(self.sp_lease)
        r2.addStretch(1)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(6)
        r3.addWidget(label("下发网关", "Dim"))
        self.ed_gateway = QLineEdit()
        self.ed_gateway.setMinimumWidth(150)
        self.ed_gateway.setPlaceholderText("例如本机 IP（引流）或真实网关")
        r3.addWidget(self.ed_gateway)
        r3.addWidget(label("下发 DNS", "Dim"))
        self.ed_dns = QLineEdit()
        self.ed_dns.setMinimumWidth(180)
        self.ed_dns.setPlaceholderText("多个用逗号隔开，例如 192.168.1.9,223.5.5.5")
        r3.addWidget(self.ed_dns, 1)
        btn_fill = QPushButton("填成本机 IP")
        btn_fill.setObjectName("Ghost")
        btn_fill.setToolTip("把网关和 DNS 都填成所选网卡的 IP —— 典型引流配置")
        btn_fill.clicked.connect(self.fill_local)
        r3.addWidget(btn_fill)
        card.add(r3)

        r4 = QHBoxLayout()
        r4.setSpacing(6)
        r4.addStretch(1)
        self.btn_rogue_start = QPushButton("⚡ 启动假 DHCP")
        self.btn_rogue_start.setObjectName("Danger")
        self.btn_rogue_start.setMinimumHeight(34)
        self.btn_rogue_start.clicked.connect(self.start_rogue)
        self.btn_rogue_stop = QPushButton("■ 停止")
        self.btn_rogue_stop.setObjectName("Success")
        self.btn_rogue_stop.setMinimumHeight(34)
        self.btn_rogue_stop.setEnabled(False)
        self.btn_rogue_stop.clicked.connect(self.stop_rogue)
        r4.addWidget(self.btn_rogue_start)
        r4.addWidget(self.btn_rogue_stop)
        self.badge_rogue = Badge("未启动", "idle")
        r4.addWidget(self.badge_rogue)
        card.add(r4)

        self.lbl_rogue_stats = label("未启动", "Dim")
        self.lbl_rogue_stats.setWordWrap(True)
        card.add(self.lbl_rogue_stats)
        lay.addWidget(card)

        card2 = Card("📋 拿了我们租约的客户端")
        bar = QHBoxLayout()
        bar.addStretch(1)
        self.lbl_rogue_count = label("0 台", "Dim")
        bar.addWidget(self.lbl_rogue_count)
        b_clear = QPushButton("清空")
        b_clear.setObjectName("Ghost")
        b_clear.clicked.connect(self.clear_rogue)
        bar.addWidget(b_clear)
        card2.add(bar)
        self.tbl_rogue = make_table(ROGUE_HEADERS, stretch_col=5)
        self.tbl_rogue.setSortingEnabled(False)
        self.tbl_rogue.setColumnWidth(0, 80)
        self.tbl_rogue.setColumnWidth(1, 150)
        self.tbl_rogue.setColumnWidth(2, 120)
        self.tbl_rogue.setColumnWidth(3, 120)
        self.tbl_rogue.setColumnWidth(4, 120)
        self.tbl_rogue.setColumnWidth(6, 80)
        card2.add(self.tbl_rogue)
        lay.addWidget(card2, 1)
        return page

    # ================= 网卡 / 权限 =================

    @safe_slot
    def reload_ifaces(self):
        """刷新三张页的网卡下拉框，并重新检查权限。"""
        self._ifaces = D.local_ifaces()
        # 默认挑一块「在线且带网关」的网卡
        default_ip = ""
        for i in self._ifaces:
            if i.gateway and i.is_up:
                default_ip = i.ip
                break
        if not default_ip and self._ifaces:
            default_ip = self._ifaces[0].ip

        for combo in (self.cmb_iface_audit, self.cmb_iface_starve, self.cmb_iface_rogue):
            old = combo.currentData()
            keep_ip = getattr(old, "ip", "") or default_ip
            combo.blockSignals(True)
            combo.clear()
            for i in self._ifaces:
                combo.addItem(i.label, i)
            for idx, i in enumerate(self._ifaces):
                if i.ip == keep_ip:
                    combo.setCurrentIndex(idx)
                    break
            combo.blockSignals(False)

        self._refresh_priv()
        self.on_iface_changed()
        self._refresh_buttons()

    def _refresh_priv(self):
        ok, reason = D.dhcp_available(need_send=True)
        if ok:
            self.badge_priv.set_state("就绪", "ok")
            self.lbl_priv.setText("管理员 + Npcap 都可用；三个功能都能跑。")
        else:
            self.badge_priv.set_state("不可用", "error")
            self.lbl_priv.setText(reason)

    def current_iface(self, which: str = "audit"):
        combo = {"audit": self.cmb_iface_audit, "starve": self.cmb_iface_starve,
                 "rogue": self.cmb_iface_rogue}[which]
        return combo.currentData()

    @safe_slot
    def on_iface_changed(self):
        """换网卡时把「本机 IP」相关的默认值跟着更新。"""
        i = self.current_iface("rogue")
        if i is None:
            return
        if not self.ed_server_ip.text().strip() or self._auto_server_ip:
            self.ed_server_ip.setText(i.ip or "")
            self._auto_server_ip = True
        if not self.ed_gateway.text().strip():
            self.ed_gateway.setText(i.ip or "")

    @safe_slot
    def fill_local(self):
        i = self.current_iface("rogue")
        if i is None or not i.ip:
            QMessageBox.warning(self, "没有网卡", "请先选择一块网卡")
            return
        self.ed_gateway.setText(i.ip)
        self.ed_dns.setText(i.ip)
        log(f"已把下发的网关 / DNS 都填成本机 IP：{i.ip}", "info", "dhcp")

    # ================= 启停辅助 =================

    def _guard(self) -> bool:
        """所有「开始」按钮共用的检查：授权勾了吗、权限够吗、选网卡了吗。"""
        if not self.chk_auth.isChecked():
            QMessageBox.warning(self, "需要授权确认",
                                "请先在最上方勾选「我已获得该网络的测试授权」。")
            return False
        ok, reason = D.dhcp_available(need_send=True)
        if not ok:
            self._refresh_priv()
            QMessageBox.warning(self, "环境不可用", reason)
            return False
        return True

    def _note(self, text: str):
        """把动作记进崩溃现场文件（主窗口注入的回调，没有就跳过）。"""
        cb = getattr(self, "note_action", None) or getattr(self, "_note_cb", None)
        if callable(cb):
            try:
                cb(text)
            except Exception:
                pass

    def _refresh_buttons(self):
        granted = self.chk_auth.isChecked()
        audit_run = self.audit is not None and self.audit.is_alive()
        starve_run = self.starve is not None and self.starve.is_alive()
        rogue_run = self.rogue is not None and self.rogue.is_alive()

        self.btn_audit_start.setEnabled(granted and not audit_run)
        self.btn_audit_stop.setEnabled(audit_run)
        self.btn_starve_start.setEnabled(granted and not starve_run)
        self.btn_starve_stop.setEnabled(starve_run)
        self.btn_rogue_start.setEnabled(granted and not rogue_run)
        self.btn_rogue_stop.setEnabled(rogue_run)

        tip = "" if granted else "请先在最上方勾选「我已获得该网络的测试授权」"
        for b in (self.btn_audit_start, self.btn_starve_start, self.btn_rogue_start):
            b.setToolTip(tip)

    def _on_tab_changed(self, _index: int):
        """切到哪一页就刷新对应那张表（省得一直刷三张）。"""
        self.refresh_all()

    # ================= ① 审计 =================

    @safe_slot
    def start_audit(self):
        if not self._guard():
            return
        iface = self.current_iface("audit")
        if iface is None:
            QMessageBox.warning(self, "缺少网卡", "请选择要监听的网卡")
            return
        if not iface.l2_name:
            log(f"网卡「{iface.alias}」没有 Npcap 设备名，抓包可能失败", "warn", "dhcp")
        self.audit = D.DhcpAudit(iface)
        self._audit_shown = 0
        self._note(f"开始 DHCP 审计 iface={iface.alias}")
        self.audit.start()
        self.badge_audit.set_state("运行中", "ok")
        self.lbl_audit_stats.setText(f"正在被动监听 {iface.alias}（不发任何包）…")
        self.timer.start()
        self._refresh_buttons()

    @safe_slot
    def stop_audit(self):
        self._note("停止 DHCP 审计")
        w = self.audit
        self.audit = None                      # 先摘掉状态，避免重入
        if w is not None:
            try:
                w.stop()
            except Exception as exc:
                log(f"停止 DHCP 审计出错（已忽略）：{type(exc).__name__}: {exc}",
                    "warn", "dhcp")
        self.badge_audit.set_state("未启动", "idle")
        self._refresh_buttons()
        self.refresh_all()

    @safe_slot
    def clear_audit(self):
        if self.tbl_audit.rowCount() and QMessageBox.question(
                self, "清空", "清空审计表格里的记录？\n"
                "（正在运行的审计会继续记录新包）") != QMessageBox.Yes:
            return
        self.tbl_audit.setRowCount(0)
        if self.audit is not None:
            self.audit.records.clear()
        self._audit_shown = 0
        self.lbl_audit_count.setText("0 条")

    @safe_slot
    def export_audit_csv(self):
        rows = list(self.audit.records) if self.audit is not None else []
        if not rows:
            QMessageBox.information(self, "没有数据",
                                    "还没有记录到任何租约。\n"
                                    "先开始审计，等网段里有设备申请地址再导出。")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出 DHCP 审计结果",
                                              "dhcp_audit.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(D.HEADERS)
                for lease in rows:
                    w.writerow(lease.row())
            log(f"已导出 {len(rows)} 条 DHCP 租约到 {path}", "success", "dhcp")
            QMessageBox.information(self, "导出成功", f"已导出到：\n{path}")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))

    # ================= ② 耗尽测试 =================

    @safe_slot
    def start_starve(self):
        # 先做参数校验，再做权限/授权检查：这样用户先看到「哪里填错了」，
        # 而不是填错了却被权限弹窗挡住，改完再点还是错的。
        prefix = self.ed_prefix.text().strip()
        if prefix:
            h = "".join(ch for ch in prefix if ch in "0123456789abcdefABCDEF")
            if len(h) != 6:
                QMessageBox.warning(
                    self, "MAC 前缀不对",
                    f"前缀要正好 3 个字节（6 位十六进制），例如 de:ad:be。\n"
                    f"现在填的是：{prefix}")
                return
        if not self._guard():
            return
        iface = self.current_iface("starve")
        if iface is None:
            QMessageBox.warning(self, "缺少网卡", "请选择发包用的网卡")
            return
        count = self.sp_count.value()
        if QMessageBox.question(
                self, "确认开始耗尽测试",
                f"网卡：{iface.alias}\n"
                f"要占掉的地址数：{count}\n"
                f"速率：{self.sp_rate.value()} 个/秒\n"
                f"伪造 MAC 前缀：{D.normalize_mac(prefix) if prefix else '随机'}\n"
                f"收到 OFFER 后补 REQUEST：{'是' if self.chk_request.isChecked() else '否'}\n\n"
                "⚠ 这会把服务器的地址池占掉，同一网段的新设备拿不到地址。\n"
                "确定开始？",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return

        self.starve = D.DhcpStarve(
            iface, count=count, mac_prefix=prefix,
            rate=float(self.sp_rate.value()), do_request=self.chk_request.isChecked())
        self._starve_shown = 0
        self._note(f"开始 DHCP 耗尽测试 iface={iface.alias} count={count}")
        self.starve.start()
        self.badge_starve.set_state("运行中", "ok")
        self.lbl_starve_stats.setText("正在发送 DISCOVER…")
        self.timer.start()
        self._refresh_buttons()

    @safe_slot
    def stop_starve(self):
        self._note("停止 DHCP 耗尽测试")
        w = self.starve
        self.starve = None
        if w is not None:
            try:
                w.stop()
            except Exception as exc:
                log(f"停止耗尽测试出错（已忽略）：{type(exc).__name__}: {exc}",
                    "warn", "dhcp")
        self.badge_starve.set_state("未启动", "idle")
        self._refresh_buttons()
        self.refresh_all()
        log("耗尽测试已停止。注意：占用的地址要等服务器租期到期才会释放。",
            "warn", "dhcp")

    @safe_slot
    def clear_starve(self):
        self.tbl_starve.setRowCount(0)
        self._starve_shown = 0
        if self.starve is not None:
            self.starve.records.clear()
        self.lbl_starve_taken.setText("0 个")

    # ================= ③ 假 DHCP =================

    @safe_slot
    def start_rogue(self):
        # 同样是先校验参数再检查权限：填错的地方要立刻指出来
        pool = self.ed_pool.text().strip()
        try:
            pool_ips = D.parse_pool(pool)
        except ValueError as exc:
            QMessageBox.warning(self, "地址池不对", f"{exc}\n\n"
                                "可以写成 192.168.50.100-192.168.50.200、"
                                "192.168.50.100-200 或 192.168.50.0/24。")
            return
        gateway = self.ed_gateway.text().strip()
        raw_dns = self.ed_dns.text().replace("；", ",").replace(";", ",")
        dns = [x.strip() for x in raw_dns.split(",") if x.strip()]
        bad = [x for x in ([gateway] if gateway else []) + dns if not D._is_ip(x)]
        if bad:
            QMessageBox.warning(self, "地址不对",
                                "下发的网关 / DNS 里有不是 IP 的值：\n" + "、".join(bad))
            return
        mask = self.ed_mask.text().strip()
        if mask and not D._is_ip(mask):
            QMessageBox.warning(self, "掩码不对", f"子网掩码不是合法的 IP：{mask}")
            return
        if not self._guard():
            return
        iface = self.current_iface("rogue")
        if iface is None:
            QMessageBox.warning(self, "缺少网卡", "请选择发包用的网卡")
            return
        server_ip = self.ed_server_ip.text().strip() or (iface.ip or "")
        if not D._is_ip(server_ip):
            QMessageBox.warning(self, "服务器地址不对",
                                f"服务器 IP 不合法：{server_ip or '(空)'}")
            return

        if QMessageBox.question(
                self, "确认启动假 DHCP 服务器",
                f"网卡：{iface.alias}\n"
                f"我们自称：{server_ip}\n"
                f"地址池：{pool_ips[0]} ~ {pool_ips[-1]}（{len(pool_ips)} 个）\n"
                f"下发网关：{gateway or '(不发)'}\n"
                f"下发 DNS：{', '.join(dns) or '(不发)'}\n"
                f"租期：{self.sp_lease.value()} 秒\n\n"
                "⚠ 这个网段里发 DISCOVER 的设备都会拿到上面这套配置，"
                "填错会让它们上不了网。\n确定启动？",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return

        try:
            self.rogue = D.RogueDhcp(iface, pool=pool, gateway=gateway, dns=dns,
                                     server_ip=server_ip,
                                     lease_time=self.sp_lease.value(),
                                     mask=mask)
        except ValueError as exc:
            QMessageBox.warning(self, "参数不对", str(exc))
            return
        self._rogue_shown = 0
        self._note(f"启动假 DHCP iface={iface.alias} pool={pool}")
        self.rogue.start()
        self.badge_rogue.set_state("运行中", "ok")
        self.lbl_rogue_stats.setText("已启动，等待客户端 DISCOVER…")
        self.timer.start()
        self._refresh_buttons()

    @safe_slot
    def stop_rogue(self):
        self._note("停止假 DHCP")
        w = self.rogue
        self.rogue = None
        if w is not None:
            try:
                w.stop()
            except Exception as exc:
                log(f"停止假 DHCP 出错（已忽略）：{type(exc).__name__}: {exc}",
                    "warn", "dhcp")
        self.badge_rogue.set_state("未启动", "idle")
        self._refresh_buttons()
        self.refresh_all()
        log("假 DHCP 已停止。DHCP 没有「撤销」报文，已经拿到我们租约的设备"
            "要等租期到期或重连网络才会回到真服务器。", "warn", "dhcp")

    @safe_slot
    def clear_rogue(self):
        """只清空界面上的记录表；已经发出去的租约不会（也无法）撤销。"""
        self.tbl_rogue.setRowCount(0)
        self._rogue_shown = 0
        if self.rogue is not None:
            self.rogue.records.clear()
        self.lbl_rogue_count.setText(f"{self.rogue.clients if self.rogue else 0} 台")

    # ================= 定时刷新 =================

    @safe_slot
    def refresh_all(self):
        """把三个 worker 的新记录刷进各自的表格，并更新状态文字。"""
        self._refresh_audit()
        self._refresh_starve()
        self._refresh_rogue()
        self._refresh_buttons()
        if not (self.audit or self.starve or self.rogue):
            self.timer.stop()

    def _append_new(self, table, records: list, shown: int) -> int:
        """
        只把第 shown 条之后的新记录追加进表格。

        工作线程一直在往 records 里追加，界面这边只读不写，永远不会丢记录，
        也不需要加锁（CPython 里 list.append 是原子的）。
        """
        total = len(records)
        if total <= shown:
            return shown
        for lease in records[shown:]:
            row = table.rowCount()
            table.insertRow(row)
            colors = {}
            if lease.msg_type == "ACK":
                colors[6] = C_MINT
            elif lease.msg_type in ("OFFER", "DISCOVER"):
                colors[6] = C_YELLOW if lease.msg_type == "OFFER" else C_TEXT_DIM
            elif lease.msg_type in ("NAK", "DECLINE", "RELEASE"):
                colors[6] = C_RED
            set_row(table, row, lease.row(), colors)
        while table.rowCount() > D.MAX_RECORDS:
            table.removeRow(0)
        sb = table.verticalScrollBar()
        sb.setValue(sb.maximum())
        return total

    def _refresh_audit(self):
        w = self.audit
        if w is None:
            return
        self._audit_shown = self._append_new(self.tbl_audit, w.records, self._audit_shown)
        s = w.stats
        self.lbl_audit_count.setText(f"{len(w.records)} 条")
        if s["running"]:
            up = int(max(0, time.time() - s["started_at"]))
            self.badge_audit.set_state("运行中", "ok")
            self.lbl_audit_stats.setText(
                f"运行中 {up // 60:02d}:{up % 60:02d} · 收到报文 {s['seen']} "
                f"（DISCOVER {s['discovers']} / REQUEST {s['requests']} / "
                f"OFFER {s['offers']} / ACK {s['acks']}）"
                + (f" · ⚠ {s['last_error']}" if s["last_error"] else ""))
        else:
            self.badge_audit.set_state("已停止", "idle")
            self.lbl_audit_stats.setText(
                f"已停止 · 收到报文 {s['seen']} · 记录 {len(w.records)} 条"
                + (f" · ⚠ {s['last_error']}" if s["last_error"] else ""))
        if w.servers:
            items = []
            for ip, macs in sorted(w.servers.items(), key=lambda kv: -len(kv[1])):
                items.append(f"{ip}（发过 {len(macs)} 台）")
            self.lbl_audit_servers.setText("发现 DHCP 服务器：" + "、".join(items[:8]))
        else:
            self.lbl_audit_servers.setText("还没发现 DHCP 服务器（网段里可能暂时没人申请地址）")

    def _refresh_starve(self):
        w = self.starve
        if w is None:
            return
        self._starve_shown = self._append_new(self.tbl_starve, w.records, self._starve_shown)
        s = w.stats
        self.lbl_starve_taken.setText(f"已占下 {s['taken']} / {s['target']} 个")
        if s["running"]:
            self.badge_starve.set_state("运行中", "ok")
            self.lbl_starve_stats.setText(
                f"运行中 · 已发 {s['sent']} 个包"
                f"（DISCOVER {s['discover']} / REQUEST {s['request']}）· "
                f"收到 OFFER {s['offers']} · ACK {s['acks']} · "
                f"占下 {s['taken']}/{s['target']} 个地址"
                + (f" · ⚠ {s['last_error']}" if s["last_error"] else ""))
        else:
            self.badge_starve.set_state("已停止", "idle")
            self.lbl_starve_stats.setText(
                f"已停止 · 共发出 {s['sent']} 个包 · 收到 ACK {s['acks']} · "
                f"占下 {s['taken']} 个地址（这些地址要等服务器租期到期才会释放）"
                + (f" · ⚠ {s['last_error']}" if s["last_error"] else ""))

    def _refresh_rogue(self):
        w = self.rogue
        if w is None:
            return
        self._rogue_shown = self._append_new(self.tbl_rogue, w.records, self._rogue_shown)
        s = w.stats
        self.lbl_rogue_count.setText(f"{w.clients} 台")
        if s["running"]:
            self.badge_rogue.set_state("运行中", "ok")
            self.lbl_rogue_stats.setText(
                f"运行中 · 看到 {s['seen']} 个请求 · 回了 OFFER {s['offered']} / "
                f"ACK {s['acked']} · {w.clients}/{s['pool_size']} 个地址已分配"
                f" · 下发网关 {w.gateway or '(无)'} · DNS {', '.join(w.dns) or '(无)'}"
                + (f" · ⚠ {s['last_error']}" if s["last_error"] else ""))
        else:
            self.badge_rogue.set_state("已停止", "idle")
            self.lbl_rogue_stats.setText(
                f"已停止 · 回了 OFFER {s['offered']} / ACK {s['acked']} · "
                f"{w.clients} 台设备拿了我们的租约"
                + (f" · ⚠ {s['last_error']}" if s["last_error"] else ""))

    # ================= 给主窗口用 =================

    def is_running(self) -> bool:
        for w in (self.audit, self.starve, self.rogue):
            if w is not None and w.is_alive():
                return True
        return False

    def status_text(self) -> str:
        bits = []
        if self.audit is not None:
            bits.append(f"DHCP 审计记录 {len(self.audit.records)} 条")
        if self.starve is not None:
            bits.append(f"耗尽测试占下 {self.starve.stats['taken']} 个地址")
        if self.rogue is not None:
            bits.append(f"假 DHCP 已分配 {self.rogue.clients} 个地址")
        return " · ".join(bits) if bits else "DHCP：未运行"

    def shutdown(self):
        """关窗口时调用：把三个 worker 都干净停掉。"""
        if self.is_running():
            log("程序退出：正在停止 DHCP 相关线程…", "warn", "dhcp")
        for w, name in ((self.audit, "DHCP 审计"), (self.starve, "地址池耗尽测试"),
                        (self.rogue, "假 DHCP 服务器")):
            if w is not None:
                try:
                    w.stop()
                except Exception as exc:
                    log(f"退出时停止{name}出错（已忽略）：{type(exc).__name__}: {exc}",
                        "warn", "dhcp")
        self.audit = self.starve = self.rogue = None
        self.timer.stop()
        self.badge_audit.set_state("未启动", "idle")
        self.badge_starve.set_state("未启动", "idle")
        self.badge_rogue.set_state("未启动", "idle")
        self._refresh_buttons()
