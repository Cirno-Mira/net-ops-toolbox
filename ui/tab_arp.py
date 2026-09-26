# -*- coding: utf-8 -*-
"""
ARP 流量牵引 / 断网 / 引流
==========================

界面按「四步走」重排，避免按钮堆在一起：

    ① 选网卡与网关   ② 选工作模式   ③ 选配套功能   ④ 开始

三种模式：
    双向中间人  目标不断网，流量经过本机（可抓包 / 改包 / 重放）
    单向抓包    目标会断网，只把上行引到本机
    断网攻击    把目标的网关指向不存在的 MAC，直接踢下线（arp death）

安全：停止 / 关闭窗口 / 程序异常退出都会自动恢复 ARP 表。
"""

from __future__ import annotations

import threading

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtWidgets import (QAbstractItemView, QButtonGroup, QCheckBox, QComboBox,
                             QFrame, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                             QPushButton, QRadioButton, QScrollArea, QSpinBox,
                             QTableWidgetItem, QVBoxLayout, QWidget)

from core import appconfig
from core import arpmitm as M
from core import dnsspoof as DS
from core import hostinfo as HI
from core.logging_bus import log
from ui.widgets import Card, find_row, hline, label, make_table, safe_slot
from theme import C_MINT, C_PINK, C_RED, C_TEXT_DIM, C_YELLOW

HEADERS = ["选", "IP 地址", "MAC 地址", "备注（主机名/用途）"]

MODE_INFO = {
    "two_way": ("双向中间人（推荐）",
                "目标 ↔ 本机 ↔ 网关。目标不断网，流量经过本机，可以抓包、改包、重放。"),
    "one_way": ("单向抓包",
                "只对目标冒充网关。上行会到本机但不转发，目标会断网，适合快速抓一段。"),
    "death": ("断网攻击 arp death",
              "告诉目标「网关在一个不存在的 MAC 上」，流量直接进黑洞，目标上不了网。"),
}


class ArpTab(QWidget):
    mitm_requested = pyqtSignal(dict)      # 请求主窗口开启透明代理
    selftest_done = pyqtSignal(dict)       # 发包自检完成（从工作线程回主线程）

    def __init__(self, parent=None):
        super().__init__(parent)
        self.spoofer: M.ArpSpoofer | None = None
        self.dns: DS.DnsSpoofer | None = None
        self._build()
        self.selftest_done.connect(self._show_selftest)
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._refresh_stats)

    # ================= 界面 =================

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)
        outer.addWidget(self._build_warning())

        body = QHBoxLayout()
        body.setSpacing(8)

        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QFrame.NoFrame)
        left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        left_scroll.setMinimumWidth(410)
        left_scroll.setMaximumWidth(540)
        left_host = QWidget()
        left = QVBoxLayout(left_host)
        left.setContentsMargins(0, 0, 6, 0)
        left.setSpacing(8)
        left.addWidget(self._step1())
        left.addWidget(self._step2())
        left.addWidget(self._step3())
        left.addWidget(self._step4())
        left.addStretch(1)
        left_scroll.setWidget(left_host)
        body.addWidget(left_scroll)

        right = QVBoxLayout()
        right.setSpacing(8)
        right.addWidget(self._build_targets(), 1)
        right.addWidget(self._build_status())
        body.addLayout(right, 1)

        outer.addLayout(body, 1)
        self.reload_ifaces()
        self._on_mode_changed()
        self._update_count()

    def _build_warning(self) -> QWidget:
        w = QFrame()
        w.setObjectName("Card")
        w.setStyleSheet(f"QFrame#Card {{ background-color:#FFF1F4;"
                        f" border:1px solid {C_PINK}; border-radius:14px; }}")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(4)
        t = QLabel("⚠️ 只能用于你本人拥有、或已获得书面授权的网络")
        t.setStyleSheet(f"color:{C_RED}; font-weight:800; font-size:10.5pt;")
        lay.addWidget(t)
        d = QLabel("ARP 牵引 / 断网都会改变目标设备与网关的 ARP 表，未经授权使用属于违法行为。"
                   "停止、关窗口、程序异常退出都会自动恢复 ARP 表；"
                   "万一进程被强杀，点「🆘 紧急恢复」或让目标重连网络即可。")
        d.setWordWrap(True)
        d.setObjectName("Dim")
        lay.addWidget(d)
        row = QHBoxLayout()
        self.chk_auth = QCheckBox("我已获得该网络的测试授权，并理解上述风险")
        self.chk_auth.setStyleSheet("font-weight:700;")
        self.chk_auth.toggled.connect(self._refresh_buttons)
        row.addWidget(self.chk_auth)
        row.addStretch(1)
        lay.addLayout(row)
        return w

    # -------- ① 网卡与网关 --------

    def _step1(self) -> QWidget:
        card = Card("① 选网卡与网关")
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("网卡", "Dim"))
        self.cmb_iface = QComboBox()
        self.cmb_iface.currentIndexChanged.connect(self._on_iface_changed)
        r1.addWidget(self.cmb_iface, 1)
        btn = QPushButton("刷新")
        btn.setObjectName("Ghost")
        btn.clicked.connect(self.reload_ifaces)
        r1.addWidget(btn)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("网关", "Dim"))
        self.ed_gw = QLineEdit()
        self.ed_gw.setPlaceholderText("网关 IP")
        r2.addWidget(self.ed_gw, 1)
        self.ed_gwmac = QLineEdit()
        self.ed_gwmac.setPlaceholderText("网关 MAC")
        r2.addWidget(self.ed_gwmac, 1)
        btn_mac = QPushButton("解析")
        btn_mac.setObjectName("Ghost")
        btn_mac.setToolTip("先查本机 ARP 缓存；查不到再主动发 ARP 请求（需管理员）")
        btn_mac.clicked.connect(self.resolve_gateway_mac)
        r2.addWidget(btn_mac)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(6)
        self.lbl_fwd = label("IP 转发：未知", "Dim")
        r3.addWidget(self.lbl_fwd)
        r3.addStretch(1)
        b_on = QPushButton("开启转发")
        b_on.setObjectName("Ghost")
        b_on.clicked.connect(self.enable_forwarding)
        b_off = QPushButton("关闭转发")
        b_off.setObjectName("Ghost")
        b_off.clicked.connect(self.disable_forwarding)
        r3.addWidget(b_on)
        r3.addWidget(b_off)
        card.add(r3)
        return card

    # -------- ② 工作模式 --------

    def _step2(self) -> QWidget:
        card = Card("② 选工作模式")
        self.mode_group = QButtonGroup(self)
        self.mode_buttons: dict[str, QRadioButton] = {}
        for i, key in enumerate(("two_way", "one_way", "death")):
            name, desc = MODE_INFO[key]
            rb = QRadioButton(name)
            rb.setChecked(key == "two_way")
            rb.toggled.connect(self._on_mode_changed)
            self.mode_group.addButton(rb, i)
            self.mode_buttons[key] = rb
            card.add(rb)
            d = QLabel("　　" + desc)
            d.setObjectName("Dim")
            d.setWordWrap(True)
            card.add(d)
        return card

    def _current_mode(self) -> str:
        for key, rb in self.mode_buttons.items():
            if rb.isChecked():
                return key
        return "two_way"

    def _on_mode_changed(self, *_):
        mode = self._current_mode()
        if not hasattr(self, "lbl_hint"):
            return
        if mode == "death":
            self.lbl_hint.setText("断网模式：不需要 IP 转发，也用不到透明代理。")
            self.chk_dns.setChecked(True)
            self.chk_dns.setEnabled(False)
            self.chk_mitm.setEnabled(False)
            self.chk_forward.setEnabled(False)
        elif mode == "one_way":
            self.lbl_hint.setText("单向模式：目标会断网，只适合抓一小段流量，"
                                  "透明代理意义不大。")
            self.chk_dns.setEnabled(True)
            self.chk_mitm.setEnabled(True)
            self.chk_forward.setEnabled(False)
        else:
            self.lbl_hint.setText("双向模式：建议同时打开 IP 转发 + DNS 引流 + 透明代理，"
                                  "这样目标访问的网页内容会直接显示在「流量劫持」页。")
            self.chk_dns.setEnabled(True)
            self.chk_mitm.setEnabled(True)
            self.chk_forward.setEnabled(True)

    # -------- ③ 配套功能 --------

    def _step3(self) -> QWidget:
        card = Card("③ 配套功能")
        self.lbl_hint = label("", "Dim")
        self.lbl_hint.setWordWrap(True)
        card.add(self.lbl_hint)
        card.add(hline())

        self.chk_forward = QCheckBox("开启 IP 转发（双向模式必开，否则目标断网）")
        self.chk_forward.setChecked(True)
        self.chk_forward.setToolTip("用 netsh 打开网卡转发 + 注册表 IPEnableRouter")
        card.add(self.chk_forward)

        self.chk_dns = QCheckBox("DNS 引流：让目标直接连到本机（关键！）")
        self.chk_dns.setChecked(True)
        self.chk_dns.setToolTip(
            "ARP 牵引只让流量「经过」本机，目标连接的目的 IP 还是真实服务器，"
            "所以 Reqable / Fiddler 这类本地代理看不到。\n"
            "打开 DNS 引流后，目标问域名时我们抢先回答「本机 IP」，"
            "它就直接连到本机，透明代理就能拿到明文请求。")
        card.add(self.chk_dns)

        self.chk_mitm = QCheckBox("同时启动内建透明代理（在「流量劫持」页看请求）")
        self.chk_mitm.setChecked(True)
        card.add(self.chk_mitm)

        r = QHBoxLayout()
        r.setSpacing(6)
        r.addWidget(label("发包间隔", "Dim"))
        self.sp_interval = QSpinBox()
        self.sp_interval.setRange(1, 30)
        self.sp_interval.setValue(int(appconfig.CFG.get("arp_interval", 2)))
        self.sp_interval.setSuffix(" 秒")
        r.addWidget(self.sp_interval)
        r.addWidget(label("恢复次数", "Dim"))
        self.sp_restore = QSpinBox()
        self.sp_restore.setRange(1, 30)
        self.sp_restore.setValue(int(appconfig.CFG.get("arp_restore_count", 5)))
        r.addWidget(self.sp_restore)
        r.addStretch(1)
        card.add(r)
        return card

    # -------- ④ 启停 --------

    def _step4(self) -> QWidget:
        card = Card("④ 开始 / 停止")
        r = QHBoxLayout()
        r.setSpacing(8)
        self.btn_start = QPushButton("⚡ 开始")
        self.btn_start.setObjectName("Danger")
        self.btn_start.setMinimumHeight(38)
        self.btn_start.clicked.connect(self.start_spoof)
        self.btn_stop = QPushButton("■ 停止并恢复")
        self.btn_stop.setObjectName("Success")
        self.btn_stop.setMinimumHeight(38)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_spoof)
        r.addWidget(self.btn_start, 2)
        r.addWidget(self.btn_stop, 2)
        card.add(r)
        self.btn_restore = QPushButton("🆘 紧急恢复（把正确 ARP 发回去）")
        self.btn_restore.setObjectName("Ghost")
        self.btn_restore.clicked.connect(self.emergency_restore)
        card.add(self.btn_restore)
        self.btn_selftest = QPushButton("🔧 发包自检（无害，只问网关的 MAC）")
        self.btn_selftest.setObjectName("Ghost")
        self.btn_selftest.setToolTip(
            "检查：本机 MAC / Npcap 设备名 / 能否向网关发出 ARP 并收到应答 /\n"
            "能否 ping 通目标。只发正常 ARP 请求，不做任何欺骗。")
        self.btn_selftest.clicked.connect(self.run_selftest)
        card.add(self.btn_selftest)
        return card

    # -------- 右侧：目标表 --------

    def _build_targets(self) -> QWidget:
        card = Card("🎯 目标设备")
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        for text, fn, tip in (
                ("全选", lambda: self._check_all(True), "勾选全部目标"),
                ("反选", self._invert, "反转勾选状态"),
                ("删除选中", self.delete_selected, "删掉选中的行（表格里按 Delete 同效）"),
                ("清空", self.clear_targets, "清空整个目标列表"),
                ("补全 MAC", self.resolve_missing_mac,
                 "对没有 MAC 的目标发 ARP 请求解析（需要管理员）")):
            b = QPushButton(text)
            b.setObjectName("Ghost")
            b.setToolTip(tip)
            b.clicked.connect(fn)
            r1.addWidget(b)
        r1.addStretch(1)
        self.lbl_count = label("已选 0 台", "Dim")
        r1.addWidget(self.lbl_count)
        card.add(r1)

        self.table = make_table(HEADERS, stretch_col=3)
        # 目标表是一份「人工维护的清单」，不能自动排序：
        # 排序开启时插入行会被立即重排，导致单元格错位/丢失
        self.table.setSortingEnabled(False)
        self.table.setColumnWidth(0, 38)
        self.table.setColumnWidth(1, 130)
        self.table.setColumnWidth(2, 150)
        self.table.setEditTriggers(QAbstractItemView.DoubleClicked
                                   | QAbstractItemView.EditKeyPressed)
        self.table.setToolTip("双击 IP / MAC / 备注 可直接修改；MAC 会自动规范化格式")
        self.table.itemChanged.connect(self._on_item_changed)
        card.add(self.table)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("手动添加", "Dim"))
        self.ed_manual = QLineEdit()
        self.ed_manual.setPlaceholderText(
            "192.168.5.10   或   192.168.5.10,94:a9:90:25:7c:1c（多个用分号隔开）")
        self.ed_manual.returnPressed.connect(self.add_manual)
        r2.addWidget(self.ed_manual, 1)
        b_add = QPushButton("加入并解析")
        b_add.setObjectName("Ghost")
        b_add.clicked.connect(self.add_manual)
        r2.addWidget(b_add)
        card.add(r2)
        return card

    def _build_status(self) -> QWidget:
        card = Card("📊 运行状态")
        self.lbl_stats = label("未运行", "Dim")
        card.add(self.lbl_stats)
        self.lbl_dns = label("DNS 引流：未启动", "Dim")
        card.add(self.lbl_dns)
        return card

    # ================= 网卡 / 网关 =================

    def reload_ifaces(self):
        self.cmb_iface.blockSignals(True)
        self.cmb_iface.clear()
        self._ifaces = HI.list_ifaces()
        for i in self._ifaces:
            self.cmb_iface.addItem(i.label, i)
        prim = HI.primary_iface()
        if prim is not None:
            for idx, i in enumerate(self._ifaces):
                if i.ip == prim.ip:
                    self.cmb_iface.setCurrentIndex(idx)
                    break
        self.cmb_iface.blockSignals(False)
        self._on_iface_changed()
        self.refresh_forwarding()

    def current_iface(self):
        return self.cmb_iface.currentData()

    def _on_iface_changed(self, *_):
        i = self.current_iface()
        if i is None:
            return
        self.ed_gw.setText(i.gateway or "")
        mac = M.resolve_mac(i.gateway, i.l2_name) if i.gateway else ""
        self.ed_gwmac.setText(mac)
        self.refresh_forwarding()

    def resolve_gateway_mac(self):
        i = self.current_iface()
        if i is None:
            return
        gw = self.ed_gw.text().strip()
        if not gw:
            QMessageBox.warning(self, "缺少网关", "请先填写网关 IP")
            return
        mac = M.resolve_mac(gw, i.l2_name, timeout=2.5)
        if mac:
            self.ed_gwmac.setText(mac)
            log(f"网关 {gw} 的 MAC = {mac}", "success", "arp")
        else:
            QMessageBox.warning(self, "解析失败",
                                "拿不到网关 MAC。请确认已用管理员运行，且网关 IP 正确。")

    # ================= IP 转发 =================

    def refresh_forwarding(self):
        i = self.current_iface()
        st = M.forwarding_status(i.alias if i else "")
        if st is True:
            self.lbl_fwd.setText("IP 转发：已开启 ✅")
            self.lbl_fwd.setStyleSheet(f"color:{C_MINT}; font-weight:700;")
        elif st is False:
            self.lbl_fwd.setText("IP 转发：未开启 ⚠")
            self.lbl_fwd.setStyleSheet(f"color:{C_YELLOW}; font-weight:700;")
        else:
            self.lbl_fwd.setText("IP 转发：未知")
            self.lbl_fwd.setStyleSheet(f"color:{C_TEXT_DIM};")

    def enable_forwarding(self):
        i = self.current_iface()
        ok, msg = M.enable_forwarding(i.alias if i else "")
        log(msg, "success" if ok else "error", "arp")
        self.refresh_forwarding()
        if not ok:
            QMessageBox.warning(self, "未能开启 IP 转发", msg)

    def disable_forwarding(self):
        i = self.current_iface()
        ok, msg = M.disable_forwarding(i.alias if i else "")
        log(msg, "info" if ok else "error", "arp")
        self.refresh_forwarding()

    # ================= 目标表 =================

    def set_candidates(self, items: list[dict]):
        """从资产页导入。已有行如果缺 MAC 会补上。"""
        added, fixed = 0, 0
        for it in items:
            ip = (it.get("ip") or "").strip()
            if not ip:
                continue
            mac = (it.get("mac") or "").strip()
            row = find_row(self.table, ip, 1)
            if row >= 0:
                cur = self.table.item(row, 2)
                if mac and cur is not None and not cur.text().strip():
                    self._set_cell(row, 2, mac)
                    fixed += 1
                continue
            self._add_row(ip, mac, it.get("note", ""), checked=True)
            added += 1
        if added or fixed:
            log(f"从资产列表导入：新增 {added} 个，补全 MAC {fixed} 个", "info", "arp")
        self._update_count()

    def _set_cell(self, row: int, col: int, text: str):
        self.table.blockSignals(True)
        item = self.table.item(row, col)
        if item is None:
            self.table.setItem(row, col, QTableWidgetItem(text))
        else:
            item.setText(text)
        self.table.blockSignals(False)

    def _add_row(self, ip: str, mac: str, note: str, checked: bool = False) -> int:
        t = self.table
        t.blockSignals(True)
        was_sorting = t.isSortingEnabled()
        t.setSortingEnabled(False)
        r = t.rowCount()
        t.insertRow(r)
        chk = QTableWidgetItem()
        chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        chk.setCheckState(Qt.Checked if checked else Qt.Unchecked)
        t.setItem(r, 0, chk)
        t.setItem(r, 1, QTableWidgetItem(ip))
        t.setItem(r, 2, QTableWidgetItem(HI.norm_mac(mac) if mac else ""))
        t.setItem(r, 3, QTableWidgetItem(note))
        t.setSortingEnabled(was_sorting)
        t.blockSignals(False)
        return r

    def _on_item_changed(self, item: QTableWidgetItem):
        if item.column() == 2:
            fixed = HI.norm_mac(item.text())
            if fixed != item.text():
                self.table.blockSignals(True)
                item.setText(fixed)
                self.table.blockSignals(False)
        self._update_count()

    def add_manual(self):
        text = self.ed_manual.text().strip()
        if not text:
            return
        current = self.current_iface()
        for part in [p.strip() for p in text.replace("；", ";").split(";") if p.strip()]:
            if "," in part:
                ip, mac = [x.strip() for x in part.split(",", 1)]
            else:
                ip, mac = part, ""
            if not ip:
                continue
            if not mac:
                mac = M.resolve_mac(ip, current.l2_name if current else "")
            row = find_row(self.table, ip, 1)
            if row >= 0:
                if mac:
                    self._set_cell(row, 2, HI.norm_mac(mac))
                self.table.blockSignals(True)
                self.table.item(row, 0).setCheckState(Qt.Checked)
                self.table.blockSignals(False)
            else:
                self._add_row(ip, mac, "手动添加", checked=True)
        self.ed_manual.clear()
        self._update_count()
        missing = [r for r in range(self.table.rowCount())
                   if not (self.table.item(r, 2) and self.table.item(r, 2).text().strip())]
        if missing:
            log(f"还有 {len(missing)} 个目标没有 MAC，可点「补全 MAC」或用管理员运行后自动解析",
                "info", "arp")

    def resolve_missing_mac(self):
        iface = self.current_iface()
        rows = [r for r in range(self.table.rowCount())
                if not (self.table.item(r, 2) and self.table.item(r, 2).text().strip())]
        if not rows:
            QMessageBox.information(self, "无需补全", "所有目标都已有 MAC")
            return
        if not HI.is_admin():
            QMessageBox.warning(
                self, "需要管理员",
                "主动发 ARP 请求解析 MAC 需要管理员权限。\n\n"
                "普通权限下可以先到「资产发现」页扫一遍 —— ping 扫描会把目标的 MAC "
                "写进本机 ARP 缓存，再回来补全就能成功。")
        ok = 0
        for r in rows:
            ip = self.table.item(r, 1).text().strip()
            mac = M.resolve_mac(ip, iface.l2_name if iface else "", timeout=1.5)
            if mac:
                self._set_cell(r, 2, HI.norm_mac(mac))
                ok += 1
        log(f"MAC 补全：{ok}/{len(rows)} 个成功", "success" if ok else "warn", "arp")
        if ok < len(rows):
            QMessageBox.information(
                self, "补全结果",
                f"{ok}/{len(rows)} 个解析成功。\n\n剩下的可以在表格里双击 MAC 列手动填写，"
                "或先到「资产发现」页扫一遍再来。")
        self._update_count()

    def delete_selected(self):
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()},
                      reverse=True)
        if not rows:
            QMessageBox.information(self, "没有选中", "先在表格里选中要删除的行")
            return
        for r in rows:
            self.table.removeRow(r)
        self._update_count()
        log(f"已删除 {len(rows)} 个目标", "info", "arp")

    def clear_targets(self):
        if self.table.rowCount() and QMessageBox.question(
                self, "清空目标", "确定清空整个目标列表？") != QMessageBox.Yes:
            return
        self.table.setRowCount(0)
        self._update_count()

    def keyPressEvent(self, ev):
        if ev.key() == Qt.Key_Delete and self.table.hasFocus():
            self.delete_selected()
        else:
            super().keyPressEvent(ev)

    def _check_all(self, on: bool):
        self.table.blockSignals(True)
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 0)
            if it:
                it.setCheckState(Qt.Checked if on else Qt.Unchecked)
        self.table.blockSignals(False)
        self._update_count()

    def _invert(self):
        self.table.blockSignals(True)
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 0)
            if it:
                it.setCheckState(
                    Qt.Unchecked if it.checkState() == Qt.Checked else Qt.Checked)
        self.table.blockSignals(False)
        self._update_count()

    def checked_targets(self) -> list[M.SpoofTarget]:
        out = []
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 0)
            if it is None or it.checkState() != Qt.Checked:
                continue
            cells = [self.table.item(r, c) for c in (1, 2, 3)]
            ip = cells[0].text().strip() if cells[0] else ""
            mac = cells[1].text().strip() if cells[1] else ""
            note = cells[2].text().strip() if cells[2] else ""
            if ip:
                out.append(M.SpoofTarget(ip=ip, mac=mac, name=note))
        return out

    def _update_count(self):
        self.lbl_count.setText(f"已选 {len(self.checked_targets())} 台 "
                               f"/ 共 {self.table.rowCount()} 台")
        self._refresh_buttons()

    def _refresh_buttons(self):
        running = self.spoofer is not None and self.spoofer.is_alive()
        self.btn_start.setEnabled(self.chk_auth.isChecked() and not running)
        self.btn_stop.setEnabled(running)
        self.btn_start.setToolTip("" if self.chk_auth.isChecked()
                                  else "请先在上方确认已获得授权")

    # ================= 启停 =================

    def _note(self, text: str):
        """把动作记进崩溃现场文件（主窗口注入的回调）。"""
        win = getattr(self, "note_action", None) or getattr(self, "_note_cb", None)
        if callable(win):
            try:
                win(text)
            except Exception:
                pass

    @safe_slot
    def start_spoof(self):
        if not self.chk_auth.isChecked():
            QMessageBox.warning(self, "需要授权确认", "请先勾选「我已获得该网络的测试授权」")
            return
        iface = self.current_iface()
        if iface is None:
            QMessageBox.warning(self, "缺少网卡", "请选择网卡")
            return
        gw = self.ed_gw.text().strip()
        gwmac = self.ed_gwmac.text().strip()
        if not gw or not gwmac:
            QMessageBox.warning(self, "缺少网关信息", "请填写网关 IP 与 MAC（可点「解析」）")
            return
        mode = self._current_mode()
        targets = self.checked_targets()
        if not targets:
            QMessageBox.warning(self, "没有目标", "请至少勾选一个目标设备")
            return

        missing = [t for t in targets if not t.mac]
        if missing:
            for t in missing:
                t.mac = M.resolve_mac(t.ip, iface.l2_name, timeout=1.5)
            still = [t.ip for t in targets if not t.mac]
            if still:
                QMessageBox.warning(
                    self, "有目标缺少 MAC",
                    "以下目标解析不到 MAC：\n" + "、".join(still[:8]) +
                    "\n\n可以在表格里双击 MAC 列手动填写，或先到「资产发现」页扫一遍。")
                return

        if not HI.is_admin():
            QMessageBox.warning(self, "需要管理员权限",
                                "ARP 原始发包需要管理员权限与 Npcap。\n"
                                "请重启工具箱，在 UAC 弹窗里点「是」。")
            return

        if mode == "two_way" and self.chk_forward.isChecked():
            if M.forwarding_status(iface.alias) is not True:
                ok, msg = M.enable_forwarding(iface.alias)
                log(msg, "success" if ok else "warn", "arp")
                self.refresh_forwarding()

        name, _ = MODE_INFO[mode]
        warn = ""
        if mode == "death":
            warn = "\n\n⚠ 断网模式会让目标设备直接掉线！"
        elif mode == "one_way":
            warn = "\n\n⚠ 单向模式会让目标设备断网。"
        if appconfig.CFG.get("confirm_arp_start", True):
            if QMessageBox.question(
                    self, "确认开始",
                    f"模式：{name}\n目标：{len(targets)} 台\n"
                    + "、".join(t.ip for t in targets[:8])
                    + ("…" if len(targets) > 8 else "")
                    + f"\n网关：{gw} ({gwmac})" + warn + "\n\n确定开始？",
                    QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                return

        appconfig.CFG.update(arp_interval=self.sp_interval.value(),
                             arp_restore_count=self.sp_restore.value())
        appconfig.CFG.save()

        self.spoofer = M.ArpSpoofer(
            iface=iface, gateway_ip=gw, gateway_mac=gwmac, targets=targets,
            mode=mode, interval=float(self.sp_interval.value()),
            restore_count=self.sp_restore.value())
        M.register(self.spoofer)
        self._note(f"开始 ARP 牵引 mode={mode} targets={len(targets)}")
        self.spoofer.start()

        if self.chk_dns.isChecked() and mode != "one_way":
            self.dns = DS.DnsSpoofer(iface, {t.ip: t.mac for t in targets}, iface.ip)
            self.dns.start()
            self.lbl_dns.setText("DNS 引流：已启动")
        if self.chk_mitm.isChecked() and mode == "two_way":
            self.mitm_requested.emit({"iface": iface,
                                      "victims": [t.ip for t in targets]})

        self.timer.start()
        self._refresh_buttons()
        self._refresh_stats()

    @safe_slot
    def stop_spoof(self):
        """
        停止牵引并恢复 ARP 表。

        每个子步骤都单独捕获异常：若异常从 Qt 槽函数中逃出，
        PyQt5 会直接 abort 整个进程。这里保证无论哪一步失败，
        状态都会被清干净、按钮恢复可用，并尽力完成 ARP 表恢复。
        """
        self.lbl_stats.setText("正在停止并恢复 ARP 表…")
        self._note("停止 ARP 牵引")

        if self.dns is not None:
            try:
                self.dns.stop()
            except Exception as exc:
                log(f"停止 DNS 引流出错（已忽略）：{type(exc).__name__}: {exc}",
                    "warn", "arp")
            self.dns = None
            self.lbl_dns.setText("DNS 引流：已停止")

        spoof = self.spoofer
        self.spoofer = None                      # 先把状态摘掉，避免重入
        if spoof is not None:
            try:
                spoof.stop(timeout=10)
            except Exception as exc:
                log(f"停止牵引线程出错（已忽略，仍会尝试恢复 ARP 表）："
                    f"{type(exc).__name__}: {exc}", "error", "arp")
                try:
                    spoof.restore_now()
                except Exception:
                    pass
            M.unregister(spoof)

        self.timer.stop()
        self._refresh_buttons()
        self._refresh_stats()
        self.lbl_stats.setText("未运行")
        log("已停止，ARP 表已恢复", "success", "arp")

    @safe_slot
    def emergency_restore(self):
        if self.spoofer is not None:
            self.spoofer.restore_now()
        else:
            M.emergency_restore_all()
        log("已执行紧急恢复", "warn", "arp")

    # ---------------- 发包自检 ----------------

    @safe_slot
    def run_selftest(self):
        iface = self.current_iface()
        if iface is None:
            QMessageBox.warning(self, "缺少网卡", "请先选择网卡")
            return
        if not HI.is_admin():
            QMessageBox.warning(self, "需要管理员权限",
                                "发包自检需要管理员 + Npcap，请重启工具箱并在 UAC 点「是」")
            return
        gw = self.ed_gw.text().strip()
        targets = self.checked_targets()
        victims = [t.ip for t in targets]
        expected = {t.ip: t.mac for t in targets}
        self.btn_selftest.setEnabled(False)
        self.btn_selftest.setText("自检中…（约 5 秒）")
        log("开始发包自检（只发正常 ARP 请求，不做任何欺骗）…", "info", "arp")

        def work():
            try:
                res = M.send_selftest(iface, gw, victims, expected)
            except Exception as exc:
                import traceback
                res = {"ok": False, "steps": [
                    {"name": "自检", "ok": False,
                     "detail": f"{type(exc).__name__}: {exc}"}],
                    "_tb": traceback.format_exc()}
            # 注意：这里在工作线程里，绝对不能用 QTimer.singleShot ——
            # 那个定时器需要所在线程有事件循环，工作线程没有，回调永远不会执行，
            # 表现就是「点了按钮没反应、没弹窗」。必须用信号跨线程投递。
            self.selftest_done.emit(res)

        threading.Thread(target=work, daemon=True, name="arp-selftest").start()

    def _show_selftest(self, res: dict):
        self.btn_selftest.setEnabled(True)
        self.btn_selftest.setText("🔧 发包自检（无害，只问网关的 MAC）")
        steps = res.get("steps", [])
        lines = []
        for s in steps:
            mark = "✅" if s["ok"] else "❌"
            lines.append(f"{mark} {s['name']}：{s['detail']}")
            log(f"发包自检 · {s['name']}：{s['detail']}",
                "info" if s["ok"] else "error", "arp")
        if res.get("_tb"):
            log(f"自检异常堆栈：{res['_tb'].splitlines()[-1]}", "error", "arp")
        if res.get("gateway_mac"):
            self.ed_gwmac.setText(res["gateway_mac"])
        if not lines:
            lines = ["自检没有返回任何检查项（内部错误，请看日志面板）"]
        title = "发包自检：全部通过 ✅" if res.get("ok") else "发包自检：发现问题 ❌"
        QMessageBox.information(self, title, "\n\n".join(lines))

    @safe_slot
    def _refresh_stats(self):
        if self.spoofer is None:
            self.lbl_stats.setText("未运行")
            self._refresh_buttons()
            return
        s = self.spoofer.stats
        extra = ""
        if s.mode != "death":
            if s.victim_packets > 0:
                extra = f" · ✅ 目标流量已到达本机 {s.victim_packets} 包（牵引生效）"
            elif s.rounds > 3:
                extra = " · ⚠ 目标流量 0 包：牵引可能没生效，点「发包自检」排查"
        self.lbl_stats.setText(
            f"运行中 {s.uptime} · {s.mode_label} · 目标 {s.targets} 台 · 已发 ARP {s.arp_sent}"
            + extra
            + (f" · ⚠ {s.last_error}" if s.last_error else ""))
        if self.dns is not None:
            d = self.dns.stats
            self.lbl_dns.setText(
                f"DNS 引流：已劫持 {d['spoofed']} 个查询"
                + (f"（最近：{self.dns.recent[-1][2]}）" if self.dns.recent else ""))
        if not self.spoofer.is_alive():
            M.unregister(self.spoofer)
            self.spoofer = None
            self.timer.stop()
            self._refresh_buttons()

    def is_running(self) -> bool:
        return self.spoofer is not None and self.spoofer.is_alive()

    def shutdown(self):
        if self.is_running():
            log("程序退出：正在恢复 ARP 表…", "warn", "arp")
        try:
            self.stop_spoof()
        except Exception as exc:
            log(f"退出时停止牵引出错：{exc}", "error", "arp")
