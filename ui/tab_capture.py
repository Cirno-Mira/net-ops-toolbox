# -*- coding: utf-8 -*-
"""
抓包页
======

* scapy 实时抓包 + BPF 过滤 + 落盘 pcap + 一键用 Wireshark 打开
* 选中任意一个包可以**编辑字段后重放**（改 MAC/IP/端口/TCP 标志/载荷）
"""

from __future__ import annotations

import os
import subprocess

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog,
                             QDialogButtonBox, QFileDialog, QFormLayout,
                             QHeaderView, QHBoxLayout, QLabel, QLineEdit,
                             QMessageBox, QPlainTextEdit, QPushButton, QSpinBox,
                             QSplitter, QTabWidget, QTableWidget,
                             QTableWidgetItem, QVBoxLayout, QWidget)

from core import capture as C
from core import hostinfo as HI
from core.logging_bus import log
from ui.widgets import BarChart, Card, label, make_table, safe_slot, set_row
from theme import C_MINT, C_TEXT_DIM

HEADERS = ["#", "时间", "源地址", "目的地址", "协议", "长度", "摘要"]

WIRESHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\Wireshark.exe",
    r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
]

MAX_ROWS = 3000


class PacketEditor(QDialog):
    """包编辑器：改完直接用 scapy 发出去。"""

    def __init__(self, raw: bytes, iface, parent=None):
        super().__init__(parent)
        self.setWindowTitle("编辑并重放数据包")
        self.resize(620, 620)
        self.iface = iface
        self.raw = raw

        from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether
        pkt = Ether(raw)
        self.pkt = pkt

        lay = QVBoxLayout(self)
        form = QFormLayout()

        def field(value):
            e = QLineEdit(str(value))
            return e

        self.ed_smac = field(pkt.src if pkt.haslayer(Ether) else "")
        self.ed_dmac = field(pkt.dst if pkt.haslayer(Ether) else "")
        form.addRow("源 MAC", self.ed_smac)
        form.addRow("目的 MAC", self.ed_dmac)

        self.ed_sip = field("")
        self.ed_dip = field("")
        self.cmb_proto = QComboBox()
        self.cmb_proto.addItems(["TCP", "UDP", "ICMP", "仅 IP", "ARP"])
        self.sp_sport = QSpinBox()
        self.sp_sport.setRange(0, 65535)
        self.sp_dport = QSpinBox()
        self.sp_dport.setRange(0, 65535)
        self.ed_flags = QLineEdit("S")
        self.ed_flags.setToolTip("TCP 标志，例如 S / SA / A / PA / FA / R")
        self.ed_payload = QPlainTextEdit()
        self.ed_payload.setFont(QFont("Cascadia Mono", 9))
        self.ed_payload.setPlaceholderText("载荷文本（UTF-8）")

        if pkt.haslayer(IP):
            ip = pkt[IP]
            self.ed_sip.setText(ip.src)
            self.ed_dip.setText(ip.dst)
            if pkt.haslayer(TCP):
                self.cmb_proto.setCurrentText("TCP")
                self.sp_sport.setValue(int(pkt[TCP].sport))
                self.sp_dport.setValue(int(pkt[TCP].dport))
                self.ed_flags.setText(str(pkt[TCP].flags))
            elif pkt.haslayer(UDP):
                self.cmb_proto.setCurrentText("UDP")
                self.sp_sport.setValue(int(pkt[UDP].sport))
                self.sp_dport.setValue(int(pkt[UDP].dport))
            elif pkt.haslayer(ICMP):
                self.cmb_proto.setCurrentText("ICMP")
            else:
                self.cmb_proto.setCurrentText("仅 IP")
        elif pkt.haslayer(ARP):
            self.cmb_proto.setCurrentText("ARP")
            self.ed_sip.setText(pkt[ARP].psrc)
            self.ed_dip.setText(pkt[ARP].pdst)

        if pkt.haslayer("Raw"):
            try:
                self.ed_payload.setPlainText(bytes(pkt["Raw"].load).decode("utf-8"))
            except UnicodeDecodeError:
                self.ed_payload.setPlainText(bytes(pkt["Raw"].load).decode("latin-1"))
        else:
            self.ed_payload.setPlainText("")

        form.addRow("源 IP", self.ed_sip)
        form.addRow("目的 IP", self.ed_dip)
        form.addRow("协议", self.cmb_proto)
        form.addRow("源端口", self.sp_sport)
        form.addRow("目的端口", self.sp_dport)
        form.addRow("TCP 标志", self.ed_flags)
        lay.addLayout(form)
        lay.addWidget(QLabel("载荷："))
        lay.addWidget(self.ed_payload, 1)

        hint = QLabel("提示：改完后点「发送」。发包需要管理员权限与 Npcap；"
                      "默认按你选的网卡二层发出。")
        hint.setObjectName("Dim")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        btns = QDialogButtonBox()
        self.btn_send = btns.addButton("发送", QDialogButtonBox.AcceptRole)
        btns.addButton("取消", QDialogButtonBox.RejectRole)
        self.btn_send.setObjectName("Primary")
        btns.accepted.connect(self.send_packet)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def send_packet(self):
        try:
            from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, sendp
        except Exception as exc:
            QMessageBox.warning(self, "scapy 不可用", str(exc))
            return
        try:
            ether = Ether(src=self.ed_smac.text().strip() or None,
                          dst=self.ed_dmac.text().strip() or None)
            proto = self.cmb_proto.currentText()
            payload = self.ed_payload.toPlainText().encode("utf-8")

            if proto == "ARP":
                layer = ARP(op=2, psrc=self.ed_sip.text().strip(),
                            pdst=self.ed_dip.text().strip())
            else:
                ip = IP(src=self.ed_sip.text().strip(), dst=self.ed_dip.text().strip())
                if proto == "TCP":
                    layer = ip / TCP(sport=self.sp_sport.value(),
                                     dport=self.sp_dport.value(),
                                     flags=self.ed_flags.text().strip() or "S")
                elif proto == "UDP":
                    layer = ip / UDP(sport=self.sp_sport.value(),
                                     dport=self.sp_dport.value())
                elif proto == "ICMP":
                    layer = ip / ICMP()
                else:
                    layer = ip
                if payload:
                    layer = layer / payload
            pkt = ether / layer
            sendp(pkt, iface=self.iface.l2_name if self.iface else None,
                  verbose=0, count=1)
            log(f"已重放数据包：{pkt.summary()}", "success", "capture")
            self.accept()
        except Exception as exc:
            QMessageBox.warning(self, "发送失败", f"{type(exc).__name__}: {exc}")



class CaptureTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.cap: C.PacketCapture | None = None
        self.raw_packets: dict[int, bytes] = {}
        self.all_packets: list[dict] = []          # 全部抓到的包（用于改规则后重筛）
        self.filter = C.PacketFilter()
        self._seq = 0
        self._build()
        self.timer = QTimer(self)
        self.timer.setInterval(300)
        self.timer.timeout.connect(self._poll)

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)
        split = QSplitter(Qt.Vertical)

        top = QWidget()
        tl = QHBoxLayout(top)
        tl.setContentsMargins(0, 0, 0, 0)
        card = Card("📡 抓包设置")

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("网卡", "Dim"))
        self.cmb_iface = QComboBox()
        self.cmb_iface.setMinimumWidth(240)
        r1.addWidget(self.cmb_iface)
        btn_reload = QPushButton("刷新")
        btn_reload.setObjectName("Ghost")
        btn_reload.clicked.connect(self.reload_ifaces)
        r1.addWidget(btn_reload)
        r1.addSpacing(8)
        r1.addWidget(label("BPF 过滤", "Dim"))
        self.ed_filter = QLineEdit()
        self.ed_filter.setPlaceholderText("例如 host 192.168.5.10 / tcp port 443 / arp / icmp")
        r1.addWidget(self.ed_filter, 1)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        self.chk_save = QCheckBox("保存到 pcap 文件")
        self.chk_save.setChecked(True)
        r2.addWidget(self.chk_save)
        self.ed_path = QLineEdit()
        self.ed_path.setText(os.path.join(os.path.expanduser("~"), "Desktop",
                                          "netops_capture.pcap"))
        r2.addWidget(self.ed_path, 1)
        btn_browse = QPushButton("浏览")
        btn_browse.setObjectName("Ghost")
        btn_browse.clicked.connect(self._browse)
        r2.addWidget(btn_browse)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(8)
        self.btn_start = QPushButton("● 开始抓包")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.start_capture)
        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_capture)
        self.btn_wireshark = QPushButton("🦈 用 Wireshark 打开")
        self.btn_wireshark.setObjectName("Ghost")
        self.btn_wireshark.clicked.connect(self.open_wireshark)
        self.btn_replay = QPushButton("✏ 编辑并重放选中包")
        self.btn_replay.setObjectName("Ghost")
        self.btn_replay.setToolTip("选中一个包 → 改 MAC/IP/端口/TCP 标志/载荷 → 重新发出去")
        self.btn_replay.clicked.connect(self.replay_selected)
        btn_clear = QPushButton("清空列表")
        btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(self.clear_list)
        r3.addWidget(self.btn_start)
        r3.addWidget(self.btn_stop)
        r3.addWidget(self.btn_wireshark)
        r3.addWidget(self.btn_replay)
        r3.addWidget(btn_clear)
        r3.addStretch(1)
        card.add(r3)

        self.lbl_stats = label("未开始", "Dim")
        card.add(self.lbl_stats)
        tl.addWidget(card, 1)
        split.addWidget(top)

        res = QWidget()
        rl = QVBoxLayout(res)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)

        self.res_tabs = QTabWidget()

        # ---- 实时包 ----
        pkt_page = QWidget()
        pl = QVBoxLayout(pkt_page)
        pl.setContentsMargins(0, 6, 0, 0)
        pl.setSpacing(6)
        bar = QHBoxLayout()
        bar.addWidget(label("实时数据包", "CardT"))
        bar.addStretch(1)
        self.lbl_proto = label("", "Dim")
        bar.addWidget(self.lbl_proto)
        pl.addLayout(bar)
        pl.addWidget(self._build_filter())

        self.table = make_table(HEADERS, stretch_col=6)
        # 包列表必须保持时间顺序，不能被表头自动排序打乱
        self.table.setSortingEnabled(False)
        self.table.setColumnWidth(0, 52)
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(2, 185)
        self.table.setColumnWidth(3, 185)
        self.table.setColumnWidth(4, 62)
        self.table.setColumnWidth(5, 62)
        self.table.itemSelectionChanged.connect(self._on_select)
        pl.addWidget(self.table, 1)
        self.res_tabs.addTab(pkt_page, "📦 实时数据包")

        # ---- 会话流（TCP 重组） ----
        stream_page = QWidget()
        sl = QVBoxLayout(stream_page)
        sl.setContentsMargins(0, 6, 0, 0)
        sl.setSpacing(6)
        sbar = QHBoxLayout()
        sbar.addWidget(label("TCP 会话（载荷已按方向重组）", "CardT"))
        sbar.addStretch(1)
        self.lbl_stream = label("0 条会话", "Dim")
        sbar.addWidget(self.lbl_stream)
        b_save_a = QPushButton("导出 A→B")
        b_save_a.setObjectName("Ghost")
        b_save_a.clicked.connect(lambda: self.save_stream("a"))
        b_save_b = QPushButton("导出 B→A")
        b_save_b.setObjectName("Ghost")
        b_save_b.clicked.connect(lambda: self.save_stream("b"))
        b_reset = QPushButton("清空会话")
        b_reset.setObjectName("Ghost")
        b_reset.clicked.connect(self.reset_streams)
        for b in (b_save_a, b_save_b, b_reset):
            sbar.addWidget(b)
        sl.addLayout(sbar)

        self.tbl_stream = make_table(
            ["A 端", "B 端", "包数", "A→B 字节", "B→A 字节", "开始时间"], stretch_col=None)
        self.tbl_stream.setColumnWidth(0, 180)
        self.tbl_stream.setColumnWidth(1, 180)
        self.tbl_stream.setColumnWidth(2, 70)
        self.tbl_stream.setColumnWidth(3, 100)
        self.tbl_stream.setColumnWidth(4, 100)
        self.tbl_stream.itemSelectionChanged.connect(self._on_pick_stream)
        sl.addWidget(self.tbl_stream, 1)

        self.txt_stream = QPlainTextEdit()
        self.txt_stream.setReadOnly(True)
        self.txt_stream.setFont(QFont("Cascadia Mono", 9))
        self.txt_stream.setMaximumHeight(180)
        self.txt_stream.setPlaceholderText(
            "选中一条会话，这里预览载荷内容（HTTP 响应、传输的文件片段…）\n"
            "「导出 A→B」通常就是下载下来的文件")
        sl.addWidget(self.txt_stream)
        self.res_tabs.addTab(stream_page, "🔗 会话流重组")

        # ---- 统计图 ----
        stat_page = QWidget()
        stl = QVBoxLayout(stat_page)
        stl.setContentsMargins(0, 6, 0, 0)
        stl.setSpacing(6)
        stl.addWidget(label("协议分布", "CardT"))
        self.chart_proto = BarChart()
        stl.addWidget(self.chart_proto)
        stl.addWidget(label("Top 会话（按字节）", "CardT"))
        self.chart_talk = BarChart()
        stl.addWidget(self.chart_talk)
        stl.addStretch(1)
        self.res_tabs.addTab(stat_page, "📊 流量统计")

        rl.addWidget(self.res_tabs, 1)
        split.addWidget(res)
        split.setSizes([280, 470])
        outer.addWidget(split)

        self.reload_ifaces()

    # ---------------- 会话流 ----------------

    def _current_pair(self):
        row = self.tbl_stream.currentRow()
        if row < 0 or self.cap is None:
            return None
        items = self.cap.stream_list()
        if row < len(items):
            return items[row]
        return None

    def _on_pick_stream(self):
        item = self._current_pair()
        if item is None:
            self.txt_stream.setPlainText("")
            return
        data = self.cap.stream_data(item["b_key"]) or self.cap.stream_data(item["a_key"])
        text = data[:4000].decode("utf-8", "replace")
        self.txt_stream.setPlainText(
            f"=== {item['a']}  →  {item['b']} ===\n"
            f"A→B {item['a_bytes']} 字节 ｜ B→A {item['b_bytes']} 字节 ｜ "
            f"{item['packets']} 个包\n\n" + text)

    @safe_slot
    def save_stream(self, direction: str):
        item = self._current_pair()
        if item is None or self.cap is None:
            QMessageBox.information(self, "没有选中", "先在会话列表里选一条")
            return
        key = item["a_key"] if direction == "a" else item["b_key"]
        if key is None:
            QMessageBox.information(self, "这个方向没有数据", "换另一个方向试试")
            return
        default = f"{item['a'].replace(':', '_')}__to__{item['b'].replace(':', '_')}.bin"
        path, _ = QFileDialog.getSaveFileName(self, "导出会话载荷", default,
                                              "所有文件 (*.*)")
        if not path:
            return
        ok, msg = self.cap.save_stream(key, path)
        if ok:
            log(f"会话载荷已导出：{path}", "success", "capture")
            QMessageBox.information(self, "导出成功", f"已保存到：\n{path}")
        else:
            QMessageBox.warning(self, "导出失败", msg)

    @safe_slot
    def reset_streams(self):
        if self.cap:
            self.cap.reset_streams()
        self.tbl_stream.setRowCount(0)
        self.txt_stream.clear()
        self.lbl_stream.setText("0 条会话")

    def _refresh_streams_and_charts(self):
        if self.cap is None:
            return
        items = self.cap.stream_list()
        self.lbl_stream.setText(f"{len(items)} 条会话")
        # 会话表：只在行数变化时重建，避免每次都清空（会打断选中）
        if self.tbl_stream.rowCount() != len(items):
            self.tbl_stream.setSortingEnabled(False)
            self.tbl_stream.setRowCount(0)
            for it in items:
                r = self.tbl_stream.rowCount()
                self.tbl_stream.insertRow(r)
                set_row(self.tbl_stream, r,
                        [it["a"], it["b"], it["packets"],
                         it["a_bytes"], it["b_bytes"], it["first"]])
            self.tbl_stream.setSortingEnabled(True)

        s = self.cap.stats
        proto = sorted(s.by_proto.items(), key=lambda kv: -kv[1])[:8]
        self.chart_proto.set_data(proto, " 包")
        talk = [(it["a"].split(":")[0], it["a_bytes"] + it["b_bytes"]) for it in items[:8]]
        self.chart_talk.set_data(talk, " 字节")

    # ---------------- 筛选 ----------------

    def _build_filter(self) -> QWidget:
        """
        筛选规则区：可以同时启用多条规则，只保留（或不保留）含指定字符串的包。
        规则之间是「与」——例：源地址包含 192.168.5.10 且 协议等于 TCP。
        """
        box = Card("🔎 筛选规则（多条同时生效，取「与」）")
        top = QHBoxLayout()
        top.setSpacing(6)
        b_add = QPushButton("➕ 添加规则")
        b_add.setObjectName("Ghost")
        b_add.clicked.connect(lambda: self.add_filter_rule())
        b_del = QPushButton("删除选中")
        b_del.setObjectName("Ghost")
        b_del.clicked.connect(self.del_filter_rule)
        b_clr = QPushButton("清空规则")
        b_clr.setObjectName("Ghost")
        b_clr.clicked.connect(self.clear_filter_rules)
        b_only = QPushButton("只看选中包的主机")
        b_only.setObjectName("Ghost")
        b_only.setToolTip("选中一个包后点这里，快速建一条只留这台主机的规则")
        b_only.clicked.connect(self.only_selected_host)
        b_x = QPushButton("排除选中包的主机")
        b_x.setObjectName("Ghost")
        b_x.clicked.connect(lambda: self.only_selected_host(exclude=True))
        for b in (b_add, b_del, b_clr, b_only, b_x):
            top.addWidget(b)
        top.addStretch(1)
        self.lbl_filter = label("未启用筛选", "Dim")
        top.addWidget(self.lbl_filter)
        box.add(top)

        self.tbl_filter = QTableWidget(0, 4)
        self.tbl_filter.setHorizontalHeaderLabels(["启用", "字段", "条件", "内容"])
        self.tbl_filter.verticalHeader().setVisible(False)
        self.tbl_filter.verticalHeader().setDefaultSectionSize(28)
        self.tbl_filter.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_filter.setEditTriggers(QAbstractItemView.NoEditTriggers)
        hh = self.tbl_filter.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        self.tbl_filter.setMaximumHeight(118)
        box.add(self.tbl_filter)
        return box

    def add_filter_rule(self, field: str = "any", op: str = "contains",
                        value: str = "") -> None:
        rule = self.filter.add(field, op, value)
        r = self.tbl_filter.rowCount()
        self.tbl_filter.insertRow(r)

        chk = QTableWidgetItem()
        chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        chk.setCheckState(Qt.Checked if rule.enabled else Qt.Unchecked)
        self.tbl_filter.setItem(r, 0, chk)
        self.tbl_filter.itemChanged.connect(self._on_filter_changed)

        cmb_f = QComboBox()
        for key, name in C.FIELD_LABELS.items():
            cmb_f.addItem(name, key)
        cmb_f.setCurrentIndex(list(C.FIELD_LABELS).index(rule.field))
        cmb_f.currentIndexChanged.connect(self._on_filter_changed)
        self.tbl_filter.setCellWidget(r, 1, cmb_f)

        cmb_o = QComboBox()
        for key, name in C.OP_LABELS.items():
            cmb_o.addItem(name, key)
        cmb_o.setCurrentIndex(list(C.OP_LABELS).index(rule.op))
        cmb_o.currentIndexChanged.connect(self._on_filter_changed)
        self.tbl_filter.setCellWidget(r, 2, cmb_o)

        edit = QLineEdit(rule.value)
        edit.setPlaceholderText("要包含/排除的字符串，规则支持正则")
        edit.textChanged.connect(self._on_filter_changed)
        self.tbl_filter.setCellWidget(r, 3, edit)

    @safe_slot
    def del_filter_rule(self):
        rows = sorted({i.row() for i in self.tbl_filter.selectionModel().selectedRows()},
                      reverse=True)
        if not rows:
            rows = [self.tbl_filter.rowCount() - 1] if self.tbl_filter.rowCount() else []
        for r in rows:
            if r >= 0:
                self.tbl_filter.removeRow(r)
        self._sync_filter_from_ui()

    @safe_slot
    def clear_filter_rules(self):
        self.tbl_filter.setRowCount(0)
        self._sync_filter_from_ui()

    @safe_slot
    def only_selected_host(self, exclude: bool = False):
        p = self._selected_packet()
        if p is None:
            QMessageBox.information(self, "没有选中包", "先在数据包列表里点一个包")
            return
        host = str(p.get("src", "")).split(":")[0]
        if not host:
            return
        self.add_filter_rule("any", "not_contains" if exclude else "contains", host)
        self._sync_filter_from_ui()

    @safe_slot
    def _on_filter_changed(self, *_):
        self._sync_filter_from_ui()

    def _sync_filter_from_ui(self):
        """把界面上的表格同步回 PacketFilter，并按新规则重筛已有数据。"""
        rules = []
        for r in range(self.tbl_filter.rowCount()):
            chk = self.tbl_filter.item(r, 0)
            cmb_f = self.tbl_filter.cellWidget(r, 1)
            cmb_o = self.tbl_filter.cellWidget(r, 2)
            edit = self.tbl_filter.cellWidget(r, 3)
            if cmb_f is None or cmb_o is None or edit is None:
                continue
            rules.append(C.FilterRule(
                field=cmb_f.currentData(), op=cmb_o.currentData(),
                value=edit.text(),
                enabled=(chk is None or chk.checkState() == Qt.Checked)))
        self.filter.rules = rules
        self.lbl_filter.setText(self.filter.describe())
        self.apply_filter()

    def apply_filter(self):
        """按当前规则把 all_packets 重新渲染到表格里。"""
        table = self.table
        table.setRowCount(0)
        shown = 0
        for p in self.all_packets:
            if self.filter.match(p):
                self._append_row(p)
                shown += 1
        total = len(self.all_packets)
        if self.filter.is_empty:
            self.lbl_filter.setText(f"未启用筛选 · 共 {total} 包")
        else:
            self.lbl_filter.setText(
                f"{self.filter.describe()} · 显示 {shown}/{total} 包")

    def _append_row(self, p: dict):
        table = self.table
        row = table.rowCount()
        table.insertRow(row)
        set_row(table, row, [p.get("seq", ""), p["time"], p["src"], p["dst"],
                             p["proto"], p["len"], p["info"]],
                {4: C_MINT if p["proto"] == "TCP" else C_TEXT_DIM})

    def _selected_packet(self) -> dict | None:
        row = self.table.currentRow()
        if row < 0:
            return None
        it = self.table.item(row, 0)
        if it is None:
            return None
        try:
            seq = int(it.text())
        except ValueError:
            return None
        for p in reversed(self.all_packets):
            if p.get("seq") == seq:
                return p
        return None

    # ---------------- 选中 / 重放 ----------------

    def selected_raw(self) -> bytes:
        row = self.table.currentRow()
        if row < 0:
            return b""
        it = self.table.item(row, 0)
        if it is None:
            return b""
        try:
            return self.raw_packets.get(int(it.text()), b"")
        except ValueError:
            return b""

    def _on_select(self):
        raw = self.selected_raw()
        if raw:
            try:
                from scapy.all import Ether
                self.lbl_proto.setText(Ether(raw).summary()[:120])
            except Exception:
                pass

    def replay_selected(self):
        raw = self.selected_raw()
        if not raw:
            QMessageBox.information(
                self, "没有选中数据包",
                "先在列表里点一个包。\n"
                "（如果表里没有包，说明还没抓到流量，或者包已经被清空过。）")
            return
        if not HI.is_admin():
            QMessageBox.warning(self, "需要管理员权限",
                                "发送原始数据包需要管理员权限与 Npcap。")
            return
        dlg = PacketEditor(raw, self.current_iface(), self)
        dlg.exec_()

    # ---------------- 网卡 ----------------

    def reload_ifaces(self):
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

    def current_iface(self):
        return self.cmb_iface.currentData()

    def _browse(self):
        path, _ = QFileDialog.getSaveFileName(self, "保存抓包文件",
                                              self.ed_path.text() or "capture.pcap",
                                              "抓包文件 (*.pcap *.pcapng)")
        if path:
            self.ed_path.setText(path)

    # ---------------- 抓包 ----------------

    def start_capture(self):
        if self.cap is not None and self.cap.running:
            return
        iface = self.current_iface()
        if iface is None:
            QMessageBox.warning(self, "缺少网卡", "请选择网卡")
            return
        if not HI.is_admin():
            QMessageBox.warning(
                self, "需要管理员权限",
                "抓包需要管理员权限与 Npcap。\n请用右上角「以管理员身份重启」重新打开。")
            return
        ok, why = HI.npcap_ready()
        if not ok:
            QMessageBox.warning(self, "Npcap 不可用", why)
            return

        path = self.ed_path.text().strip() if self.chk_save.isChecked() else ""
        self.cap = C.PacketCapture(iface, self.ed_filter.text().strip(), path)
        na = getattr(self, "note_action", None)
        if callable(na):
            na(f"开始抓包 iface={iface.l2_name} bpf={self.ed_filter.text().strip()!r}")
        try:
            self.cap.start()
        except Exception as exc:
            self.cap = None
            QMessageBox.warning(self, "启动失败", str(exc))
            return
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.timer.start()

    def stop_capture(self):
        if self.cap is None:
            return
        na = getattr(self, "note_action", None)
        if callable(na):
            na("停止抓包")
        self.cap.stop()
        self.timer.stop()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self._poll()
        self.lbl_stats.setText(f"已停止  ·  共 {self.cap.stats.packets} 个包")
        if self.cap.stats.pcap_path:
            log(f"抓包文件：{self.cap.stats.pcap_path}", "info", "capture")

    def clear_list(self):
        self.table.setRowCount(0)
        self.raw_packets.clear()
        self.all_packets.clear()
        if self.cap:
            self.cap.clear()
        self.apply_filter()

    def _poll(self):
        if self.cap is None:
            return
        packets = self.cap.drain(400)
        if packets:
            table = self.table
            for p in packets:
                self._seq += 1
                p["seq"] = self._seq
                self.all_packets.append(p)
                if p.get("raw"):
                    self.raw_packets[self._seq] = p["raw"]
                if self.filter.match(p):
                    self._append_row(p)
            # 控制内存：太老的丢掉
            while len(self.all_packets) > MAX_ROWS:
                old = self.all_packets.pop(0)
                self.raw_packets.pop(old.get("seq"), None)
            while table.rowCount() > MAX_ROWS:
                table.removeRow(0)
            sb = table.verticalScrollBar()
            sb.setValue(sb.maximum())
            total = len(self.all_packets)
            if self.filter.is_empty:
                self.lbl_filter.setText(f"未启用筛选 · 共 {total} 包")
            else:
                self.lbl_filter.setText(
                    f"{self.filter.describe()} · 显示 {table.rowCount()}/{total} 包")

        s = self.cap.stats
        self.lbl_stats.setText(
            f"{'抓包中' if s.running else '已停止'} {s.uptime}  ·  "
            f"{s.packets} 个包  ·  {s.bytes / 1024:.1f} KB  ·  {s.pps:.0f} pps"
            + (f"  ·  → {s.pcap_path}" if s.pcap_path else "")
            + (f"  ·  ⚠ {s.last_error}" if s.last_error else ""))
        top = sorted(s.by_proto.items(), key=lambda kv: -kv[1])[:5]
        self.lbl_proto.setText("  ".join(f"{k}:{v}" for k, v in top))
        self._refresh_streams_and_charts()

    def open_wireshark(self):
        path = ""
        if self.cap is not None and self.cap.stats.pcap_path:
            path = self.cap.stats.pcap_path
        else:
            path = self.ed_path.text().strip()
        exe = next((p for p in WIRESHARK_CANDIDATES if os.path.exists(p)), "")
        if not exe:
            QMessageBox.information(
                self, "没找到 Wireshark",
                "没有在默认路径找到 Wireshark.exe。\n"
                "可以手动打开抓包文件：" + (path or "（还没有抓包文件）"))
            return
        try:
            args = [exe] + ([path] if path and os.path.exists(path) else [])
            subprocess.Popen(args)
            log(f"已启动 Wireshark{' 并载入 ' + path if len(args) > 1 else ''}",
                "info", "capture")
        except Exception as exc:
            QMessageBox.warning(self, "启动失败", str(exc))

    def shutdown(self):
        if self.cap is not None and self.cap.running:
            self.stop_capture()
