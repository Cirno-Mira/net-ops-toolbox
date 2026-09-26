# -*- coding: utf-8 -*-
"""
假服务页（一键起本地 DNS / HTTP）
=================================

把「本机假冒成 DNS 服务器 / 网站服务器」这件事做成一页可视化操作：

* **假 DNS**：配几条「域名 → IP」，命中的按配置回答；没命中的可以转发上游、
  回 NXDOMAIN、或者干脆不响应。左边表格就是记录表，右边是实时查询日志。
* **假 HTTP**：两种模式 —— 固定内容（可自定义状态码 / Content-Type）
  或把某个目录当根目录提供文件；下面实时显示每个请求的来源 / 路径 / User-Agent。

配合「ARP 牵引 + DNS 引流」用：把目标设备的 DNS 指到本机之后，
它访问哪个域名、看到什么页面，全在这一页里，用来验证流量到底有没有被牵引过来。
顶部一行直接给出本机 IP，复制走去目标设备上写 hosts 或改 DNS 即可。
"""

from __future__ import annotations

import os
from datetime import datetime

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (QApplication, QComboBox, QFileDialog, QHBoxLayout,
                             QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
                             QPushButton, QSpinBox, QSplitter, QStackedWidget,
                             QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from core import fakeserv as FS
from core.logging_bus import log
from ui.widgets import Badge, Card, hline, label, make_table, safe_slot, set_row
from theme import C_MINT, C_RED, C_TEXT_DIM, C_YELLOW

DNS_LOG_HEADERS = ["时间", "来源", "查询域名", "类型", "处理结果"]
HTTP_LOG_HEADERS = ["#", "时间", "方法", "路径", "来源", "User-Agent"]

MAX_LOG_ROWS = 500          # 界面上的日志表最多留多少行，多了删最旧的

CONTENT_TYPES = [
    "text/html; charset=utf-8",
    "text/plain; charset=utf-8",
    "application/json; charset=utf-8",
    "application/javascript; charset=utf-8",
    "text/css; charset=utf-8",
    "application/octet-stream",
]


def _edit_table(headers: list) -> QTableWidget:
    """可编辑的小表格（用于「域名 | IP」这种记录表）。"""
    t = make_table(headers)
    t.setSortingEnabled(False)
    t.setEditTriggers(t.DoubleClicked | t.EditKeyPressed | t.AnyKeyPressed
                      | t.SelectedClicked)
    return t


def _blank(text: str) -> str:
    """把「空的占位内容」（空串或用户敲的 - / — / –）统一当成空。"""
    return "" if not text.strip().strip("-—–").strip() else text


class FakeservTab(QWidget):
    dns_query_signal = pyqtSignal(str, str, str, str)     # 域名 类型 来源 结果
    http_hit_signal = pyqtSignal(object)                  # 请求信息 dict

    def __init__(self, parent=None):
        super().__init__(parent)
        self.dns: FS.FakeDnsServer | None = None
        self.http: FS.FakeHttpServer | None = None
        self.dns_rows = 0
        self.http_rows = 0
        self._local_ips: list[str] = []
        self._build()
        self.dns_query_signal.connect(self.on_dns_query)
        self.http_hit_signal.connect(self.on_http_request)

    # ================= 界面 =================

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)

        outer.addWidget(self._build_top())

        split = QSplitter(Qt.Vertical)
        split.addWidget(self._build_dns())
        split.addWidget(self._build_http())
        split.setSizes([420, 380])
        outer.addWidget(split, 1)

        # 三个 IP 下拉框都建好了再灌数据（_build_top 里还不能填）
        self.reload_ips()
        # 换监听地址时顶部提示跟着变（提醒「现在只有本机能访问」还是有对外监听）
        self.cmb_dns_ip.currentTextChanged.connect(self._refresh_ip_tip)

    # ---------------- 顶部：本机 IP 提示 ----------------

    def _build_top(self) -> QWidget:
        card = Card("🏠 本机 IP（把它填到目标设备的 hosts 或 DNS 里）")
        row = QHBoxLayout()
        row.setSpacing(6)
        row.addWidget(label("可用地址", "Dim"))
        self.cmb_local_ip = QComboBox()
        self.cmb_local_ip.setMinimumWidth(190)
        self.cmb_local_ip.setToolTip("本机可用于访问的 IPv4。目标设备要能连到哪个，就用哪个。")
        row.addWidget(self.cmb_local_ip)
        btn_refresh = QPushButton("刷新")
        btn_refresh.setObjectName("Ghost")
        btn_refresh.setToolTip("重新枚举网卡（换了 WiFi / 插了网线之后点一下）")
        btn_refresh.clicked.connect(self.reload_ips)
        row.addWidget(btn_refresh)
        btn_copy = QPushButton("复制 IP")
        btn_copy.setObjectName("Ghost")
        btn_copy.clicked.connect(self.copy_local_ip)
        row.addWidget(btn_copy)
        row.addStretch(1)
        self.lbl_top_tip = label("", "Dim")
        self.lbl_top_tip.setWordWrap(True)
        row.addWidget(self.lbl_top_tip)
        card.add(row)

        tip = QLabel(
            "用法：目标设备的 DNS 改成上面的 IP（假 DNS 监听 53），"
            "或在它的 hosts 里写「域名 → 本机 IP」直接指向假 HTTP 的端口。\n"
            "两个服务都只监听你选的那张网卡，默认 127.0.0.1 只有本机能访问；"
            "要让目标设备连进来，把监听 IP 换成局域网地址，并在防火墙里放行对应端口。")
        tip.setObjectName("Dim")
        tip.setWordWrap(True)
        card.add(tip)
        return card

    # ---------------- 假 DNS ----------------

    def _build_dns(self) -> QWidget:
        card = Card("🌐 假 DNS 服务")
        card.setMinimumHeight(300)

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        self.btn_dns = QPushButton("▶ 启动假 DNS")
        self.btn_dns.setObjectName("Primary")
        self.btn_dns.clicked.connect(self.toggle_dns)
        r1.addWidget(self.btn_dns)
        r1.addWidget(label("监听 IP", "Dim"))
        self.cmb_dns_ip = QComboBox()
        self.cmb_dns_ip.setEditable(True)
        self.cmb_dns_ip.setMinimumWidth(150)
        self.cmb_dns_ip.setToolTip("0.0.0.0 = 所有网卡都能连进来；"
                                   "只想本机测试就选 127.0.0.1")
        r1.addWidget(self.cmb_dns_ip)
        r1.addWidget(label("端口", "Dim"))
        self.sp_dns_port = QSpinBox()
        self.sp_dns_port.setRange(1, 65535)
        self.sp_dns_port.setValue(53)
        self.sp_dns_port.setToolTip("53 是标准 DNS 端口，需要管理员权限；\n"
                                    "免提权测试可以改成 5353（目标设备得手动指到这个端口）")
        r1.addWidget(self.sp_dns_port)
        r1.addWidget(label("未命中", "Dim"))
        self.cmb_miss = QComboBox()
        for key in (FS.MISS_FORWARD, FS.MISS_NXDOMAIN, FS.MISS_SILENT):
            self.cmb_miss.addItem(FS.MISS_LABELS[key], key)
        self.cmb_miss.setToolTip("查不到记录时怎么办：\n"
                                 "转发上游 = 当正常 DNS 用（需要有外网）\n"
                                 "返回 NXDOMAIN = 告诉它域名不存在（演示断网）\n"
                                 "不响应 = 直接丢包（客户端会转圈到超时）")
        r1.addWidget(self.cmb_miss)
        r1.addWidget(label("上游 DNS", "Dim"))
        self.ed_upstream = QLineEdit(FS.DEFAULT_UPSTREAM)
        self.ed_upstream.setFixedWidth(130)
        self.ed_upstream.setToolTip("「转发上游」时把查询转给谁，例如 223.5.5.5 / 8.8.8.8；\n"
                                    "非 53 端口写成 127.0.0.1:5353")
        r1.addWidget(self.ed_upstream)
        r1.addStretch(1)
        self.badge_dns = Badge("未启动", "idle")
        r1.addWidget(self.badge_dns)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("记录表（双击单元格直接改，支持 *.example.com 通配）", "Dim"))
        r2.addStretch(1)
        for text, fn in (("＋ 添加一行", self.dns_add_row),
                         ("删除选中行", self.dns_del_row),
                         ("示例", self.dns_fill_demo)):
            b = QPushButton(text)
            b.setObjectName("Ghost")
            b.clicked.connect(fn)
            r2.addWidget(b)
        card.add(r2)

        self.tbl_records = _edit_table(["域名", "IP"])
        self.tbl_records.setToolTip("命中就按这里的 IP 回答；IP 填目标设备能连到的地址，\n"
                                    "想让它连到本机就填本机 IP。")
        self.tbl_records.setMaximumHeight(130)
        self.tbl_records.setColumnWidth(0, 330)
        card.add(self.tbl_records)

        card.add(hline())
        bar = QHBoxLayout()
        bar.addWidget(label("实时查询日志", "CardT"))
        bar.addStretch(1)
        self.lbl_dns_stats = label("暂无查询", "Dim")
        bar.addWidget(self.lbl_dns_stats)
        btn_clear = QPushButton("清空日志")
        btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(self.clear_dns_log)
        bar.addWidget(btn_clear)
        card.add(bar)

        self.tbl_dns = make_table(DNS_LOG_HEADERS, stretch_col=4)
        self.tbl_dns.setSortingEnabled(False)
        self.tbl_dns.setColumnWidth(0, 80)
        self.tbl_dns.setColumnWidth(1, 140)
        self.tbl_dns.setColumnWidth(2, 280)
        self.tbl_dns.setColumnWidth(3, 60)
        card.add(self.tbl_dns)
        return card

    # ---------------- 假 HTTP ----------------

    def _build_http(self) -> QWidget:
        card = Card("📄 假 HTTP 服务")
        card.setMinimumHeight(300)

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        self.btn_http = QPushButton("▶ 启动假 HTTP")
        self.btn_http.setObjectName("Primary")
        self.btn_http.clicked.connect(self.toggle_http)
        r1.addWidget(self.btn_http)
        r1.addWidget(label("监听 IP", "Dim"))
        self.cmb_http_ip = QComboBox()
        self.cmb_http_ip.setEditable(True)
        self.cmb_http_ip.setMinimumWidth(150)
        self.cmb_http_ip.currentTextChanged.connect(self._refresh_ip_tip)
        r1.addWidget(self.cmb_http_ip)
        r1.addWidget(label("端口", "Dim"))
        self.sp_http_port = QSpinBox()
        self.sp_http_port.setRange(1, 65535)
        self.sp_http_port.setValue(80)
        self.sp_http_port.setToolTip("80 需要管理员权限；免提权测试改成 8080，\n"
                                     "目标设备访问时记得带上端口号")
        r1.addWidget(self.sp_http_port)
        r1.addWidget(label("状态码", "Dim"))
        self.sp_status = QSpinBox()
        self.sp_status.setRange(100, 599)
        self.sp_status.setValue(200)
        self.sp_status.setToolTip("固定内容模式下返回的状态码，例如 200 / 302 / 403 / 404")
        r1.addWidget(self.sp_status)
        r1.addWidget(label("Content-Type", "Dim"))
        self.cmb_ctype = QComboBox()
        self.cmb_ctype.setEditable(True)
        self.cmb_ctype.addItems(CONTENT_TYPES)
        self.cmb_ctype.setMinimumWidth(210)
        r1.addWidget(self.cmb_ctype)
        r1.addStretch(1)
        self.badge_http = Badge("未启动", "idle")
        r1.addWidget(self.badge_http)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("模式", "Dim"))
        self.cmb_mode = QComboBox()
        self.cmb_mode.addItem("固定内容（任何路径都回同一份内容）", "fixed")
        self.cmb_mode.addItem("目录（把某个目录当根目录提供文件）", "dir")
        self.cmb_mode.currentIndexChanged.connect(self._on_mode_changed)
        r2.addWidget(self.cmb_mode)
        r2.addStretch(1)
        card.add(r2)

        self.stack = QStackedWidget()
        # 第 0 页：固定内容
        page_fixed = QWidget()
        fl = QVBoxLayout(page_fixed)
        fl.setContentsMargins(0, 0, 0, 0)
        fl.setSpacing(4)
        fl.addWidget(label("返回内容（UTF-8）", "Dim"))
        self.txt_content = QPlainTextEdit()
        self.txt_content.setFont(QFont("Cascadia Mono", 9))
        self.txt_content.setPlaceholderText("例如：<h1>这是一个假页面</h1>")
        self.txt_content.setPlainText(FS.DEFAULT_INDEX)
        fl.addWidget(self.txt_content)
        self.stack.addWidget(page_fixed)

        # 第 1 页：目录
        page_dir = QWidget()
        dl = QVBoxLayout(page_dir)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.setSpacing(4)
        dl.addWidget(label("根目录（里面的文件会按路径提供出去，含目录列表）", "Dim"))
        dr = QHBoxLayout()
        dr.setSpacing(6)
        self.ed_dir = QLineEdit()
        self.ed_dir.setPlaceholderText("选择一个目录，例如装了个静态页面的文件夹")
        dr.addWidget(self.ed_dir, 1)
        btn_dir = QPushButton("选择目录…")
        btn_dir.setObjectName("Ghost")
        btn_dir.clicked.connect(self.browse_dir)
        dr.addWidget(btn_dir)
        dl.addLayout(dr)
        dl.addStretch(1)
        self.stack.addWidget(page_dir)
        card.add(self.stack)

        card.add(hline())
        bar = QHBoxLayout()
        bar.addWidget(label("实时请求", "CardT"))
        bar.addStretch(1)
        self.lbl_http_stats = label("暂无请求", "Dim")
        bar.addWidget(self.lbl_http_stats)
        btn_clear_h = QPushButton("清空列表")
        btn_clear_h.setObjectName("Ghost")
        btn_clear_h.clicked.connect(self.clear_http_log)
        bar.addWidget(btn_clear_h)
        card.add(bar)

        self.tbl_http = make_table(HTTP_LOG_HEADERS, stretch_col=5)
        self.tbl_http.setSortingEnabled(False)
        self.tbl_http.setColumnWidth(0, 50)
        self.tbl_http.setColumnWidth(1, 80)
        self.tbl_http.setColumnWidth(2, 70)
        self.tbl_http.setColumnWidth(3, 300)
        self.tbl_http.setColumnWidth(4, 140)
        card.add(self.tbl_http)
        return card

    # ================= 本机 IP =================

    @safe_slot
    def reload_ips(self):
        ips = FS.local_ips()
        self._local_ips = ips
        primary = ips[0] if ips else "127.0.0.1"
        allowed = list(ips) + ["0.0.0.0"]
        for combo, fallback in ((self.cmb_local_ip, primary),
                                (self.cmb_dns_ip, "127.0.0.1"),
                                (self.cmb_http_ip, "127.0.0.1")):
            # 监听框默认只绑回环：本机就能测通，也不会一启动就弹防火墙；
            # 用户自己选过局域网地址 / 0.0.0.0 的话就留着，别给他改回去。
            old = combo.currentText().strip()
            keep = old if (old in allowed and old != primary) else fallback
            combo.clear()
            combo.addItems(allowed)
            combo.setCurrentText(keep)
        self.cmb_local_ip.setCurrentText(primary)
        self._refresh_ip_tip()

    @safe_slot
    def _refresh_ip_tip(self):
        listen_ips = {self.cmb_dns_ip.currentText().strip(),
                      self.cmb_http_ip.currentText().strip()}
        remote = [ip for ip in listen_ips
                  if ip == "0.0.0.0" or ip[:3] in ("192", "10.", "172")
                  or ip.startswith("169.")]
        tail = "，目标设备可以连进来（记得在防火墙放行端口）" if remote else "，目前只有本机能访问"
        self.lbl_top_tip.setText(
            f"共 {len(self._local_ips)} 个地址，主用 {self.cmb_local_ip.currentText()}{tail}")

    @safe_slot
    def copy_local_ip(self):
        ip = self.cmb_local_ip.currentText().strip()
        if not ip:
            return
        QApplication.clipboard().setText(ip)
        log(f"已复制本机 IP：{ip}", "info", "fakeserv")

    # ================= 记录表 =================

    def dns_add_row(self, name: str = "", ip: str = ""):
        row = self.tbl_records.rowCount()
        self.tbl_records.insertRow(row)
        self.tbl_records.setItem(row, 0, QTableWidgetItem(name))
        self.tbl_records.setItem(row, 1, QTableWidgetItem(ip))
        self.tbl_records.setCurrentCell(row, 0)

    @safe_slot
    def dns_del_row(self):
        rows = sorted({i.row() for i in self.tbl_records.selectedIndexes()},
                      reverse=True)
        if not rows:
            QMessageBox.information(self, "没有选中", "先在记录表里点一行（或几行）再删")
            return
        for r in rows:
            self.tbl_records.removeRow(r)

    @safe_slot
    def dns_fill_demo(self):
        """一键填两条示例记录，方便第一次用就知道该填什么。"""
        if self.tbl_records.rowCount() == 0:
            self.dns_add_row("demo.test", "127.0.0.1")
            self.dns_add_row("*.demo.test", "127.0.0.1")
        else:
            QMessageBox.information(
                self, "记录表非空",
                "记录表里已经有内容了，先手动清空或删掉再点示例。\n\n"
                "示例的意思是：把 demo.test 指到本机 IP，"
                "这样在目标设备上访问 http://demo.test/ 就会打到本页的假 HTTP。")
        log("已填入示例记录：demo.test / *.demo.test → 127.0.0.1（记得改成局域网 IP）",
            "info", "fakeserv")

    def _dns_records(self) -> list:
        out = []
        for r in range(self.tbl_records.rowCount()):
            name_item = self.tbl_records.item(r, 0)
            ip_item = self.tbl_records.item(r, 1)
            name = name_item.text().strip() if name_item else ""
            ip = ip_item.text().strip() if ip_item else ""
            name = _blank(name)
            ip = _blank(ip)
            if name and ip:
                out.append((name, ip))
        return out

    # ================= 假 DNS 启停 =================

    @safe_slot
    def toggle_dns(self):
        if self.dns is not None and self.dns.running:
            self.dns.stop()
            self.dns = None
            self._refresh_dns()
            return

        records = self._dns_records()
        if not records:
            QMessageBox.warning(self, "没有记录",
                                "记录表是空的：先加一条「域名 → IP」，"
                                "或点「示例」看看怎么写。")
            return
        policy = self.cmb_miss.currentData()
        if policy == FS.MISS_FORWARD and not self.ed_upstream.text().strip():
            QMessageBox.warning(self, "缺少上游 DNS",
                                "未命中策略选了「转发到上游 DNS」，但上游地址是空的。\n"
                                "填一个（例如 223.5.5.5），或者把策略改成返回 NXDOMAIN。")
            return

        self.dns = FS.FakeDnsServer(
            bind_ip=self.cmb_dns_ip.currentText().strip() or "0.0.0.0",
            port=self.sp_dns_port.value(),
            upstream=self.ed_upstream.text().strip(),
            miss_policy=policy,
            on_query=lambda name, qtype, cip, ans: self.dns_query_signal.emit(
                name, qtype, cip, ans),
        )
        self.dns.set_records(records)
        self.dns.start()
        self._refresh_dns()
        if not self.dns.running:
            errs = "\n\n".join(self.dns.bind_errors) or "端口没能监听成功，看底部日志"
            self.dns = None
            self._refresh_dns()
            QMessageBox.warning(self, "启动失败", errs)

    def _refresh_dns(self):
        running = self.dns is not None and self.dns.running
        self.btn_dns.setText("■ 停止假 DNS" if running else "▶ 启动假 DNS")
        self.badge_dns.set_state("运行中" if running else "未启动",
                                 "ok" if running else "idle")
        if running:
            s = self.dns.stats
            self.lbl_dns_stats.setText(
                f"查询 {s['queries']} · 命中 {s['answered']} · NXDOMAIN {s['nxdomain']}"
                f" · 转发 {s['forwarded']} · 丢弃 {s['silent']}"
                + (f" · ⚠ 出错 {s['errors']}" if s["errors"] else ""))
        elif self.lbl_dns_stats.text() == "暂无查询":
            self.lbl_dns_stats.setText("未启动")

    def on_dns_query(self, name: str, qtype: str, client_ip: str, answered: str):
        """DNS 回调（已经在主线程）：写进实时查询日志表。"""
        row = self.tbl_dns.rowCount()
        self.tbl_dns.insertRow(row)
        if "失败" in answered or "SERVFAIL" in answered:
            color = {4: C_RED}
        elif "NXDOMAIN" in answered or "不响应" in answered:
            color = {4: C_YELLOW}
        else:
            color = {4: C_MINT if answered and "。" not in answered else C_TEXT_DIM}
        set_row(self.tbl_dns, row,
                [datetime.now().strftime("%H:%M:%S"), client_ip, name.rstrip("."),
                 qtype, answered], color)
        self._trim(self.tbl_dns)
        sb = self.tbl_dns.verticalScrollBar()
        sb.setValue(sb.maximum())
        self._refresh_dns()

    @safe_slot
    def clear_dns_log(self):
        self.tbl_dns.setRowCount(0)
        if self.dns is not None:
            self.dns.clear_stats()
        self._refresh_dns()

    # ================= 假 HTTP 启停 =================

    @safe_slot
    def _on_mode_changed(self):
        self.stack.setCurrentIndex(0 if self.cmb_mode.currentData() == "fixed" else 1)

    @safe_slot
    def browse_dir(self):
        start = self.ed_dir.text().strip() or os.path.expanduser("~")
        path = QFileDialog.getExistingDirectory(self, "选择要提供出去的目录", start)
        if path:
            self.ed_dir.setText(os.path.normpath(path))

    @safe_slot
    def toggle_http(self):
        if self.http is not None and self.http.running:
            self.http.stop()
            self.http = None
            self._refresh_http()
            return

        mode = self.cmb_mode.currentData()
        directory = self.ed_dir.text().strip()
        if mode == "dir" and not directory:
            QMessageBox.warning(self, "没有选目录",
                                "目录模式下要先选一个根目录，里面的文件才会被提供出去。")
            return
        if mode == "dir" and not os.path.isdir(directory):
            QMessageBox.warning(self, "目录不存在", f"这个目录打不开：\n{directory}")
            return

        self.http = FS.FakeHttpServer(
            bind_ip=self.cmb_http_ip.currentText().strip() or "0.0.0.0",
            port=self.sp_http_port.value(),
            mode=mode,
            content=self.txt_content.toPlainText(),
            directory=directory,
            status=self.sp_status.value(),
            content_type=self.cmb_ctype.currentText().strip(),
            on_request=self.http_hit_signal.emit,
        )
        self.http.start()
        self._refresh_http()
        if not self.http.running:
            errs = "\n\n".join(self.http.bind_errors) or "端口没能监听成功，看底部日志"
            self.http = None
            self._refresh_http()
            QMessageBox.warning(self, "启动失败", errs)

    def _refresh_http(self):
        running = self.http is not None and self.http.running
        self.btn_http.setText("■ 停止假 HTTP" if running else "▶ 启动假 HTTP")
        self.badge_http.set_state("运行中" if running else "未启动",
                                  "ok" if running else "idle")
        if running:
            s = self.http.stats
            where = ("固定内容" if self.http.mode == "fixed"
                     else f"目录 {os.path.basename(self.http.directory) or self.http.directory}")
            self.lbl_http_stats.setText(
                f"请求 {s['requests']} · {where}"
                f" · http://{self.http.bind_ip}:{self.http.port}/")
        elif self.lbl_http_stats.text() == "暂无请求":
            self.lbl_http_stats.setText("未启动")

    def on_http_request(self, info: dict):
        """HTTP 回调（已经在主线程）：写进实时请求表。"""
        self.http_rows += 1
        row = self.tbl_http.rowCount()
        self.tbl_http.insertRow(row)
        ua = str(info.get("ua", ""))
        set_row(self.tbl_http, row,
                [self.http_rows, info.get("time", ""), info.get("method", ""),
                 info.get("path", ""), info.get("client", ""), ua[:70]],
                {2: C_MINT if info.get("method") in ("GET", "HEAD") else C_TEXT_DIM})
        self._trim(self.tbl_http)
        sb = self.tbl_http.verticalScrollBar()
        sb.setValue(sb.maximum())
        self._refresh_http()

    @safe_slot
    def clear_http_log(self):
        self.tbl_http.setRowCount(0)
        self.http_rows = 0
        if self.http is not None:
            self.http.clear_stats()
        self._refresh_http()

    @staticmethod
    def _trim(table):
        while table.rowCount() > MAX_LOG_ROWS:
            table.removeRow(0)

    # ================= 给主窗口用 =================

    def shutdown(self):
        """窗口关闭时调用：把两个服务都干净停掉，避免端口被占着不放。"""
        for srv, name in ((self.dns, "假 DNS"), (self.http, "假 HTTP")):
            if srv is not None and srv.running:
                try:
                    srv.stop()
                except Exception as exc:
                    log(f"退出时停止{name}出错（已忽略）：{type(exc).__name__}: {exc}",
                        "warn", "fakeserv")
        self.dns = None
        self.http = None
        self._refresh_dns()
        self._refresh_http()
