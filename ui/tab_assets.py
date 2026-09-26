# -*- coding: utf-8 -*-
"""资产发现页：ARP/ping 扫描局域网，识别 IP / MAC / 厂商 / 主机名 / 开放端口。"""

from __future__ import annotations

import csv
import threading

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout,
                             QLineEdit, QMessageBox, QProgressBar,
                             QPushButton, QSplitter, QVBoxLayout, QWidget)

from core import assets as A
from core import hostinfo as HI
from core.logging_bus import log
from core.ports import parse_ports
from ui.widgets import Card, find_row, label, make_table, set_row
from theme import C_MINT, C_TEXT_DIM, C_YELLOW

HEADERS = ["IP 地址", "MAC", "厂商", "主机名", "开放端口", "状态", "操作系统", "来源", "最后在线"]

PROBE_CHOICES = {
    "不探测": "",
    "常用 (Top 30)": "常用 (Top 30)",
    "Web 服务": "Web 服务",
    "监控/摄像头": "监控/摄像头",
    "Windows 常见": "Windows 常见",
}


class AssetWorker(QThread):
    found = pyqtSignal(object)
    progress = pyqtSignal(int, int, str)
    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, hosts, iface, opts: dict, cancel: threading.Event, parent=None):
        super().__init__(parent)
        self.hosts = hosts
        self.iface = iface
        self.opts = opts
        self.cancel = cancel

    def run(self):
        try:
            res = A.discover(
                self.hosts, self.iface,
                use_arp=self.opts["arp"],
                use_ping=self.opts["ping"],
                resolve_names=self.opts["names"],
                lookup_vendor=self.opts["vendor"],
                probe_ports=self.opts["ports"],
                use_arp_cache=self.opts["cache"],
                use_mdns=self.opts["mdns"],
                arp_timeout=self.opts["arp_timeout"],
                ping_timeout_ms=self.opts["ping_timeout"],
                cancel=self.cancel,
                on_asset=lambda a: self.found.emit(a),
                progress=lambda d, t, m: self.progress.emit(d, t, m),
            )
            self.done.emit(res)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class AssetsTab(QWidget):
    send_to_ports = pyqtSignal(list)
    send_to_arp = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: AssetWorker | None = None
        self.cancel = threading.Event()
        self.assets: dict[str, A.Asset] = {}
        self._build()

    # ---------------- 界面 ----------------

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)

        split = QSplitter(Qt.Vertical)

        # ---- 控制区 ----
        top = QWidget()
        tl = QHBoxLayout(top)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.setSpacing(8)

        card = Card("🎯 扫描目标")
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("网卡", "Dim"))
        self.cmb_iface = QComboBox()
        self.cmb_iface.setMinimumWidth(240)
        self.cmb_iface.currentIndexChanged.connect(self._on_iface_changed)
        r1.addWidget(self.cmb_iface)
        btn_reload_if = QPushButton("刷新网卡")
        btn_reload_if.setObjectName("Ghost")
        btn_reload_if.clicked.connect(self.reload_ifaces)
        r1.addWidget(btn_reload_if)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("目标", "Dim"))
        self.ed_target = QLineEdit()
        self.ed_target.setPlaceholderText("留空=当前网段；也支持 192.168.1.0/24、192.168.1.10-50、多段用逗号分隔")
        r2.addWidget(self.ed_target, 1)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(10)
        self.chk_arp = QCheckBox("ARP 扫描（准，需管理员）")
        self.chk_arp.setChecked(True)
        self.chk_ping = QCheckBox("Ping 扫描")
        self.chk_ping.setChecked(True)
        self.chk_cache = QCheckBox("合并本机 ARP 缓存")
        self.chk_cache.setChecked(True)
        r3.addWidget(self.chk_arp)
        r3.addWidget(self.chk_ping)
        r3.addWidget(self.chk_cache)
        r3.addStretch(1)
        card.add(r3)

        r4 = QHBoxLayout()
        r4.setSpacing(10)
        self.chk_names = QCheckBox("解析主机名 / NetBIOS")
        self.chk_names.setChecked(True)
        self.chk_vendor = QCheckBox("识别厂商")
        self.chk_vendor.setChecked(True)
        self.chk_mdns = QCheckBox("mDNS 探测（慢 3 秒）")
        r4.addWidget(self.chk_names)
        r4.addWidget(self.chk_vendor)
        r4.addWidget(self.chk_mdns)
        r4.addStretch(1)
        r4.addWidget(label("端口探测", "Dim"))
        self.cmb_probe = QComboBox()
        self.cmb_probe.addItems(list(PROBE_CHOICES))
        r4.addWidget(self.cmb_probe)
        card.add(r4)

        r5 = QHBoxLayout()
        r5.setSpacing(8)
        self.btn_start = QPushButton("▶ 开始扫描")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        r5.addWidget(self.btn_start)
        r5.addWidget(self.btn_stop)
        r5.addSpacing(10)
        self.btn_ports = QPushButton("→ 选中项送入端口扫描")
        self.btn_ports.setObjectName("Ghost")
        self.btn_ports.clicked.connect(self._send_ports)
        self.btn_arp = QPushButton("→ 选中项送入 ARP 牵引")
        self.btn_arp.setObjectName("Ghost")
        self.btn_arp.clicked.connect(self._send_arp)
        r5.addWidget(self.btn_ports)
        r5.addWidget(self.btn_arp)
        r5.addStretch(1)
        self.btn_export = QPushButton("导出 CSV")
        self.btn_export.setObjectName("Ghost")
        self.btn_export.clicked.connect(self.export_csv)
        r5.addWidget(self.btn_export)
        card.add(r5)

        self.pbar = QProgressBar()
        self.pbar.setRange(0, 100)
        self.pbar.setValue(0)
        card.add(self.pbar)
        self.lbl_stat = label("就绪", "Dim")
        card.add(self.lbl_stat)

        tl.addWidget(card, 1)
        split.addWidget(top)

        # ---- 结果表 ----
        res = QWidget()
        rl = QVBoxLayout(res)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)
        bar = QHBoxLayout()
        bar.addWidget(label("扫描结果", "CardT"))
        bar.addStretch(1)
        self.lbl_count = label("0 台设备", "Dim")
        bar.addWidget(self.lbl_count)
        btn_clear = QPushButton("清空结果")
        btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(self.clear_results)
        bar.addWidget(btn_clear)
        rl.addLayout(bar)

        self.table = make_table(HEADERS, stretch_col=None)
        self.table.setColumnWidth(0, 130)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 190)
        self.table.setColumnWidth(3, 180)
        self.table.setColumnWidth(4, 130)
        self.table.setColumnWidth(5, 60)
        self.table.setColumnWidth(6, 110)
        self.table.setColumnWidth(7, 80)
        self.table.doubleClicked.connect(lambda *_: self._send_ports())
        rl.addWidget(self.table, 1)
        split.addWidget(res)
        split.setSizes([330, 420])
        outer.addWidget(split)

        self.reload_ifaces()

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
        self._on_iface_changed()

    def current_iface(self):
        return self.cmb_iface.currentData()

    def _on_iface_changed(self, *_):
        i = self.current_iface()
        if i is not None:
            self.ed_target.setPlaceholderText(f"留空 = {i.cidr}")

    # ---------------- 扫描 ----------------

    def start_scan(self):
        if self.worker is not None and self.worker.isRunning():
            return
        iface = self.current_iface()
        text = self.ed_target.text().strip()
        if not text:
            if iface is None:
                QMessageBox.warning(self, "缺少目标", "请先选择网卡或手动填写目标网段")
                return
            text = iface.cidr
        hosts = HI.expand_targets(text)
        if not hosts:
            QMessageBox.warning(self, "目标无效", f"无法解析目标：{text}")
            return
        if len(hosts) > HI.MAX_HOSTS:
            QMessageBox.warning(self, "目标过大", f"目标超过 {HI.MAX_HOSTS} 个，已截断")
            hosts = hosts[:HI.MAX_HOSTS]

        probe = PROBE_CHOICES.get(self.cmb_probe.currentText(), "")
        opts = {
            "arp": self.chk_arp.isChecked(),
            "ping": self.chk_ping.isChecked(),
            "names": self.chk_names.isChecked(),
            "vendor": self.chk_vendor.isChecked(),
            "mdns": self.chk_mdns.isChecked(),
            "cache": self.chk_cache.isChecked(),
            "ports": parse_ports(probe) if probe else None,
            "arp_timeout": 2.0,
            "ping_timeout": 1200,
        }
        if not opts["arp"] and not opts["ping"] and not opts["cache"]:
            QMessageBox.warning(self, "没有选择探测方式", "至少勾选 ARP 扫描或 Ping 扫描")
            return

        self.assets.clear()
        self.table.setRowCount(0)
        self.cancel = threading.Event()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pbar.setValue(0)
        log(f"开始扫描 {len(hosts)} 个目标（{text}）", "info", "assets")
        self.lbl_stat.setText(f"扫描中… 共 {len(hosts)} 个目标")

        self.worker = AssetWorker(hosts, iface, opts, self.cancel, self)
        self.worker.found.connect(self.on_found)
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    def stop_scan(self):
        if self.worker is not None and self.worker.isRunning():
            self.cancel.set()
            self.lbl_stat.setText("正在停止…")
            log("已请求停止扫描", "warn", "assets")

    def on_found(self, asset: A.Asset):
        self.assets[asset.ip] = asset
        self._upsert_row(asset)
        self.lbl_count.setText(f"{len(self.assets)} 台设备")

    def _upsert_row(self, a: A.Asset):
        table = self.table
        table.setSortingEnabled(False)
        row = find_row(table, a.ip, 0)
        if row < 0:
            row = table.rowCount()
            table.insertRow(row)
        colors = {}
        if not a.online:
            colors[5] = C_TEXT_DIM
        elif a.mac:
            colors[5] = C_MINT
        else:
            colors[5] = C_YELLOW
        set_row(table, row, a.row(), colors)
        table.setSortingEnabled(True)

    def on_progress(self, done: int, total: int, msg: str):
        if total:
            self.pbar.setValue(min(100, int(done * 100 / total)))
        self.lbl_stat.setText(f"{msg}   ({done}/{total})")

    def on_done(self, result: list):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.pbar.setValue(100)
        n = len(result)
        self.lbl_stat.setText(f"完成，共 {n} 条记录")
        log(f"扫描完成，共 {n} 条记录", "success", "assets")

    def on_failed(self, msg: str):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_stat.setText(f"失败：{msg}")
        log(f"扫描失败：{msg}", "error", "assets")
        QMessageBox.warning(self, "扫描失败", msg)

    def clear_results(self):
        self.assets.clear()
        self.table.setRowCount(0)
        self.lbl_count.setText("0 台设备")
        self.pbar.setValue(0)

    # ---------------- 导出 / 联动 ----------------

    def export_csv(self):
        if not self.assets:
            QMessageBox.information(self, "没有数据", "先扫描出结果再导出")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出资产清单",
                                              "assets.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(HEADERS)
                for a in sorted(self.assets.values(),
                                key=lambda x: tuple(int(p) for p in x.ip.split("."))):
                    w.writerow(a.row())
            log(f"已导出 {len(self.assets)} 条资产到 {path}", "success", "assets")
            QMessageBox.information(self, "导出成功", f"已导出到：\n{path}")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))

    def _selected_ips(self) -> list[str]:
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()})
        if not rows:
            rows = list(range(self.table.rowCount()))
        out = []
        for r in rows:
            it = self.table.item(r, 0)
            if it is not None:
                out.append(it.text())
        return out

    def _send_ports(self):
        ips = self._selected_ips()
        if ips:
            self.send_to_ports.emit(ips)

    def _send_arp(self):
        ips = self._selected_ips()
        if ips:
            self.send_to_arp.emit(ips)

    def select_ips(self, ips: list[str]):
        """供 ARP 页反向选中用。"""
        self.table.clearSelection()
        for ip in ips:
            r = find_row(self.table, ip, 0)
            if r >= 0:
                self.table.selectRow(r)
