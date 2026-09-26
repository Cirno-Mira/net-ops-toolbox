# -*- coding: utf-8 -*-
"""端口扫描页：TCP connect 扫描 + banner 抓取 + 服务识别。"""

from __future__ import annotations

import csv
import threading

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout,
                             QLineEdit, QMessageBox, QProgressBar,
                             QPushButton, QSpinBox, QSplitter, QVBoxLayout, QWidget)

from core import hostinfo as HI
from core import ports as P
from core.logging_bus import log
from ui.widgets import Card, label, make_table, set_row
from theme import C_MINT

HEADERS = ["主机", "端口", "状态", "服务", "延迟", "Banner"]


class PortWorker(QThread):
    result = pyqtSignal(object)
    progress = pyqtSignal(int, int, str)
    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, targets, ports, timeout, workers, banners, cancel, parent=None):
        super().__init__(parent)
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.banners = banners
        self.cancel = cancel

    def run(self):
        try:
            res = P.scan_hosts(
                self.targets, self.ports, timeout=self.timeout,
                workers=self.workers, host_workers=6, cancel=self.cancel,
                banners=self.banners,
                progress=lambda d, t, m: self.progress.emit(d, t, m),
                on_result=lambda r: self.result.emit(r),
            )
            self.done.emit(res)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class PortsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: PortWorker | None = None
        self.cancel = threading.Event()
        self.results: list[P.PortResult] = []
        self._last_port_count = 0
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)
        split = QSplitter(Qt.Vertical)

        # ---- 控制区 ----
        top = QWidget()
        tl = QHBoxLayout(top)
        tl.setContentsMargins(0, 0, 0, 0)
        card = Card("🔎 扫描目标与端口")

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("目标", "Dim"))
        self.ed_targets = QLineEdit()
        self.ed_targets.setPlaceholderText("支持 192.168.1.10、192.168.1.0/24、192.168.1.10-50，逗号或空格分隔")
        r1.addWidget(self.ed_targets, 1)
        btn_from_assets = QPushButton("用当前网段")
        btn_from_assets.setObjectName("Ghost")
        btn_from_assets.clicked.connect(self._fill_subnet)
        r1.addWidget(btn_from_assets)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("端口", "Dim"))
        self.cmb_preset = QComboBox()
        self.cmb_preset.addItems(list(P.PRESETS))
        self.cmb_preset.setCurrentText("常用 (Top 30)")
        self.cmb_preset.currentTextChanged.connect(self._on_preset)
        r2.addWidget(self.cmb_preset)
        self.ed_ports = QLineEdit()
        self.ed_ports.setPlaceholderText("自定义：22,80,8000-8100")
        r2.addWidget(self.ed_ports, 1)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(8)
        r3.addWidget(label("超时(秒)", "Dim"))
        self.sp_timeout = QSpinBox()
        self.sp_timeout.setRange(1, 30)
        self.sp_timeout.setValue(1)
        r3.addWidget(self.sp_timeout)
        r3.addWidget(label("并发", "Dim"))
        self.sp_workers = QSpinBox()
        self.sp_workers.setRange(10, 1000)
        self.sp_workers.setValue(200)
        self.sp_workers.setSingleStep(50)
        r3.addWidget(self.sp_workers)
        self.chk_banner = QCheckBox("抓取 Banner")
        self.chk_banner.setChecked(True)
        r3.addWidget(self.chk_banner)
        r3.addStretch(1)
        self.btn_start = QPushButton("▶ 开始扫描")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        r3.addWidget(self.btn_start)
        r3.addWidget(self.btn_stop)
        self.btn_export = QPushButton("导出 CSV")
        self.btn_export.setObjectName("Ghost")
        self.btn_export.clicked.connect(self.export_csv)
        r3.addWidget(self.btn_export)
        card.add(r3)

        self.pbar = QProgressBar()
        card.add(self.pbar)
        self.lbl_stat = label("就绪", "Dim")
        card.add(self.lbl_stat)
        tl.addWidget(card, 1)
        split.addWidget(top)

        # ---- 结果 ----
        res = QWidget()
        rl = QVBoxLayout(res)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)
        bar = QHBoxLayout()
        bar.addWidget(label("开放端口", "CardT"))
        bar.addStretch(1)
        self.lbl_count = label("0 个", "Dim")
        bar.addWidget(self.lbl_count)
        btn_clear = QPushButton("清空")
        btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(self.clear_results)
        bar.addWidget(btn_clear)
        rl.addLayout(bar)

        self.table = make_table(HEADERS, stretch_col=5)
        self.table.setColumnWidth(0, 140)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 70)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(4, 80)
        rl.addWidget(self.table, 1)
        split.addWidget(res)
        split.setSizes([300, 450])
        outer.addWidget(split)

    # ---------------- 逻辑 ----------------

    def _fill_subnet(self):
        i = HI.primary_iface()
        if i:
            self.ed_targets.setText(i.cidr)

    def _on_preset(self, name: str):
        spec = P.PRESETS.get(name)
        if isinstance(spec, tuple):
            self.ed_ports.setText(f"{spec[0]}-{spec[1]}")
        else:
            self.ed_ports.setText(",".join(str(p) for p in spec[:20]) +
                                  ("…" if spec and len(spec) > 20 else ""))

    def resolved_ports(self) -> list[int]:
        custom = self.ed_ports.text().strip()
        if custom and not custom.endswith("…"):
            got = P.parse_ports(custom)
            if got:
                return got
        return P.parse_ports(self.cmb_preset.currentText())

    def set_targets(self, ips: list[str]):
        self.ed_targets.setText(",".join(ips))

    def start_scan(self):
        if self.worker is not None and self.worker.isRunning():
            return
        text = self.ed_targets.text().strip()
        if not text:
            QMessageBox.warning(self, "缺少目标", "请填写目标 IP / 网段")
            return
        targets = HI.expand_targets(text)
        if not targets:
            QMessageBox.warning(self, "目标无效", f"无法解析：{text}")
            return
        ports = self.resolved_ports()
        if not ports:
            QMessageBox.warning(self, "端口为空", "请选择或填写要扫描的端口")
            return
        if len(targets) * len(ports) > 400000:
            if QMessageBox.question(
                    self, "任务很大",
                    f"将扫描 {len(targets)} 台主机 × {len(ports)} 个端口，"
                    f"可能耗时很久，确定继续？") != QMessageBox.Yes:
                return

        self.results.clear()
        self.table.setRowCount(0)
        self._last_port_count = len(ports)
        self.cancel = threading.Event()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pbar.setValue(0)
        log(f"开始端口扫描：{len(targets)} 台主机 × {len(ports)} 个端口", "info", "ports")

        self.worker = PortWorker(targets, ports, self.sp_timeout.value(),
                                 self.sp_workers.value(), self.chk_banner.isChecked(),
                                 self.cancel, self)
        self.worker.result.connect(self.on_result)
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    def stop_scan(self):
        if self.worker is not None and self.worker.isRunning():
            self.cancel.set()
            self.lbl_stat.setText("正在停止…")

    def on_result(self, r: P.PortResult):
        self.results.append(r)
        table = self.table
        table.setSortingEnabled(False)
        row = table.rowCount()
        table.insertRow(row)
        set_row(table, row, r.row(), {2: C_MINT})
        table.setSortingEnabled(True)
        self.lbl_count.setText(f"{len(self.results)} 个")

    def on_progress(self, done: int, total: int, msg: str):
        if total:
            self.pbar.setValue(min(100, int(done * 100 / total)))
        self.lbl_stat.setText(f"已扫 {done}/{total} 台  ·  发现 {len(self.results)} 个开放端口")

    def on_done(self, res: list):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.pbar.setValue(100)
        n_hosts = len(set(r.host for r in res)) or len(HI.expand_targets(self.ed_targets.text()))
        summary = P.summarize(res, self._last_port_count, n_hosts)
        self.lbl_stat.setText(f"完成：{summary}")
        log(f"端口扫描完成：{summary}", "success" if "⚠" not in summary else "warn", "ports")

    def on_failed(self, msg: str):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        log(f"端口扫描失败：{msg}", "error", "ports")
        QMessageBox.warning(self, "扫描失败", msg)

    def clear_results(self):
        self.results.clear()
        self.table.setRowCount(0)
        self.lbl_count.setText("0 个")

    def export_csv(self):
        if not self.results:
            QMessageBox.information(self, "没有数据", "先扫描再导出")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出端口扫描结果",
                                              "ports.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(HEADERS)
                for r in self.results:
                    w.writerow(r.row())
            QMessageBox.information(self, "导出成功", f"已导出到：\n{path}")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))
