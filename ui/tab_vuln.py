# -*- coding: utf-8 -*-
"""
安全体检页（漏洞快速指纹扫描）
==============================

只做**检测**，不做利用：对目标跑一组只读探针，找出「明显没设防」的服务。
结果按严重程度排序，可以导出。

弱口令检测默认关闭，需要先勾选授权确认 —— 它会真的尝试登录。
"""

from __future__ import annotations

import threading

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QGridLayout,
                             QHBoxLayout, QLineEdit, QMessageBox, QProgressBar,
                             QPushButton, QScrollArea, QSpinBox, QSplitter,
                             QVBoxLayout, QWidget)

from core import hostinfo as HI
from core import vulncheck as VC
from core.logging_bus import log
from ui.widgets import Card, hline, label, make_table, safe_slot, set_row
from theme import C_RED, C_TEXT_DIM

HEADERS = ["主机", "端口", "问题", "严重程度", "说明", "证据"]

SEV_COLOR = {
    VC.CRITICAL: "#C0392B",
    VC.HIGH: "#E8457C",
    VC.MEDIUM: "#C98A12",
    VC.LOW: "#2E86DE",
    VC.INFO: C_TEXT_DIM,
}


class VulnWorker(QThread):
    result = pyqtSignal(object)
    progress = pyqtSignal(int, int, str)
    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, hosts, checks, timeout, workers, cancel, parent=None):
        super().__init__(parent)
        self.hosts = hosts
        self.checks = checks
        self.timeout = timeout
        self.workers = workers
        self.cancel = cancel

    def run(self):
        try:
            res = VC.scan(self.hosts, self.checks, self.timeout, self.workers,
                          self.cancel,
                          on_result=lambda f: self.result.emit(f),
                          progress=lambda d, t, m: self.progress.emit(d, t, m))
            self.done.emit(res)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class VulnTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: VulnWorker | None = None
        self.cancel = threading.Event()
        self.findings: list[VC.Finding] = []
        self._build()

    # ---------------- 界面 ----------------

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(8)
        split = QSplitter(Qt.Vertical)

        top = QWidget()
        tl = QHBoxLayout(top)
        tl.setContentsMargins(0, 0, 0, 0)
        card = Card("🛡 安全体检（只检测，不利用）")

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("目标", "Dim"))
        self.ed_targets = QLineEdit()
        self.ed_targets.setPlaceholderText(
            "192.168.5.10 或 192.168.5.0/24，也会自动带入「资产发现」扫到的设备")
        r1.addWidget(self.ed_targets, 1)
        btn_subnet = QPushButton("用当前网段")
        btn_subnet.setObjectName("Ghost")
        btn_subnet.clicked.connect(self._fill_subnet)
        r1.addWidget(btn_subnet)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("检查项", "Dim"))
        self.cmb_preset = QComboBox()
        self.cmb_preset.addItems(["快速（8 项高命中率）", "全部检查"])
        r2.addWidget(self.cmb_preset)
        r2.addWidget(label("超时(秒)", "Dim"))
        self.sp_timeout = QSpinBox()
        self.sp_timeout.setRange(1, 20)
        self.sp_timeout.setValue(3)
        r2.addWidget(self.sp_timeout)
        r2.addWidget(label("并发", "Dim"))
        self.sp_workers = QSpinBox()
        self.sp_workers.setRange(1, 64)
        self.sp_workers.setValue(12)
        r2.addWidget(self.sp_workers)
        r2.addStretch(1)
        self.btn_start = QPushButton("▶ 开始体检")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_export = QPushButton("导出 CSV")
        self.btn_export.setObjectName("Ghost")
        self.btn_export.clicked.connect(self.export_csv)
        r2.addWidget(self.btn_start)
        r2.addWidget(self.btn_stop)
        r2.addWidget(self.btn_export)
        card.add(r2)

        # 检查项勾选
        self.chk_boxes: dict[str, QCheckBox] = {}
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(2)
        for i, name in enumerate(VC.CHECK_NAMES):
            cb = QCheckBox(name)
            cb.setChecked(name in VC.FAST_CHECKS)
            self.chk_boxes[name] = cb
            grid.addWidget(cb, i // 5, i % 5)
        holder = QWidget()
        holder.setLayout(grid)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setWidget(holder)
        scroll.setMaximumHeight(96)
        card.add(scroll)

        card.add(hline())
        wr = QHBoxLayout()
        self.chk_weak = QCheckBox("同时做弱口令检测")
        self.chk_weak.setToolTip(
            "会真的用常见弱口令去尝试登录（FTP/SSH/MySQL），每次尝试有间隔。\n"
            "只在你拥有或已获授权的目标上使用。需要装 paramiko / pymysql。")
        self.chk_weak.toggled.connect(self._on_weak_toggled)
        wr.addWidget(self.chk_weak)
        wr.addWidget(label("服务", "Dim"))
        self.cmb_weak_svc = QComboBox()
        self.cmb_weak_svc.addItems(["ftp", "ssh", "mysql"])
        self.cmb_weak_svc.setEnabled(False)
        wr.addWidget(self.cmb_weak_svc)
        wr.addStretch(1)
        self.lbl_weak_warn = label("", "Dim")
        wr.addWidget(self.lbl_weak_warn)
        card.add(wr)

        self.pbar = QProgressBar()
        card.add(self.pbar)
        self.lbl_stat = label("就绪", "Dim")
        card.add(self.lbl_stat)

        tl.addWidget(card, 1)
        split.addWidget(top)

        res = QWidget()
        rl = QVBoxLayout(res)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)
        bar = QHBoxLayout()
        bar.addWidget(label("体检结果", "CardT"))
        bar.addStretch(1)
        self.lbl_count = label("0 项", "Dim")
        bar.addWidget(self.lbl_count)
        btn_clear = QPushButton("清空")
        btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(self.clear_results)
        bar.addWidget(btn_clear)
        rl.addLayout(bar)

        self.table = make_table(HEADERS, stretch_col=4)
        self.table.setColumnWidth(0, 130)
        self.table.setColumnWidth(1, 60)
        self.table.setColumnWidth(2, 190)
        self.table.setColumnWidth(3, 80)
        rl.addWidget(self.table, 1)
        split.addWidget(res)
        split.setSizes([330, 420])
        outer.addWidget(split)

    # ---------------- 逻辑 ----------------

    def _on_weak_toggled(self, on: bool):
        self.cmb_weak_svc.setEnabled(on)
        self.lbl_weak_warn.setText(
            "⚠ 会真的尝试登录，仅限授权目标" if on else "")
        self.lbl_weak_warn.setStyleSheet(
            f"color:{C_RED}; font-weight:700;" if on else f"color:{C_TEXT_DIM};")

    def _fill_subnet(self):
        i = HI.primary_iface()
        if i:
            self.ed_targets.setText(i.cidr)

    def set_targets(self, ips: list[str]):
        self.ed_targets.setText(",".join(ips))

    def selected_checks(self) -> list[str]:
        if self.cmb_preset.currentIndex() == 0:
            return [n for n, cb in self.chk_boxes.items()
                    if cb.isChecked() and n in VC.FAST_CHECKS] or list(VC.FAST_CHECKS)
        return [n for n, cb in self.chk_boxes.items() if cb.isChecked()]

    @safe_slot
    def start_scan(self):
        if self.worker is not None and self.worker.isRunning():
            return
        text = self.ed_targets.text().strip()
        if not text:
            QMessageBox.warning(self, "缺少目标", "请填写目标 IP / 网段")
            return
        hosts = HI.expand_targets(text)
        if not hosts:
            QMessageBox.warning(self, "目标无效", f"无法解析：{text}")
            return
        checks = self.selected_checks()
        if not checks:
            QMessageBox.warning(self, "没有选择检查项", "至少勾选一项")
            return

        weak = self.chk_weak.isChecked()
        if weak and QMessageBox.question(
                self, "确认弱口令检测",
                "弱口令检测会用常见口令**真的尝试登录**目标服务。\n"
                "请确认你对这些目标拥有测试授权。\n\n继续吗？",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return

        self.findings.clear()
        self.table.setRowCount(0)
        self.cancel = threading.Event()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pbar.setValue(0)
        log(f"开始安全体检：{len(hosts)} 台主机 × {len(checks)} 项检查"
            + ("（含弱口令检测）" if weak else ""), "info", "vuln")

        self.worker = VulnWorker(hosts, checks, self.sp_timeout.value(),
                                 self.sp_workers.value(), self.cancel, self)
        self.worker.result.connect(self.on_result)
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(lambda r: self.on_done(r, hosts, weak))
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    @safe_slot
    def stop_scan(self):
        if self.worker is not None and self.worker.isRunning():
            self.cancel.set()
            self.lbl_stat.setText("正在停止…")

    @safe_slot
    def on_result(self, f: VC.Finding):
        self.findings.append(f)
        t = self.table
        t.setSortingEnabled(False)
        row = t.rowCount()
        t.insertRow(row)
        set_row(t, row, f.row(), {3: SEV_COLOR.get(f.severity, C_TEXT_DIM)})
        t.setSortingEnabled(True)
        self.table.sortItems(3, Qt.AscendingOrder)
        self.lbl_count.setText(f"{len(self.findings)} 项")

    @safe_slot
    def on_progress(self, done: int, total: int, msg: str):
        if total:
            self.pbar.setValue(min(100, int(done * 100 / total)))
        self.lbl_stat.setText(f"已扫 {done}/{total} 台  ·  发现 {len(self.findings)} 个问题")

    @safe_slot
    def on_done(self, res: list, hosts: list, weak: bool):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.pbar.setValue(100)
        self.lbl_stat.setText("完成：" + VC.summarize(res))
        log("安全体检完成：" + VC.summarize(res), "success", "vuln")

        if weak:
            svc = self.cmb_weak_svc.currentText()
            for h in hosts:
                if self.cancel.is_set():
                    break
                f = VC.weak_credentials(h, svc, cancel=self.cancel)
                if f:
                    self.on_result(f)
                    log(f"{h} 的 {svc} 存在弱口令！", "error", "vuln")

    @safe_slot
    def on_failed(self, msg: str):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        log(f"安全体检失败：{msg}", "error", "vuln")
        QMessageBox.warning(self, "体检失败", msg)

    @safe_slot
    def clear_results(self):
        self.findings.clear()
        self.table.setRowCount(0)
        self.lbl_count.setText("0 项")

    @safe_slot
    def export_csv(self):
        if not self.findings:
            QMessageBox.information(self, "没有数据", "先跑一次体检")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出体检结果",
                                              "vulnscan.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        import csv
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(HEADERS)
                for f in self.findings:
                    w.writerow(f.row())
            QMessageBox.information(self, "导出成功", f"已导出到：\n{path}")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))
