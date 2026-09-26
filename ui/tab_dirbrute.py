# -*- coding: utf-8 -*-
"""目录爆破页：内置/自定义字典 + 并发探测 + 软 404 过滤，双击结果用浏览器打开。"""

from __future__ import annotations

import csv
import os
import threading
import webbrowser

from PyQt5.QtCore import Qt, QThread, QUrl, pyqtSignal
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (QButtonGroup, QCheckBox, QComboBox, QDoubleSpinBox,
                             QFileDialog, QHBoxLayout, QLineEdit, QMessageBox,
                             QPlainTextEdit, QProgressBar, QPushButton, QRadioButton,
                             QSpinBox, QSplitter, QVBoxLayout, QWidget)

from core import dirbrute as D
from core.logging_bus import log
from ui.widgets import Card, label, make_table, safe_slot, set_row
from theme import C_BLUE, C_MINT, C_RED, C_YELLOW

HEADERS = ["状态码", "长度", "路径", "Content-Type", "跳转", "标题"]
CSV_HEADERS = ["状态码", "长度", "URL", "Content-Type", "跳转", "标题"]

METHODS = ["GET", "HEAD", "POST"]

# 后缀快捷勾选（默认勾上的就是后端 EXTENSIONS 里那几个）
EXT_QUICK = [".php", ".html", ".htm", ".txt", ".bak", ".zip", ".rar", ".tar.gz",
             ".js", ".json", ".asp", ".aspx", ".jsp", ".do", ".action", ".old",
             ".swp", ".sql"]
EXT_DEFAULT = [e for e in D.EXTENSIONS if e]

MAX_ROWS = 5000          # 结果表最多显示这么多行，再多只留在内存里


def status_color(status: int) -> str:
    """状态码配色：200 绿、403 黄、3xx 蓝、其余红。"""
    if status == 200:
        return C_MINT
    if status == 403:
        return C_YELLOW
    if 300 <= status < 400:
        return C_BLUE
    return C_RED


class DirBruteWorker(QThread):
    found = pyqtSignal(object)
    progress = pyqtSignal(int, int)
    note = pyqtSignal(str)
    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, target, paths, exts, opts: dict, cancel: threading.Event,
                 parent=None):
        super().__init__(parent)
        self.target = target
        self.paths = paths
        self.exts = exts
        self.opts = opts
        self.cancel = cancel

    def run(self):
        try:
            # 软 404 基线先探一次，既能把状态显示到界面上，也省得 scan() 再探一遍
            baseline = None
            if self.opts["soft404"]:
                baseline = D.soft404_baseline(
                    self.target, timeout=self.opts["timeout"],
                    method=self.opts["method"],
                    follow_redirect=self.opts["follow"])
                if baseline:
                    self.note.emit(f"软 404 基线：状态 {baseline[0]}，"
                                   f"正文 {baseline[1]} 字节")
                else:
                    self.note.emit("软 404 基线探测失败，本次不做过滤")

            res = D.scan(
                self.target, self.paths, self.exts,
                workers=self.opts["workers"], timeout=self.opts["timeout"],
                method=self.opts["method"], follow_redirect=self.opts["follow"],
                cancel=self.cancel, filter_soft404=self.opts["soft404"],
                baseline=baseline,
                progress=lambda d, t: self.progress.emit(d, t),
                on_result=lambda r: self.found.emit(r),
            )
            self.done.emit(res)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class DirBruteTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: DirBruteWorker | None = None
        self.cancel = threading.Event()
        self.results: list[D.DirResult] = []
        self._ext_checks: dict[str, QCheckBox] = {}
        self._file_cache = None
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
        card = Card("🗂 目录爆破")

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("目标", "Dim"))
        self.ed_target = QLineEdit()
        self.ed_target.setPlaceholderText("http://127.0.0.1:8080（不写协议会自动补 http://）")
        self.ed_target.textChanged.connect(self.refresh_total)
        r1.addWidget(self.ed_target, 1)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(8)
        r2.addWidget(label("并发", "Dim"))
        self.sp_workers = QSpinBox()
        self.sp_workers.setRange(1, 500)
        self.sp_workers.setValue(30)
        self.sp_workers.setSingleStep(10)
        r2.addWidget(self.sp_workers)
        r2.addWidget(label("超时(秒)", "Dim"))
        self.sp_timeout = QDoubleSpinBox()
        self.sp_timeout.setRange(0.5, 60.0)
        self.sp_timeout.setSingleStep(0.5)
        self.sp_timeout.setDecimals(1)
        self.sp_timeout.setValue(5.0)
        r2.addWidget(self.sp_timeout)
        r2.addWidget(label("方法", "Dim"))
        self.cmb_method = QComboBox()
        self.cmb_method.addItems(METHODS)
        r2.addWidget(self.cmb_method)
        self.chk_follow = QCheckBox("跟随跳转")
        r2.addWidget(self.chk_follow)
        r2.addStretch(1)
        card.add(r2)

        # ---- 字典来源 ----
        r3 = QHBoxLayout()
        r3.setSpacing(8)
        r3.addWidget(label("字典", "Dim"))
        self.rb_builtin = QRadioButton(f"内置字典（{len(D.DEFAULT_PATHS)} 条）")
        self.rb_builtin.setChecked(True)
        self.rb_file = QRadioButton("自定义文件")
        self.rb_text = QRadioButton("自定义文本框")
        self.grp_dict = QButtonGroup(self)
        for rb in (self.rb_builtin, self.rb_file, self.rb_text):
            self.grp_dict.addButton(rb)
            rb.toggled.connect(self._on_dict_mode)
            r3.addWidget(rb)
        r3.addStretch(1)
        card.add(r3)

        r4 = QHBoxLayout()
        r4.setSpacing(6)
        r4.addWidget(label("文件", "Dim"))
        self.ed_dict_file = QLineEdit()
        self.ed_dict_file.setPlaceholderText("字典文件路径（每行一条，# 开头是注释）")
        self.ed_dict_file.textChanged.connect(self.refresh_total)
        r4.addWidget(self.ed_dict_file, 1)
        self.btn_browse = QPushButton("浏览…")
        self.btn_browse.setObjectName("Ghost")
        self.btn_browse.clicked.connect(self.browse_dict)
        r4.addWidget(self.btn_browse)
        card.add(r4)

        self.ed_dict_text = QPlainTextEdit()
        self.ed_dict_text.setPlaceholderText("每行一条，例如：\nadmin\nflag.php\n.git/HEAD")
        self.ed_dict_text.setMaximumHeight(76)
        self.ed_dict_text.textChanged.connect(self.refresh_total)
        card.add(self.ed_dict_text)

        # ---- 后缀 ----
        r5 = QHBoxLayout()
        r5.setSpacing(10)
        r5.addWidget(label("后缀", "Dim"))
        r5.addWidget(label("（无后缀始终会试）", "Dim"))
        r5.addStretch(1)
        card.add(r5)

        for chunk in (EXT_QUICK[:9], EXT_QUICK[9:]):
            row = QHBoxLayout()
            row.setSpacing(10)
            for ext in chunk:
                chk = QCheckBox(ext)
                chk.setChecked(ext in EXT_DEFAULT)
                chk.toggled.connect(self.refresh_total)
                self._ext_checks[ext] = chk
                row.addWidget(chk)
            row.addStretch(1)
            card.add(row)

        r6 = QHBoxLayout()
        r6.setSpacing(6)
        r6.addWidget(label("其他后缀", "Dim"))
        self.ed_ext_more = QLineEdit()
        self.ed_ext_more.setPlaceholderText("补充后缀，逗号分隔，例如 .jsp,.xml")
        self.ed_ext_more.textChanged.connect(self.refresh_total)
        r6.addWidget(self.ed_ext_more, 1)
        card.add(r6)

        # ---- 过滤 + 按钮 ----
        r7 = QHBoxLayout()
        r7.setSpacing(10)
        self.chk_soft404 = QCheckBox("软 404 过滤")
        self.chk_soft404.setChecked(True)
        self.chk_soft404.setToolTip("先访问一个随机不存在的路径取基线，状态码和长度都一样的响应直接丢弃")
        r7.addWidget(self.chk_soft404)
        self.lbl_soft = label("软 404 过滤：开启（未探测）", "Dim")
        r7.addWidget(self.lbl_soft)
        r7.addStretch(1)
        card.add(r7)

        r8 = QHBoxLayout()
        r8.setSpacing(8)
        self.btn_start = QPushButton("▶ 开始爆破")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_export = QPushButton("导出 CSV")
        self.btn_export.setObjectName("Ghost")
        self.btn_export.clicked.connect(self.export_csv)
        r8.addWidget(self.btn_start)
        r8.addWidget(self.btn_stop)
        r8.addWidget(self.btn_export)
        r8.addStretch(1)
        self.lbl_total = label("共 0 个请求", "Dim")
        r8.addWidget(self.lbl_total)
        card.add(r8)

        self.pbar = QProgressBar()
        self.pbar.setRange(0, 100)
        self.pbar.setValue(0)
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
        bar.addWidget(label("有效路径", "CardT"))
        bar.addSpacing(8)
        bar.addWidget(label("双击一行可用系统浏览器打开", "Dim"))
        bar.addStretch(1)
        self.lbl_count = label("0 条", "Dim")
        bar.addWidget(self.lbl_count)
        btn_clear = QPushButton("清空")
        btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(self.clear_results)
        bar.addWidget(btn_clear)
        rl.addLayout(bar)

        self.table = make_table(HEADERS, stretch_col=5)
        self.table.setColumnWidth(0, 70)
        self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 340)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(4, 260)
        self.table.doubleClicked.connect(self.open_selected)
        rl.addWidget(self.table, 1)
        split.addWidget(res)
        split.setSizes([380, 420])
        outer.addWidget(split)

        self._on_dict_mode()
        self.refresh_total()

    # ---------------- 字典 / 后缀 ----------------

    @safe_slot
    def _on_dict_mode(self):
        mode = self.dict_mode()
        self.ed_dict_file.setEnabled(mode == "file")
        self.btn_browse.setEnabled(mode == "file")
        self.ed_dict_text.setEnabled(mode == "text")
        self.refresh_total()

    def dict_mode(self) -> str:
        if self.rb_file.isChecked():
            return "file"
        if self.rb_text.isChecked():
            return "text"
        return "builtin"

    def _read_dict_file(self, path: str) -> list[str]:
        """读字典文件（按 路径+修改时间 缓存，避免每敲一个字就重读一遍）。"""
        try:
            st = os.stat(path)
        except OSError as exc:
            log(f"读取字典文件失败：{exc}", "warn", "dirbrute")
            return []
        key = (path, st.st_mtime, st.st_size)
        if self._file_cache is not None and self._file_cache[0] == key:
            return self._file_cache[1]
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                paths = D.parse_paths(fh.read())
        except OSError as exc:
            log(f"读取字典文件失败：{exc}", "warn", "dirbrute")
            return []
        self._file_cache = (key, paths)
        return paths

    def resolved_paths(self) -> list[str]:
        mode = self.dict_mode()
        if mode == "builtin":
            return list(D.DEFAULT_PATHS)
        if mode == "file":
            path = self.ed_dict_file.text().strip()
            return self._read_dict_file(path) if path else []
        return D.parse_paths(self.ed_dict_text.toPlainText())

    def resolved_extensions(self) -> list[str]:
        exts = [""]                      # 无后缀始终会试
        for ext, chk in self._ext_checks.items():
            if chk.isChecked():
                exts.append(ext)
        exts += D.parse_extensions(self.ed_ext_more.text())
        out: list[str] = []
        for e in exts:
            if e not in out:
                out.append(e)
        return out

    @safe_slot
    def browse_dict(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择字典文件", "",
                                              "文本文件 (*.txt);;所有文件 (*)")
        if path:
            self.ed_dict_file.setText(path)

    @safe_slot
    def refresh_total(self):
        """刷新「共 N 个请求」，让用户开跑之前心里有数。"""
        paths = self.resolved_paths()
        exts = self.resolved_extensions()
        if len(paths) > 30000:
            self.lbl_total.setText(f"共 {len(paths)} 条字典（太多，不估算请求数）")
            return
        n = len(D.build_targets("http://x", paths, exts))
        self.lbl_total.setText(f"共 {n} 个请求（{len(paths)} 条 × {len(exts)} 种后缀）")

    # ---------------- 扫描 ----------------

    @safe_slot
    def start_scan(self):
        if self.worker is not None and self.worker.isRunning():
            return
        target = self.ed_target.text().strip()
        if not target:
            QMessageBox.warning(self, "缺少目标", "请填写目标 URL，例如 http://127.0.0.1:8080")
            return
        target = D.normalize_base(target)
        self.ed_target.setText(target)

        paths = self.resolved_paths()
        if not paths:
            QMessageBox.warning(self, "字典为空",
                                "当前字典来源没有任何条目，请换一种来源或补充内容")
            return
        exts = self.resolved_extensions()
        total = len(D.build_targets(target, paths, exts))
        if total > 20000:
            if QMessageBox.question(
                    self, "任务很大",
                    f"将发出 {total} 个请求，可能耗时很久，确定继续？") != QMessageBox.Yes:
                return

        opts = {
            "workers": self.sp_workers.value(),
            "timeout": self.sp_timeout.value(),
            "method": self.cmb_method.currentText(),
            "follow": self.chk_follow.isChecked(),
            "soft404": self.chk_soft404.isChecked(),
        }

        self.results.clear()
        self.table.setRowCount(0)
        self.lbl_count.setText("0 条")
        self.cancel = threading.Event()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pbar.setValue(0)
        self.lbl_soft.setText("软 404 过滤：探测基线中…" if opts["soft404"]
                              else "软 404 过滤：已关闭")
        self.lbl_stat.setText(f"爆破中… 最多 {total} 个请求")
        log(f"开始目录爆破：{target}，{len(paths)} 条字典 × {len(exts)} 种后缀 "
            f"= {total} 个请求", "info", "dirbrute")

        self.worker = DirBruteWorker(target, paths, exts, opts, self.cancel, self)
        self.worker.found.connect(self.on_found)
        self.worker.progress.connect(self.on_progress)
        self.worker.note.connect(self.on_note)
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    @safe_slot
    def stop_scan(self):
        if self.worker is not None and self.worker.isRunning():
            self.cancel.set()
            self.lbl_stat.setText("正在停止…")
            log("已请求停止目录爆破", "warn", "dirbrute")

    @safe_slot
    def on_found(self, r: D.DirResult):
        self.results.append(r)
        self.lbl_count.setText(f"{len(self.results)} 条")
        if self.table.rowCount() >= MAX_ROWS:
            return                       # 界面不再加行，数据仍在 self.results 里
        table = self.table
        color = status_color(r.status)
        table.setSortingEnabled(False)
        row = table.rowCount()
        table.insertRow(row)
        set_row(table, row, r.row(), {0: color, 2: color})
        item = table.item(row, 2)
        if item is not None:
            item.setData(Qt.UserRole, r.url)      # 双击时用完整 URL
            item.setToolTip(r.url)
        table.setSortingEnabled(True)

    @safe_slot
    def on_progress(self, done: int, total: int):
        if total:
            self.pbar.setValue(min(100, int(done * 100 / total)))
        self.lbl_stat.setText(f"已请求 {done}/{total}  ·  发现 {len(self.results)} 条有效路径")

    @safe_slot
    def on_note(self, msg: str):
        self.lbl_soft.setText(f"软 404 过滤：{msg}")
        if "失败" in msg:
            log(msg, "warn", "dirbrute")

    @safe_slot
    def on_done(self, res: list):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.pbar.setValue(100)
        stopped = self.cancel.is_set()
        summary = D.summarize(res)
        self.lbl_stat.setText(("已停止，" if stopped else "完成：") + summary)
        log(f"目录爆破{'已停止' if stopped else '完成'}：{summary}",
            "warn" if stopped else "success", "dirbrute")

    @safe_slot
    def on_failed(self, msg: str):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_stat.setText(f"失败：{msg}")
        log(f"目录爆破失败：{msg}", "error", "dirbrute")
        QMessageBox.warning(self, "爆破失败", msg)

    # ---------------- 退出 ----------------

    def shutdown(self):
        """关窗口时调用：置位取消并等线程收尾，避免 QThread 还在跑就被销毁。"""
        if self.worker is not None and self.worker.isRunning():
            self.cancel.set()
            self.worker.wait(5000)
        self.worker = None

    # ---------------- 结果 ----------------

    @safe_slot
    def open_selected(self):
        """双击结果行：用系统默认浏览器打开该 URL。"""
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 2)
        if item is None:
            return
        url = item.data(Qt.UserRole) or item.text()
        if not url:
            return
        self.lbl_stat.setText(f"用浏览器打开：{url}")
        log(f"用系统浏览器打开：{url}", "info", "dirbrute")
        if not QDesktopServices.openUrl(QUrl(url)):
            webbrowser.open(url)

    @safe_slot
    def clear_results(self):
        self.results.clear()
        self.table.setRowCount(0)
        self.lbl_count.setText("0 条")
        self.pbar.setValue(0)

    @safe_slot
    def export_csv(self):
        if not self.results:
            QMessageBox.information(self, "没有数据", "先爆破出结果再导出")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出目录爆破结果",
                                              "dirbrute.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(CSV_HEADERS)
                for r in self.results:
                    w.writerow([r.status, r.length, r.url, r.content_type,
                                r.redirect, r.title])
            log(f"已导出 {len(self.results)} 条目录爆破结果到 {path}", "success", "dirbrute")
            QMessageBox.information(self, "导出成功", f"已导出到：\n{path}")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))
