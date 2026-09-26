# -*- coding: utf-8 -*-
"""哈希工具箱页：识别 / 爆破 / 字典生成（内部用 QTabWidget 分三个子页）。"""

from __future__ import annotations

import os
import threading
import time

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog,
                             QHBoxLayout, QLineEdit, QMessageBox,
                             QPlainTextEdit, QProgressBar, QPushButton, QSpinBox,
                             QTabWidget, QVBoxLayout, QWidget)

from core import hashkit as HK
from core.logging_bus import log
from ui.widgets import Card, label, make_table, safe_slot, set_row
from theme import C_MINT, C_RED, C_YELLOW

IDENT_HEADERS = ["候选类型", "位数", "判断依据"]
WORD_SOURCES = ["内置弱口令", "选择字典文件", "自定义口令"]


class CrackWorker(QThread):
    """爆破工作线程：只发信号，绝不碰界面控件。"""

    progress = pyqtSignal(int, int, str)
    found = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, target, algo, source, words, path, cancel, parent=None):
        super().__init__(parent)
        self.target = target
        self.algo = algo
        self.source = source
        self.words = words
        self.path = path
        self.cancel = cancel

    def run(self):
        """
        注意：工作线程中不能使用 QTimer.singleShot —— 该线程没有事件循环，
        定时器回调永远不会执行。跨线程回主线程只能通过 pyqtSignal。
        """
        try:
            if self.source == "选择字典文件":
                words = HK.load_wordlist(self.path)
                if not words:
                    self.failed.emit(f"字典文件读不出内容：{self.path}")
                    return
            elif self.source == "内置弱口令":
                words = list(HK.DEFAULT_PASSWORDS)
            else:
                words = [w.strip() for w in (self.words or "").splitlines() if w.strip()]
                if not words:
                    self.failed.emit("自定义口令是空的，先填几行再开始")
                    return

            res = HK.crack_hash(
                self.target, words, algo=self.algo, cancel=self.cancel,
                on_progress=lambda t, total, w: self.progress.emit(t, total, w))
            self.found.emit(res)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class HashTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: CrackWorker | None = None
        self.cancel = threading.Event()
        self.gen_words: list[str] = []
        self._gen_elapsed = 0.0
        self._build()

    # ---------------- 页面骨架 ----------------

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._page_identify(), "🔍 识别")
        self.tabs.addTab(self._page_crack(), "💥 爆破")
        self.tabs.addTab(self._page_generate(), "🧩 字典生成")
        outer.addWidget(self.tabs)

    # ---------------- 1. 识别 ----------------

    def _page_identify(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(8)

        card = Card("🔍 哈希识别")
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("待识别内容", "Dim"))
        self.ed_ident = QLineEdit()
        self.ed_ident.setPlaceholderText("粘贴哈希 / Base64 / URL 编码串，回车即识别")
        self.ed_ident.returnPressed.connect(self.do_identify)
        r1.addWidget(self.ed_ident, 1)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        btn_ident = QPushButton("▶ 识别")
        btn_ident.setObjectName("Primary")
        btn_ident.clicked.connect(self.do_identify)
        r2.addWidget(btn_ident)
        btn_paste = QPushButton("粘贴剪贴板")
        btn_paste.setObjectName("Ghost")
        btn_paste.clicked.connect(self.paste_identify)
        r2.addWidget(btn_paste)
        btn_clear = QPushButton("清空")
        btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(self.clear_identify)
        r2.addWidget(btn_clear)
        r2.addStretch(1)
        card.add(r2)

        self.tbl_ident = make_table(IDENT_HEADERS, stretch_col=2)
        # 关掉排序：候选表按「可能性从高到低」排列，按字符串排序会把顺序打乱
        self.tbl_ident.setSortingEnabled(False)
        self.tbl_ident.setColumnWidth(0, 150)
        self.tbl_ident.setColumnWidth(1, 70)
        self.tbl_ident.setMinimumHeight(170)
        card.add(self.tbl_ident)

        self.lbl_ident = label("支持 MD5 / SHA 系列 / NTLM / MySQL / bcrypt / "
                               "SHA512-crypt / JWT / Base64 / URL 编码 / hex 编码", "Dim")
        self.lbl_ident.setWordWrap(True)
        card.add(self.lbl_ident)
        lay.addWidget(card, 1)

        # ---- 计算哈希 ----
        card2 = Card("🧮 计算哈希")
        r3 = QHBoxLayout()
        r3.setSpacing(6)
        r3.addWidget(label("明文", "Dim"))
        self.ed_plain = QLineEdit()
        self.ed_plain.setPlaceholderText("要计算哈希的原文，回车即计算")
        self.ed_plain.returnPressed.connect(self.do_hash)
        r3.addWidget(self.ed_plain, 1)
        r3.addWidget(label("算法", "Dim"))
        self.cmb_algo = QComboBox()
        self.cmb_algo.addItems(HK.supported_algos())
        r3.addWidget(self.cmb_algo)
        btn_hash = QPushButton("计算")
        btn_hash.setObjectName("Primary")
        btn_hash.clicked.connect(self.do_hash)
        r3.addWidget(btn_hash)
        card2.add(r3)

        r4 = QHBoxLayout()
        r4.setSpacing(6)
        r4.addWidget(label("结果", "Dim"))
        self.ed_digest = QLineEdit()
        self.ed_digest.setReadOnly(True)
        self.ed_digest.setObjectName("Mono")
        self.ed_digest.setPlaceholderText("点「计算」后在这里显示摘要")
        r4.addWidget(self.ed_digest, 1)
        btn_copy = QPushButton("复制")
        btn_copy.setObjectName("Ghost")
        btn_copy.clicked.connect(self.copy_digest)
        r4.addWidget(btn_copy)
        card2.add(r4)
        self.lbl_hash = label("ntlm 会按 Windows 规则先转 UTF-16LE 再做 MD4", "Dim")
        self.lbl_hash.setWordWrap(True)
        card2.add(self.lbl_hash)
        lay.addWidget(card2)
        return w

    @safe_slot
    def paste_identify(self):
        text = QApplication.clipboard().text().strip()
        if not text:
            self.lbl_ident.setText("剪贴板是空的")
            return
        self.ed_ident.setText(text)
        self.do_identify()

    @safe_slot
    def clear_identify(self):
        self.ed_ident.clear()
        self.tbl_ident.setRowCount(0)
        self.lbl_ident.setText("已清空")

    @safe_slot
    def do_identify(self):
        text = self.ed_ident.text().strip()
        if not text:
            self.lbl_ident.setText("先填一段内容再识别")
            return
        cands = HK.identify_hash(text)
        t = self.tbl_ident
        t.setRowCount(0)
        for i, c in enumerate(cands):
            t.insertRow(i)
            bits = c["bits"] if c["bits"] else "-"
            set_row(t, i, [c["algo"], bits, c["note"]],
                    {0: C_MINT if i == 0 else C_YELLOW})
        # ⚠ 这里不能碰 setSortingEnabled(True)：候选表是按「可能性从高到低」排的，
        # 一开排序 Qt 会按第一列字符串重排（"NTLM" 会跑到 "MD5" 前面）。
        top = cands[0]["algo"] if cands else "未知"
        self.lbl_ident.setText(f"共 {len(cands)} 个候选，最可能：{top}")
        log(f"哈希识别（{len(text)} 字符）：{HK.describe_identify(text)}", "info", "hash")

    @safe_slot
    def do_hash(self):
        plain = self.ed_plain.text()
        algo = self.cmb_algo.currentText()
        try:
            digest = HK.hash_text(algo, plain)
        except ValueError as exc:
            self.lbl_hash.setText(f"❌ {exc}")
            self.lbl_hash.setStyleSheet(f"color:{C_RED};")
            return
        self.ed_digest.setText(digest)
        self.lbl_hash.setText(f"{algo.upper()} 计算完成，共 {len(digest)} 个十六进制字符")
        self.lbl_hash.setStyleSheet(f"color:{C_MINT};")
        log(f"{algo.upper()} 计算完成：{digest}", "success", "hash")

    @safe_slot
    def copy_digest(self):
        text = self.ed_digest.text().strip()
        if not text:
            return
        QApplication.clipboard().setText(text)
        self.lbl_hash.setText("摘要已复制到剪贴板")

    # ---------------- 2. 爆破 ----------------

    def _page_crack(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(8)

        card = Card("💥 字典爆破")
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("目标哈希", "Dim"))
        self.ed_target = QLineEdit()
        self.ed_target.setPlaceholderText("粘贴 MD5 / SHA1 / SHA256 / NTLM / $1$ / $6$ 等哈希")
        r1.addWidget(self.ed_target, 1)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("字典来源", "Dim"))
        self.cmb_source = QComboBox()
        self.cmb_source.addItems(WORD_SOURCES)
        self.cmb_source.currentTextChanged.connect(self._on_source)
        r2.addWidget(self.cmb_source)
        self.ed_path = QLineEdit()
        self.ed_path.setPlaceholderText("字典文件路径（一行一个口令）")
        r2.addWidget(self.ed_path, 1)
        self.btn_browse = QPushButton("选择文件…")
        self.btn_browse.setObjectName("Ghost")
        self.btn_browse.clicked.connect(self.browse_dict)
        r2.addWidget(self.btn_browse)
        card.add(r2)

        self.txt_words = QPlainTextEdit()
        self.txt_words.setPlaceholderText("自定义口令，一行一个")
        self.txt_words.setMaximumBlockCount(20000)
        self.txt_words.setMinimumHeight(70)
        self.txt_words.setVisible(False)
        card.add(self.txt_words)

        r3 = QHBoxLayout()
        r3.setSpacing(6)
        r3.addWidget(label("算法", "Dim"))
        self.cmb_crack_algo = QComboBox()
        self.cmb_crack_algo.addItem("自动识别")
        self.cmb_crack_algo.addItems(HK.supported_algos())
        r3.addWidget(self.cmb_crack_algo)
        self.btn_start = QPushButton("▶ 开始爆破")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.start_crack)
        r3.addWidget(self.btn_start)
        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_crack)
        r3.addWidget(self.btn_stop)
        r3.addStretch(1)
        card.add(r3)

        self.pbar = QProgressBar()
        card.add(self.pbar)
        self.lbl_crack = label("就绪：内置弱口令约 %d 条，先用它试一遍最快"
                               % len(HK.DEFAULT_PASSWORDS), "Dim")
        self.lbl_crack.setWordWrap(True)
        card.add(self.lbl_crack)
        lay.addWidget(card)

        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setMaximumBlockCount(2000)
        self.txt_log.setMinimumHeight(120)
        lay.addWidget(self.txt_log, 1)
        self._on_source(self.cmb_source.currentText())
        return w

    @safe_slot
    def _on_source(self, name: str):
        is_file = name == "选择字典文件"
        is_custom = name == "自定义口令"
        self.ed_path.setVisible(is_file)
        self.btn_browse.setVisible(is_file)
        self.txt_words.setVisible(is_custom)
        if name == "内置弱口令":
            self.lbl_crack.setText(f"内置弱口令共 {len(HK.DEFAULT_PASSWORDS)} 条，"
                                   "适合先做一轮快速尝试")

    @safe_slot
    def browse_dict(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择字典文件", "",
                                              "文本文件 (*.txt *.dic *.lst);;所有文件 (*)")
        if path:
            self.ed_path.setText(path)

    @safe_slot
    def start_crack(self):
        if self.worker is not None and self.worker.isRunning():
            return
        target = self.ed_target.text().strip()
        if not target:
            QMessageBox.warning(self, "缺少目标", "请先粘贴要爆破的哈希")
            return
        source = self.cmb_source.currentText()
        path = self.ed_path.text().strip()
        if source == "选择字典文件" and not path:
            QMessageBox.warning(self, "缺少字典", "请选择字典文件")
            return
        if source == "选择字典文件" and not os.path.isfile(path):
            QMessageBox.warning(self, "字典不存在", f"找不到文件：\n{path}")
            return
        if source == "自定义口令" and not self.txt_words.toPlainText().strip():
            QMessageBox.warning(self, "缺少口令", "自定义口令是空的")
            return

        algo = self.cmb_crack_algo.currentText()
        algo = "auto" if algo == "自动识别" else algo
        self.cancel = threading.Event()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pbar.setValue(0)
        self.txt_log.clear()
        self.txt_log.appendPlainText(f"目标：{target}")
        self.txt_log.appendPlainText(f"算法：{'自动识别' if algo == 'auto' else algo.upper()}"
                                     f"　字典来源：{source}")
        self.lbl_crack.setText("正在爆破…")
        log(f"开始哈希爆破：算法 {algo}，字典来源 {source}", "info", "hash")

        self.worker = CrackWorker(target, algo, source,
                                  self.txt_words.toPlainText(), path,
                                  self.cancel, self)
        self.worker.progress.connect(self.on_progress)
        self.worker.found.connect(self.on_found)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    @safe_slot
    def stop_crack(self):
        if self.worker is not None and self.worker.isRunning():
            self.cancel.set()
            self.lbl_crack.setText("正在停止…")

    @safe_slot
    def on_progress(self, tried: int, total: int, word: str):
        if total:
            self.pbar.setValue(min(100, int(tried * 100 / total)))
        else:
            self.pbar.setValue(0)          # 生成器式字典没有总数，进度条就只晃着
        self.lbl_crack.setText(f"已试 {tried} 个" +
                               (f"/{total}" if total else "") + f"　当前候选：{word}")
        if tried % 2000 == 0:
            self.txt_log.appendPlainText(f"… 已试 {tried} 个，当前 {word}")

    @safe_slot
    def on_found(self, res: dict):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.pbar.setValue(100)
        if res.get("found"):
            self.lbl_crack.setText(
                f"✅ 命中：{res['plain']}　算法 {res['algo'].upper()}　"
                f"共试 {res['tried']} 个")
            self.lbl_crack.setStyleSheet(f"color:{C_MINT};")
            self.txt_log.appendPlainText(
                f"✅ 明文 = {res['plain']}（{res['algo'].upper()}，试了 {res['tried']} 个）")
            log(f"哈希爆破成功：{res['plain']}", "success", "hash")
        else:
            self.lbl_crack.setText(f"❌ 未命中，共试 {res.get('tried', 0)} 个候选"
                                   "（可换更大的字典或加规则）")
            self.lbl_crack.setStyleSheet(f"color:{C_RED};")
            self.txt_log.appendPlainText("❌ 字典里没有，建议换更大的字典或用「字典生成」造一批")

    @safe_slot
    def on_failed(self, msg: str):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_crack.setText(f"❌ {msg}")
        self.lbl_crack.setStyleSheet(f"color:{C_RED};")
        log(f"哈希爆破失败：{msg}", "error", "hash")
        QMessageBox.warning(self, "爆破失败", msg)

    # ---------------- 3. 字典生成 ----------------

    def _page_generate(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(8)

        card = Card("🧩 社工字典生成")
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("姓名拼音", "Dim"))
        self.ed_names = QLineEdit()
        self.ed_names.setPlaceholderText("zhangsan,lisi 或 张三,李四（逗号或空格分隔）")
        r1.addWidget(self.ed_names, 1)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("关键词", "Dim"))
        self.ed_keywords = QLineEdit()
        self.ed_keywords.setPlaceholderText("单位简称、项目名、爱好、品牌、生日等")
        r2.addWidget(self.ed_keywords, 1)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(6)
        self.chk_digits = QCheckBox("拼数字 0-9999")
        self.chk_digits.setChecked(True)
        r3.addWidget(self.chk_digits)
        self.chk_years = QCheckBox("拼年份 1990-2026")
        self.chk_years.setChecked(True)
        r3.addWidget(self.chk_years)
        r3.addWidget(label("特殊符号", "Dim"))
        self.ed_specials = QLineEdit("!@#$._")
        self.ed_specials.setFixedWidth(110)
        r3.addWidget(self.ed_specials)
        r3.addWidget(label("长度", "Dim"))
        self.sp_min = QSpinBox()
        self.sp_min.setRange(1, 64)
        self.sp_min.setValue(6)
        r3.addWidget(self.sp_min)
        r3.addWidget(label("~", "Dim"))
        self.sp_max = QSpinBox()
        self.sp_max.setRange(1, 64)
        self.sp_max.setValue(16)
        r3.addWidget(self.sp_max)
        r3.addWidget(label("上限", "Dim"))
        self.sp_cap = QSpinBox()
        self.sp_cap.setRange(1000, 2000000)
        self.sp_cap.setValue(200000)
        self.sp_cap.setSingleStep(50000)
        r3.addWidget(self.sp_cap)
        r3.addStretch(1)
        card.add(r3)

        r4 = QHBoxLayout()
        r4.setSpacing(6)
        btn_gen = QPushButton("▶ 生成字典")
        btn_gen.setObjectName("Primary")
        btn_gen.clicked.connect(self.do_generate)
        r4.addWidget(btn_gen)
        self.btn_save = QPushButton("保存到文件…")
        self.btn_save.setObjectName("Ghost")
        self.btn_save.setEnabled(False)
        self.btn_save.clicked.connect(self.save_generated)
        r4.addWidget(self.btn_save)
        btn_copy_words = QPushButton("复制全部")
        btn_copy_words.setObjectName("Ghost")
        btn_copy_words.clicked.connect(self.copy_generated)
        r4.addWidget(btn_copy_words)
        r4.addStretch(1)
        card.add(r4)

        self.lbl_gen = label("填姓名/关键词后点生成；上限用来防止内存被撑爆", "Dim")
        self.lbl_gen.setWordWrap(True)
        card.add(self.lbl_gen)
        lay.addWidget(card)

        lay.addWidget(label("预览（最多显示前 100 条）", "CardT"))
        self.txt_preview = QPlainTextEdit()
        self.txt_preview.setReadOnly(True)
        self.txt_preview.setObjectName("Mono")
        self.txt_preview.setMaximumBlockCount(200)
        lay.addWidget(self.txt_preview, 1)
        return w

    @safe_slot
    def do_generate(self):
        names = self.ed_names.text().strip()
        keywords = self.ed_keywords.text().strip()
        if not names and not keywords:
            QMessageBox.warning(self, "缺少输入", "至少填一个姓名拼音或关键词")
            return
        specials = [c for c in self.ed_specials.text().strip()] or None
        if self.sp_min.value() > self.sp_max.value():
            QMessageBox.warning(self, "长度不合法", "最小长度不能大于最大长度")
            return

        t0 = time.perf_counter()
        self.gen_words = HK.gen_social_dict(
            names=names, keywords=keywords,
            digits=self.chk_digits.isChecked(),
            years=None if self.chk_years.isChecked() else [],
            specials=specials,
            min_len=self.sp_min.value(), max_len=self.sp_max.value(),
            cap=self.sp_cap.value())
        self._gen_elapsed = time.perf_counter() - t0

        self.txt_preview.setPlainText("\n".join(self.gen_words[:100]))
        self.btn_save.setEnabled(bool(self.gen_words))
        if self.gen_words:
            self.lbl_gen.setText(f"共生成 {len(self.gen_words)} 条"
                                 f"（耗时 {self._gen_elapsed:.2f} 秒），"
                                 f"上限 {self.sp_cap.value()}；文件保存为 UTF-8")
            self.lbl_gen.setStyleSheet(f"color:{C_MINT};")
        else:
            self.lbl_gen.setText("没生成出任何内容，检查一下长度限制是不是太苛刻")
            self.lbl_gen.setStyleSheet(f"color:{C_YELLOW};")

    @safe_slot
    def save_generated(self):
        if not self.gen_words:
            QMessageBox.information(self, "没有内容", "先生成字典再保存")
            return
        path, _ = QFileDialog.getSaveFileName(self, "保存字典", "social_dict.txt",
                                              "文本文件 (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(self.gen_words))
                fh.write("\n")
        except OSError as exc:
            QMessageBox.warning(self, "保存失败", str(exc))
            return
        self.lbl_gen.setText(f"已保存 {len(self.gen_words)} 条到：{path}")
        log(f"社工字典已保存 {len(self.gen_words)} 条 -> {path}", "success", "hash")
        QMessageBox.information(self, "保存成功", f"已保存到：\n{path}")

    @safe_slot
    def copy_generated(self):
        if not self.gen_words:
            self.lbl_gen.setText("还没有可复制的内容")
            return
        QApplication.clipboard().setText("\n".join(self.gen_words))
        self.lbl_gen.setText(f"已复制 {len(self.gen_words)} 条到剪贴板")

    # ---------------- 收尾 ----------------

    @safe_slot
    def stop_all(self):
        """主窗口关闭时调用：把还在跑的爆破线程叫停。"""
        if self.worker is not None and self.worker.isRunning():
            self.cancel.set()
            self.worker.wait(3000)
