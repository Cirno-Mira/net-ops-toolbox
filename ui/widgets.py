# -*- coding: utf-8 -*-
"""通用控件：卡片、徽章、日志面板、延迟折线、表格工厂。"""

from __future__ import annotations

import functools
import html
import inspect
import traceback
from datetime import datetime

from PyQt5.QtCore import QObject, QRectF, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog,
                             QFrame, QHBoxLayout, QHeaderView, QLabel,
                             QMessageBox, QPlainTextEdit, QPushButton, QSizePolicy,
                             QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from core.logging_bus import BUS
from theme import LEVEL_COLORS, LEVEL_TAGS, STATE_COLORS, C_TEXT, C_TEXT_DIM


def crash_log_path() -> str:
    from core.paths import app_path
    return app_path("crash.log")


def safe_slot(fn):
    """
    Qt 槽函数装饰器 —— 很重要。

    PyQt5 碰到「槽函数里未捕获的异常」会直接调用 abort() 干掉整个进程
    （退出码 0xC0000409）。界面用 pythonw / 启动.vbs 跑的时候没有控制台，
    用户看到的就是莫名其妙的「一按就闪退」。

    这个装饰器把异常兜住：写进界面日志面板 + crash.log，程序继续运行。

    ⚠ 另一个坑：包装函数是 `(*args, **kwargs)`，PyQt5 看到「能接受任意个参数」
    就会把信号自带的参数也塞进来（比如 clicked(bool) 的 checked），
    导致 `start_spoof() takes 1 positional argument but 2 were given`。
    所以这里按被包装函数的真实形参个数做截断。
    """
    try:
        params = list(inspect.signature(fn).parameters.values())
        allowed = sum(1 for p in params
                      if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD))
        takes_varargs = any(p.kind == p.VAR_POSITIONAL for p in params)
    except (TypeError, ValueError):
        allowed, takes_varargs = None, True

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not takes_varargs and allowed is not None and len(args) > allowed:
            args = args[:allowed]
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            tb = traceback.format_exc()
            name = getattr(fn, "__name__", "slot")
            try:
                from core.logging_bus import log
                log(f"{name} 执行出错：{type(exc).__name__}: {exc}"
                    f"（完整堆栈见 crash.log）", "error", "ui")
            except Exception:
                pass
            try:
                with open(crash_log_path(), "a", encoding="utf-8") as fh:
                    fh.write(f"\n===== {datetime.now():%Y-%m-%d %H:%M:%S} "
                             f"[slot {name}] =====\n{tb}\n")
            except Exception:
                pass
            return None

    return wrapper


# --------------------------------------------------------------------------- #
# 基础
# --------------------------------------------------------------------------- #

class Card(QFrame):
    """白底圆角卡片，带可选标题行。"""

    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(14, 12, 14, 12)
        self._outer.setSpacing(8)
        self.head = QHBoxLayout()
        self.head.setSpacing(8)
        if title:
            lab = QLabel(title)
            lab.setObjectName("CardT")
            self.head.addWidget(lab)
        self.head.addStretch(1)
        self._outer.addLayout(self.head)
        self.body = QVBoxLayout()
        self.body.setSpacing(7)
        self._outer.addLayout(self.body)

    def add_head_widget(self, w: QWidget):
        self.head.addWidget(w)

    def add(self, w):
        if isinstance(w, QWidget):
            self.body.addWidget(w)
        else:
            self.body.addLayout(w)


class Badge(QLabel):
    """彩色状态小标签。"""

    def __init__(self, text: str = "", kind: str = "idle", parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignCenter)
        self.set_state(text, kind)

    def set_state(self, text: str, kind: str = "idle"):
        bg, fg = STATE_COLORS.get(kind, STATE_COLORS["idle"])
        self.setText(text)
        self.setStyleSheet(
            f"background-color:{bg}; color:{fg}; border-radius:9px;"
            f"padding:3px 10px; font-weight:700; font-size:9pt;")


def hline() -> QFrame:
    f = QFrame()
    f.setObjectName("Line")
    f.setFrameShape(QFrame.NoFrame)
    f.setFixedHeight(1)
    return f


def label(text: str, kind: str = "") -> QLabel:
    lab = QLabel(text)
    if kind:
        lab.setObjectName(kind)
    return lab


def make_table(headers: list[str], stretch_col: int | None = None) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSortingEnabled(True)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(26)
    hh = t.horizontalHeader()
    hh.setSectionResizeMode(QHeaderView.Interactive)
    hh.setHighlightSections(False)
    if stretch_col is not None:
        hh.setSectionResizeMode(stretch_col, QHeaderView.Stretch)
    else:
        hh.setStretchLastSection(True)
    return t


def set_row(table: QTableWidget, row: int, values: list, colors: dict | None = None):
    """写入一行（自动补 QTableWidgetItem，可指定某列颜色）。"""
    for col, val in enumerate(values):
        item = QTableWidgetItem("" if val is None else str(val))
        if colors and col in colors:
            item.setForeground(QColor(colors[col]))
        if col == 0:
            item.setData(Qt.UserRole, values[0])
        table.setItem(row, col, item)


def find_row(table: QTableWidget, key: str, col: int = 0) -> int:
    for r in range(table.rowCount()):
        it = table.item(r, col)
        if it is not None and it.text() == key:
            return r
    return -1


def selected_first_col(table: QTableWidget) -> list[str]:
    return [table.item(i.row(), 0).text()
            for i in table.selectionModel().selectedRows()
            if table.item(i.row(), 0) is not None]


# --------------------------------------------------------------------------- #
# 日志面板
# --------------------------------------------------------------------------- #

class LogBridge(QObject):
    """把核心层的日志总线接到 Qt 信号（跨线程安全）。"""

    message = pyqtSignal(str, str, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        BUS.subscribe(self._on_message)

    def _on_message(self, level: str, source: str, text: str, ts: str):
        self.message.emit(level, source, text, ts)


class LogPanel(QWidget):
    """底部日志面板：级别过滤 + 清空 + 导出。"""

    LEVEL_ORDER = {"debug": 0, "info": 1, "success": 1, "warn": 2, "error": 3}

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: list[tuple[str, str, str, str]] = []

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        title = QLabel("📋 运行日志")
        title.setObjectName("CardT")
        bar.addWidget(title)

        bar.addWidget(label("级别", "Dim"))
        self.cmb_level = QComboBox()
        self.cmb_level.addItems(["全部", "信息及以上", "警告及以上", "仅错误"])
        self.cmb_level.setCurrentIndex(0)
        self.cmb_level.currentIndexChanged.connect(self._rebuild)
        bar.addWidget(self.cmb_level)

        bar.addWidget(label("搜索", "Dim"))
        self.ed_search = QComboBox()
        self.ed_search.setEditable(True)
        self.ed_search.addItem("")
        self.ed_search.setMinimumWidth(150)
        self.ed_search.editTextChanged.connect(self._rebuild)
        bar.addWidget(self.ed_search)

        bar.addStretch(1)
        self.chk_auto = QCheckBox("自动滚动")
        self.chk_auto.setChecked(True)
        bar.addWidget(self.chk_auto)

        btn_clear = QPushButton("清空")
        btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(self.clear)
        bar.addWidget(btn_clear)

        btn_save = QPushButton("导出日志")
        btn_save.setObjectName("Ghost")
        btn_save.clicked.connect(self.export)
        bar.addWidget(btn_save)
        lay.addLayout(bar)

        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(6000)
        self.view.setFont(QFont("Cascadia Mono", 9))
        self.view.setMinimumHeight(110)
        lay.addWidget(self.view)

    # ---------- 数据 ----------

    def append(self, level: str, source: str, text: str, ts: str = ""):
        if not ts:
            ts = datetime.now().strftime("%H:%M:%S")
        rec = (level, source, text, ts)
        self._records.append(rec)
        if len(self._records) > 6000:
            del self._records[:2000]
        if self._pass_filter(rec):
            self._write(rec)

    def _pass_filter(self, rec) -> bool:
        level, _src, text, _ts = rec
        need = [None, 1, 2, 3][self.cmb_level.currentIndex()]
        if need is not None and self.LEVEL_ORDER.get(level, 1) < need:
            return False
        kw = self.ed_search.currentText().strip().lower()
        if kw and kw not in text.lower() and kw not in rec[1].lower():
            return False
        return True

    def _fmt(self, rec) -> str:
        level, src, text, ts = rec
        color = LEVEL_COLORS.get(level, LEVEL_COLORS["info"])
        tag = LEVEL_TAGS.get(level, level)
        return (f"<span style='color:#A79FBC'>{ts}</span> "
                f"<span style='color:{color};font-weight:700'>[{tag}]</span> "
                f"<span style='color:#8A7FA8'>{html.escape(src)}</span> "
                f"<span style='color:{color}'>{html.escape(text)}</span>")

    def _write(self, rec):
        self.view.appendHtml(self._fmt(rec))
        if self.chk_auto.isChecked():
            sb = self.view.verticalScrollBar()
            sb.setValue(sb.maximum())

    def _rebuild(self):
        self.view.clear()
        for rec in self._records:
            if self._pass_filter(rec):
                self._write(rec)

    def clear(self):
        self._records.clear()
        self.view.clear()

    def export(self):
        path, _ = QFileDialog.getSaveFileName(self, "导出日志", "netops_log.txt",
                                              "文本文件 (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                for level, src, text, ts in self._records:
                    fh.write(f"{ts}\t{LEVEL_TAGS.get(level, level)}\t{src}\t{text}\n")
            QMessageBox.information(self, "导出成功", f"已导出到：\n{path}")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))


# --------------------------------------------------------------------------- #
# 延迟折线
# --------------------------------------------------------------------------- #

class BarChart(QWidget):
    """
    横向柱状图（纯 QPainter 手绘，不依赖 matplotlib）。

    用来显示协议分布、Top 会话之类的统计。
    """

    PALETTE = ["#A78BFA", "#7FD8F7", "#FFB3C7", "#8FE9D7", "#FFD166",
               "#C4B5FD", "#93C5FD", "#FCA5A5"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(140)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.data: list[tuple[str, float]] = []
        self.unit = ""

    def set_data(self, data, unit: str = "") -> None:
        self.data = [(str(k), float(v)) for k, v in list(data)[:8]]
        self.unit = unit
        self.update()

    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor("#FFFFFF"))

        if not self.data:
            p.setPen(QPen(QColor(C_TEXT_DIM)))
            p.drawText(self.rect(), Qt.AlignCenter, "还没有统计数据")
            p.end()
            return

        top = max(v for _k, v in self.data) or 1.0
        row_h = max(18.0, min(28.0, (h - 8) / len(self.data)))
        label_w = 84.0
        value_w = 78.0
        bar_max = max(20.0, w - label_w - value_w - 16)

        f = QFont("Microsoft YaHei UI")
        f.setPointSizeF(8.5)
        p.setFont(f)

        for i, (name, val) in enumerate(self.data):
            y = 4 + i * row_h
            p.setPen(QPen(QColor("#8A7FA8")))
            p.drawText(QRectF(4, y, label_w - 6, row_h),
                       Qt.AlignVCenter | Qt.AlignLeft, name[:10])

            bar_w = bar_max * (val / top)
            rect = QRectF(label_w, y + row_h * 0.22, bar_w, row_h * 0.56)
            path = QPainterPath()
            path.addRoundedRect(rect, rect.height() / 2, rect.height() / 2)
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(self.PALETTE[i % len(self.PALETTE)]))
            p.drawPath(path)

            p.setPen(QPen(QColor(C_TEXT)))
            txt = f"{val:,.0f}{self.unit}" if val >= 1 else f"{val:.1f}{self.unit}"
            p.drawText(QRectF(w - value_w - 4, y, value_w, row_h),
                       Qt.AlignVCenter | Qt.AlignRight, txt)
        p.end()


class Sparkline(QWidget):
    """ping 延迟折线图（自动缩放，丢包用红点表示）。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(110)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.values: list[float | None] = []
        self.max_points = 240

    def push(self, rtt: float | None):
        self.values.append(rtt)
        if len(self.values) > self.max_points:
            del self.values[:len(self.values) - self.max_points]
        self.update()

    def clear(self):
        self.values.clear()
        self.update()

    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor("#FFFFFF"))

        # 网格
        p.setPen(QPen(QColor("#F1ECFA"), 1))
        for i in range(1, 4):
            y = h * i / 4
            p.drawLine(0, int(y), w, int(y))
        for i in range(1, 8):
            x = w * i / 8
            p.drawLine(int(x), 0, int(x), h)

        good = [v for v in self.values if v is not None]
        if not good:
            p.setPen(QPen(QColor(C_TEXT_DIM)))
            p.drawText(self.rect(), Qt.AlignCenter, "还没有数据")
            p.end()
            return

        top = max(good) * 1.15 or 1.0
        n = len(self.values)
        step = w / max(1, n - 1)

        path = QPainterPath()
        started = False
        for i, v in enumerate(self.values):
            if v is None:
                started = False
                continue
            x = i * step
            y = h - (v / top) * (h - 6) - 3
            if not started:
                path.moveTo(x, y)
                started = True
            else:
                path.lineTo(x, y)
        p.setPen(QPen(QColor("#7C5CFF"), 2))
        p.drawPath(path)

        # 丢包点
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#E8457C"))
        for i, v in enumerate(self.values):
            if v is None:
                p.drawEllipse(int(i * step) - 2, h // 2 - 2, 4, 4)

        # 刻度
        p.setPen(QPen(QColor(C_TEXT_DIM)))
        f = QFont("Microsoft YaHei UI")
        f.setPointSizeF(7.5)
        p.setFont(f)
        p.drawText(4, 12, f"{top:.0f} ms")
        p.drawText(4, h - 4, "0 ms")
        p.end()
