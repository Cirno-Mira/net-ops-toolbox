# -*- coding: utf-8 -*-
"""
穿透隧道页
==========

三个功能区 + 一个交互控制台：

  ① 端口转发    本地监听 → 目标 IP:端口（TCP / UDP）
  ② 反向监听    等目标机器的 shell 连回来，然后在这里敲命令
  ③ 正向连接    直接连目标已开好的 shell 端口

⚠ 只能用于你本人拥有或已获书面授权的目标。本工具只做连接管理与字节收发，
不生成 payload、不做免杀、不做持久化。
"""

from __future__ import annotations

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QLineEdit,
                             QMessageBox, QPlainTextEdit, QPushButton,
                             QScrollArea, QSpinBox, QSplitter, QVBoxLayout,
                             QWidget)

from core import hostinfo as HI
from core import tunnel as TN
from ui.widgets import Card, label, make_table, safe_slot, set_row
from theme import C_MINT, C_RED, C_TEXT_DIM

FWD_HEADERS = ["ID", "协议", "本地监听", "转发到", "状态", "连接数", "收/发", "错误"]
SESS_HEADERS = ["ID", "类型", "对端", "建立时间", "收", "发", "状态"]


class TunnelTab(QWidget):
    session_opened = pyqtSignal(object)
    data_received = pyqtSignal(int, bytes)
    session_closed = pyqtSignal(int)
    stat_update = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.forwards: dict[int, object] = {}
        self.sessions: dict[int, TN.Session] = {}
        self._fid = 0
        self._sid = 0
        self.shell_server: TN.ShellServer | None = None
        self._build()
        self.session_opened.connect(self._on_session)
        self.data_received.connect(self._on_data)
        self.session_closed.connect(self._on_closed)
        self.stat_update.connect(self._on_stat)

    # ---------------- 界面 ----------------

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(8)

        warn = QLabel("⚠ 只能用于你本人拥有或已获书面授权的目标。"
                      "本页只做连接管理与字节收发，不生成 payload、不做免杀/持久化。")
        warn.setWordWrap(True)
        warn.setStyleSheet(
            f"background:#FFF1F4; border:1px solid #E8457C; border-radius:12px;"
            f"padding:8px 12px; color:{C_RED}; font-weight:700;")
        outer.addWidget(warn)

        split = QSplitter(Qt.Horizontal)

        # ---- 左：三个功能区 ----
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QScrollArea.NoFrame)
        left_host = QWidget()
        left = QVBoxLayout(left_host)
        left.setContentsMargins(0, 0, 6, 0)
        left.setSpacing(8)
        left.addWidget(self._card_forward())
        left.addWidget(self._card_listen())
        left.addWidget(self._card_connect())
        left.addStretch(1)
        left_scroll.setWidget(left_host)
        left_scroll.setMinimumWidth(430)
        split.addWidget(left_scroll)

        # ---- 右：会话 + 控制台 ----
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(8)

        sc = Card("💬 会话")
        bar = QHBoxLayout()
        self.lbl_sess = label("还没有会话", "Dim")
        bar.addWidget(self.lbl_sess)
        bar.addStretch(1)
        btn_close = QPushButton("断开选中")
        btn_close.setObjectName("Ghost")
        btn_close.clicked.connect(self.close_selected)
        btn_all = QPushButton("全部断开")
        btn_all.setObjectName("Ghost")
        btn_all.clicked.connect(self.close_all)
        bar.addWidget(btn_close)
        bar.addWidget(btn_all)
        sc.add(bar)
        self.tbl_sess = make_table(SESS_HEADERS, stretch_col=None)
        self.tbl_sess.setColumnWidth(0, 46)
        self.tbl_sess.setColumnWidth(1, 70)
        self.tbl_sess.setColumnWidth(2, 150)
        self.tbl_sess.setColumnWidth(3, 90)
        self.tbl_sess.setMinimumHeight(140)
        self.tbl_sess.itemSelectionChanged.connect(self._on_pick_session)
        sc.add(self.tbl_sess)
        rl.addWidget(sc)

        cc = Card("⌨ 交互控制台")
        row = QHBoxLayout()
        self.lbl_target = label("未选择会话", "Dim")
        row.addWidget(self.lbl_target)
        row.addStretch(1)
        row.addWidget(label("行尾", "Dim"))
        self.cmb_eol = QComboBox()
        self.cmb_eol.addItems([r"\n (Linux)", r"\r\n (Windows)", "无"])
        row.addWidget(self.cmb_eol)
        btn_clear = QPushButton("清屏")
        btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(lambda: self.txt_out.clear())
        row.addWidget(btn_clear)
        cc.add(row)

        self.txt_out = QPlainTextEdit()
        self.txt_out.setReadOnly(True)
        self.txt_out.setFont(QFont("Cascadia Mono", 9))
        self.txt_out.setPlaceholderText(
            "选中一个会话后，在这里看输出；在下面输入命令回车即发送。")
        cc.add(self.txt_out)

        send = QHBoxLayout()
        self.ed_cmd = QLineEdit()
        self.ed_cmd.setPlaceholderText("输入命令后回车发送（↑ 可翻历史）")
        self.ed_cmd.returnPressed.connect(self.send_command)
        self._history: list[str] = []
        self._hist_idx = 0
        self.btn_send = QPushButton("发送")
        self.btn_send.setObjectName("Primary")
        self.btn_send.clicked.connect(self.send_command)
        send.addWidget(self.ed_cmd, 1)
        send.addWidget(self.btn_send)
        cc.add(send)
        rl.addWidget(cc, 1)

        split.addWidget(right)
        split.setSizes([460, 620])
        outer.addWidget(split, 1)

    def _card_forward(self) -> QWidget:
        card = Card("① 端口转发（本地监听 → 目标）")
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("本地端口", "Dim"))
        self.sp_lport = QSpinBox()
        self.sp_lport.setRange(1, 65535)
        self.sp_lport.setValue(8080)
        r1.addWidget(self.sp_lport)
        r1.addWidget(label("→ 目标", "Dim"))
        self.ed_thost = QLineEdit()
        self.ed_thost.setPlaceholderText("目标 IP")
        r1.addWidget(self.ed_thost, 1)
        self.sp_tport = QSpinBox()
        self.sp_tport.setRange(1, 65535)
        self.sp_tport.setValue(80)
        r1.addWidget(self.sp_tport)
        self.cmb_proto = QComboBox()
        self.cmb_proto.addItems(["TCP", "UDP"])
        r1.addWidget(self.cmb_proto)
        card.add(r1)

        r2 = QHBoxLayout()
        b_add = QPushButton("➕ 添加转发")
        b_add.setObjectName("Primary")
        b_add.clicked.connect(self.add_forward)
        b_stop = QPushButton("停止选中")
        b_stop.setObjectName("Ghost")
        b_stop.clicked.connect(self.stop_selected_forward)
        b_fill = QPushButton("填本机网段目标")
        b_fill.setObjectName("Ghost")
        b_fill.clicked.connect(self._fill_target)
        r2.addWidget(b_add)
        r2.addWidget(b_stop)
        r2.addWidget(b_fill)
        r2.addStretch(1)
        card.add(r2)

        self.tbl_fwd = make_table(FWD_HEADERS)
        self.tbl_fwd.setColumnWidth(0, 40)
        self.tbl_fwd.setColumnWidth(1, 50)
        self.tbl_fwd.setColumnWidth(2, 120)
        self.tbl_fwd.setColumnWidth(3, 130)
        self.tbl_fwd.setMinimumHeight(110)
        card.add(self.tbl_fwd)
        return card

    def _card_listen(self) -> QWidget:
        card = Card("② 反向 Shell 监听（等目标连回来）")
        r = QHBoxLayout()
        r.setSpacing(6)
        r.addWidget(label("监听地址", "Dim"))
        self.cmb_lip = QComboBox()
        self.cmb_lip.addItem("0.0.0.0")
        for ip in TN.local_ips():
            self.cmb_lip.addItem(ip)
        r.addWidget(self.cmb_lip)
        r.addWidget(label("端口", "Dim"))
        self.sp_lport2 = QSpinBox()
        self.sp_lport2.setRange(1, 65535)
        self.sp_lport2.setValue(4444)
        r.addWidget(self.sp_lport2)
        self.btn_listen = QPushButton("▶ 开始监听")
        self.btn_listen.setObjectName("Primary")
        self.btn_listen.clicked.connect(self.toggle_listen)
        r.addWidget(self.btn_listen)
        r.addStretch(1)
        card.add(r)
        self.lbl_listen = label("未监听", "Dim")
        self.lbl_listen.setWordWrap(True)
        card.add(self.lbl_listen)
        return card

    def _card_connect(self) -> QWidget:
        card = Card("③ 正向连接（连到目标已开好的 shell）")
        r = QHBoxLayout()
        r.setSpacing(6)
        r.addWidget(label("目标", "Dim"))
        self.ed_chost = QLineEdit()
        self.ed_chost.setPlaceholderText("目标 IP")
        r.addWidget(self.ed_chost, 1)
        self.sp_cport = QSpinBox()
        self.sp_cport.setRange(1, 65535)
        self.sp_cport.setValue(4444)
        r.addWidget(self.sp_cport)
        btn = QPushButton("🔌 连接")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.do_connect)
        r.addWidget(btn)
        card.add(r)
        return card

    # ---------------- 端口转发 ----------------

    def _fill_target(self):
        i = HI.primary_iface()
        if i:
            self.ed_thost.setText(i.gateway or i.ip)

    @safe_slot
    def add_forward(self):
        target = self.ed_thost.text().strip()
        if not target:
            QMessageBox.warning(self, "缺少目标", "请填写目标 IP")
            return
        self._fid += 1
        lport, tport = self.sp_lport.value(), self.sp_tport.value()
        proto = self.cmb_proto.currentText()
        cls = TN.TcpForwarder if proto == "TCP" else TN.UdpForwarder
        fwd = cls(self._fid, "0.0.0.0", lport, target, tport,
                  on_stat=self.stat_update.emit)
        self.forwards[self._fid] = fwd
        fwd.start()
        t = self.tbl_fwd
        t.setSortingEnabled(False)
        row = t.rowCount()
        t.insertRow(row)
        set_row(t, row, fwd.stat.row(), {4: C_MINT})
        t.setSortingEnabled(True)

    @safe_slot
    def stop_selected_forward(self):
        rows = {i.row() for i in self.tbl_fwd.selectionModel().selectedRows()}
        if not rows:
            rows = set(range(self.tbl_fwd.rowCount()))
        for r in rows:
            it = self.tbl_fwd.item(r, 0)
            if it is None:
                continue
            try:
                fid = int(it.text())
            except ValueError:
                continue
            fwd = self.forwards.pop(fid, None)
            if fwd:
                fwd.stop()
                set_row(self.tbl_fwd, r, ["", "", "", "", "已停止", "", "", ""],
                        {4: C_TEXT_DIM})

    @safe_slot
    def _on_stat(self, stat):
        for r in range(self.tbl_fwd.rowCount()):
            it = self.tbl_fwd.item(r, 0)
            if it is not None and it.text() == str(stat.fid):
                set_row(self.tbl_fwd, r, stat.row(),
                        {4: C_MINT if stat.running else C_TEXT_DIM})
                break

    # ---------------- 反向监听 ----------------

    @safe_slot
    def toggle_listen(self):
        if self.shell_server is not None and self.shell_server.is_alive():
            self.shell_server.stop()
            self.shell_server = None
            self.btn_listen.setText("▶ 开始监听")
            self.lbl_listen.setText("未监听")
            return
        ip = self.cmb_lip.currentText()
        port = self.sp_lport2.value()
        self.shell_server = TN.ShellServer(
            ip, port,
            on_session=self.session_opened.emit,
            on_data=self.data_received.emit,
            on_close=self.session_closed.emit,
            on_stat=self.stat_update.emit)
        self.shell_server.start()
        self.btn_listen.setText("■ 停止监听")
        self.lbl_listen.setText(
            f"正在监听 {ip}:{port} —— 在目标机器上执行反弹命令，"
            f"连上来后会自动出现在右边的会话列表里")

    # ---------------- 正向连接 ----------------

    @safe_slot
    def do_connect(self):
        host = self.ed_chost.text().strip()
        if not host:
            QMessageBox.warning(self, "缺少目标", "请填写目标 IP")
            return
        self._sid += 1
        try:
            sess = TN.connect_shell(host, self.sp_cport.value(),
                                    on_data=self.data_received.emit,
                                    on_close=self.session_closed.emit,
                                    sid=self._sid)
        except Exception as exc:
            QMessageBox.warning(self, "连接失败", f"{type(exc).__name__}: {exc}")
            return
        self.session_opened.emit(sess)

    # ---------------- 会话 ----------------

    @safe_slot
    def _on_session(self, sess: TN.Session):
        self.sessions[sess.sid] = sess
        t = self.tbl_sess
        t.setSortingEnabled(False)
        row = t.rowCount()
        t.insertRow(row)
        set_row(t, row, sess.row(), {6: C_MINT})
        t.setSortingEnabled(True)
        self.lbl_sess.setText(f"{len(self.sessions)} 个会话")
        self.tbl_sess.selectRow(row)
        self.txt_out.appendPlainText(f"\n===== {sess.name}  {sess.peer} 已建立 =====\n")

    @safe_slot
    def _on_data(self, sid: int, data: bytes):
        sess = self.sessions.get(sid)
        if sess is None:
            return
        if self._current_sid() != sid:
            return                        # 只看当前选中会话的输出
        text = data.decode("utf-8", "replace")
        if "\r" in text and "\n" not in text:
            text = text.replace("\r", "\n")
        self.txt_out.moveCursor(self.txt_out.textCursor().End)
        self.txt_out.insertPlainText(text)
        sb = self.txt_out.verticalScrollBar()
        sb.setValue(sb.maximum())
        self._refresh_session_row(sess)

    @safe_slot
    def _on_closed(self, sid: int):
        sess = self.sessions.get(sid)
        if sess:
            self._refresh_session_row(sess)
        self.lbl_sess.setText(f"{len(self.sessions)} 个会话")

    def _refresh_session_row(self, sess: TN.Session):
        for r in range(self.tbl_sess.rowCount()):
            it = self.tbl_sess.item(r, 0)
            if it is not None and it.text() == str(sess.sid):
                set_row(self.tbl_sess, r, sess.row(),
                        {6: C_MINT if sess.alive else C_TEXT_DIM})
                return

    def _current_sid(self) -> int:
        row = self.tbl_sess.currentRow()
        if row < 0:
            return -1
        it = self.tbl_sess.item(row, 0)
        try:
            return int(it.text()) if it else -1
        except ValueError:
            return -1

    @safe_slot
    def _on_pick_session(self):
        sid = self._current_sid()
        sess = self.sessions.get(sid)
        if sess is None:
            self.lbl_target.setText("未选择会话")
            return
        self.lbl_target.setText(f"当前：{sess.name}  {sess.peer}")
        self.txt_out.clear()
        self.txt_out.appendPlainText(f"===== {sess.name}  {sess.peer} =====\n")

    def current_session(self) -> TN.Session | None:
        return self.sessions.get(self._current_sid())

    @safe_slot
    def send_command(self):
        text = self.ed_cmd.text()
        sess = self.current_session()
        if sess is None:
            QMessageBox.information(self, "没有选中会话", "先在会话列表里点一个")
            return
        if not sess.alive:
            QMessageBox.warning(self, "会话已断开", "这个会话已经断开了")
            return
        data = text.encode("utf-8", "replace")
        eol = self.cmb_eol.currentText()
        if eol.startswith(r"\r\n"):
            data += b"\r\n"
        elif eol.startswith(r"\n"):
            data += b"\n"
        if not sess.send(data):
            QMessageBox.warning(self, "发送失败", "会话可能已经断开")
            return
        self.txt_out.appendPlainText(f"\n$ {text}")
        if text:
            self._history.append(text)
            self._hist_idx = len(self._history)
        self.ed_cmd.clear()
        self._refresh_session_row(sess)

    @safe_slot
    def close_selected(self):
        sess = self.current_session()
        if sess:
            sess.close()
            self._refresh_session_row(sess)

    @safe_slot
    def close_all(self):
        for sess in list(self.sessions.values()):
            sess.close()
            self._refresh_session_row(sess)

    def keyPressEvent(self, ev):
        # 上下键翻命令历史
        if self.ed_cmd.hasFocus() and self._history:
            if ev.key() == Qt.Key_Up:
                self._hist_idx = max(0, self._hist_idx - 1)
                self.ed_cmd.setText(self._history[self._hist_idx])
                return
            if ev.key() == Qt.Key_Down:
                self._hist_idx = min(len(self._history), self._hist_idx + 1)
                self.ed_cmd.setText(
                    self._history[self._hist_idx] if self._hist_idx < len(self._history) else "")
                return
        super().keyPressEvent(ev)

    # ---------------- 退出 ----------------

    def shutdown(self):
        for fwd in list(self.forwards.values()):
            try:
                fwd.stop()
            except Exception:
                pass
        self.forwards.clear()
        if self.shell_server is not None:
            try:
                self.shell_server.stop()
            except Exception:
                pass
            self.shell_server = None
        for sess in list(self.sessions.values()):
            try:
                sess.close()
            except Exception:
                pass
