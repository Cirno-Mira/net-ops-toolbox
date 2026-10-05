# -*- coding: utf-8 -*-
"""
压力测试页
==========

把「并发连接数测试」（TcpSessionBench 那类）和 TCP / UDP / ICMP / HTTP 压力、
慢速连接耗尽都收在这一页，全部支持自定义 IP / 域名 / 端口。

重活都在 `core.stress` 里，这里只负责收集参数、起停，以及每隔 500ms 把统计
刷到界面上。压测器用的是普通线程（不是 QThread），所以统计靠界面这边的
QTimer 主动拉取——不要试图从工作线程发信号，这套在本项目里踩过坑。
"""

from __future__ import annotations

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QFrame, QGridLayout,
                             QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                             QPushButton, QSpinBox, QStackedWidget,
                             QVBoxLayout, QWidget)

from core import hostinfo as HI
from core import stress as S
from core.logging_bus import log
from theme import C_MINT, C_PINK, C_RED, C_YELLOW
from ui.widgets import Card, label

# 每种压测器的显示名 -> (kind, 一句说明)
KIND_LIST = [
    ("并发连接数测试", "tcp-session",
     "建立并长期保持大量 TCP 连接，摸清目标的连接表容量（TcpSessionBench 那类）"),
    ("TCP 压力", "tcp-flood",
     "connect 模式跑完整握手后断开；syn 模式发半开连接（需管理员 + Npcap）"),
    ("UDP 压力", "udp-flood", "向目标端口持续发随机长度载荷，不需要管理员"),
    ("ICMP 压力", "icmp-flood", "Echo Request 洪泛（需管理员 + Npcap）"),
    ("HTTP 压力", "http-flood", "按指定方法并发请求，可复用连接、随机路径与 UA"),
    ("Slowloris 慢速连接", "slowloris", "请求头永远不发完并持续续命，占住服务端连接槽"),
]


def _spin(lo: int, hi: int, val: int, suffix: str = "", step: int = 1) -> QSpinBox:
    s = QSpinBox()
    s.setRange(lo, hi)
    s.setValue(val)
    s.setSingleStep(step)
    if suffix:
        s.setSuffix(suffix)
    return s


class StressTab(QWidget):
    """压力测试页。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.runner: S.StressBase | None = None
        self._resolved: list[str] = []
        self._build()

        # 统计刷新用的定时器：常驻但只在跑的时候干活
        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self._refresh_stats)
        self.timer.start()

    # ==================== 界面 ====================

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)

        outer.addWidget(self._build_warning())
        outer.addWidget(self._build_control())
        outer.addWidget(self._build_stats(), 1)

    def _build_warning(self) -> QWidget:
        w = QFrame()
        w.setObjectName("Card")
        w.setStyleSheet(f"QFrame#Card {{ background-color:#FFF1F4;"
                        f" border:1px solid {C_PINK}; border-radius:14px; }}")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(4)

        t = QLabel("⚠️ 只能用于你本人拥有、或已获得书面授权的目标")
        t.setStyleSheet(f"color:{C_RED}; font-weight:800; font-size:10.5pt;")
        lay.addWidget(t)

        d = QLabel("压力测试会真实占用目标的带宽、连接表与 CPU，测试期间对方业务"
                   "很可能不可用，还可能触发对方的告警与封禁。请在业务低峰期、"
                   "可控范围内使用，并提前和相关方确认。"
                   "本页不会在目标上留下任何持久化改动，点停止即断开全部连接。")
        d.setWordWrap(True)
        d.setObjectName("Dim")
        lay.addWidget(d)

        row = QHBoxLayout()
        self.chk_auth = QCheckBox("我已获得该目标的测试授权，并理解上述风险")
        self.chk_auth.setStyleSheet("font-weight:700;")
        self.chk_auth.toggled.connect(self._refresh_buttons)
        row.addWidget(self.chk_auth)
        row.addStretch(1)
        lay.addLayout(row)
        return w

    def _build_control(self) -> QWidget:
        card = Card("🎯 测试目标")

        # ---- 目标与端口 ----
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("目标", "Dim"))
        self.ed_target = QLineEdit()
        self.ed_target.setPlaceholderText(
            "IP 或域名，可多个：192.168.1.10、example.com、10.0.0.0/24")
        self.ed_target.textChanged.connect(self._on_target_changed)
        r1.addWidget(self.ed_target, 1)

        btn_local = QPushButton("本机")
        btn_local.setObjectName("Ghost")
        btn_local.setToolTip("填本机 IP，方便做本机回环自测")
        btn_local.clicked.connect(self._fill_local)
        r1.addWidget(btn_local)

        btn_resolve = QPushButton("解析")
        btn_resolve.setObjectName("Ghost")
        btn_resolve.setToolTip("把域名/网段展开成 IP 列表")
        btn_resolve.clicked.connect(self._do_resolve)
        r1.addWidget(btn_resolve)

        r1.addWidget(label("端口", "Dim"))
        self.sp_port = _spin(1, 65535, 80)
        r1.addWidget(self.sp_port)
        card.add(r1)

        self.lbl_resolved = label("还没解析目标", "Dim")
        self.lbl_resolved.setWordWrap(True)
        card.add(self.lbl_resolved)

        # ---- 测试类型 ----
        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("类型", "Dim"))
        self.cmb_kind = QComboBox()
        for name, _kind, _tip in KIND_LIST:
            self.cmb_kind.addItem(name)
        self.cmb_kind.currentIndexChanged.connect(self._on_kind_changed)
        r2.addWidget(self.cmb_kind, 1)
        card.add(r2)

        self.lbl_kind_tip = label("", "Dim")
        self.lbl_kind_tip.setWordWrap(True)
        card.add(self.lbl_kind_tip)

        # ---- 各类型的专属参数 ----
        self.stack = QStackedWidget()
        self.stack.addWidget(self._pane_session())
        self.stack.addWidget(self._pane_tcp())
        self.stack.addWidget(self._pane_udp())
        self.stack.addWidget(self._pane_icmp())
        self.stack.addWidget(self._pane_http())
        self.stack.addWidget(self._pane_slow())
        card.add(self.stack)

        # ---- 通用参数 ----
        r3 = QHBoxLayout()
        r3.setSpacing(8)
        r3.addWidget(label("线程", "Dim"))
        self.sp_threads = _spin(1, S.MAX_THREADS, 32, step=8)
        self.sp_threads.setToolTip("并发工作线程数；连接数测试里线程只负责建连，"
                                   "每个线程可以持有大量连接")
        r3.addWidget(self.sp_threads)

        r3.addWidget(label("限时", "Dim"))
        self.sp_duration = _spin(0, 86400, 60, " 秒")
        self.sp_duration.setToolTip("到点自动停止；0 = 不限时（手动停）")
        r3.addWidget(self.sp_duration)

        r3.addWidget(label("速率上限", "Dim"))
        self.ed_rate = QLineEdit()
        self.ed_rate.setPlaceholderText("留空=不限，可写 1k / 2M")
        self.ed_rate.setMaximumWidth(160)
        r3.addWidget(self.ed_rate)

        r3.addWidget(label("网卡", "Dim"))
        self.cmb_iface = QComboBox()
        self.cmb_iface.setMinimumWidth(150)
        self.cmb_iface.setToolTip("只有 syn / icmp 模式需要——它们走二层发包")
        r3.addWidget(self.cmb_iface, 1)

        btn_reload = QPushButton("刷新网卡")
        btn_reload.setObjectName("Ghost")
        btn_reload.clicked.connect(self.reload_ifaces)
        r3.addWidget(btn_reload)
        card.add(r3)

        # ---- 起停 ----
        r4 = QHBoxLayout()
        r4.setSpacing(8)
        self.btn_start = QPushButton("▶ 开始测试")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.start_test)
        r4.addWidget(self.btn_start)

        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_test)
        r4.addWidget(self.btn_stop)

        r4.addStretch(1)
        self.btn_ports = QPushButton("查看本机端口占用")
        self.btn_ports.setObjectName("Ghost")
        self.btn_ports.setToolTip("连接数测试很容易先把自己的动态端口用光，"
                                  "先看这里才能分清是谁扛不住")
        self.btn_ports.clicked.connect(self.show_port_usage)
        r4.addWidget(self.btn_ports)
        card.add(r4)

        self.reload_ifaces()
        self._on_kind_changed(0)
        return card

    # ---- 各类型参数面板 ----

    def _pane_session(self) -> QWidget:
        w = QWidget()
        g = QGridLayout(w)
        g.setContentsMargins(0, 0, 0, 0)
        g.addWidget(label("目标并发连接数", "Dim"), 0, 0)
        self.sp_conns = _spin(1, S.MAX_CONNECTIONS, 500, step=100)
        self.sp_conns.setToolTip("要同时挂住的连接数量")
        g.addWidget(self.sp_conns, 0, 1)
        g.addWidget(label("保持时长", "Dim"), 0, 2)
        self.sp_hold = _spin(0, 86400, 0, " 秒")
        self.sp_hold.setToolTip("0 = 一直保持到手动停止；填了就到点换新连接")
        g.addWidget(self.sp_hold, 0, 3)
        g.addWidget(label("存活检查间隔", "Dim"), 0, 4)
        self.sp_check = _spin(1, 600, 5, " 秒")
        g.addWidget(self.sp_check, 0, 5)
        g.setColumnStretch(6, 1)
        return w

    def _pane_tcp(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(label("模式", "Dim"))
        self.cmb_tcp_mode = QComboBox()
        self.cmb_tcp_mode.addItems(["connect（完整握手，免管理员）",
                                    "syn（半开连接，需管理员 + Npcap）"])
        h.addWidget(self.cmb_tcp_mode)
        h.addWidget(label("载荷字节", "Dim"))
        self.sp_tcp_payload = _spin(0, 1400, 0)
        h.addWidget(self.sp_tcp_payload)
        self.chk_spoof = QCheckBox("随机源 IP")
        self.chk_spoof.setToolTip("只在你自己控制的网段里才有意义；"
                                  "跨网段伪造通常会被上游丢弃")
        h.addWidget(self.chk_spoof)
        h.addStretch(1)
        return w

    def _pane_udp(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(label("载荷字节", "Dim"))
        self.sp_udp_payload = _spin(1, 65000, 512, step=128)
        h.addWidget(self.sp_udp_payload)
        h.addStretch(1)
        return w

    def _pane_icmp(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(label("载荷字节", "Dim"))
        self.sp_icmp_payload = _spin(0, 1400, 32, step=8)
        h.addWidget(self.sp_icmp_payload)
        h.addStretch(1)
        return w

    def _pane_http(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        r1 = QHBoxLayout()
        r1.addWidget(label("方法", "Dim"))
        self.cmb_http_method = QComboBox()
        self.cmb_http_method.addItems(["GET", "POST", "HEAD", "PUT"])
        r1.addWidget(self.cmb_http_method)
        self.chk_https = QCheckBox("HTTPS")
        r1.addWidget(self.chk_https)
        self.chk_keepalive = QCheckBox("复用连接")
        self.chk_keepalive.setChecked(True)
        self.chk_keepalive.setToolTip("勾上=同一条 TCP 连接连发；取消=每个请求新建连接")
        r1.addWidget(self.chk_keepalive)
        r1.addWidget(label("Host 头", "Dim"))
        self.ed_host = QLineEdit()
        self.ed_host.setPlaceholderText("留空则用目标 IP / 域名")
        r1.addWidget(self.ed_host, 1)
        v.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(label("请求路径", "Dim"))
        self.ed_paths = QLineEdit()
        self.ed_paths.setPlaceholderText("留空用内置的一组；多个用逗号分隔，例如 /a,/b")
        r2.addWidget(self.ed_paths, 1)
        v.addLayout(r2)
        return w

    def _pane_slow(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(label("目标连接数", "Dim"))
        self.sp_slow_conns = _spin(1, S.MAX_CONNECTIONS, 300, step=50)
        h.addWidget(self.sp_slow_conns)
        h.addWidget(label("续命间隔", "Dim"))
        self.sp_slow_keep = _spin(1, 600, 10, " 秒")
        h.addWidget(self.sp_slow_keep)
        h.addStretch(1)
        return w

    def _build_stats(self) -> QWidget:
        card = Card("📊 实时统计")
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(4)

        self.lbl_stats: dict[str, QLabel] = {}
        fields = [("sent", "已发"), ("ok", "成功"), ("fail", "失败"),
                  ("active", "当前连接"), ("peak_active", "连接峰值"),
                  ("rate", "速率"), ("elapsed", "已跑"), ("bytes", "出流量"),
                  ("rtt", "建连耗时"), ("error", "主要错误")]
        for col, (key, title) in enumerate(fields):
            grid.addWidget(label(title, "Dim"), 0, col)
            value = QLabel("—")
            value.setObjectName("Mono")
            self.lbl_stats[key] = value
            grid.addWidget(value, 1, col)
        grid.setColumnStretch(len(fields), 1)
        card.add(grid)

        self.lbl_state = label("空闲", "Dim")
        self.lbl_state.setWordWrap(True)
        card.add(self.lbl_state)
        return card

    # ==================== 交互 ====================

    def reload_ifaces(self) -> None:
        self.cmb_iface.clear()
        try:
            for i in HI.list_ifaces():
                self.cmb_iface.addItem(f"{i.name}  {i.ip}/{i.prefix}", i.l2_name or i.name)
        except Exception as exc:
            log(f"枚举网卡失败：{exc}", "warn", "stress")
        if self.cmb_iface.count() == 0:
            self.cmb_iface.addItem("（没有可用网卡）", "")

    def _fill_local(self) -> None:
        i = HI.primary_iface()
        if i and i.ip:
            self.ed_target.setText(i.ip)
        elif S.local_port_usage():
            self.ed_target.setText("127.0.0.1")

    def _on_target_changed(self) -> None:
        self._resolved = []
        self.lbl_resolved.setText("目标已改动，记得点「解析」")
        self.lbl_resolved.setStyleSheet(f"color:{C_YELLOW};")
        self._refresh_buttons()

    def _do_resolve(self) -> None:
        ips, note = S.resolve_target(self.ed_target.text())
        self._resolved = ips
        if ips:
            preview = "、".join(ips[:8]) + ("…" if len(ips) > 8 else "")
            self.lbl_resolved.setText(f"✅ {note}：{preview}")
            self.lbl_resolved.setStyleSheet(f"color:{C_MINT};")
        else:
            self.lbl_resolved.setText(f"❌ {note}")
            self.lbl_resolved.setStyleSheet(f"color:{C_RED};")
        self._refresh_buttons()

    def _on_kind_changed(self, idx: int) -> None:
        self.stack.setCurrentIndex(max(0, min(idx, self.stack.count() - 1)))
        _name, _kind, tip = KIND_LIST[idx]
        self.lbl_kind_tip.setText(tip)
        self._refresh_buttons()

    def current_kind(self) -> str:
        return KIND_LIST[self.cmb_kind.currentIndex()][1]

    def _refresh_buttons(self) -> None:
        running = self.runner is not None and self.runner.is_running()
        self.btn_start.setEnabled(bool(self.chk_auth.isChecked()) and not running)
        self.btn_stop.setEnabled(running)
        self.btn_start.setToolTip(
            "" if self.chk_auth.isChecked() else "先勾选上面的授权确认")

    # ==================== 起停 ====================

    def _build_runner(self) -> S.StressBase | None:
        kind = self.current_kind()
        targets = self._resolved or S.resolve_target(self.ed_target.text())[0]
        if not targets:
            QMessageBox.warning(self, "没有目标", "请填写并解析目标 IP / 域名")
            return None

        port = self.sp_port.value()
        threads = self.sp_threads.value()
        duration = float(self.sp_duration.value())
        rate = S.parse_rate(self.ed_rate.text())
        iface = self.cmb_iface.currentData() or ""

        if kind == "tcp-session":
            return S.TcpSessionTest(targets, port, connections=self.sp_conns.value(),
                                    threads=threads, hold=float(self.sp_hold.value()),
                                    check_interval=float(self.sp_check.value()),
                                    duration=duration)
        if kind == "tcp-flood":
            mode = "syn" if self.cmb_tcp_mode.currentIndex() == 1 else "connect"
            return S.TcpFlood(targets, port, mode=mode, threads=threads,
                              duration=duration, rate=rate, iface=iface,
                              spoof_source=self.chk_spoof.isChecked(),
                              payload_size=self.sp_tcp_payload.value())
        if kind == "udp-flood":
            return S.UdpFlood(targets, port, threads=threads, duration=duration,
                              rate=rate, payload_size=self.sp_udp_payload.value())
        if kind == "icmp-flood":
            return S.IcmpFlood(targets, threads=threads, duration=duration,
                               rate=rate, iface=iface,
                               payload_size=self.sp_icmp_payload.value())
        if kind == "http-flood":
            paths = [p.strip() for p in self.ed_paths.text().split(",") if p.strip()]
            return S.HttpFlood(targets, port, https=self.chk_https.isChecked(),
                               host_header=self.ed_host.text().strip(),
                               method=self.cmb_http_method.currentText(),
                               threads=threads, duration=duration, rate=rate,
                               keep_alive=self.chk_keepalive.isChecked(),
                               paths=paths or None)
        if kind == "slowloris":
            return S.Slowloris(targets, port, connections=self.sp_slow_conns.value(),
                               threads=threads, keepalive=float(self.sp_slow_keep.value()),
                               duration=duration,
                               host_header=self.ed_host.text().strip())
        return None

    def start_test(self) -> None:
        if self.runner is not None and self.runner.is_running():
            return
        if not self.chk_auth.isChecked():
            QMessageBox.warning(self, "未确认授权", "请先勾选页面顶部的授权确认")
            return

        runner = self._build_runner()
        if runner is None:
            return

        kind = runner.kind
        if kind in ("tcp-flood",) and getattr(runner, "mode", "") == "syn":
            if not HI.is_admin():
                QMessageBox.warning(self, "需要管理员",
                                    "syn 模式要发原始报文，请以管理员身份重启后再试")
                return
            if not runner.iface:
                QMessageBox.warning(self, "需要网卡", "syn 模式要先选一张网卡")
                return
        if kind == "icmp-flood":
            if not HI.is_admin():
                QMessageBox.warning(self, "需要管理员",
                                    "ICMP 压力要发原始报文，请以管理员身份重启后再试")
                return
            if not runner.iface:
                QMessageBox.warning(self, "需要网卡", "ICMP 压力要先选一张网卡")
                return

        # 大参数再确认一次，避免手滑把内网打穿
        duration = float(self.sp_duration.value())
        heavy = ""
        if isinstance(runner, S.TcpSessionTest) and runner.connections >= 5000:
            heavy = f"{runner.connections} 条并发连接"
        elif isinstance(runner, S.Slowloris) and runner.connections >= 2000:
            heavy = f"{runner.connections} 条慢速连接"
        elif duration == 0 and kind != "tcp-session":
            heavy = "不限时的持续压测"
        if heavy:
            if QMessageBox.question(
                    self, "确认压力参数",
                    f"即将对 {len(runner.targets)} 个目标发起 {heavy}。\n\n"
                    f"确认目标是你拥有或已获授权的吗？") != QMessageBox.Yes:
                return

        self.runner = runner
        if not runner.start():
            self.runner = None
            QMessageBox.warning(self, "启动失败", "压测器没有启动，请检查目标和参数")
            return
        self.lbl_state.setText(f"运行中：{runner.title}")
        self.lbl_state.setStyleSheet(f"color:{C_MINT};")
        self._refresh_buttons()

    def stop_test(self) -> None:
        if self.runner is None:
            return
        self.lbl_state.setText("正在停止…")
        self.runner.stop()
        self._refresh_stats()
        self.lbl_state.setText("已停止")
        self.lbl_state.setStyleSheet(f"color:{C_YELLOW};")
        self._refresh_buttons()

    def shutdown(self) -> None:
        """主窗口关闭时调用：一定要把压测线程收干净。"""
        try:
            self.timer.stop()
        except Exception:
            pass
        if self.runner is not None and self.runner.is_running():
            self.runner.stop()

    # ==================== 统计刷新 ====================

    def _refresh_stats(self) -> None:
        running = self.runner is not None and self.runner.is_running()
        if self.runner is None:
            self._refresh_buttons()
            return

        snap = self.runner.snapshot()
        self.lbl_stats["sent"].setText(f"{snap['sent']:,}")
        self.lbl_stats["ok"].setText(f"{snap['ok']:,}")
        self.lbl_stats["fail"].setText(f"{snap['fail']:,}")
        self.lbl_stats["active"].setText(f"{snap['active']:,}")
        self.lbl_stats["peak_active"].setText(f"{snap['peak_active']:,}")
        self.lbl_stats["rate"].setText(f"{snap['rate']:.0f}/s")
        self.lbl_stats["elapsed"].setText(_hms(snap["elapsed"]))
        self.lbl_stats["bytes"].setText(_size(snap["bytes_out"]))
        self.lbl_stats["rtt"].setText(
            f"{snap['rtt_avg_ms']:.1f}ms" if snap["rtt_avg_ms"] else "—")
        errs = snap["errors"]
        self.lbl_stats["error"].setText(
            "、".join(f"{k}×{v}" for k, v in errs) if errs else "无")

        self.lbl_stats["fail"].setStyleSheet(
            f"color:{C_RED};" if snap["fail"] else "")

        # 连接数明显达不到目标时给一句人话提示
        note = ""
        if isinstance(self.runner, (S.TcpSessionTest, S.Slowloris)):
            target = self.runner.connections
            if snap["active"] < target * 0.6 and snap["elapsed"] > 3:
                note = (f"（只挂住 {snap['active']}/{target} —— 可能是目标拒绝、"
                        f"本机动态端口不够，或线程数太少）")
        self.lbl_state.setText(
            ("运行中：%s  %s" % (self.runner.title, note)) if note
            else ("运行中：%s" % self.runner.title))
        self.lbl_state.setStyleSheet(f"color:{C_MINT};" if running else f"color:{C_YELLOW};")

        if not running:
            self._refresh_buttons()

    def show_port_usage(self) -> None:
        usage = S.local_port_usage()
        tcp = usage.get("tcp", 0)
        udp = usage.get("udp", 0)
        states = "、".join(f"{k} {v}" for k, v in
                           sorted(usage.get("states", {}).items(),
                                  key=lambda kv: -kv[1])[:6]) or "—"
        log(f"本机连接：TCP {tcp} 条 / UDP {udp} 条；状态分布 {states}", "info", "stress")
        self.lbl_state.setText(
            f"本机当前 TCP {tcp} 条、UDP {udp} 条。"
            f"Windows 默认动态端口约 1.6 万个，连接数测试打到 {tcp} 以上就可能"
            f"先耗光本机端口，而不是目标扛不住。")
        self.lbl_state.setStyleSheet(f"color:{C_YELLOW};")


def _hms(seconds: float) -> str:
    total = max(0, int(seconds))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def _size(n: int) -> str:
    v = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024 or unit == "GB":
            return f"{v:.0f}{unit}" if unit == "B" else f"{v:.1f}{unit}"
        v /= 1024
    return f"{v:.1f}GB"
