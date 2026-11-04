# -*- coding: utf-8 -*-
"""
SYN Flood 测试页
================

只发 SYN、不完成握手，用来验证目标的 SYN backlog / 连接表容量。
**只能用于你本人拥有或已获书面授权的目标。**

页面结构：

* 顶部红色授权横幅，没勾选之前「开始」一直是灰的；
* 目标、网卡、源地址、速率、时长、包数上限都可调；
* 开始前先「解析目标 MAC」和「探测端口」，确认链路真的通；
* 统计每 500ms 刷新一次，停止用独立 Event，点一下就断。
"""

from __future__ import annotations

from PyQt5.QtCore import QThread, QTimer, Qt, pyqtSignal
from PyQt5.QtWidgets import (QApplication, QCheckBox, QComboBox,
                             QFrame, QHBoxLayout, QLabel, QLineEdit,
                             QMessageBox, QProgressBar, QPushButton, QSpinBox,
                             QVBoxLayout, QWidget)

from core import hostinfo as HI
from core import synflood as S
from core.logging_bus import log
from theme import C_MINT, C_PINK, C_RED, C_TEXT_DIM, C_YELLOW
from ui.widgets import Card, label, safe_slot

SRC_MODES = [("本机 IP", "local"), ("随机源 IP", "random"), ("自定义源 IP", "custom")]


class ProbeTask(QThread):
    """探测 SYN+ACK，可能要等 1-2 秒，不能卡界面。"""

    done = pyqtSignal(object)

    def __init__(self, target: str, port: int, iface, dst_mac: str = "",
                 parent=None):
        super().__init__(parent)
        self.target = target
        self.port = port
        self.iface = iface
        self.dst_mac = dst_mac

    def run(self):
        try:
            self.done.emit(S.probe_syn(self.target, self.port, self.iface,
                                       self.dst_mac))
        except Exception as exc:
            self.done.emit((False, f"{type(exc).__name__}: {exc}"))


class SynFloodTab(QWidget):
    """SYN Flood 测试页。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.flood: S.SynFlood | None = None
        self._probe: ProbeTask | None = None
        self._last_snap: dict = {}
        self._finish_noted = False
        self._ifaces: list = []
        self._build()

        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self.refresh_stats)
        self.timer.start()

    # ==================== 界面 ====================

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)
        outer.addWidget(self._build_warning())
        outer.addWidget(self._build_control())
        outer.addWidget(self._build_stats(), 1)
        self.reload_ifaces()

    def _build_warning(self) -> QWidget:
        w = QFrame()
        w.setObjectName("Card")
        w.setStyleSheet("QFrame#Card { background-color:#FFF1F4;"
                        f" border:1px solid {C_PINK}; border-radius:14px; }}")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(4)
        title = QLabel("⚠️ SYN Flood 会真实占用目标连接表，只能用于你拥有或已获授权的目标")
        title.setStyleSheet(f"color:{C_RED}; font-weight:800; font-size:10.5pt;")
        title.setWordWrap(True)
        lay.addWidget(title)
        desc = QLabel(
            "工具只发半开 SYN，不完成三次握手，也不会在目标上留下持久化改动；"
            "但目标可能因此拒绝正常用户，甚至触发上游清洗/封禁。"
            "开始前建议先点「探测端口」确认链路可达；停止会立刻中断发送，"
            "建议从低速率、短时长开始。")
        desc.setWordWrap(True)
        desc.setObjectName("Dim")
        lay.addWidget(desc)
        row = QHBoxLayout()
        self.chk_auth = QCheckBox("我已获得该目标的测试授权，并理解上述风险")
        self.chk_auth.setStyleSheet("font-weight:700;")
        self.chk_auth.toggled.connect(self._refresh_buttons)
        row.addWidget(self.chk_auth)
        row.addStretch(1)
        lay.addLayout(row)
        return w

    def _build_control(self) -> QWidget:
        card = Card("🎯 目标与参数")

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("网卡", "Dim"))
        self.cmb_iface = QComboBox()
        self.cmb_iface.setMinimumWidth(300)
        self.cmb_iface.currentIndexChanged.connect(self._on_iface_changed)
        r1.addWidget(self.cmb_iface)
        btn_reload = QPushButton("刷新网卡")
        btn_reload.setObjectName("Ghost")
        btn_reload.clicked.connect(self.reload_ifaces)
        r1.addWidget(btn_reload)
        r1.addSpacing(8)
        r1.addWidget(label("目标 IP", "Dim"))
        self.ed_target = QLineEdit()
        self.ed_target.setPlaceholderText("例如 192.168.1.10")
        self.ed_target.setMinimumWidth(170)
        r1.addWidget(self.ed_target)
        r1.addWidget(label("端口", "Dim"))
        self.sp_port = QSpinBox()
        self.sp_port.setRange(1, 65535)
        self.sp_port.setValue(80)
        r1.addWidget(self.sp_port)
        r1.addStretch(1)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("目标 MAC", "Dim"))
        self.ed_dst_mac = QLineEdit()
        self.ed_dst_mac.setPlaceholderText("点右侧「解析」自动填；跨网段时自动用网关 MAC")
        self.ed_dst_mac.setMinimumWidth(260)
        r2.addWidget(self.ed_dst_mac)
        self.btn_resolve = QPushButton("解析目标 MAC")
        self.btn_resolve.setObjectName("Ghost")
        self.btn_resolve.clicked.connect(self.resolve_mac)
        r2.addWidget(self.btn_resolve)
        self.btn_probe = QPushButton("探测端口")
        self.btn_probe.setObjectName("Ghost")
        self.btn_probe.setToolTip("发一个 SYN，确认目标会回 SYN+ACK 或 RST")
        self.btn_probe.clicked.connect(self.probe_port)
        r2.addWidget(self.btn_probe)
        self.lbl_hint = label("", "Dim")
        r2.addWidget(self.lbl_hint)
        r2.addStretch(1)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(6)
        r3.addWidget(label("源地址", "Dim"))
        self.cmb_src = QComboBox()
        for text, data in SRC_MODES:
            self.cmb_src.addItem(text, data)
        self.cmb_src.currentIndexChanged.connect(self._on_src_changed)
        r3.addWidget(self.cmb_src)
        self.ed_src = QLineEdit()
        self.ed_src.setPlaceholderText("自定义源 IP，例如 192.168.1.200")
        self.ed_src.setMaximumWidth(180)
        self.ed_src.setEnabled(False)
        r3.addWidget(self.ed_src)
        r3.addSpacing(8)
        r3.addWidget(label("速率", "Dim"))
        self.sp_rate = QSpinBox()
        self.sp_rate.setRange(0, S.MAX_RATE)
        self.sp_rate.setValue(2000)
        self.sp_rate.setSingleStep(500)
        self.sp_rate.setSuffix(" pps")
        self.sp_rate.setSpecialValueText("不限速")
        self.sp_rate.setToolTip("0 = 不限速；建议先用几百 pps 验证链路")
        r3.addWidget(self.sp_rate)
        r3.addWidget(label("时长", "Dim"))
        self.sp_duration = QSpinBox()
        self.sp_duration.setRange(1, int(S.MAX_DURATION))
        self.sp_duration.setValue(10)
        self.sp_duration.setSuffix(" 秒")
        r3.addWidget(self.sp_duration)
        r3.addWidget(label("包数上限", "Dim"))
        self.sp_count = QSpinBox()
        self.sp_count.setRange(0, S.MAX_COUNT)
        self.sp_count.setValue(0)
        self.sp_count.setSingleStep(10000)
        self.sp_count.setSpecialValueText("不限")
        r3.addWidget(self.sp_count)
        r3.addWidget(label("批次", "Dim"))
        self.sp_batch = QSpinBox()
        self.sp_batch.setRange(1, 512)
        self.sp_batch.setValue(S.DEFAULT_BATCH)
        self.sp_batch.setToolTip("一次交给 Npcap 的包数；丢包多时调小")
        r3.addWidget(self.sp_batch)
        r3.addStretch(1)
        card.add(r3)

        r4 = QHBoxLayout()
        r4.setSpacing(10)
        self.chk_public = QCheckBox("允许公网目标")
        self.chk_public.setToolTip("默认只允许私有 / 链路本地地址")
        r4.addWidget(self.chk_public)
        self.chk_dry = QCheckBox("演练模式（只构造包，不发送）")
        self.chk_dry.setToolTip("不需要管理员权限，用来核对参数和报文构造")
        r4.addWidget(self.chk_dry)
        r4.addStretch(1)
        self.lbl_state = label("未开始", "Dim")
        self.lbl_state.setStyleSheet(f"color:{C_TEXT_DIM}; font-weight:700;")
        r4.addWidget(self.lbl_state)
        self.btn_start = QPushButton("▶ 开始测试")
        self.btn_start.setObjectName("Danger")
        self.btn_start.clicked.connect(self.start_test)
        r4.addWidget(self.btn_start)
        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Ghost")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_test)
        r4.addWidget(self.btn_stop)
        card.add(r4)
        return card

    def _build_stats(self) -> QWidget:
        card = Card("📈 发送统计")
        row = QHBoxLayout()
        row.setSpacing(18)
        self.lbl_sent = label("已发送 0", "CardT")
        row.addWidget(self.lbl_sent)
        self.lbl_failed = label("失败 0", "Dim")
        row.addWidget(self.lbl_failed)
        self.lbl_pps = label("0 pps", "Dim")
        row.addWidget(self.lbl_pps)
        self.lbl_mbps = label("0 Mbps", "Dim")
        row.addWidget(self.lbl_mbps)
        self.lbl_elapsed = label("0 秒", "Dim")
        row.addWidget(self.lbl_elapsed)
        row.addStretch(1)
        self.lbl_error = label("", "Dim")
        row.addWidget(self.lbl_error)
        card.add(row)

        self.pbar = QProgressBar()
        self.pbar.setRange(0, 100)
        self.pbar.setValue(0)
        card.add(self.pbar)

        tip = QLabel(
            "提示：目标端口关闭时通常会回 RST，说明链路和 MAC 都没问题；"
            "完全没有回应多半是 MAC 解析错、目标在别的 VLAN，或被防火墙静默丢弃。"
            "统计里的「已发送」是 Npcap 接受的包数，不代表目标一定收到。")
        tip.setWordWrap(True)
        tip.setObjectName("Dim")
        card.add(tip)
        card.body.addStretch(1)
        return card

    # ==================== 网卡 / 源地址 ====================

    @safe_slot
    def reload_ifaces(self) -> None:
        self.cmb_iface.blockSignals(True)
        self.cmb_iface.clear()
        self._ifaces = HI.list_ifaces()
        for iface in self._ifaces:
            self.cmb_iface.addItem(iface.label, iface)
        prim = HI.primary_iface()
        if prim is not None:
            for idx, iface in enumerate(self._ifaces):
                if iface.ip == prim.ip:
                    self.cmb_iface.setCurrentIndex(idx)
                    break
        self.cmb_iface.blockSignals(False)
        self._on_iface_changed()

    def current_iface(self):
        return self.cmb_iface.currentData()

    @safe_slot
    def _on_iface_changed(self, *_args) -> None:
        iface = self.current_iface()
        self.ed_dst_mac.clear()
        if iface is not None:
            self.lbl_hint.setText(
                f"本机 {iface.ip} / 网关 {iface.gateway or '-'}")
        self._refresh_buttons()

    @safe_slot
    def _on_src_changed(self, *_args) -> None:
        self.ed_src.setEnabled(self.cmb_src.currentData() == "custom")

    # ==================== MAC / 探测 ====================

    @safe_slot
    def resolve_mac(self) -> None:
        iface = self.current_iface()
        target = self.ed_target.text().strip()
        if iface is None:
            QMessageBox.warning(self, "没有网卡", "先选择网卡")
            return
        ok, why = S.validate_target(target, self.sp_port.value(),
                                    self.chk_public.isChecked())
        if not ok:
            QMessageBox.warning(self, "目标不可用", why)
            return
        self.lbl_hint.setText("解析 MAC 中…")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            mac = S.resolve_dst_mac(target, iface)
        finally:
            QApplication.restoreOverrideCursor()
        if mac:
            self.ed_dst_mac.setText(mac)
            self.lbl_hint.setText(f"已解析：{mac}")
            log(f"{target} 的 MAC = {mac}", "info", "synflood")
        else:
            self.lbl_hint.setText("解析失败")
            QMessageBox.warning(
                self, "解析失败",
                "拿不到目标 MAC。请确认目标在同一网段、网卡选对，"
                "或以管理员身份运行（ARP 请求需要原始套接字）。")

    @safe_slot
    def probe_port(self) -> None:
        iface = self.current_iface()
        target = self.ed_target.text().strip()
        if iface is None:
            QMessageBox.warning(self, "没有网卡", "先选择网卡")
            return
        ok, why = S.validate_target(target, self.sp_port.value(),
                                    self.chk_public.isChecked())
        if not ok:
            QMessageBox.warning(self, "目标不可用", why)
            return
        if self._probe is not None and self._probe.isRunning():
            return
        self.btn_probe.setEnabled(False)
        self.lbl_hint.setText("探测中…")
        self._probe = ProbeTask(target, self.sp_port.value(), iface,
                                self.ed_dst_mac.text().strip(), self)
        self._probe.done.connect(self._on_probe_done)
        self._probe.finished.connect(lambda: self.btn_probe.setEnabled(True))
        self._probe.start()

    @safe_slot
    def _on_probe_done(self, result) -> None:
        ok, detail = result if isinstance(result, tuple) else (False, str(result))
        self.lbl_hint.setText(detail)
        if ok:
            self.lbl_hint.setStyleSheet(f"color:{C_MINT};")
            log(detail, "success", "synflood")
        else:
            self.lbl_hint.setStyleSheet(f"color:{C_YELLOW};")
            log(detail, "warn", "synflood")

    # ==================== 起停 ====================

    def _refresh_buttons(self, *_args) -> None:
        running = self.flood is not None and self.flood.is_running()
        self.btn_start.setEnabled(bool(self.chk_auth.isChecked()) and not running)
        self.btn_stop.setEnabled(running)

    @safe_slot
    def start_test(self) -> None:
        if self.flood is not None and self.flood.is_running():
            return
        if not self.chk_auth.isChecked():
            QMessageBox.warning(self, "未确认授权", "请先勾选顶部的授权确认")
            return
        iface = self.current_iface()
        if iface is None:
            QMessageBox.warning(self, "没有网卡", "先选择网卡")
            return
        target = self.ed_target.text().strip()
        port = int(self.sp_port.value())
        allow_public = self.chk_public.isChecked()
        dry = self.chk_dry.isChecked()
        ok, why = S.validate_target(target, port, allow_public)
        if not ok:
            QMessageBox.warning(self, "目标不可用", why)
            return
        dst_mac = self.ed_dst_mac.text().strip()
        if not dst_mac:
            QMessageBox.warning(self, "缺少目标 MAC",
                                "请先点「解析目标 MAC」，确认链路后再开始")
            return
        if not dry and not HI.is_admin():
            QMessageBox.warning(self, "需要管理员",
                                "原始发包需要管理员权限 + Npcap。\n"
                                "可以先勾选「演练模式」检查参数。")
            return

        rate = int(self.sp_rate.value())
        duration = float(self.sp_duration.value())
        count = int(self.sp_count.value())
        summary = (f"目标：{target}:{port}\n"
                   f"网卡：{iface.alias}\n"
                   f"速率：{rate} pps" + ("（不限速）" if rate == 0 else "") + "\n"
                   f"时长：{duration:g} 秒\n"
                   f"包数上限：{count if count else '不限'}\n"
                   f"模式：{'演练（不发包）' if dry else '真实发送'}\n\n"
                   f"确认目标是你拥有或已获授权的吗？")
        if QMessageBox.question(self, "确认 SYN Flood 参数", summary) \
                != QMessageBox.Yes:
            return

        flood = S.SynFlood(
            target, port, iface, dst_mac=dst_mac,
            src_mode=self.cmb_src.currentData() or "local",
            src_ip=self.ed_src.text().strip(),
            rate=rate, duration=duration, count=count,
            batch=int(self.sp_batch.value()),
            allow_public=allow_public, dry_run=dry)
        ok, why = flood.check()
        if not ok:
            QMessageBox.warning(self, "参数不完整", why)
            return
        if not flood.start():
            QMessageBox.warning(self, "启动失败", "发送线程没有启动，详见日志")
            return
        self.flood = flood
        self._finish_noted = False
        self._last_snap = {}
        self.lbl_state.setText("运行中…")
        self.lbl_state.setStyleSheet(f"color:{C_RED}; font-weight:800;")
        self.lbl_error.setText("")
        self.pbar.setRange(0, 0)
        self._refresh_buttons()

    @safe_slot
    def stop_test(self) -> None:
        if self.flood is None:
            return
        self.lbl_state.setText("正在停止…")
        self.flood.stop()
        self.refresh_stats(force=True)
        self.lbl_state.setText("已停止")
        self.lbl_state.setStyleSheet(f"color:{C_YELLOW}; font-weight:700;")
        self._refresh_buttons()

    def is_running(self) -> bool:
        return bool(self.flood is not None and self.flood.is_running())

    # ==================== 统计 ====================

    @safe_slot
    def refresh_stats(self, force: bool = False) -> None:
        flood = self.flood
        if flood is None:
            if force:
                self._render(self._last_snap)
            return
        snap = flood.snapshot()
        self._last_snap = snap
        self._render(snap)
        if snap["running"]:
            duration = float(self.sp_duration.value())
            count = int(self.sp_count.value())
            if duration > 0:
                self.pbar.setRange(0, 100)
                self.pbar.setValue(min(100, int(snap["elapsed"] * 100 / duration)))
            elif count:
                self.pbar.setRange(0, 100)
                self.pbar.setValue(min(100, int(snap["sent"] * 100 / count)))
        elif not self._finish_noted:
            self._finish_noted = True
            self.pbar.setRange(0, 100)
            self.pbar.setValue(100)
            self.lbl_state.setText("已结束")
            self.lbl_state.setStyleSheet(f"color:{C_YELLOW}; font-weight:700;")
            self._refresh_buttons()

    def _render(self, snap: dict) -> None:
        if not snap:
            return
        self.lbl_sent.setText(f"已发送 {snap.get('sent', 0):,}")
        self.lbl_failed.setText(f"失败 {snap.get('failed', 0):,}")
        self.lbl_pps.setText(f"{snap.get('pps', 0):g} pps")
        self.lbl_mbps.setText(f"{snap.get('mbps', 0):g} Mbps")
        self.lbl_elapsed.setText(f"{snap.get('elapsed', 0):g} 秒")
        errors = snap.get("errors") or []
        if errors:
            self.lbl_error.setText(errors[-1][:60])
            self.lbl_error.setToolTip("\n".join(errors))
        else:
            self.lbl_error.setText("")

    # ==================== 收尾 ====================

    def shutdown(self) -> None:
        """主窗口关闭时调用。"""
        try:
            self.timer.stop()
        except Exception:
            pass
        if self.flood is not None:
            try:
                self.flood.stop()
            except Exception:
                pass
            self.flood = None
        probe = self._probe
        if probe is not None and probe.isRunning():
            try:
                probe.wait(3000)
            except Exception:
                pass
        self._probe = None
